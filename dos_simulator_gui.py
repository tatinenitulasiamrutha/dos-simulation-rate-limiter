"""
DoS Simulation & Rate Limiting Tool
------------------------------------
A self-contained educational tool that demonstrates:
  1. A Flask server protected by a sliding-window rate limiter.
  2. A multi-threaded "attacker" client that floods the server with
     requests to show the rate limiter kicking in (HTTP 429).
  3. A Tkinter/ttkbootstrap GUI to control both sides and watch live
     stats (Requests Sent / 200 OK / 429 Blocked) and a scrolling log.
  4. [Enhancement #1] A browser-based dashboard (/dashboard) and a
     JSON API (/api/stats) that mirror the desktop GUI's live stats,
     so the same data can be watched from a browser or polled by
     other tools.
  5. [Enhancement #2] A simulated defense chain the request passes
     through before it reaches the app: Firewall (blocklist) -> WAF
     (pattern filter) -> Load Balancer (worker tag) -> Rate Limiter.
     Live CPU/memory graphs (via psutil) show system load during an
     attack, in both the desktop GUI and the web dashboard.
  6. [Enhancement #3] Defense Automation: repeat offenders are
     auto-blacklisted by the firewall for 60 seconds; a background
     sweep thread lifts the block automatically on expiry ("Auto
     Unblock"), and every block/unblock is logged with timestamps in
     a Blocked IPs table (desktop GUI + web dashboard).
  7. [Enhancement #4] AI/ML-based anomaly detection: a small
     IsolationForest classifies each active IP as "Normal" or
     "Attack" from live request-rate, error-ratio and timing-entropy
     features, shown live in both the desktop GUI and the dashboard.
  8. [Enhancement #5] Logging, Reporting & Alerting: every request
     event and every alert-worthy moment (firewall block/unblock, ML
     flips an IP to "Attack") is persisted to a SQLite database
     (dos_simulator_log.db). An "Alerts" panel shows recent alerts
     live, and a "Generate Security Report" button builds a
     timestamped HTML report summarizing the session.

IMPORTANT: This tool only ever talks to 127.0.0.1 (itself). It is for
learning about rate limiting / DoS defense on your own machine, not
for attacking anything else.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
import threading
import time
import os
import webbrowser
from datetime import datetime
from queue import Queue, Empty

from flask import Flask, request, jsonify, render_template_string
from collections import deque
import requests
import logging
import werkzeug
import re
from urllib.parse import unquote_plus
import psutil
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Silence Flask's default per-request console logging; the GUI has its
# own request log instead.
logging.getLogger("werkzeug").setLevel(logging.ERROR)
werkzeug.serving.WSGIRequestHandler.log_request = lambda *a, **k: None


# --- 1. THE BACKEND: SERVER & RATE LIMITER LOGIC ---------------------

app = Flask(__name__)

request_counts = {}          # ip -> list[timestamp]
TIME_WINDOW = 30             # seconds
MAX_REQUESTS = 5             # requests allowed per IP per window
_lock = threading.Lock()     # request_counts is shared across threads

# --- Server-side stats, for the web dashboard / API (Enhancement #1) ---
server_stats = {"total": 0, "allowed": 0, "blocked": 0}
recent_events = deque(maxlen=50)   # most-recent-first ring buffer for the dashboard table
_stats_lock = threading.Lock()

# Per-IP request history (timestamp, status_code), used to build the ML
# features in Enhancement #4. Kept separate from rate_limit()'s own
# timestamp-only history because the ML model also needs status codes.
ip_request_log = {}    # ip -> deque[(timestamp, status_code)]
IP_LOG_MAXLEN = 100


def rate_limit(ip_address: str) -> bool:
    """Return True if the request from ip_address should be blocked."""
    current_time = time.time()
    with _lock:
        history = request_counts.get(ip_address, [])
        history = [t for t in history if t > current_time - TIME_WINDOW]
        history.append(current_time)
        request_counts[ip_address] = history
        return len(history) > MAX_REQUESTS


def _record_event(ip_address: str, status_code: int, layer: str):
    with _stats_lock:
        server_stats["total"] += 1
        if status_code == 200:
            server_stats["allowed"] += 1
        else:
            server_stats["blocked"] += 1
        layer_counts[layer] = layer_counts.get(layer, 0) + 1
        recent_events.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "ip": ip_address,
            "status": status_code,
            "layer": layer,
        })
        log = ip_request_log.setdefault(ip_address, deque(maxlen=IP_LOG_MAXLEN))
        log.append((time.time(), status_code))
    log_event(ip_address, status_code, layer)   # Enhancement #5: persist to SQLite


# --- Enhancement #2: Defense chain (Firewall -> WAF -> Load Balancer -> Rate Limiter) ---

FIREWALL_OFFENSE_THRESHOLD = 15   # 429s from one IP before the firewall blocklists it
WAF_SUSPICIOUS_PATTERN = re.compile(r"(?:<script|union\s+select|\.\./|;\s*drop\s+table)", re.I)
LOAD_BALANCER_WORKERS = ["worker-1", "worker-2", "worker-3"]

offense_counts = {}              # ip -> count of rate-limit (429) offenses, feeds the firewall
_lb_counter = {"i": 0}
layer_counts = {"Firewall": 0, "WAF": 0, "LoadBalancer": 0, "RateLimiter": 0, "App": 0}


def _next_worker() -> str:
    with _stats_lock:
        _lb_counter["i"] += 1
        return LOAD_BALANCER_WORKERS[_lb_counter["i"] % len(LOAD_BALANCER_WORKERS)]


# --- Enhancement #3: Defense Automation (timed auto-blacklist + Auto Unblock) ---
#
# When 429s exceed FIREWALL_OFFENSE_THRESHOLD, the IP is auto-blacklisted
# for BLOCK_DURATION_SECONDS. A background sweep thread actively lifts the
# block once it expires ("Auto Unblock"), independent of new traffic, and
# every block/unblock is logged with timestamps for the GUI's blocked-IP
# table.

BLOCK_DURATION_SECONDS = 60      # how long an auto-blacklisted IP stays blocked

firewall_blocklist = {}          # ip -> {"blocked_at": float, "unblock_at": float, "reason": str}
blocked_ip_log = deque(maxlen=100)   # most-recent-first history of block/unblock events, for the GUI table


def _log_block_event(ip_address: str, event: str, reason: str = "", unblock_at: float = None):
    """event: 'blocked' or 'unblocked' (manual or auto)."""
    blocked_ip_log.appendleft({
        "ip": ip_address,
        "event": event,
        "reason": reason,
        "time": datetime.now().strftime("%H:%M:%S"),
        "unblock_at": datetime.fromtimestamp(unblock_at).strftime("%H:%M:%S") if unblock_at else "",
    })
    if event == "blocked":   # Enhancement #5: alert on every firewall block
        log_alert(ip_address, "firewall_block", f"Blocked ({reason}).")


def _record_offense(ip_address: str):
    """Called whenever the rate limiter blocks an IP; promotes repeat
    offenders to a timed firewall blacklist."""
    with _stats_lock:
        offense_counts[ip_address] = offense_counts.get(ip_address, 0) + 1
        if offense_counts[ip_address] >= FIREWALL_OFFENSE_THRESHOLD and ip_address not in firewall_blocklist:
            now = time.time()
            unblock_at = now + BLOCK_DURATION_SECONDS
            firewall_blocklist[ip_address] = {
                "blocked_at": now, "unblock_at": unblock_at, "reason": "repeat offender",
            }
            offense_counts[ip_address] = 0   # reset so it doesn't instantly re-trigger post-unblock
            _log_block_event(ip_address, "blocked", "repeat offender", unblock_at)


def _auto_unblock_sweep():
    """Background thread: lifts expired firewall blocks on its own
    schedule, so the blocked-IP table updates even with no new traffic."""
    while True:
        time.sleep(1)
        now = time.time()
        with _stats_lock:
            expired = [ip for ip, info in firewall_blocklist.items() if info["unblock_at"] <= now]
            for ip in expired:
                del firewall_blocklist[ip]
                _log_block_event(ip, "unblocked", "auto (block duration expired)")


_auto_unblock_started = {"flag": False}


def start_auto_unblock_sweep():
    if _auto_unblock_started["flag"]:
        return
    _auto_unblock_started["flag"] = True
    threading.Thread(target=_auto_unblock_sweep, daemon=True).start()


SIMULATED_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def get_client_ip() -> str:
    """Enhancement #6: Multi-Vector & DDoS Scenarios.

    This whole tool only ever talks to 127.0.0.1, so there's no real
    network path to send traffic from genuinely different source IPs
    (that would mean actual IP spoofing, which this project
    deliberately does not do). Instead, a 'botnet' of simulated
    attacker threads tags its own requests with an
    'X-Simulated-IP' header carrying a made-up private-range address,
    and the server treats that as the client's identity for every
    defense layer below - so the firewall, rate limiter, and ML
    monitor each track and block many distinct 'IPs' independently,
    the way they would against a real distributed attack, while the
    traffic itself never leaves the local machine.
    """
    simulated = request.headers.get("X-Simulated-IP")
    if simulated and SIMULATED_IP_PATTERN.match(simulated):
        return simulated
    return request.remote_addr


@app.route("/", methods=["GET"])
def index():
    client_ip = get_client_ip()

    # Layer 1: Firewall - timed blocklist (manual or auto-promoted repeat offenders)
    if client_ip in firewall_blocklist:
        _record_event(client_ip, 403, "Firewall")
        return jsonify({"error": "Blocked by firewall (repeat offender). Temporary block."}), 403

    # Layer 2: WAF - simple malicious-pattern filter on the query string.
    # Decode percent-encoding first: real attack traffic arrives URL-encoded
    # (e.g. "<script" -> "%3Cscript"), so matching the raw query string would
    # miss it entirely.
    decoded_query = unquote_plus(request.query_string.decode("utf-8", "ignore"))
    if WAF_SUSPICIOUS_PATTERN.search(decoded_query):
        _record_event(client_ip, 403, "WAF")
        return jsonify({"error": "Blocked by WAF (suspicious request pattern)."}), 403

    # Layer 3: Load Balancer - just tags which simulated backend handles it
    worker = _next_worker()

    # Layer 4: Rate Limiter
    if rate_limit(client_ip):
        _record_offense(client_ip)
        _record_event(client_ip, 429, "RateLimiter")
        resp = jsonify({"error": "Rate limit exceeded. Try again later."})
        resp.headers["X-Handled-By"] = worker
        return resp, 429

    # Layer 5: App
    _record_event(client_ip, 200, "App")
    resp = jsonify({"message": "OK"})
    resp.headers["X-Handled-By"] = worker
    return resp, 200


@app.route("/api/firewall/block", methods=["POST"])
def firewall_block():
    """Manually block an IP for BLOCK_DURATION_SECONDS (still auto-unblocked by the sweep)."""
    ip_address = (request.json or {}).get("ip") if request.is_json else request.form.get("ip")
    if not ip_address:
        return jsonify({"error": "ip required"}), 400
    with _stats_lock:
        now = time.time()
        unblock_at = now + BLOCK_DURATION_SECONDS
        firewall_blocklist[ip_address] = {"blocked_at": now, "unblock_at": unblock_at, "reason": "manual"}
        _log_block_event(ip_address, "blocked", "manual", unblock_at)
    return jsonify({"blocked": sorted(firewall_blocklist)})


@app.route("/api/firewall/unblock", methods=["POST"])
def firewall_unblock():
    """Manually lift a block early ('Auto Unblock' test control)."""
    ip_address = (request.json or {}).get("ip") if request.is_json else request.form.get("ip")
    with _stats_lock:
        if ip_address in firewall_blocklist:
            del firewall_blocklist[ip_address]
            _log_block_event(ip_address, "unblocked", "manual")
        offense_counts.pop(ip_address, None)
    return jsonify({"blocked": sorted(firewall_blocklist)})


@app.route("/api/firewall/blocklist", methods=["GET"])
def firewall_blocklist_api():
    """Current blocklist with timestamps, plus recent block/unblock history —
    feeds the GUI's and dashboard's blocked-IP table."""
    with _stats_lock:
        now = time.time()
        active = [
            {
                "ip": ip,
                "blocked_at": datetime.fromtimestamp(info["blocked_at"]).strftime("%H:%M:%S"),
                "unblock_at": datetime.fromtimestamp(info["unblock_at"]).strftime("%H:%M:%S"),
                "seconds_remaining": max(0, round(info["unblock_at"] - now)),
                "reason": info["reason"],
            }
            for ip, info in firewall_blocklist.items()
        ]
        return jsonify({"active": active, "history": list(blocked_ip_log)})


# --- System resource monitoring (psutil) ---------------------------------

system_samples = deque(maxlen=60)   # last ~60s of (time, cpu%, mem%)
_monitor_started = {"flag": False}


def _system_monitor_loop():
    while True:
        cpu = psutil.cpu_percent(interval=1)   # this call itself blocks ~1s, acting as our tick
        mem = psutil.virtual_memory().percent
        with _stats_lock:
            system_samples.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "cpu": cpu,
                "mem": mem,
            })


def start_system_monitor():
    if _monitor_started["flag"]:
        return
    _monitor_started["flag"] = True
    threading.Thread(target=_system_monitor_loop, daemon=True).start()


@app.route("/api/system", methods=["GET"])
def api_system():
    with _stats_lock:
        return jsonify({"samples": list(system_samples)})


# --- Enhancement #4: AI/ML-based Anomaly Detection ------------------------
#
# A small IsolationForest (unsupervised: trained only on what "normal"
# traffic looks like, then flags anything that doesn't fit) classifies
# each active IP as "normal" or "attack" from three features computed
# over its recent request history:
#   - request_rate   : requests/second in the trailing window
#   - error_ratio     : fraction of that IP's recent requests that were
#                       non-200 (429/403) - attack traffic gets blocked a lot
#   - timing_entropy  : Shannon entropy of its inter-arrival times. A human
#                       clicking around has irregular (high-entropy) gaps;
#                       a scripted flood fires at a near-constant interval,
#                       so its entropy collapses toward 0. (True "IP
#                       entropy" - diversity across many source IPs - is
#                       degenerate when every request comes from 127.0.0.1
#                       in this local demo, so timing regularity per-IP is
#                       used as the practical stand-in for that feature.)

import numpy as np
from sklearn.ensemble import IsolationForest

ML_WINDOW_SECONDS = 30       # trailing window used to compute features (matches the rate limiter's own window)
ml_predictions = {}          # ip -> {features..., prediction, score}
_ml_model = {"model": None}


def _shannon_entropy(values):
    """Entropy (bits) of a small list of numbers, after binning into
    deciles of their own range. 0 = perfectly regular, higher = more random."""
    if len(values) < 2:
        return 0.0
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        return 0.0   # every interval identical -> zero entropy (very bot-like)
    bins = np.linspace(lo, hi, 6)
    counts, _ = np.histogram(values, bins=bins)
    probs = counts[counts > 0] / counts.sum()
    return float(-(probs * np.log2(probs)).sum())


def _train_ml_model():
    """Bootstraps the model on synthetic 'normal' traffic (a human
    browsing: ~1 request every 2-8s, irregular timing, occasionally
    tripping the rate limiter the way any real burst of clicks can)
    so IsolationForest learns that shape and flags the flood-attack
    shape (high rate, high error ratio, low entropy) as anomalous -
    without needing a real labeled attack dataset."""
    rng = np.random.default_rng(42)
    n = 400
    request_rate = rng.uniform(0.1, 0.6, n)                  # ~1 req every 2-8s
    error_ratio = np.clip(rng.normal(0.08, 0.1, n), 0, 1)    # occasional 429s are normal
    timing_entropy = rng.uniform(1.0, 2.3, n)                # irregular human timing
    X = np.column_stack([request_rate, error_ratio, timing_entropy])
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    _ml_model["model"] = model


MIN_SAMPLES_FOR_PREDICTION = 4   # need a few intervals before entropy is a meaningful signal


def _compute_ip_features(ip_address: str, now: float):
    log = ip_request_log.get(ip_address)
    if not log:
        return None
    recent = [(t, s) for t, s in log if t > now - ML_WINDOW_SECONDS]
    if len(recent) < MIN_SAMPLES_FOR_PREDICTION:
        return None
    timestamps = [t for t, _ in recent]
    statuses = [s for _, s in recent]
    span = max(timestamps) - min(timestamps)
    request_rate = len(recent) / span if span > 0 else len(recent)
    error_ratio = sum(1 for s in statuses if s != 200) / len(statuses)
    intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    timing_entropy = _shannon_entropy(intervals)
    return {
        "request_rate": round(request_rate, 3),
        "error_ratio": round(error_ratio, 3),
        "timing_entropy": round(timing_entropy, 3),
        "sample_count": len(recent),
    }


def _ml_monitor_loop():
    while True:
        time.sleep(1)
        now = time.time()
        with _stats_lock:
            active_ips = list(ip_request_log.keys())
        results = {}
        for ip in active_ips:
            feats = _compute_ip_features(ip, now)
            if feats is None:
                continue
            X = np.array([[feats["request_rate"], feats["error_ratio"], feats["timing_entropy"]]])
            model = _ml_model["model"]
            raw_pred = model.predict(X)[0]          # 1 = normal, -1 = anomaly
            score = float(model.decision_function(X)[0])  # higher = more normal
            prediction = "Normal" if raw_pred == 1 else "Attack"
            results[ip] = {
                **feats,
                "prediction": prediction,
                "score": round(score, 3),
                "time": datetime.now().strftime("%H:%M:%S"),
            }
            check_ml_alert(ip, prediction)   # Enhancement #5: alert on Normal->Attack transition
        with _stats_lock:
            ml_predictions.clear()
            ml_predictions.update(results)


_ml_monitor_started = {"flag": False}


def start_ml_monitor():
    if _ml_monitor_started["flag"]:
        return
    _ml_monitor_started["flag"] = True
    if _ml_model["model"] is None:
        _train_ml_model()
    threading.Thread(target=_ml_monitor_loop, daemon=True).start()


@app.route("/api/ml/predictions", methods=["GET"])
def api_ml_predictions():
    with _stats_lock:
        return jsonify({
            "window_seconds": ML_WINDOW_SECONDS,
            "predictions": dict(ml_predictions),
        })


# --- Enhancement #5: Logging, Reporting & Alerting -------------------------
#
# Every request event is persisted to a SQLite database, plus a separate
# "alerts" table for the moments that actually matter (a firewall block/
# unblock, or the ML monitor flipping an IP to "Attack"). Writes go through
# a queue drained by one dedicated writer thread, since sqlite3 connections
# aren't safe to share across threads and a flood can generate hundreds of
# events/second that shouldn't each block the Flask request thread.

import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dos_simulator_log.db")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

_db_write_queue = Queue()
_db_writer_started = {"flag": False}
_last_ml_classification = {}   # ip -> "Normal"/"Attack", to only alert on transitions
recent_alerts = deque(maxlen=50)   # most-recent-first, for the GUI/dashboard "Alerts" panel


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            ip TEXT NOT NULL,
            status INTEGER NOT NULL,
            layer TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            ip TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            detail TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip)")
    conn.commit()
    conn.close()


def log_event(ip_address: str, status_code: int, layer: str):
    _db_write_queue.put(("event", time.time(), ip_address, status_code, layer))


def log_alert(ip_address: str, alert_type: str, detail: str):
    now = time.time()
    _db_write_queue.put(("alert", now, ip_address, alert_type, detail))
    recent_alerts.appendleft({
        "time": datetime.fromtimestamp(now).strftime("%H:%M:%S"),
        "ip": ip_address,
        "type": alert_type,
        "detail": detail,
    })


def _db_writer_loop():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    while True:
        batch = [_db_write_queue.get()]
        # drain whatever else has queued up, so a flood is written in batches
        # rather than one commit per request
        while not _db_write_queue.empty() and len(batch) < 500:
            batch.append(_db_write_queue.get_nowait())
        events = [b[1:] for b in batch if b[0] == "event"]
        alerts = [b[1:] for b in batch if b[0] == "alert"]
        if events:
            cur.executemany("INSERT INTO events (ts, ip, status, layer) VALUES (?, ?, ?, ?)", events)
        if alerts:
            cur.executemany("INSERT INTO alerts (ts, ip, alert_type, detail) VALUES (?, ?, ?, ?)", alerts)
        if events or alerts:
            conn.commit()


def start_db_logging():
    if _db_writer_started["flag"]:
        return
    _db_writer_started["flag"] = True
    _init_db()
    threading.Thread(target=_db_writer_loop, daemon=True).start()


def check_ml_alert(ip_address: str, prediction: str):
    """Call whenever a fresh ML prediction comes in; only fires an alert
    on a Normal->Attack transition, not on every repeated classification."""
    prev = _last_ml_classification.get(ip_address)
    _last_ml_classification[ip_address] = prediction
    if prediction == "Attack" and prev != "Attack":
        log_alert(ip_address, "ml_anomaly", "ML classified traffic from this IP as an attack pattern.")


def generate_security_report() -> str:
    """Queries the SQLite DB and writes a timestamped HTML security report.
    Returns the file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    allowed = cur.execute("SELECT COUNT(*) c FROM events WHERE status=200").fetchone()["c"]
    blocked = total - allowed
    by_layer = cur.execute("SELECT layer, COUNT(*) c FROM events GROUP BY layer ORDER BY c DESC").fetchall()
    top_ips = cur.execute(
        "SELECT ip, COUNT(*) c, SUM(CASE WHEN status!=200 THEN 1 ELSE 0 END) blocked "
        "FROM events GROUP BY ip ORDER BY c DESC LIMIT 10"
    ).fetchall()
    alerts = cur.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT 50").fetchall()
    first_ts = cur.execute("SELECT MIN(ts) t FROM events").fetchone()["t"]
    last_ts = cur.execute("SELECT MAX(ts) t FROM events").fetchone()["t"]
    conn.close()

    span = f"{datetime.fromtimestamp(first_ts).strftime('%Y-%m-%d %H:%M:%S')} - {datetime.fromtimestamp(last_ts).strftime('%H:%M:%S')}" if first_ts else "No data yet"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_layer = "".join(f"<tr><td>{r['layer']}</td><td>{r['c']}</td></tr>" for r in by_layer) or "<tr><td colspan='2'>No data</td></tr>"
    rows_ips = "".join(
        f"<tr><td>{r['ip']}</td><td>{r['c']}</td><td>{r['blocked']}</td></tr>" for r in top_ips
    ) or "<tr><td colspan='3'>No data</td></tr>"
    rows_alerts = "".join(
        f"<tr><td>{datetime.fromtimestamp(a['ts']).strftime('%H:%M:%S')}</td>"
        f"<td>{a['ip']}</td><td>{a['alert_type']}</td><td>{a['detail']}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='4'>No alerts recorded</td></tr>"

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>DoS Simulator - Security Report</title>
<style>
body {{ background:#0f1117; color:#e6e6e6; font-family: Segoe UI, Arial, sans-serif; margin:0; padding:28px; }}
h1 {{ font-size:22px; margin-bottom:2px; }} h2 {{ font-size:15px; color:#cfd3db; margin-top:28px; }}
.sub {{ color:#8a8f98; font-size:13px; margin-bottom:20px; }}
.cards {{ display:flex; gap:16px; flex-wrap:wrap; }}
.card {{ background:#171a21; border:1px solid #262a33; border-radius:10px; padding:14px 20px; min-width:140px; }}
.card .label {{ color:#8a8f98; font-size:11px; text-transform:uppercase; }} .card .value {{ font-size:26px; font-weight:700; margin-top:4px; }}
.ok {{ color:#3ddc84; }} .bad {{ color:#ff5c5c; }}
table {{ width:100%; border-collapse:collapse; background:#171a21; border:1px solid #262a33; border-radius:10px; overflow:hidden; margin-top:8px; }}
th, td {{ text-align:left; padding:7px 12px; font-size:13px; border-bottom:1px solid #262a33; }}
th {{ color:#8a8f98; text-transform:uppercase; font-size:11px; }}
</style></head><body>
<h1>DoS Simulator &mdash; Security Report</h1>
<div class="sub">Generated {generated_at} &middot; Session span: {span}</div>
<div class="cards">
  <div class="card"><div class="label">Total Requests</div><div class="value">{total}</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value ok">{allowed}</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value bad">{blocked}</div></div>
  <div class="card"><div class="label">Alerts</div><div class="value bad">{len(alerts)}</div></div>
</div>
<h2>Requests by Defense Layer</h2>
<table><thead><tr><th>Layer</th><th>Count</th></tr></thead><tbody>{rows_layer}</tbody></table>
<h2>Top Source IPs</h2>
<table><thead><tr><th>IP</th><th>Total Requests</th><th>Blocked</th></tr></thead><tbody>{rows_ips}</tbody></table>
<h2>Alert Log</h2>
<table><thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Detail</th></tr></thead><tbody>{rows_alerts}</tbody></table>
</body></html>"""

    filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    return jsonify({"alerts": list(recent_alerts)})


@app.route("/api/report", methods=["POST"])
def api_generate_report():
    filepath = generate_security_report()
    return jsonify({"report_path": filepath, "filename": os.path.basename(filepath)})


# --- Enhancement #1: Web Dashboard / API Integration --------------------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """JSON API mirroring the GUI's live counters, for the dashboard
    page (below) or any external tool/script to poll."""
    with _stats_lock:
        return jsonify({
            "total": server_stats["total"],
            "allowed": server_stats["allowed"],
            "blocked": server_stats["blocked"],
            "rate_limit": {"max_requests": MAX_REQUESTS, "time_window_s": TIME_WINDOW},
            "tracked_ips": len(request_counts),
            "recent_events": list(recent_events),
            "defense_chain": {
                "layer_counts": dict(layer_counts),
                "firewall_blocklist": sorted(firewall_blocklist.keys()),
                "firewall_threshold": FIREWALL_OFFENSE_THRESHOLD,
                "block_duration_s": BLOCK_DURATION_SECONDS,
            },
            "ml_predictions": dict(ml_predictions),
        })


DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DoS Simulator - Live Dashboard</title>
  <meta http-equiv="refresh" content="1">
  <style>
    body { background:#0f1117; color:#e6e6e6; font-family: Segoe UI, Arial, sans-serif; margin:0; padding:24px; }
    h1 { font-size:22px; margin-bottom:4px; }
    .sub { color:#8a8f98; margin-bottom:24px; font-size:13px; }
    .cards { display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; }
    .card { background:#171a21; border:1px solid #262a33; border-radius:10px; padding:16px 22px; min-width:150px; }
    .card .label { color:#8a8f98; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
    .card .value { font-size:30px; font-weight:700; margin-top:4px; }
    .ok { color:#3ddc84; }
    .blocked { color:#ff5c5c; }
    table { width:100%; border-collapse:collapse; background:#171a21; border:1px solid #262a33; border-radius:10px; overflow:hidden; }
    th, td { text-align:left; padding:8px 14px; font-size:13px; border-bottom:1px solid #262a33; }
    th { color:#8a8f98; font-weight:600; text-transform:uppercase; font-size:11px; }
    tr:last-child td { border-bottom:none; }
    .status-200 { color:#3ddc84; font-weight:600; }
    .status-429, .status-403 { color:#ff5c5c; font-weight:600; }
    h2 { font-size:14px; color:#8a8f98; text-transform:uppercase; letter-spacing:.05em; margin:28px 0 10px; }
    .chain { display:flex; align-items:center; gap:0; margin-bottom:24px; flex-wrap:wrap; }
    .chain-box { background:#171a21; border:1px solid #262a33; border-radius:10px; padding:12px 18px; min-width:120px; text-align:center; }
    .chain-box .name { font-weight:700; font-size:13px; }
    .chain-box .count { font-size:20px; margin-top:4px; }
    .chain-arrow { color:#4a4f5a; font-size:20px; padding:0 10px; }
    .chart-wrap { background:#171a21; border:1px solid #262a33; border-radius:10px; padding:16px; margin-bottom:24px; }
    canvas { width:100%; height:160px; display:block; }
    .legend { font-size:12px; margin-top:8px; }
    .legend span { margin-right:16px; }
    .dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:4px; }
  </style>
</head>
<body>
  <h1>DoS Simulator &mdash; Live Dashboard</h1>
  <div class="sub">Rate limit: {{ max_requests }} requests / {{ window }}s per IP &middot; auto-refreshes every second</div>

  <div class="cards">
    <div class="card"><div class="label">Total Requests</div><div class="value">{{ total }}</div></div>
    <div class="card"><div class="label">Allowed (200)</div><div class="value ok">{{ allowed }}</div></div>
    <div class="card"><div class="label">Blocked (all layers)</div><div class="value blocked">{{ blocked }}</div></div>
    <div class="card"><div class="label">Tracked IPs</div><div class="value">{{ tracked_ips }}</div></div>
  </div>

  <h2>Defense Chain</h2>
  <div class="chain">
    <div class="chain-box"><div class="name">Firewall</div><div class="count blocked">{{ layer_counts.Firewall }}</div></div>
    <div class="chain-arrow">&rarr;</div>
    <div class="chain-box"><div class="name">WAF</div><div class="count blocked">{{ layer_counts.WAF }}</div></div>
    <div class="chain-arrow">&rarr;</div>
    <div class="chain-box"><div class="name">Load Balancer</div><div class="count">{{ layer_counts.LoadBalancer }}</div></div>
    <div class="chain-arrow">&rarr;</div>
    <div class="chain-box"><div class="name">Rate Limiter</div><div class="count blocked">{{ layer_counts.RateLimiter }}</div></div>
    <div class="chain-arrow">&rarr;</div>
    <div class="chain-box"><div class="name">App</div><div class="count ok">{{ layer_counts.App }}</div></div>
  </div>
  <div class="sub">Firewall auto-blocklists an IP for {{ block_duration }}s after {{ firewall_threshold }} rate-limit offenses &middot; expired blocks are lifted automatically</div>

  <h2>Blocked IPs (live, auto-unblocks when the timer expires)</h2>
  <table style="margin-bottom:24px;">
    <thead><tr><th>IP</th><th>Blocked At</th><th>Unblocks At</th><th>Seconds Left</th><th>Reason</th></tr></thead>
    <tbody>
      {% for b in active_blocks %}
      <tr>
        <td>{{ b.ip }}</td>
        <td>{{ b.blocked_at }}</td>
        <td>{{ b.unblock_at }}</td>
        <td class="status-429">{{ b.seconds_remaining }}s</td>
        <td>{{ b.reason }}</td>
      </tr>
      {% else %}
      <tr><td colspan="5">No IPs currently blocked.</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>System Load (psutil)</h2>
  <div class="chart-wrap">
    <canvas id="sysChart" width="900" height="160"></canvas>
    <div class="legend">
      <span><span class="dot" style="background:#3ddc84"></span>CPU %</span>
      <span><span class="dot" style="background:#5c9bff"></span>Memory %</span>
    </div>
  </div>

  <h2>Anomaly Detection (ML &mdash; IsolationForest, {{ ml_window }}s window)</h2>
  <table style="margin-bottom:24px;">
    <thead><tr><th>IP</th><th>Req Rate /s</th><th>Error Ratio</th><th>Timing Entropy</th><th>Prediction</th><th>Score</th></tr></thead>
    <tbody>
      {% for ip, p in ml_predictions.items() %}
      <tr>
        <td>{{ ip }}</td>
        <td>{{ p.request_rate }}</td>
        <td>{{ p.error_ratio }}</td>
        <td>{{ p.timing_entropy }}</td>
        <td class="{{ 'status-429' if p.prediction == 'Attack' else 'status-200' }}">{{ p.prediction }}</td>
        <td>{{ p.score }}</td>
      </tr>
      {% else %}
      <tr><td colspan="6">No active traffic to analyze yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Alerts <span style="font-weight:400; color:#8a8f98; font-size:13px;">(logged to SQLite &mdash; firewall blocks + ML attack detections)</span></h2>
  <table style="margin-bottom:24px;">
    <thead><tr><th>Time</th><th>IP</th><th>Type</th><th>Detail</th></tr></thead>
    <tbody>
      {% for a in alerts %}
      <tr>
        <td>{{ a.time }}</td>
        <td>{{ a.ip }}</td>
        <td class="status-429">{{ a.type }}</td>
        <td>{{ a.detail }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4">No alerts yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <h2>Recent Requests</h2>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>Layer</th><th>Status</th></tr></thead>
    <tbody>
      {% for ev in events %}
      <tr>
        <td>{{ ev.time }}</td>
        <td>{{ ev.ip }}</td>
        <td>{{ ev.layer }}</td>
        <td class="status-{{ ev.status }}">{{ ev.status }}</td>
      </tr>
      {% else %}
      <tr><td colspan="4">No requests yet.</td></tr>
      {% endfor %}
    </tbody>
  </table>

  <script>
    // Lightweight client-side line chart for CPU/Mem, polled separately
    // from the page's own auto-refresh so the chart updates smoothly.
    async function drawChart() {
      try {
        const res = await fetch('/api/system');
        const data = await res.json();
        const samples = data.samples || [];
        const canvas = document.getElementById('sysChart');
        const ctx = canvas.getContext('2d');
        const w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);
        if (samples.length < 2) return;
        const n = samples.length;
        const stepX = w / (n - 1);
        function plot(key, color) {
          ctx.beginPath();
          ctx.strokeStyle = color;
          ctx.lineWidth = 2;
          samples.forEach((s, i) => {
            const x = i * stepX;
            const y = h - (s[key] / 100) * h;
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
          });
          ctx.stroke();
        }
        plot('cpu', '#3ddc84');
        plot('mem', '#5c9bff');
      } catch (e) { /* server may be offline between polls */ }
    }
    drawChart();
    setInterval(drawChart, 1000);
  </script>
</body>
</html>
"""


@app.route("/dashboard", methods=["GET"])
def dashboard():
    """Browser-based live dashboard mirroring the desktop GUI."""
    with _stats_lock:
        now = time.time()
        active_blocks = [
            {
                "ip": ip,
                "blocked_at": datetime.fromtimestamp(info["blocked_at"]).strftime("%H:%M:%S"),
                "unblock_at": datetime.fromtimestamp(info["unblock_at"]).strftime("%H:%M:%S"),
                "seconds_remaining": max(0, round(info["unblock_at"] - now)),
                "reason": info["reason"],
            }
            for ip, info in firewall_blocklist.items()
        ]
        return render_template_string(
            DASHBOARD_HTML,
            total=server_stats["total"],
            allowed=server_stats["allowed"],
            blocked=server_stats["blocked"],
            tracked_ips=len(request_counts),
            events=list(recent_events),
            max_requests=MAX_REQUESTS,
            window=TIME_WINDOW,
            layer_counts=layer_counts,
            active_blocks=active_blocks,
            firewall_threshold=FIREWALL_OFFENSE_THRESHOLD,
            block_duration=BLOCK_DURATION_SECONDS,
            ml_predictions=dict(ml_predictions),
            ml_window=ML_WINDOW_SECONDS,
            alerts=list(recent_alerts),
        )


# --- 2. THE CLIENT: DOS ATTACKER LOGIC --------------------------------
#
# Enhancement #6: Multi-Vector & DDoS Scenarios
#   - Attack patterns: Flood (continuous rapid-fire), Burst (short bursts
#     with pauses), Randomized Delay (low-and-slow, irregular spacing),
#     and Slowloris (hold many connections open, trickling partial
#     headers, to exhaust the server's connection-handling threads
#     without ever completing a request).
#   - Botnet Mode: spin up several *simulated* source IPs (see
#     get_client_ip() above for how/why these are simulated, not
#     spoofed) each running their own pool of worker threads, so the
#     server's defenses have to deal with many distinct attackers at
#     once instead of just one.

import random
import socket

ATTACK_PATTERNS = ["Flood", "Burst", "Randomized Delay", "Slowloris"]


class DoSAttacker:
    """Spins up a pool of threads that hammer target_url using a chosen
    attack pattern, optionally across several simulated source IPs."""

    def __init__(self, host: str, port: int, num_threads: int = 20):
        self.host = host
        self.port = port
        self.target_url = f"http://{host}:{port}/"
        self.num_threads = num_threads
        self.running = False
        self.threads = []
        self.requests_sent = 0
        self.success_count = 0
        self.failed_count = 0
        self.open_slow_connections = 0   # live count of held-open slowloris sockets
        self.simulated_ips = []          # the 'botnet' member IPs for this run
        self.pattern = "Flood"
        self._stats_lock = threading.Lock()

        # Pattern tuning
        self.burst_size = 8
        self.burst_pause_s = (1.5, 3.0)
        self.random_delay_s = (0.3, 2.5)
        self.slowloris_trickle_s = 3.0
        self.slowloris_max_lines = 25   # safety cap so a connection can't hang forever

    @staticmethod
    def _random_simulated_ip() -> str:
        # Private (RFC1918) 10.x.x.x range - clearly a simulated, non-routable
        # address, never a real external IP.
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _fire_once(self, session, headers, log_queue: Queue):
        try:
            resp = session.get(self.target_url, headers=headers, timeout=2)
            with self._stats_lock:
                self.requests_sent += 1
                if resp.status_code == 200:
                    self.success_count += 1
                else:
                    self.failed_count += 1
            log_queue.put(f"[{headers.get('X-Simulated-IP', 'local')}] Status: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            with self._stats_lock:
                self.requests_sent += 1
                self.failed_count += 1
            log_queue.put(f"Request failed: {e}")

    def _http_worker(self, simulated_ip, log_queue: Queue):
        """Handles Flood, Burst, and Randomized Delay - all normal HTTP
        requests, just paced differently."""
        session = requests.Session()
        headers = {"X-Simulated-IP": simulated_ip} if simulated_ip else {}
        while self.running:
            if self.pattern == "Burst":
                for _ in range(self.burst_size):
                    if not self.running:
                        break
                    self._fire_once(session, headers, log_queue)
                time.sleep(random.uniform(*self.burst_pause_s))
            elif self.pattern == "Randomized Delay":
                self._fire_once(session, headers, log_queue)
                time.sleep(random.uniform(*self.random_delay_s))
            else:  # Flood
                self._fire_once(session, headers, log_queue)

    def _slowloris_worker(self, simulated_ip, log_queue: Queue):
        """Opens a raw socket, sends the start of an HTTP request, then
        trickles harmless extra header lines just fast enough to avoid a
        timeout - never sending the blank line that completes the
        request. This ties up a server-side connection-handling thread
        without ever counting as a real request to the app, for as long
        as the connection stays open (verified: /api/stats shows zero
        new requests while connections are held).

        Note: Werkzeug's dev server, like many simple HTTP servers, is
        lenient about an abrupt disconnect - if the socket closes before
        the blank line ever arrives, it treats that EOF as 'end of
        headers' and processes whatever it has as one request. So a
        held connection that gets closed (e.g. when you click Stop
        Attack) may register as a single late request at that moment;
        that's expected and doesn't change the live 'held open with
        nothing processed' behavior this pattern demonstrates."""
        while self.running:
            sock = None
            try:
                sock = socket.create_connection((self.host, self.port), timeout=5)
                req_line = f"GET / HTTP/1.1\r\nHost: {self.host}\r\n"
                if simulated_ip:
                    req_line += f"X-Simulated-IP: {simulated_ip}\r\n"
                sock.sendall(req_line.encode())
                with self._stats_lock:
                    self.open_slow_connections += 1
                log_queue.put(f"[{simulated_ip or 'local'}] Slowloris connection opened")
                for _ in range(self.slowloris_max_lines):
                    if not self.running:
                        break
                    time.sleep(self.slowloris_trickle_s)
                    sock.sendall(f"X-Pad: {random.randint(1, 999999)}\r\n".encode())
            except (OSError, socket.error) as e:
                log_queue.put(f"Slowloris connection dropped: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                with self._stats_lock:
                    self.open_slow_connections = max(0, self.open_slow_connections - 1)
            time.sleep(0.2)

    def _worker(self, simulated_ip, log_queue: Queue):
        if self.pattern == "Slowloris":
            self._slowloris_worker(simulated_ip, log_queue)
        else:
            self._http_worker(simulated_ip, log_queue)

    def start(self, log_queue: Queue, pattern: str = "Flood",
              botnet_mode: bool = False, num_simulated_ips: int = 5,
              threads_per_ip: int = 4):
        if self.running:
            return
        self.running = True
        self.pattern = pattern if pattern in ATTACK_PATTERNS else "Flood"
        self.requests_sent = 0
        self.success_count = 0
        self.failed_count = 0
        self.open_slow_connections = 0
        self.threads = []

        if botnet_mode:
            self.simulated_ips = [self._random_simulated_ip() for _ in range(num_simulated_ips)]
            log_queue.put(f"Botnet mode: simulating {num_simulated_ips} source IPs "
                           f"({threads_per_ip} threads each) running '{self.pattern}'.")
            for sim_ip in self.simulated_ips:
                for _ in range(threads_per_ip):
                    th = threading.Thread(target=self._worker, args=(sim_ip, log_queue), daemon=True)
                    self.threads.append(th)
        else:
            self.simulated_ips = []
            log_queue.put(f"Single-source mode: {self.num_threads} threads running '{self.pattern}'.")
            for _ in range(self.num_threads):
                th = threading.Thread(target=self._worker, args=(None, log_queue), daemon=True)
                self.threads.append(th)

        for th in self.threads:
            th.start()

    def stop(self):
        self.running = False


# --- 3. THE GUI --------------------------------------------------------

class DoSSimulatorApp:
    HOST = "127.0.0.1"
    PORT = 5000

    def __init__(self, root):
        self.root = root
        self.root.title("DoS Simulation & Rate Limiting")
        self.root.geometry("700x900")

        self.server_thread = None
        self.server_running = False
        self.attacker = DoSAttacker(self.HOST, self.PORT, num_threads=20)
        self.log_queue = Queue()

        self._build_ui()
        self._poll_log_queue()
        self._poll_stats()
        self._poll_defense_chain()
        self._poll_chart()
        self._poll_blocked_ips()
        self._poll_ml_predictions()
        self._poll_alerts()

    # -- UI construction --------------------------------------------
    def _build_ui(self):
        main_frame = tb.Frame(self.root, padding=15)
        main_frame.pack(fill="both", expand=True)

        title = tb.Label(
            main_frame, text="DoS Simulation & Rate Limiting",
            font=("Helvetica", 16, "bold"),
        )
        title.pack(pady=(0, 10))

        # Server Control
        server_frame = tb.LabelFrame(main_frame, text="Server Control", padding=15)
        server_frame.pack(fill="x", pady=10)
        self.server_status_label = tb.Label(
            server_frame, text="Server Status: Offline", bootstyle="danger"
        )
        self.server_status_label.pack(side="left", padx=10)
        tb.Button(
            server_frame, text="Open Web Dashboard", command=self.open_dashboard,
            bootstyle="info-outline",
        ).pack(side="right", padx=10)
        tb.Button(
            server_frame, text="Start Server", command=self.start_server,
            bootstyle="success",
        ).pack(side="right", padx=10)

        # Attacker Control (Enhancement #6: Multi-Vector & DDoS Scenarios)
        attacker_frame = tb.LabelFrame(main_frame, text="Attacker Control", padding=15)
        attacker_frame.pack(fill="x", pady=10)

        status_row = tb.Frame(attacker_frame)
        status_row.pack(fill="x")
        self.attacker_status_label = tb.Label(
            status_row, text="Attacker Status: Inactive", bootstyle="secondary"
        )
        self.attacker_status_label.pack(side="left")
        tb.Button(
            status_row, text="Start Attack", command=self.start_attack, bootstyle="primary",
        ).pack(side="right", padx=5)
        tb.Button(
            status_row, text="Stop Attack", command=self.stop_attack, bootstyle="danger",
        ).pack(side="right", padx=5)

        settings_row = tb.Frame(attacker_frame)
        settings_row.pack(fill="x", pady=(12, 0))

        tb.Label(settings_row, text="Pattern:").pack(side="left")
        self.pattern_var = tk.StringVar(value="Flood")
        tb.Combobox(
            settings_row, textvariable=self.pattern_var, values=ATTACK_PATTERNS,
            state="readonly", width=16,
        ).pack(side="left", padx=(5, 20))

        self.botnet_var = tk.BooleanVar(value=False)
        tb.Checkbutton(
            settings_row, text="Botnet Mode (simulate multiple source IPs)",
            variable=self.botnet_var, bootstyle="round-toggle",
        ).pack(side="left", padx=(0, 15))

        tb.Label(settings_row, text="Simulated IPs:").pack(side="left")
        self.num_ips_var = tk.IntVar(value=5)
        tb.Spinbox(
            settings_row, from_=2, to=30, textvariable=self.num_ips_var, width=4,
        ).pack(side="left", padx=5)

        tb.Label(
            attacker_frame,
            text="Flood = continuous rapid-fire. Burst = short bursts with pauses. "
                 "Randomized Delay = low-and-slow, irregular timing. "
                 "Slowloris = holds connections open without completing requests.",
            font=("Helvetica", 9), bootstyle="secondary", wraplength=640, justify="left",
        ).pack(fill="x", pady=(8, 0))

        # Stats Display
        stats_frame = tb.Frame(main_frame)
        stats_frame.pack(fill="x", pady=(10, 0))

        tb.Label(stats_frame, text="Requests Sent:", font=("Helvetica", 12)).pack(side="left", padx=5)
        self.total_requests_label = tb.Label(stats_frame, text="0", font=("Helvetica", 12, "bold"))
        self.total_requests_label.pack(side="left")

        tb.Label(stats_frame, text="   Successful (200 OK):", font=("Helvetica", 12)).pack(side="left", padx=5)
        self.success_label = tb.Label(stats_frame, text="0", font=("Helvetica", 12, "bold"), bootstyle="success")
        self.success_label.pack(side="left")

        tb.Label(stats_frame, text="   Blocked (429):", font=("Helvetica", 12)).pack(side="left", padx=5)
        self.blocked_label = tb.Label(stats_frame, text="0", font=("Helvetica", 12, "bold"), bootstyle="danger")
        self.blocked_label.pack(side="left")

        tb.Label(stats_frame, text="   Open Slow Conns:", font=("Helvetica", 12)).pack(side="left", padx=5)
        self.slow_conn_label = tb.Label(stats_frame, text="0", font=("Helvetica", 12, "bold"), bootstyle="warning")
        self.slow_conn_label.pack(side="left")

        # Defense Chain
        chain_frame = tb.LabelFrame(main_frame, text="Defense Chain (Firewall > WAF > Load Balancer > Rate Limiter > App)", padding=12)
        chain_frame.pack(fill="x", pady=10)

        self.chain_labels = {}
        chain_layers = [
            ("Firewall", "danger"), ("WAF", "danger"), ("LoadBalancer", "info"),
            ("RateLimiter", "danger"), ("App", "success"),
        ]
        for i, (layer, style) in enumerate(chain_layers):
            cell = tb.Frame(chain_frame)
            cell.grid(row=0, column=i, padx=8)
            tb.Label(cell, text=layer, font=("Helvetica", 10, "bold")).pack()
            lbl = tb.Label(cell, text="0", font=("Helvetica", 14, "bold"), bootstyle=style)
            lbl.pack()
            self.chain_labels[layer] = lbl
        tb.Label(
            chain_frame, text=f"Auto-blacklists an IP for {BLOCK_DURATION_SECONDS}s after "
                              f"{FIREWALL_OFFENSE_THRESHOLD} rate-limit offenses; Auto Unblock lifts it on expiry.",
            font=("Helvetica", 9), bootstyle="secondary",
        ).grid(row=1, column=0, columnspan=5, pady=(8, 0), sticky="w")

        # Blocked IPs table (Enhancement #3: Defense Automation)
        blocked_frame = tb.LabelFrame(main_frame, text="Blocked IPs (live, Auto Unblock on expiry)", padding=10)
        blocked_frame.pack(fill="both", pady=10)

        columns = ("ip", "blocked_at", "unblock_at", "remaining", "reason")
        self.blocked_tree = tb.Treeview(
            blocked_frame, columns=columns, show="headings", height=4, bootstyle="danger",
        )
        for col, label, width in [
            ("ip", "IP", 110), ("blocked_at", "Blocked At", 90), ("unblock_at", "Unblocks At", 90),
            ("remaining", "Seconds Left", 90), ("reason", "Reason", 140),
        ]:
            self.blocked_tree.heading(col, text=label)
            self.blocked_tree.column(col, width=width, anchor="center")
        self.blocked_tree.pack(side="left", fill="both", expand=True)

        btn_col = tb.Frame(blocked_frame)
        btn_col.pack(side="left", padx=(10, 0), fill="y")
        tb.Button(
            btn_col, text="Unblock Selected", command=self.unblock_selected_ip, bootstyle="warning-outline",
        ).pack(fill="x", pady=2)

        # System Load (psutil)
        sys_frame = tb.LabelFrame(main_frame, text="System Load (CPU / Memory %)", padding=10)
        sys_frame.pack(fill="x", pady=10)

        self.fig = Figure(figsize=(6, 1.8), dpi=80)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_ylim(0, 100)
        self.ax.set_xticks([])
        self.cpu_line, = self.ax.plot([], [], color="#2ecc71", label="CPU %")
        self.mem_line, = self.ax.plot([], [], color="#3498db", label="Mem %")
        self.ax.legend(loc="upper left", fontsize=7)
        self.fig.tight_layout()
        self.chart_canvas = FigureCanvasTkAgg(self.fig, master=sys_frame)
        self.chart_canvas.get_tk_widget().pack(fill="x")

        # Anomaly Detection (Enhancement #4)
        ml_frame = tb.LabelFrame(main_frame, text="Anomaly Detection (ML - IsolationForest)", padding=10)
        ml_frame.pack(fill="both", pady=10)

        ml_columns = ("ip", "rate", "error_ratio", "entropy", "prediction", "score")
        self.ml_tree = tb.Treeview(ml_frame, columns=ml_columns, show="headings", height=4)
        for col, label, width in [
            ("ip", "IP", 110), ("rate", "Req Rate/s", 85), ("error_ratio", "Error Ratio", 85),
            ("entropy", "Timing Entropy", 100), ("prediction", "Prediction", 90), ("score", "Score", 80),
        ]:
            self.ml_tree.heading(col, text=label)
            self.ml_tree.column(col, width=width, anchor="center")
        self.ml_tree.tag_configure("attack", foreground="#ff5c5c")
        self.ml_tree.tag_configure("normal", foreground="#3ddc84")
        self.ml_tree.pack(fill="both", expand=True)

        # Alerts + Reporting (Enhancement #5)
        alerts_frame = tb.LabelFrame(main_frame, text="Alerts & Reporting", padding=10)
        alerts_frame.pack(fill="both", pady=10)

        alerts_top = tb.Frame(alerts_frame)
        alerts_top.pack(fill="x")
        tb.Label(alerts_top, text="Events are logged to dos_simulator_log.db as they happen.",
                  font=("Helvetica", 9), bootstyle="secondary").pack(side="left")
        tb.Button(
            alerts_top, text="Generate Security Report", command=self.generate_report, bootstyle="info",
        ).pack(side="right")

        self.alerts_list = tk.Listbox(alerts_frame, height=5)
        self.alerts_list.pack(fill="both", expand=True, pady=(8, 0))

        # Request Log
        log_frame = tb.LabelFrame(main_frame, text="Request Log", padding=10)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.log_text = tk.Text(log_frame, height=10, state="disabled", wrap="none")
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar = tb.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=scrollbar.set)

    # -- Server control ------------------------------------------------
    def start_server(self):
        if self.server_running:
            return
        try:
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.server_status_label.config(text="Server Status: Online", bootstyle="success")
        except Exception as e:
            messagebox.showerror("Server Error", str(e))

    def _run_server(self):
        start_db_logging()
        start_system_monitor()
        start_auto_unblock_sweep()
        start_ml_monitor()
        app.run(host=self.HOST, port=self.PORT, threaded=True, use_reloader=False)

    def open_dashboard(self):
        if not self.server_running:
            messagebox.showwarning("Server Offline", "Start the server before opening the dashboard.")
            return
        webbrowser.open(f"http://{self.HOST}:{self.PORT}/dashboard")

    def generate_report(self):
        if not self.server_running:
            messagebox.showwarning("Server Offline", "Start the server first so there's data to report on.")
            return
        try:
            filepath = generate_security_report()
        except Exception as e:
            messagebox.showerror("Report Failed", str(e))
            return
        if messagebox.askyesno("Report Generated", f"Saved to:\n{filepath}\n\nOpen it now?"):
            webbrowser.open(f"file://{filepath}")

    def unblock_selected_ip(self):
        """Manual 'Auto Unblock' test control: lift a block early to verify
        the rate limiter resets for that IP."""
        selection = self.blocked_tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Select a blocked IP in the table first.")
            return
        ip_address = self.blocked_tree.item(selection[0])["values"][0]
        try:
            requests.post(f"http://{self.HOST}:{self.PORT}/api/firewall/unblock", json={"ip": ip_address}, timeout=2)
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Unblock Failed", str(e))

    # -- Attacker control -----------------------------------------------
    def start_attack(self):
        if not self.server_running:
            messagebox.showwarning("Server Offline", "Start the server before launching an attack.")
            return
        self.attacker.start(
            self.log_queue,
            pattern=self.pattern_var.get(),
            botnet_mode=self.botnet_var.get(),
            num_simulated_ips=self.num_ips_var.get(),
        )
        mode_desc = f"Botnet ({self.num_ips_var.get()} IPs)" if self.botnet_var.get() else "Single-source"
        self.attacker_status_label.config(
            text=f"Attacker Status: Active - {self.pattern_var.get()} / {mode_desc}", bootstyle="warning",
        )

    def stop_attack(self):
        self.attacker.stop()
        self.attacker_status_label.config(text="Attacker Status: Inactive", bootstyle="secondary")

    # -- Background pollers ----------------------------------------------
    def _poll_log_queue(self):
        """Drain queued log lines into the Text widget without blocking the UI thread."""
        drained = 0
        try:
            while drained < 200:  # cap per tick so the UI stays responsive under flood
                line = self.log_queue.get_nowait()
                self._append_log(line)
                drained += 1
        except Empty:
            pass
        self.root.after(100, self._poll_log_queue)

    def _append_log(self, line: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{line}\n")
        # Keep the log bounded so it doesn't grow forever during a flood.
        if float(self.log_text.index("end-1c").split(".")[0]) > 500:
            self.log_text.delete("1.0", "2.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll_stats(self):
        self.total_requests_label.config(text=str(self.attacker.requests_sent))
        self.success_label.config(text=str(self.attacker.success_count))
        self.blocked_label.config(text=str(self.attacker.failed_count))
        self.slow_conn_label.config(text=str(self.attacker.open_slow_connections))
        self.root.after(200, self._poll_stats)

    def _poll_defense_chain(self):
        with _stats_lock:
            counts = dict(layer_counts)
        for layer, lbl in self.chain_labels.items():
            lbl.config(text=str(counts.get(layer, 0)))
        self.root.after(500, self._poll_defense_chain)

    def _poll_blocked_ips(self):
        """Refresh the Blocked IPs table from server state. Works entirely
        off shared process state (no HTTP round-trip needed) since the GUI
        and Flask app share the same Python process."""
        now = time.time()
        with _stats_lock:
            rows = [
                (
                    ip,
                    datetime.fromtimestamp(info["blocked_at"]).strftime("%H:%M:%S"),
                    datetime.fromtimestamp(info["unblock_at"]).strftime("%H:%M:%S"),
                    max(0, round(info["unblock_at"] - now)),
                    info["reason"],
                )
                for ip, info in firewall_blocklist.items()
            ]
        selected_ip = None
        sel = self.blocked_tree.selection()
        if sel:
            selected_ip = self.blocked_tree.item(sel[0])["values"][0]
        self.blocked_tree.delete(*self.blocked_tree.get_children())
        for row in rows:
            iid = self.blocked_tree.insert("", "end", values=row)
            if row[0] == selected_ip:
                self.blocked_tree.selection_set(iid)
        self.root.after(1000, self._poll_blocked_ips)

    def _poll_ml_predictions(self):
        with _stats_lock:
            preds = dict(ml_predictions)
        self.ml_tree.delete(*self.ml_tree.get_children())
        for ip, p in preds.items():
            tag = "attack" if p["prediction"] == "Attack" else "normal"
            self.ml_tree.insert(
                "", "end",
                values=(ip, p["request_rate"], p["error_ratio"], p["timing_entropy"], p["prediction"], p["score"]),
                tags=(tag,),
            )
        self.root.after(1000, self._poll_ml_predictions)

    def _poll_alerts(self):
        with _stats_lock:
            alerts = list(recent_alerts)
        self.alerts_list.delete(0, "end")
        for a in alerts[:20]:
            self.alerts_list.insert("end", f"[{a['time']}] {a['ip']} - {a['type']}: {a['detail']}")
        self.root.after(1000, self._poll_alerts)

    def _poll_chart(self):
        with _stats_lock:
            samples = list(system_samples)
        if samples:
            xs = list(range(len(samples)))
            cpu_vals = [s["cpu"] for s in samples]
            mem_vals = [s["mem"] for s in samples]
            self.cpu_line.set_data(xs, cpu_vals)
            self.mem_line.set_data(xs, mem_vals)
            self.ax.set_xlim(0, max(len(samples) - 1, 1))
            self.chart_canvas.draw_idle()
        self.root.after(1000, self._poll_chart)


if __name__ == "__main__":
    root = tb.Window(themename="superhero")
    gui = DoSSimulatorApp(root)
    root.mainloop()
