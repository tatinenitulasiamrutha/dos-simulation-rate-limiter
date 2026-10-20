# DoS Simulation & Rate Limiting Tool

A desktop app demonstrating a sliding-window rate limiter and a
simulated defense chain protecting a local Flask server against a
flood of requests, with a browser dashboard and live system metrics.

## What it does
- **Server**: Flask app on `127.0.0.1:5000`, protected by a 4-layer
  defense chain:
  `Firewall -> WAF -> Load Balancer -> Rate Limiter -> App`
  - **Firewall**: outright blocks any IP on its blocklist (manual, or
    auto-added after repeated rate-limit offenses).
  - **WAF**: scans the (URL-decoded) query string for suspicious
    patterns (`<script`, `union select`, `../`, `; drop table`) and
    blocks matches with `403`.
  - **Load Balancer**: tags each request with a simulated backend
    worker (`worker-1/2/3`), round-robin.
  - **Rate Limiter**: sliding window, default **5 requests / 30s**
    per IP → `429` when exceeded.
- **Defense Automation**: after **15** rate-limit offenses from one
  IP, the firewall auto-blocklists it for **60 seconds**. A background
  sweep thread actively lifts the block the moment it expires
  ("Auto Unblock") — no new traffic required to trigger it. Every
  block/unblock (manual or automatic) is logged with timestamps in a
  dedicated **Blocked IPs** table, in both the desktop GUI and the
  web dashboard, with a "Unblock Selected" button to test the reset
  manually.
- **System metrics**: live CPU/memory % via `psutil`, graphed in both
  the desktop GUI (matplotlib) and the web dashboard (canvas chart).
- **Anomaly detection (ML)**: a small `IsolationForest` (scikit-learn)
  classifies each active IP every second as **Normal** or **Attack**
  from three live features over a 30s window — request rate, error
  (429/403) ratio, and timing entropy (how regular its request
  spacing is — scripted floods fire at near-constant intervals, real
  usage doesn't). It's trained once at startup on synthetic
  human-like traffic, so it needs no labeled attack dataset. Shown
  live in a table in both the desktop GUI and the web dashboard.
- **Logging & Reporting**: every request event is persisted to a
  SQLite database (`dos_simulator_log.db`, created next to the
  script). An **Alerts** panel fires on firewall blocks and on the ML
  monitor flagging an IP as an attack (shown live in the GUI and the
  dashboard, under `/api/alerts`). A **Generate Security Report**
  button builds a timestamped HTML report (`reports/security_report_
  <timestamp>.html`) summarizing total/allowed/blocked requests,
  per-layer breakdown, top source IPs, and the full alert log.
- **Multi-vector / botnet simulation**: the attacker supports 4
  patterns and an optional "Botnet Mode":
  - **Flood** — continuous rapid-fire (the original behavior).
  - **Burst** — short bursts of requests, then a pause, repeated.
  - **Randomized Delay** — single requests at irregular, human-ish
    intervals (low-and-slow).
  - **Slowloris** — opens raw sockets and trickles harmless partial
    headers without ever completing the request, tying up a
    connection-handling thread instead of sending real traffic. The
    "Open Slow Connections" stat shows how many are held open live.
  - **Botnet Mode** spins up several *simulated* source IPs (each its
    own thread pool) by tagging requests with an `X-Simulated-IP`
    header carrying a private-range (`10.x.x.x`) address. The server
    validates that header and, if present, uses it as the request's
    identity through every defense layer — firewall, rate limiter, ML
    monitor — so you can watch many distinct "attackers" get tracked
    and blocked independently. **This is simulation, not real IP
    spoofing**: every byte still goes to `127.0.0.1`; only the
    *label* the server uses for "who sent this" is faked, entirely
    for local demo purposes.
- **Attacker**: a 20-thread client that continuously hits the server.
- **Desktop GUI** (Tkinter/ttkbootstrap): start/stop the server and
  the attack, live counters, a defense-chain panel showing per-layer
  block counts + the firewall blocklist, a CPU/Mem chart, and a
  scrolling request log.
- **Web Dashboard** (`/dashboard`): browser view of the same stats,
  defense chain, blocked-IP table, and system chart — auto-refreshes
  every second.
- **JSON API**: `/api/stats`, `/api/system`, `/api/firewall/blocklist`
  (active blocks + block/unblock history), and `/api/ml/predictions`
  (live per-IP classification) for scripts or other tools to poll.
  `/api/firewall/block` and `/api/firewall/unblock` manage the
  blocklist (`POST {"ip": "..."}`) — unblock is also how you manually
  test the "Auto Unblock" reset. `/api/alerts` returns recent alerts;
  `POST /api/report` generates a fresh HTML security report and
  returns its path.

Everything stays on `127.0.0.1` (your own machine) — it's for
learning rate-limiting and DoS-defense concepts, not for attacking
anything else.

## Run it
```bash
pip install -r requirements.txt
python dos_simulator_gui.py
```
1. Click **Start Server**.
2. Click **Open Web Dashboard**, or hit `http://127.0.0.1:5000/api/stats`.
3. Click **Start Attack** — watch the defense chain panel fill in:
   most traffic gets caught by the **Rate Limiter**, and once one IP
   racks up 15 offenses it gets escalated to the **Firewall** layer
   and blocked outright (`403`) — it shows up in the **Blocked IPs**
   table with a live countdown, and auto-unblocks itself after 60s
   (or click **Unblock Selected** to lift it early).
4. Watch the **Anomaly Detection** table — once the attacking IP has
   enough samples in its 30s window, its row flips to **Attack** with
   a negative score; stop the flood and send a few slow requests and
   it flips back to **Normal**.
5. Click **Stop Attack** to end the flood.
6. Try a different **Pattern** (Burst / Randomized Delay / Slowloris)
   and toggle **Botnet Mode** with a few simulated IPs — watch the
   Blocked IPs and Anomaly Detection tables fill with several
   different addresses instead of just one.
7. Click **Generate Security Report** to get a timestamped HTML
   summary of the session (requests by layer, top offending IPs, full
   alert log) — it'll offer to open the report in your browser.

## Tune it
Near the top of `dos_simulator_gui.py`:
```python
TIME_WINDOW = 30                   # rate-limiter window, seconds
MAX_REQUESTS = 5                   # allowed requests per IP per window
FIREWALL_OFFENSE_THRESHOLD = 15    # 429s before the firewall auto-blocks an IP
BLOCK_DURATION_SECONDS = 60        # how long an auto-block lasts
ML_WINDOW_SECONDS = 30             # trailing window for ML features
MIN_SAMPLES_FOR_PREDICTION = 4     # min requests in-window before classifying
```

## Roadmap (from the project's own enhancement plan, in order)
1. ✅ **Web Dashboard / API Integration**
2. ✅ **Realistic Server Metrics & Defense Layers** — firewall/WAF/load-
   balancer simulation, defense-chain visualization, psutil CPU/memory
   graphs.
3. ✅ **Defense Automation** — timed (60s) auto-blacklist, a background
   sweep thread for **Auto Unblock**, and a Blocked IPs table with
   timestamps in both the desktop GUI and the web dashboard.
4. ✅ **AI/ML-based Anomaly Detection** — an IsolationForest classifying
   each IP as Normal/Attack from request-rate, error ratio and timing
   entropy, live in the GUI and dashboard.
5. ✅ **Logging, Reporting & Alerting** — every event persisted to
   SQLite, live Alerts panel, one-click HTML security report.
6. ✅ **Multi-Vector & DDoS Scenarios** — Flood / Burst / Randomized
   Delay / Slowloris patterns, and Botnet Mode simulating multiple
   source IPs via a validated `X-Simulated-IP` header.

**All 6 stages complete.** The project now matches the full
enhancement plan from the original video, end to end, with every
stage individually tested against the running server (not just
read for correctness).

### A note on "simulated" vs "real" in this project
Two things in this build are explicitly simulations, not the real
thing, and that's intentional for a local, safe, educational tool:
- **Botnet IPs** are a header the attacker sets and the server
  chooses to trust (`X-Simulated-IP`) — not real IP spoofing, which
  would require raw sockets/packet crafting and a real network path
  to misuse. Every byte still goes to `127.0.0.1`.
- **"IP entropy"** in the ML features (stage 4) is approximated by
  per-IP timing entropy, since true cross-IP diversity is degenerate
  when (even with Botnet Mode) all traffic still originates from one
  machine.
Both are called out in code comments at the point they're used.

### A note on the ML feature "IP entropy"
The video's notes call for an "IP entropy" feature. True IP-distribution
entropy (diversity across many *different* source IPs) is degenerate in
this local single-machine demo — every request comes from 127.0.0.1.
As a practical stand-in that still captures the same underlying signal
("is this traffic shaped like a bot?"), this build uses **timing
entropy** — the irregularity of an IP's request spacing — since
scripted floods fire at near-constant intervals while real usage
doesn't. If you run this against multiple real client IPs (e.g. behind
a real network), swapping in true cross-IP entropy as an additional
feature would be a natural extension.
