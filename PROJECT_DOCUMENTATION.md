# Project Documentation
# AI-Powered DDoS Detection & Autonomous Mitigation for Financial Networks

---

## PART 1: WHAT THE PROJECT IS

This project is a simulated banking platform that can detect and autonomously respond to DDoS (Distributed Denial of Service) attacks in real time using machine learning and a large language model agent.

The idea is: most DDoS mitigation today is either fully manual (a human has to notice, diagnose, and respond) or fully rule-based (static rules that don't adapt). This project explores a middle ground — a hybrid system where a rule engine handles the first 20 seconds of an attack instantly and deterministically, then a Claude AI agent takes over to reason about the situation, make judgment calls, take targeted actions, and communicate with human staff.

It's built around a mock bank because financial services are one of the highest-value DDoS targets in the world, and the consequences of downtime (failed transactions, customer trust, regulatory exposure) are concrete and easy to explain.

---

## PART 2: FULL CODEBASE WALKTHROUGH

### How the System is Structured

The project has four independently running services:

```
Bank Server       (port 8000)  — the "victim" application
Inference Service (port 8001)  — the ML detection layer
Mitigation Controller (no port) — the response layer
Attack Simulator  (no port)   — generates attack traffic
```

These communicate over HTTP and WebSockets. No message broker or database is shared between them — they are loosely coupled by design.

---

### 1. Bank Server — `bank/`

**What it does:** A fully functional mock banking API built with FastAPI. Supports creating accounts, depositing, withdrawing, and transferring funds. Uses SQLite via SQLAlchemy for persistence.

**Key design choice — NetFlow middleware (`bank/main.py`):**
Every single HTTP request that hits the bank server is intercepted by a middleware layer before it reaches the application logic. The middleware records the source IP, destination, port, bytes transferred, and exact timestamps. This produces a "flow record" — exactly the same format used in real enterprise network monitoring (NetFlow v9). This is how the system sees traffic rather than individual requests.

**Worker queue (`bank/worker.py`):**
All database writes go through a single asyncio queue processed by one background worker. This serialises all writes, guaranteeing data consistency without any locking complexity. It also gives the system natural backpressure — when under attack, the queue size grows, which is a real-time signal of system stress.

**Metrics (`bank/worker.py` — Metrics class):**
The system tracks live metrics in memory: transactions per minute (10s rolling window), average latency (30s rolling window), queue depth, total accounts, and the last 50 transactions. These are streamed over WebSocket to dashboards every 500ms.

**WebSocket channels:**
- `/ws/stats` — streams live banking metrics to the banking dashboard
- `/ws/security` — a broadcast channel. Anything sent here goes to all connected security dashboard clients. The inference service and mitigation controller both use this to push alerts.

**Mitigation enforcement hook:**
The bank server runs a background task every 5 seconds that reads a JSON file at `/tmp/mitigation_state.json`. If the mitigation controller has blocked any IPs, they appear in this file. The middleware checks incoming request IPs against this list and returns HTTP 429 (Too Many Requests) for blocked IPs. This is the enforcement bridge between the controller and the bank.

**Dashboards:**
Two static HTML dashboards served from `bank/static/`:
- Banking dashboard: live TPM chart, latency chart, transaction table
- Security dashboard: real-time alert feed, threat level indicator, incident details

---

### 2. NetFlow Ingestion — `ingest/netflow_v9_parser.py`

**What it does:** Takes the canonical flow records from the middleware and persists them to disk as CSV files. The directory structure rotates hourly: `data/raw/netflow/YYYY/MM/DD/HH/flows_0.csv`. Each row is a single HTTP request, represented as 32 NetFlow v9 fields.

This is important because the ML model was trained on this exact format. The inference service reads these same files to get data to run predictions on.

---

### 3. Feature Engineering — `features/window_agg.py`

**What it does:** The `WindowAggregator` class takes raw flow records and computes over 50 aggregate metrics across a sliding time window. This is where raw traffic becomes meaningful signals.

Key metrics computed:
- **Volume**: flows/sec, bytes/sec, packets/sec
- **Diversity**: unique source IPs, unique source ports, unique protocols
- **Entropy**: Shannon entropy of source IPs (low entropy = very few unique IPs = potential spoofed flood), entropy of ports
- **TCP flags**: SYN count, SYN ratio, RST ratio (high SYN ratio = SYN flood)
- **Behavioural**: one-packet flow ratio, small flow ratio, bytes per packet
- **Rate-of-change**: deltas between current and previous window for all major metrics

The mitigation controller uses this class directly to get a rich picture of what traffic currently looks like.

---

### 4. ML Model Training — `models/`

Two models are available:

**PCA + SVC (`models/train_pca_svc.py`):**
- Data is loaded and cleaned. Non-informative columns (IPs, timestamps) are dropped.
- A scikit-learn Pipeline applies: StandardScaler → PCA (10 components) → SVC with RBF kernel.
- PCA reduces 23 features to 10 principal components, which removes noise and helps the SVC generalise.
- Trained on labelled NetFlow data. The label column (`ALERT`) contains attack type strings: 'None' (benign), 'DDoS', 'PortScan', etc.
- Saved to `models/artifacts/model.joblib`.

**LightGBM (`models/train_lightgbm.py`):**
- Gradient boosting alternative. Better on imbalanced classes due to `class_weight='balanced'`.
- Uses LabelEncoder for the target since LightGBM requires integer labels.

The currently deployed model is the PCA+SVC pipeline.

---

### 5. Inference Service — `inference/app.py`

**What it does:** Continuously monitors the netflow CSV files and runs every new flow record through the ML model.

**File watcher loop:**
Runs every 1 second. Finds all CSV files under `data/raw/netflow/`, tracks the byte offset of each file it has already read (so it never re-processes old data), reads any new rows incrementally, and passes each one to the inference function.

**Feature mapping:**
The raw CSV row is converted to a 23-feature DataFrame that matches exactly what the model was trained on: ports, protocol, timing, byte counts, TCP window sizes, etc.

**Prediction:**
`model.predict()` returns an attack label. If it's anything other than 'None', the service sends an alert JSON payload over a WebSocket connection to `ws://localhost:8000/ws/security`. The bank server broadcasts this to all connected security dashboard clients.

Alert format:
```json
{
  "alert": "Attack Detected: DDoS",
  "type": "critical",
  "details": { ...flow fields... }
}
```

---

### 6. Mitigation Controller — `mitigation/`

This is the most complex part of the system. It's a standalone asyncio Python service that ties everything together.

#### `config.py` — Configuration
A single dataclass holding all tunable parameters: FSM thresholds, action TTLs, whitelist, API URLs, LLM model name, etc. Changing behaviour means changing one file.

#### `logger.py` — Structured Logging
All events (state transitions, actions taken, feedback measurements, LLM tool calls, incident reports) are emitted as newline-delimited JSON to both stdout and daily log files at `mitigation/logs/controller_YYYYMMDD.jsonl`. This makes the controller's behaviour fully auditable.

#### `fsm.py` — Finite State Machine
Five states with explicit transition rules:

```
NORMAL → SUSPICIOUS       composite threat score >= 0.40
SUSPICIOUS → UNDER_ATTACK score >= 0.75 sustained for 5s, or score >= 0.80 instantly
UNDER_ATTACK → MITIGATING automatic (next evaluation cycle)
MITIGATING → STABILIZING  score < 0.35 sustained for 30s + metrics recovering
STABILIZING → NORMAL      score < 0.25 sustained for 60s
```

There are also reverse transitions (false-alarm decay from SUSPICIOUS back to NORMAL, and re-escalation from STABILIZING back to UNDER_ATTACK if the attack resumes). All transitions are logged with the full decision score that triggered them.

#### `context.py` — Context Layer
Three responsibilities:
1. **Wraps WindowAggregator** — ingests each flow from the CSV watcher and computes the 50+ traffic metrics on demand.
2. **Baseline tracking** — during the first 3 minutes of uptime, samples system metrics to establish what "normal" looks like (TPM, latency, flows/sec, entropy). After warmup, updates the baseline using an exponential moving average (alpha=0.05) so it slowly adapts to genuine long-term traffic growth without being fooled by an ongoing attack.
3. **Top-N talker tracking** — maintains a sliding 30-second deque of request timestamps per source IP. On demand, returns the top N IPs ranked by current request rate.

#### `decision_engine.py` — Composite Scoring
Evaluates four signals and combines them into a single threat score (0.0–1.0):

| Signal | Weight | What it measures |
|---|---|---|
| ML confidence | 40% | How many attack alerts in the last 10s (frequency as a proxy for confidence, since the model outputs labels not probabilities) |
| Traffic volume | 25% | flows/sec linearly mapped from [500, 1500] to [0, 1] |
| Entropy (inverted) | 20% | Low src_ip_entropy = few unique IPs = spoofed flood |
| System health | 15% | TPM and latency as multiples of their baseline values |

Also produces action recommendations based on the current FSM state: rate-limit top talkers in SUSPICIOUS, block + shape + SYN cookies in UNDER_ATTACK/MITIGATING.

#### `actions.py` — Mitigation Tools
Four tools, all in-memory (no actual OS firewall since this is a simulation):

- **`block_ip(ip, ttl)`**: Adds IP to a blocked set with expiry timestamp. Enforced via the IPC file → bank middleware. Safeguards: IP whitelist check, max 20 blocks/minute, 30s cooldown per IP.
- **`rate_limit(ip, rps_cap)`**: Records a per-IP rate cap.
- **`shape_traffic(delay_ms)`**: Sets a global response delay flag.
- **`enable_syn_cookies()`**: Sets a SYN cookie mode flag.

All return a standardised `ActionResult` dict so the LLM agent gets consistent feedback from every tool call.

#### `feedback.py` — Feedback Loop
After each action is applied, records a pre-action snapshot of system metrics. Waits 15 seconds, then snapshots again. Computes deltas (did TPM drop? did latency improve?). Logs whether the action was effective. During STABILIZING, progressively lifts restrictions in reverse order of aggressiveness: SYN cookies → shaping → unblock IPs → remove rate limits.

#### `ipc.py` — IPC Bridge
Writes the full enforcement state (blocked IPs with expiry times, rate limits, mode flags) to `/tmp/mitigation_state.json` atomically (write to `.tmp` then rename, to avoid partial reads). The bank server polls this file every 5 seconds.

#### `llm_agent.py` — The Claude Agent
This is where the LLM becomes an active participant rather than a passive reporter.

**When it fires:** Either immediately when the FSM enters MITIGATING, or after 20 seconds in SUSPICIOUS — whichever comes first. Only one agent instance runs at a time per incident.

**Tool-calling loop:** Uses the Anthropic API with `claude-haiku-4-5`. Given a system prompt explaining its role and constraints, and an initial user message describing the current situation (threat score, metrics snapshot, what the rule engine already did), Claude runs an agentic loop:

1. Calls `get_current_metrics` and `get_top_talkers` to understand the situation
2. Calls `block_ip`, `rate_limit`, `shape_traffic`, or `enable_syn_cookies` based on its reasoning
3. Re-calls `get_current_metrics` to verify its actions are having an effect
4. Calls `send_alert` to notify human security staff with a clear, plain-English message
5. Stops when it determines the situation is under control (no more tool calls → `end_turn`)

Maximum 10 iterations to prevent runaway loops. Every tool call and its result is logged.

**Post-incident report:** When the FSM returns to NORMAL, Claude generates a plain-English incident report summarising what happened, what was done, and recommended follow-up. This is injected into the security dashboard.

#### `controller.py` — Orchestrator
Runs five concurrent asyncio tasks:
1. `/ws/security` listener — consumes attack alerts, feeds them to context
2. `/ws/stats` listener — consumes live metrics, tracks peak values
3. Flow file watcher — tails the same CSV files as the inference service, feeds flows to WindowAggregator
4. Evaluation loop — runs every 2 seconds: score → FSM → rule engine actions → spawn agent if needed → sync IPC
5. Janitor — every 10 seconds: expire old blocks, sync IPC file

All WebSocket listeners use exponential backoff reconnection (max 30s) so the controller survives bank server restarts.

---

### 7. Attack Simulator — `tests/attack_load.py`

An interactive CLI with four modes:
- **Init accounts**: Creates N test accounts with random balances
- **Background traffic**: Generates continuous normal transaction traffic at a configurable TPM with randomly spoofed source IPs
- **DDoS attack**: Launches N threads each making rapid HTTP requests from distinct spoofed IPs — simulates a volumetric flood
- **Port scan**: Probes TCP ports using raw sockets — simulates reconnaissance

---

## PART 3: HOW TO EXPLAIN THIS TO JUDGES

### The One-Sentence Pitch
"We built a banking server that detects DDoS attacks with a machine learning model and then uses an AI agent to autonomously respond — blocking attackers, adjusting traffic controls, and briefing human staff — all within seconds."

### The Two-Minute Version
Start with the problem. DDoS attacks on financial institutions are not theoretical — they cost millions in downtime, trigger regulatory scrutiny, and destroy customer trust. Current solutions are either purely manual (too slow) or purely rule-based (too rigid). Rules written for last year's attack pattern won't catch this year's.

Explain the three-layer response:
1. A machine learning model (PCA + SVC) watches every network flow in real time and detects attack patterns the moment they appear.
2. A rule-based engine responds instantly — blocking the worst offenders, rate-limiting secondary sources, and hardening the connection layer.
3. A Claude AI agent takes over within 20 seconds. Unlike the rule engine, the agent can reason: it checks whether its actions are working, escalates or de-escalates based on what it sees, makes judgment calls about which IPs to block versus which to rate-limit, and writes a human-readable briefing for security staff.

The result is a system that responds faster than any human could, adapts to the specifics of each attack, and still keeps humans informed and in control.

### What Makes This Different From a Simple Rule Engine
A rule engine has a fixed playbook: if X then do Y. It cannot check whether Y worked. It cannot decide to do something different if the attack changes character mid-way. It cannot write a briefing for a human explaining what happened and why.

The Claude agent has tools — the same block, rate-limit, and shape-traffic functions the rule engine uses — but it decides when and how to use them by reasoning about the situation. It reads the current metrics, sees that blocking 3 IPs only reduced traffic by 10%, and decides to also enable traffic shaping. It can re-assess and escalate. It communicates its decisions in natural language. That's qualitatively different from rules.

### What Makes This Different From Just Calling an LLM
The LLM is not in the critical path for the first response. The rule engine fires in under 2 seconds — before the LLM even receives its first token. This matters because LLM latency (1–3 seconds) is too slow for the initial response window, and API reliability cannot be guaranteed. The LLM augments the system; it doesn't depend on it. If the API key is missing or the call fails, the rule engine and FSM keep running.

---

## PART 4: ANTICIPATED JUDGE QUESTIONS

**Q: Is this a real firewall? Would this work in production?**

The mitigation actions are simulated in memory and enforced at the application layer — the bank middleware returns HTTP 429 for blocked IPs. In production, you would replace the IPC file with calls to a real firewall API (AWS WAF, Cloudflare, iptables, etc.). The controller architecture — FSM, decision engine, tool-calling agent — would be identical. The `actions.py` module is the only layer that changes.

**Q: Why not just use a rule engine and skip the LLM?**

A rule engine is fast and deterministic but brittle. It can't verify that its actions worked. It can't reason about which specific IPs are most responsible. It can't adapt to attack patterns it wasn't explicitly programmed for. The LLM adds adaptive reasoning, effectiveness verification, and human communication — things a rule engine fundamentally cannot do.

**Q: Why not skip the rule engine and let the LLM do everything?**

LLM API calls take 1–3 seconds and depend on external network availability. The first 20 seconds of a DDoS attack can cause significant damage. The rule engine provides a guaranteed, fast initial response that doesn't depend on any external service. The two layers are complementary.

**Q: How does the ML model actually detect attacks?**

It's trained on labelled NetFlow data containing both normal traffic and known attack patterns (DDoS, port scans, etc.). For each flow, 23 features are extracted (ports, protocol, byte counts, timing, TCP flags). PCA reduces these to 10 principal components that capture the most variance, stripping out noise. An SVC classifier then draws decision boundaries in that 10-dimensional space. In production you'd retrain periodically on fresh traffic to catch new attack patterns.

**Q: What if an attacker spoofs a legitimate IP and it gets blocked?**

Three safeguards: First, a whitelist (`127.0.0.1`, configurable) that can never be blocked. Second, a maximum block rate of 20 IPs per minute, preventing bulk blocking from a single false-alarm burst. Third, all blocks auto-expire (5 minutes by default). The LLM agent also has access to `unblock_ip` and can choose to lift a block if metrics suggest it was mistaken.

**Q: What is the baseline and how does it prevent false positives?**

During the first 3 minutes of uptime, the controller samples system metrics (TPM, latency, flows/sec, entropy) to establish a "normal" baseline. The composite threat score is partially derived from how much current metrics deviate from this baseline. If the bank is always busy, the baseline will reflect that, and the system won't flag normal peak-hour traffic as an attack. Post-warmup, the baseline updates via exponential moving average (alpha=0.05) so it adapts slowly to genuine long-term growth.

**Q: How do you know the LLM agent's actions are actually working?**

The feedback loop records a snapshot of system metrics before each action, waits 15 seconds, then snapshots again. Deltas are computed and logged — did TPM drop, did latency improve? This data is also fed back to the LLM agent in subsequent iterations via `get_current_metrics`, so it can observe the effect of its own actions and adjust. All of this is in the structured JSON logs for post-incident review.

**Q: Couldn't an attacker overwhelm the system before the LLM even responds?**

Yes — which is exactly why the rule engine exists. The first layer (rate-limiting top talkers) fires within 2 seconds. By the time the LLM agent starts its first iteration (~20s into SUSPICIOUS, or immediately on MITIGATING), the worst traffic has already been throttled. The LLM's job is refinement and communication, not first response.

**Q: What does the LLM actually say to the security team?**

It uses the `send_alert` tool to post a natural-language message to the security dashboard. Something like: "DDoS attack detected from 5 source IPs. Blocked 3 high-volume attackers. Rate-limited 2 secondary sources. Traffic shaping enabled. TPM has dropped from 4,200 to 890. Situation is stabilising. Recommend reviewing blocked IPs in 5 minutes." At incident resolution, a full post-incident report is generated.

**Q: How much does the LLM cost to run?**

Claude Haiku is the fastest and cheapest model in the Claude family. Each agent loop (up to 10 iterations with tool results) costs a few cents at most. Given that this only fires during active attacks, the operational cost is negligible compared to the cost of DDoS downtime.

**Q: What happens if the Anthropic API is down?**

The rule engine and FSM continue operating normally. The LLM agent logs an error and returns silently. The system degrades gracefully — you lose the adaptive reasoning and human communication layers, but not the core detection and initial mitigation capability. This is by design.

**Q: How is this different from existing commercial products like Cloudflare or AWS Shield?**

Commercial products rely primarily on traffic volume thresholds and IP reputation databases — they're reactive at the infrastructure level. This project demonstrates an application-layer mitigation system with a reasoning agent that understands the semantic context of what's happening (which specific IPs, what the traffic patterns look like, whether mitigations are working) and can explain its decisions in plain English. It's a research prototype for the agent-driven approach rather than a replacement for infrastructure-level solutions.

**Q: Why a bank specifically?**

Financial services are the most targeted sector for DDoS attacks globally, and the stakes are high and tangible. A bank going down for 10 minutes is a regulatory event, a headline, and a breach of customer trust. It's also a domain where the cost of false positives (legitimate customers blocked) is concrete, which forces you to think carefully about safeguards — whitelist, max block rate, cooldowns, auto-expiry. Any serious application has to grapple with those trade-offs.

---

## PART 5: TECHNICAL STACK SUMMARY

| Component | Technology |
|---|---|
| Banking API | FastAPI, SQLAlchemy, SQLite, asyncio |
| Network monitoring | NetFlow v9 format, CSV persistence |
| ML detection | scikit-learn (PCA + SVC), joblib, pandas |
| Feature engineering | Custom WindowAggregator (50+ metrics) |
| Real-time comms | WebSockets (websockets library) |
| LLM agent | Anthropic Claude Haiku via anthropic SDK |
| HTTP client | aiohttp |
| Dashboards | Vanilla JS, WebSocket API, Chart.js |
| IPC enforcement | Atomic file write + asyncio background task |
| Logging | Structured JSON (NDJSON format) |
| Language | Python 3.12, fully async |
