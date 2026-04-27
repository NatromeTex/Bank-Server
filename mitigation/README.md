# Mitigation Controller

Stateful, risk-aware DDoS mitigation service. Monitors the bank server for attack detections and autonomously applies countermeasures through three phases: an instant rule engine, an adaptive LLM agent, and a structured de-escalation.

---

## Detection Pipeline Integration

The controller receives two streams from the bank server:
- **`/ws/security`** — ML alerts carrying `p_attack` (model probability), `req_rate` (packets/s), and `srcIP`
- **`/ws/stats`** — Live metrics: TPM, average latency, queue size

It also tails `data/raw/netflow/**/*.jsonl` directly to feed the traffic aggregator independent of the inference service.

---

## Risk Scoring

For every alerted IP the controller computes a continuous risk score:

```
risk = min(0.6 × p_attack + 0.4 × log(1 + req_rate) / log(1 + 50), 1.0)
```

Scores are **EMA-smoothed** (α = 0.7) across evaluation cycles to absorb transient spikes, and **persistence-gated**: an IP must register HIGH risk for ≥ 3 consecutive evaluations before a block fires. During the waiting window it receives a tighter rate limit instead.

| Smoothed risk | Tier | Action |
|---|---|---|
| < 0.35 | LOW | allow (logged) |
| 0.35 – 0.70 | MODERATE | rate limit (50 rps) |
| ≥ 0.70, count < 3 | HIGH (pending) | rate limit (10 rps) |
| ≥ 0.70, count ≥ 3 | HIGH (sustained) | block IP |

---

## Phase 1 — Rule Engine (instant, deterministic)

Fires every evaluation cycle (default: 2 s). Applies immediate first-responder actions:

1. Per-IP tiered decisions from recent ML alerts (risk score → block / rate-limit / allow)
2. SYN cookie activation if SYN ratio > 70%
3. Traffic shaping (artificial delay) if composite score > 0.70

---

## Phase 2 — LLM Agent (tool-calling, adaptive)

Spawned when the FSM enters MITIGATING, or after 20 s sustained in SUSPICIOUS. Claude receives the current metrics, top talkers, and the initial actions already taken, then runs an agentic tool-calling loop:

- Calls `get_current_metrics` and `get_top_talkers` to assess the situation
- Calls `block_ip`, `rate_limit`, `shape_traffic`, `enable_syn_cookies` as appropriate
- Re-checks metrics after each action to verify effectiveness
- Calls `send_alert` to notify human security staff
- Stops when the situation is stabilising

---

## Phase 3 — De-escalation & Incident Report

When traffic returns to baseline the FSM moves through STABILIZING → NORMAL. Blocks and rate limits are progressively lifted by the feedback loop. Claude generates a plain-English post-incident report sent to the security dashboard.

---

## FSM States

```
NORMAL → SUSPICIOUS → UNDER_ATTACK → MITIGATING → STABILIZING → NORMAL
              ↑                                           │
              └──────────── re-escalation ────────────────┘
```

Transitions are driven by the **composite threat score**:

```
S = 0.40 × C_ml + 0.25 × V + 0.20 × E + 0.15 × H
```

Where `C_ml` is the ML confidence from recent alert risk scores, `V` is the normalised flow rate, `E` is the inverted source-IP entropy, and `H` is the system health degradation vs baseline. See [`docs/mathematical_formulation.md`](../docs/mathematical_formulation.md) for the full derivation.

---

## How to Start

```bash
# From the project root, venv active:
python mitigation/app.py
```

Shadow mode — logs decisions but does **not** block any IPs:
```bash
SHADOW=1 python mitigation/app.py
```

---

## Startup Order

```
1. python bank/main.py            (port 8000)
2. python inference/app.py        (port 8001)
3. python mitigation/app.py       (client only — no port)
4. python tests/attack_load.py    (attack simulator)
```

---

## Prerequisites

```bash
pip install websockets aiohttp anthropic
export ANTHROPIC_API_KEY=sk-ant-...   # optional — LLM step skipped if absent
```

The bank server must be running on port 8000 before starting the controller.

---

## Enforcement

The controller writes the current enforcement state to `/tmp/mitigation_state.json`. The bank server middleware reads this file every 5 seconds and returns `HTTP 429 Too Many Requests` for blocked IPs.

---

## Terminal Output

The controller produces human-readable, colour-coded output. Each event type has its own format:

```
14:23:07.412  STATE CHANGE
  NORMAL  →  SUSPICIOUS
  Composite score : ████████░░░░░░░░░░░░ 0.423
  ML confidence   : 0.610
  ...

14:23:09.801  RISK DECISION
  IP     : 192.168.1.45
  Risk   : ████████████████░░░░ 0.791
  Tier   : HIGH
  Action : RATE LIMIT  [escalation pending]  streak 2/3

14:23:11.802  ✓ BLOCK  192.168.1.45  (ttl=300s)
```

Colours: green = safe, yellow = caution, red = threat, cyan = IP/target, magenta = FSM/incident. All events are also written as structured JSON to `mitigation/logs/controller_YYYYMMDD.jsonl`.

---

## Configuration

All thresholds live in `mitigation/config.py` as a single dataclass — no config files to edit.

| Setting | Default | Description |
|---|---|---|
| `enforcement_mode` | `True` | `False` = shadow / log-only |
| `suspicious_threshold` | `0.40` | Composite score → SUSPICIOUS |
| `attack_threshold` | `0.80` | Composite score → UNDER_ATTACK |
| `block_ttl_seconds` | `300` | Auto-expiry for blocked IPs (5 min) |
| `max_blocks_per_minute` | `20` | Safeguard: max blocks per 60 s window |
| `cooldown_seconds` | `30.0` | Min gap between same action on same target |
| `ip_whitelist` | `127.0.0.1, ::1` | Never blocked |
| `baseline_window_minutes` | `3.0` | Warmup before FSM activates |
| `rate_limit_rps_suspicious` | `50` | Per-IP cap in SUSPICIOUS / MODERATE tier |
| `rate_limit_rps_attack` | `10` | Per-IP cap for HIGH-tier pending block |
| `llm_enabled` | `True` | Generate incident reports with Claude |
| `llm_model` | `claude-haiku-4-5-20251001` | Model for agent and reports |

---

## Module Layout

```
mitigation/
├── app.py             ← START HERE
├── config.py          ← all thresholds & settings
├── controller.py      ← main orchestrator (asyncio tasks, JSONL watcher)
├── decision_engine.py ← risk score, EMA smoothing, persistence counter, tiered actions
├── fsm.py             ← 5-state finite state machine
├── context.py         ← baseline tracker, top-talker windows, flow format adapter
├── actions.py         ← rate_limit, block_ip, shape_traffic, syn_cookies
├── feedback.py        ← post-action measurement & de-escalation
├── ipc.py             ← writes /tmp/mitigation_state.json
├── llm_agent.py       ← Claude tool-calling agent (Phase 2 + incident report)
├── logger.py          ← coloured terminal output + JSONL file logger
└── logs/              ← daily .jsonl log files (created on first run)
```
