# Mitigation Controller

Stateful DDoS mitigation service that watches the bank server for attack detections and autonomously applies countermeasures.

## What it does

### Phase 1 — Rule engine (instant, deterministic)
Fires the moment an attack is detected. Applies immediate actions based on composite threat score: blocks top attacking IPs, rate-limits mid-tier IPs, enables SYN cookies, shapes traffic.

### Phase 2 — LLM agent (tool-calling, adaptive)
Spawned in the background when the FSM enters MITIGATING. Claude receives the current situation (metrics, top talkers, initial actions) and runs an agentic tool-calling loop:
- Calls `get_current_metrics` and `get_top_talkers` to assess the situation
- Calls `block_ip`, `rate_limit`, `shape_traffic`, `enable_syn_cookies` as it sees fit
- Re-checks metrics to verify actions are working
- Calls `send_alert` to notify human security staff
- Stops when satisfied the situation is stabilising

### Phase 3 — De-escalation & report
When traffic returns to baseline, the FSM transitions through STABILIZING → NORMAL. Enforcement rules are progressively lifted, and Claude generates a plain-English incident report sent to the security dashboard.

---

The FSM states: `NORMAL → SUSPICIOUS → UNDER_ATTACK → MITIGATING → STABILIZING → NORMAL`

## How to start

```bash
# From the project root, with the venv active:
python mitigation/app.py
```

Shadow mode (logs everything but does NOT block any IPs — safe for testing the logic):
```bash
SHADOW=1 python mitigation/app.py
```

Logs are written to `mitigation/logs/controller_YYYYMMDD.jsonl` and stdout.

## Prerequisites

The bank server must already be running (port 8000). The controller connects to it via WebSocket.

Install extra dependencies if not already in your venv:
```bash
pip install websockets aiohttp anthropic
```

For LLM incident reports you need an Anthropic API key:
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

If the key is missing the controller still works — the LLM step is silently skipped.

## Startup order

```
1. python bank/main.py         (port 8000)
2. python inference/app.py     (port 8001)
3. python mitigation/app.py    (no port — client only)
4. python tests/attack_load.py (run attacks)
```

Or use `./start.sh` which opens the first three in separate Terminal windows (add a fourth terminal for the attack tool if needed).

## Enforcement

The controller writes blocked IPs to `/tmp/mitigation_state.json`. The bank server middleware reads this file every 5 seconds and returns `HTTP 429` for blocked IPs.

To disable enforcement (observe decisions without blocking), run with `SHADOW=1`.

## Configuration

All thresholds are in `mitigation/config.py` as a single dataclass. Key settings:

| Setting | Default | Description |
|---|---|---|
| `enforcement_mode` | `True` | Set False for shadow/log-only mode |
| `suspicious_threshold` | `0.40` | Composite score to enter SUSPICIOUS |
| `attack_threshold` | `0.80` | Composite score to enter UNDER_ATTACK |
| `block_ttl_seconds` | `300` | How long blocked IPs stay blocked |
| `max_blocks_per_minute` | `20` | Safeguard: max IP blocks per minute |
| `ip_whitelist` | `127.0.0.1, ::1` | IPs never blocked |
| `baseline_window_minutes` | `3.0` | Warmup period before FSM activates |
| `llm_enabled` | `True` | Generate incident reports with Claude |

## Module layout

```
mitigation/
├── app.py             ← START HERE
├── config.py          ← all thresholds & settings
├── controller.py      ← main orchestrator (asyncio tasks)
├── fsm.py             ← finite state machine (5 states)
├── decision_engine.py ← composite scoring + rule-based first-responder actions
├── context.py         ← baseline tracker, top-talker windows, WindowAggregator
├── actions.py         ← rate_limit, block_ip, shape_traffic, syn_cookies
├── feedback.py        ← post-action measurement & de-escalation
├── ipc.py             ← writes /tmp/mitigation_state.json
├── llm_agent.py       ← Claude tool-calling agent (Phase 2 + incident report)
├── logger.py          ← structured JSON logger
└── logs/              ← daily .jsonl log files (created on first run)
```
