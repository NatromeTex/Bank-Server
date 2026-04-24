# AI Multi-Layer DDoS Detection & Mitigation for Financial Networks

This project implements a secure Bank Server with integrated AI-based DDoS detection and autonomous mitigation. It consists of a banking application, a NetFlow ingestion pipeline, an ML inference service, and a reactive mitigation controller powered by a rule engine and an LLM tool-calling agent.

## Project Structure

- **`bank/`**: FastAPI banking application.
    - `main.py`: Entry point with NetFlow logging middleware, WebSocket endpoints, and mitigation enforcement hook.
    - `static/`: Banking dashboard (`index.html`) and Security dashboard (`security.html`).
- **`inference/`**: Real-time ML inference service.
    - `app.py`: Loads the trained model, watches netflow CSVs, predicts attacks, pushes alerts via WebSocket.
- **`mitigation/`**: Autonomous mitigation controller (new).
    - `app.py`: Entry point. Runs the rule engine + LLM agent.
    - See [`mitigation/README.md`](mitigation/README.md) for full module breakdown.
- **`ingest/`**: Data ingestion.
    - `netflow_v9_parser.py`: Parses flow records and logs them to rotating CSVs.
- **`models/`**: ML model training.
    - `train_pca_svc.py`: PCA + SVC pipeline.
    - `train_lightgbm.py`: LightGBM pipeline.
- **`features/`**: Feature engineering.
    - `window_agg.py`: Sliding window aggregator for 50+ traffic metrics (entropy, rates, TCP flags, etc.).
- **`tests/`**: Attack simulation.
    - `attack_load.py`: Interactive CLI for DDoS simulation, port scanning, and background traffic generation.
- **`data/`**: Raw netflow logs and training data.

## Architecture

```
                        ┌────────────────────────┐
                        │   Attack Simulator     │
                        │   tests/attack_load.py │
                        └───────────┬────────────┘
                                    │ HTTP floods / spoofed IPs
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│                     Bank Server (:8000)                       │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ Middleware: extract flow → write CSV → check block list │  │
│  └────────────────────┬──────────────────────┬─────────────┘  │
│                       │                      │                │
│          /ws/stats (metrics)      /ws/security (alerts)       │
└───────────┬───────────────────────────────────┬───────────────┘
            │                                   │
            ▼                                   ▼
┌──────────────────────┐            ┌──────────────────────────┐
│ Inference Service    │            │ Mitigation Controller    │
│ (:8001)              │            │ (no port — client only)  │
│                      │            │                          │
│ Watches CSV files    │──alerts──▶ │ 1. Rule engine (instant) │
│ ML model predicts    │            │ 2. LLM agent (tool calls)│
│ Sends alerts via WS  │            │ 3. De-escalation + report│
└──────────────────────┘            │                          │
                                    │ Writes blocked IPs to    │
                                    │ /tmp/mitigation_state.json│
                                    └──────────────────────────┘
```

### Detection → Mitigation Flow

1. **Traffic Ingestion**: HTTP requests hit the bank server. The middleware extracts flow metadata (IPs, ports, bytes, timing) and writes it to rotating CSVs.
2. **ML Inference**: The inference service tails the CSVs, runs each flow through a PCA+SVC model, and broadcasts attack alerts to `/ws/security`.
3. **Rule Engine** (instant): The mitigation controller's FSM transitions from `NORMAL → SUSPICIOUS → UNDER_ATTACK → MITIGATING`. The decision engine immediately blocks top attacking IPs, rate-limits secondary IPs, and enables traffic shaping or SYN cookies.
4. **LLM Agent** (adaptive): After 20 seconds in SUSPICIOUS (or immediately on MITIGATING), a Claude tool-calling agent spawns. It assesses live metrics, takes further targeted actions (block, rate-limit, shape), verifies effectiveness, and alerts human staff via the security dashboard.
5. **De-escalation**: When metrics return to baseline, the FSM transitions through `STABILIZING → NORMAL`. Blocks and rate limits are progressively lifted. A post-incident report is generated and sent to the dashboard.

### FSM States

```
NORMAL → SUSPICIOUS → UNDER_ATTACK → MITIGATING → STABILIZING → NORMAL
                 ↑                                      │
                 └──────── re-escalation ───────────────┘
```

## Setup

### 1. Install Dependencies

```bash
pip install fastapi uvicorn sqlalchemy pandas scikit-learn joblib pyyaml websockets aiohttp anthropic
```

### 2. Set API Key (required for the LLM agent)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Add to `~/.zshrc` for persistence. The system still works without it — only the LLM agent steps are skipped.

### 3. Train the Model

```bash
python models/train_pca_svc.py
```

Saves the trained model to `models/artifacts/model.joblib`.

## Usage

### Quick Start — Launch Everything

```bash
./start.sh
```

Opens 4 Terminal windows: bank server, inference, mitigation controller, and attack simulator.

### Manual Start (in separate terminals)

```bash
# Terminal 1: Bank Server
cd bank && python -m uvicorn main:app --reload

# Terminal 2: Inference Service
python inference/app.py

# Terminal 3: Mitigation Controller
python mitigation/app.py

# Terminal 4: Attack Simulator
python tests/attack_load.py
```

### Shadow Mode (log-only, no IP blocking)

```bash
SHADOW=1 python mitigation/app.py
```

### Dashboards

- **Banking Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Security Dashboard**: [http://localhost:8000/security](http://localhost:8000/security)
- **Inference Health**: [http://localhost:8001/health](http://localhost:8001/health)

## Logging

- **NetFlow Logs**: `data/raw/netflow/YYYY/MM/DD/HH/flows_0.csv`
- **Mitigation Logs**: `mitigation/logs/controller_YYYYMMDD.jsonl` (structured JSON — FSM transitions, actions, feedback, LLM tool calls, incident reports)

## Mitigation Tools

The rule engine and LLM agent share the same set of tools:

| Tool | Description |
|---|---|
| `block_ip(ip, ttl)` | Block an IP for a duration (default 5 min). Enforced by bank middleware returning HTTP 429. |
| `rate_limit(ip, rps_cap)` | Cap per-IP request rate. |
| `shape_traffic(delay_ms)` | Add artificial response delay to throttle all traffic. |
| `enable_syn_cookies()` | Enable SYN flood protection mode. |
| `unblock_ip(ip)` | Lift a block early. |
| `send_alert(message, level)` | Send a human-readable alert to the security dashboard. |

Safeguards: IP whitelist (never blocks `127.0.0.1`), max 20 blocks/minute, 30s cooldown per action per target, auto-expiry on all blocks.
