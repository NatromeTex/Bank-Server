# AI Multi-Layer DDoS Detection & Mitigation for Financial Networks

A secure bank server with integrated AI-based DDoS detection and autonomous mitigation. Traffic is captured as bidirectional flows, classified by ML models trained on **CICDDoS2019**, and responded to by a risk-aware mitigation controller backed by a finite state machine, a rule engine, and a Claude LLM tool-calling agent.

## Project Structure

```
Bank Server/
├── bank/                        # FastAPI banking application
│   ├── main.py                  # Routes, middleware, WebSocket endpoints, mitigation hook
│   └── static/                  # Banking dashboard & Security dashboard (HTML)
├── inference/                   # Real-time ML inference service
│   └── app.py                   # Watches JSONL flow logs, predicts attacks, pushes alerts
├── mitigation/                  # Autonomous mitigation controller
│   ├── app.py                   # Entry point
│   ├── controller.py            # Main orchestrator (asyncio tasks)
│   ├── decision_engine.py       # Risk scoring, EMA smoothing, tiered actions
│   ├── fsm.py                   # 5-state finite state machine
│   ├── context.py               # Baseline tracker, top-talker windows, WindowAggregator
│   ├── actions.py               # block_ip, rate_limit, shape_traffic, syn_cookies
│   ├── feedback.py              # Post-action measurement & de-escalation
│   ├── ipc.py                   # Writes /tmp/mitigation_state.json for bank middleware
│   ├── llm_agent.py             # Claude tool-calling agent (Phase 2 + incident report)
│   ├── logger.py                # Human-readable coloured terminal + JSONL file logger
│   └── config.py                # All thresholds and settings (single dataclass)
├── ingest/
│   └── netflow_v9_parser.py     # Flow extractor — outputs CICFlowMeter-compatible JSONL
├── features/
│   └── window_agg.py            # Sliding-window traffic aggregator (50+ metrics)
├── models/
│   ├── train_lightgbm_ddos2019.py   # LightGBM trainer (CICDDoS2019, 80/20 split)
│   ├── train_rf_ddos2019.py         # Random Forest trainer
│   ├── train_pca_svc_ddos2019.py    # PCA + SVC trainer
│   └── artifacts_ddos2019/          # Saved models and metrics (created at train time)
├── dataset/                     # CICDDoS2019 parquet files (cleaned)
├── tests/
│   ├── attack_load.py           # Interactive DDoS simulator, port scanner, traffic gen
│   ├── test_inference_fix.py    # Inference pipeline smoke tests
│   └── unit/
│       ├── test_netflow_parser.py   # 19 unit tests for the flow extractor
│       └── test_window_agg.py       # Unit tests for the window aggregator
└── docs/
    └── mathematical_formulation.md  # Full mathematical spec of the detection system
```

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
│  │ Middleware: extract flow → write JSONL → check blocklist│  │
│  └─────────────────────┬─────────────────────┬─────────────┘  │
│                        │                     │                │
│          /ws/stats (metrics)     /ws/security (alerts)        │
└──────────┬────────────────────────────────────┬──────────────┘
           │                                    │
           ▼                                    ▼
┌──────────────────────┐            ┌──────────────────────────┐
│ Inference Service    │            │ Mitigation Controller    │
│ (:8001)              │            │ (client only)            │
│                      │            │                          │
│ Watches JSONL files  │──alerts──▶ │ 1. Rule engine (instant) │
│ CICDDoS2019 model    │            │ 2. LLM agent (adaptive)  │
│ predicts attack type │            │ 3. De-escalation + report│
│ Sends WS alert with  │            │                          │
│ p_attack + req_rate  │            │ Writes blocked IPs →     │
└──────────────────────┘            │ /tmp/mitigation_state.json
                                    └──────────────────────────┘
```

### Detection → Mitigation Flow

1. **Traffic Ingestion**: HTTP requests hit the bank server. Middleware extracts bidirectional flow metadata (IPs, ports, packet counts, byte counts, flag counts, timing) and appends each flow as a JSON line to a rotating hourly `.jsonl` file.

2. **ML Inference**: The inference service tails the JSONL files, maps each flow to the 77 CICFlowMeter feature columns, runs the CICDDoS2019-trained model, and broadcasts attack alerts with `p_attack` (probability) and `req_rate` (packets/s) to `/ws/security`.

3. **Risk Scoring**: For each alerted IP, a continuous risk score is computed:
   ```
   risk = min(0.6 × p_attack + 0.4 × log(1 + req_rate) / log(1 + 50), 1.0)
   ```
   Scores are EMA-smoothed (α=0.7) across evaluation cycles to suppress transient spikes.

4. **Tiered Response**: Each IP is classified into a risk tier and acted on:
   - **LOW** (< 0.35) → allow
   - **MODERATE** (0.35–0.70) → rate limit
   - **HIGH** (≥ 0.70, sustained ≥ 3 cycles) → block

5. **FSM + Rule Engine**: The composite threat score drives FSM state transitions. The decision engine applies immediate first-responder actions (block top talkers, rate-limit mid-tier, SYN cookies, traffic shaping) based on current state.

6. **LLM Agent**: After 20 seconds in SUSPICIOUS, or immediately on entering MITIGATING, a Claude tool-calling agent spawns. It assesses live metrics, takes targeted actions, verifies effectiveness, and alerts human staff.

7. **De-escalation**: When metrics return to baseline the FSM transitions through STABILIZING → NORMAL. Blocks and rate limits are progressively lifted. A post-incident report is generated.

### FSM States

```
NORMAL → SUSPICIOUS → UNDER_ATTACK → MITIGATING → STABILIZING → NORMAL
              ↑                                           │
              └──────────── re-escalation ────────────────┘
```

## Dataset

Models are trained on **CICDDoS2019** (Canadian Institute for Cybersecurity, 2019), stored as cleaned parquet files in `dataset/`. The dataset covers 18 attack types including SYN flood, UDP flood, LDAP, MSSQL, NetBIOS, DNS, NTP, SNMP, TFTP, Portmap, and UDPLag amplification attacks, alongside benign traffic.

| Property | Value |
|---|---|
| Total rows | ~431,000 |
| Feature columns | 77 (CICFlowMeter) |
| Label column | `Label` (`Benign` + 17 attack classes) |
| Train/test split | 80 / 20 stratified |
| File format | Parquet |

## Setup

### 1. Install Dependencies

```bash
pip install fastapi uvicorn sqlalchemy pandas scikit-learn lightgbm joblib \
            pyarrow pyyaml websockets aiohttp anthropic
```

### 2. Set API Key (required for LLM agent and incident reports)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

The system works without this key — the LLM agent steps are silently skipped.

### 3. Train a Model

Run any of the three trainers from the project root. Each performs an 80/20 stratified split, trains, prints a classification report, saves artifacts to `models/artifacts_ddos2019/<model>/`, and removes legacy NetFlow v9 CSV files.

```bash
# LightGBM (fastest, recommended)
python models/train_lightgbm_ddos2019.py

# Random Forest (also writes feature importances to metrics.json)
python models/train_rf_ddos2019.py

# PCA + SVC (uses a 60k stratified subsample for SVC fit — see note in script)
python models/train_pca_svc_ddos2019.py
```

Point the inference service at the model you want by editing `MODEL_PATH` in `inference/app.py`.

## Usage

### Quick Start

```bash
./start.sh
```

### Manual Start (separate terminals)

```bash
# Terminal 1 — Bank Server
python bank/main.py

# Terminal 2 — Inference Service
python inference/app.py

# Terminal 3 — Mitigation Controller
python mitigation/app.py

# Terminal 4 — Attack Simulator
python tests/attack_load.py
```

### Shadow Mode (observe decisions without blocking any IPs)

```bash
SHADOW=1 python mitigation/app.py
```

### Run Unit Tests

```bash
python -m unittest tests/unit/test_netflow_parser.py -v
python -m unittest tests/unit/test_window_agg.py -v
```

### Inference Smoke Test (requires running bank server)

```bash
python tests/test_inference_fix.py
```

### Dashboards

| Dashboard | URL |
|---|---|
| Banking | http://localhost:8000 |
| Security | http://localhost:8000/security |
| Inference Health | http://localhost:8001/health |

## Flow Record Format

The flow extractor writes one JSON object per line to `data/raw/netflow/YYYY/MM/DD/HH/flows_0.jsonl`. Key fields:

| Field | Description |
|---|---|
| `srcIP`, `dstIP` | Source and destination IP |
| `srcPort`, `dstPort` | Ports |
| `protocol` | IP protocol number (6=TCP, 17=UDP) |
| `fwd_packets`, `bwd_packets` | Bidirectional packet counts |
| `fwd_bytes`, `bwd_bytes` | Bidirectional byte counts |
| `flow_duration_us` | Flow duration in microseconds |
| `{fin,syn,rst,psh,ack,urg,cwe,ece}_flag_count` | TCP flag counts |
| `fwd_pkt_len_{max,min,mean,std}` | Forward packet length statistics |
| `init_{fwd,bwd}_win_bytes` | Initial TCP window sizes |

Fields requiring packet-level timestamps (IAT, Active/Idle, Bulk stats) are derived as zero in the 77-column feature vector — they are present in the dataset but unavailable from flow-level captures without a full packet capture agent.

## Mitigation Tools

| Tool | Description |
|---|---|
| `block_ip(ip, ttl)` | Block an IP (default 5 min). Bank middleware returns HTTP 429. |
| `rate_limit(ip, rps_cap)` | Cap per-IP request rate. |
| `shape_traffic(delay_ms)` | Add artificial response delay to throttle all traffic. |
| `enable_syn_cookies()` | Enable SYN flood protection mode. |
| `unblock_ip(ip)` | Lift a block early. |
| `send_alert(message, level)` | Push a human-readable alert to the security dashboard. |

**Safeguards**: IP whitelist (never blocks `127.0.0.1`), max 20 blocks/minute, 30s cooldown per action per target, automatic block expiry after TTL.

## Logging

| Log | Location | Format |
|---|---|---|
| Flow records | `data/raw/netflow/YYYY/MM/DD/HH/flows_0.jsonl` | JSONL |
| Mitigation decisions | `mitigation/logs/controller_YYYYMMDD.jsonl` | JSONL |
| Terminal output | stdout | Human-readable coloured text with timestamps |

The mitigation terminal output includes coloured state transitions, risk bars, decision trees with streak counters, feedback results, and incident reports. See `mitigation/logger.py` for the full format.
