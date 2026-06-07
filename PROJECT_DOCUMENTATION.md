# Bank Server Project Documentation

Comprehensive technical reference for the Bank Server system: architecture, API endpoints, data models, ML pipeline, and the detection/mitigation subsystem.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Directory Structure](#directory-structure)
3. [Banking Application](#banking-application)
4. [ML Detection Pipeline](#ml-detection-pipeline)
5. [Mitigation Controller](#mitigation-controller)
6. [API Reference](#api-reference)
7. [Data Models](#data-models)
8. [Configuration Reference](#configuration-reference)

---

## Project Overview

The Bank Server is a FastAPI-based banking application augmented with an end-to-end AI-driven DDoS detection and mitigation system. Key design goals:

- **Real traffic capture**: every HTTP request is converted to a bidirectional flow record and logged as JSONL
- **CICDDoS2019 feature compatibility**: flow records produce the same 77 CICFlowMeter columns used in training
- **Continuous risk scoring**: ML probability + traffic intensity → smoothed risk score → tiered enforcement
- **Autonomous mitigation**: FSM + rule engine fires immediately; Claude LLM agent handles nuanced escalation
- **Audit trail**: every decision (state transition, action, risk score, feedback) written to structured JSONL logs with human-readable coloured terminal output

---

## Directory Structure

```
Bank Server/
├── bank/
│   ├── main.py          # FastAPI app, middleware, WebSocket endpoints, mitigation hook
│   ├── worker.py        # Async transaction queue and real-time metrics
│   ├── models.py        # SQLAlchemy ORM models (Account, Transaction)
│   ├── schemas.py       # Pydantic request/response schemas
│   ├── database.py      # DB connection and session factory
│   └── static/          # Banking dashboard (index.html) and Security dashboard
│
├── inference/
│   └── app.py           # Flow watcher, CICDDoS2019 feature mapping, model inference
│
├── mitigation/
│   ├── app.py           # Entry point
│   ├── config.py        # All thresholds (single MitigationConfig dataclass)
│   ├── controller.py    # Orchestrator: WebSocket listeners, JSONL watcher, eval loop
│   ├── decision_engine.py  # Risk score, EMA, persistence counter, tiered actions
│   ├── fsm.py           # 5-state FSM with sustained-condition timers
│   ├── context.py       # Baseline, top-talker windows, flow format adapter
│   ├── actions.py       # block_ip, rate_limit, shape_traffic, enable_syn_cookies
│   ├── feedback.py      # Post-action measurement and de-escalation
│   ├── ipc.py           # IPC file writer (/tmp/mitigation_state.json)
│   ├── llm_agent.py     # Claude tool-calling agent
│   ├── logger.py        # Coloured terminal output + JSONL file logger
│   └── logs/            # Daily .jsonl log files
│
├── ingest/
│   └── netflow_v9_parser.py  # Flow extractor: JSON bytes → canonical dict → JSONL
│
├── features/
│   └── window_agg.py    # Sliding-window traffic aggregator (50+ metrics)
│
├── models/
│   ├── train_lightgbm_ddos2019.py   # LightGBM trainer
│   ├── train_rf_ddos2019.py         # Random Forest trainer
│   ├── train_pca_svc_ddos2019.py    # PCA + SVC trainer
│   └── artifacts_ddos2019/          # Saved model artifacts (created at train time)
│
├── dataset/             # CICDDoS2019 parquet files (cleaned, ~431k rows, 17 attack types)
│
├── tests/
│   ├── attack_load.py           # Interactive DDoS simulator and background traffic tool
│   ├── test_inference_fix.py    # Inference pipeline smoke tests
│   └── unit/
│       ├── test_netflow_parser.py   # 19 unit tests for the flow extractor
│       └── test_window_agg.py       # Window aggregator unit tests
│
└── docs/
    └── mathematical_formulation.md  # Mathematical spec of the detection system
```

---

## Banking Application

### Async Transaction Processing

All write operations (create account, deposit, withdraw, transfer, delete) are queued in an `asyncio.Queue` and processed sequentially by a background worker. This:
- Serialises database writes — no race conditions without explicit locking
- Decouples request acceptance from processing for stable latency under load
- Tracks per-operation metrics (latency, success/failure counts)

### Real-time Metrics

An in-memory `Metrics` object tracks:
- **TPM**: sliding 10-second window of transaction completions
- **Avg Latency**: 30-second exponential moving average
- **Queue Size**: current backlog
- **Last 50 Transactions**: status and timing for dashboard display

Metrics are broadcast over `/ws/stats` every 500ms.

### NetFlow Middleware

Every HTTP request passing through the bank server is converted to a canonical bidirectional flow record and appended to a rotating hourly JSONL file. The middleware also reads `/tmp/mitigation_state.json` (written by the mitigation controller) and returns `HTTP 429` for any source IP currently in the block list.

---

## ML Detection Pipeline

### Dataset: CICDDoS2019

| Property | Value |
|---|---|
| Source | Canadian Institute for Cybersecurity, 2019 |
| Storage | `dataset/*.parquet` (cleaned) |
| Total rows | ~431,000 |
| Feature columns | 77 (CICFlowMeter) |
| Label column | `Label` — `Benign` + 17 attack classes |
| Train/test split | 80/20 stratified |

Attack classes: `DrDoS_DNS`, `DrDoS_LDAP`, `DrDoS_MSSQL`, `DrDoS_NTP`, `DrDoS_NetBIOS`, `DrDoS_SNMP`, `DrDoS_UDP`, `LDAP`, `MSSQL`, `NetBIOS`, `Portmap`, `Syn`, `TFTP`, `UDP`, `UDP-lag`, `UDPLag`, `WebDDoS`

### Available Models

| Script | Algorithm | Notes |
|---|---|---|
| `train_lightgbm_ddos2019.py` | LightGBM | 300 trees, `num_leaves=63`, fastest inference |
| `train_rf_ddos2019.py` | Random Forest | 200 trees, writes feature importances to metrics |
| `train_pca_svc_ddos2019.py` | PCA (30 components) + SVC RBF | SVC fit capped at 60k rows; evaluated on full test set |

All three trainers:
1. Load all parquet files from `dataset/`
2. Apply 80/20 stratified split (`random_state=42`)
3. Replace `inf`/`NaN` (common in CICFlowMeter zero-duration flows) with 0
4. Train and evaluate (accuracy, precision, recall, weighted F1, classification report)
5. Save `model.joblib` + `label_encoder.joblib` + `metrics.json` to `models/artifacts_ddos2019/<model>/`
6. Delete legacy NetFlow v9 CSV files from `data/`

### Flow Feature Extraction

The flow extractor (`ingest/netflow_v9_parser.py`) converts raw network metadata to the 77-column CICFlowMeter feature schema. Fields derivable from bidirectional flow totals are computed; fields requiring packet-level timestamps (IAT, Active/Idle, Bulk stats) are zero-filled.

**Computed at flow level:**
`Protocol`, `Flow Duration`, `Total Fwd/Bwd Packets`, `Fwd/Bwd Packets Length Total`, packet length min/max/mean, `Flow Bytes/s`, `Flow Packets/s`, `Fwd/Bwd Packets/s`, flag counts, `Down/Up Ratio`, `Avg Packet Size`, `Avg Fwd/Bwd Segment Size`, `Init Fwd/Bwd Win Bytes`, `Subflow Fwd/Bwd Packets/Bytes`

**Zero-filled (require packet capture):**
All IAT statistics, Active/Idle statistics, Bulk transfer statistics, `Packet Length Std/Variance`

### Inference Service

`inference/app.py` runs as a FastAPI service on port 8001. On startup it:
1. Loads the model from `MODEL_PATH`
2. Starts a background watcher that tails `data/raw/netflow/**/*.jsonl`
3. Maps each new flow line to the 77-column feature DataFrame
4. Runs `model.predict_proba` to get `p_attack`
5. If prediction ≠ `"Benign"`, broadcasts a WebSocket alert to `/ws/security` with `p_attack`, `req_rate`, and full flow metadata

Also exposes `POST /infer/flow` for direct inference calls and `GET /health`.

---

## Mitigation Controller

See [`mitigation/README.md`](mitigation/README.md) for the full operational guide.

### Risk Scoring Summary

```
risk = min(0.6 × p_attack + 0.4 × log(1 + req_rate) / log(1 + 50), 1.0)
smoothed_risk = 0.7 × current_risk + 0.3 × previous_risk   (EMA, α=0.7)
```

A block fires only after ≥ 3 consecutive HIGH evaluations on the same IP. Before that threshold, a tight rate limit (10 rps) is applied as an intermediate response.

### Composite Score

```
S = 0.40 × C_ml + 0.25 × V + 0.20 × E + 0.15 × H
```

`C_ml = max(risk) × 0.7 + mean(risk) × 0.3` across recent alert window — balances peak attack intensity with sustained behaviour.

Full derivation: [`docs/mathematical_formulation.md`](docs/mathematical_formulation.md)

---

## API Reference

### Account Management

#### `POST /accounts`
Create a new account.
```json
{ "name": "string", "pin": "string" }
```

#### `DELETE /accounts?account_id=&pin=`
Delete an account with PIN verification.

### Financial Operations

#### `POST /deposit`
```json
{ "account_id": 0, "amount": 0.0 }
```

#### `POST /withdraw`
```json
{ "amount": 0.0, "account_id": 0, "pin": "string" }
```

#### `POST /transfer`
```json
{ "amount": 0.0, "from_account_id": 0, "to_account_id": 0, "pin": "string" }
```

### Monitoring

#### `GET /admin/stats`
Snapshot of current server metrics.
```json
{
  "total_funds": 0.0,
  "account_count": 0,
  "avg_latency": 0.0,
  "tpm": 0,
  "queue_size": 0,
  "last_50_transactions": []
}
```

#### `WS /ws/stats`
Real-time metrics broadcast every 500ms.

#### `WS /ws/security`
Security alert channel. Inference service publishes here; mitigation controller and dashboards subscribe.

#### `POST /sys/admin/inject`
Inject a synthetic alert (used by attack simulator for testing):
```json
{ "alert": "string", "type": "critical|warning|info", "details": {} }
```

### Inference Service

#### `POST /infer/flow` (port 8001)
Direct inference on a single flow:
```json
{
  "srcIP": "string", "dstIP": "string",
  "srcPort": 0, "dstPort": 0, "protocol": 0,
  "fwd_packets": 0, "bwd_packets": 0,
  "fwd_bytes": 0, "bwd_bytes": 0,
  "flow_duration_us": 0,
  "syn_flag_count": 0, "ack_flag_count": 0,
  ...
}
```
Response:
```json
{ "status": "processed", "prediction": "Benign", "p_attack": 0.03, "req_rate": 66.7 }
```

#### `GET /health` (port 8001)
```json
{ "status": "ok", "model_loaded": true }
```

---

## Data Models

### Account

| Field | Type | Description |
|---|---|---|
| `id` | Integer (PK) | Auto-increment |
| `name` | String | Account holder name |
| `balance` | Float | Current balance (default 0.0) |
| `pin` | String | Transaction PIN |

### Transaction

| Field | Type | Description |
|---|---|---|
| `id` | Integer (PK) | Auto-increment |
| `type` | String | `deposit`, `withdraw`, or `transfer` |
| `amount` | Float | Transaction value |
| `from_account` | Integer (nullable) | Source account ID |
| `to_account` | Integer (nullable) | Destination account ID |
| `timestamp` | DateTime | UTC time of transaction |

### Flow Record (JSONL)

One JSON object per line in `data/raw/netflow/YYYY/MM/DD/HH/flows_0.jsonl`:

| Field | Type | Description |
|---|---|---|
| `srcIP`, `dstIP` | str | Source / destination IP |
| `srcPort`, `dstPort` | int | Ports |
| `protocol` | int | IP protocol (6=TCP, 17=UDP) |
| `fwd_packets`, `bwd_packets` | int | Bidirectional packet counts |
| `fwd_bytes`, `bwd_bytes` | int | Bidirectional byte counts |
| `flow_duration_us` | int | Duration in microseconds |
| `*_flag_count` | int | Per-type TCP flag counts (fin/syn/rst/psh/ack/urg/cwe/ece) |
| `fwd_pkt_len_{max,min,mean,std}` | float | Forward packet length statistics |
| `bwd_pkt_len_{max,min,mean,std}` | float | Backward packet length statistics |
| `init_{fwd,bwd}_win_bytes` | int | Initial TCP window sizes |
| `fwd_header_length`, `bwd_header_length` | int | Header lengths |
| `fwd_act_data_packets` | int | Forward data-carrying packets |

---

## Configuration Reference

All mitigation settings are in `mitigation/config.py` → `MitigationConfig` dataclass. Key values:

| Setting | Default | Description |
|---|---|---|
| `suspicious_threshold` | 0.40 | Composite score → SUSPICIOUS |
| `attack_threshold` | 0.80 | Composite score → UNDER_ATTACK |
| `weight_ml` | 0.40 | ML confidence weight in composite score |
| `weight_volume` | 0.25 | Traffic volume weight |
| `weight_entropy` | 0.20 | Source IP entropy weight |
| `weight_health` | 0.15 | System health weight |
| `rate_limit_rps_suspicious` | 50 | Per-IP cap for MODERATE tier |
| `rate_limit_rps_attack` | 10 | Per-IP cap for HIGH-pending-block |
| `block_ttl_seconds` | 300 | Block auto-expiry (5 min) |
| `max_blocks_per_minute` | 20 | Burst safeguard |
| `cooldown_seconds` | 30.0 | Min gap between same action/target |
| `baseline_window_minutes` | 3.0 | Warmup before FSM activates |
| `evaluation_interval_secs` | 2.0 | How often the eval loop runs |
| `llm_model` | `claude-haiku-4-5-20251001` | Claude model for agent and reports |
