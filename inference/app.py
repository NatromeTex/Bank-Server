from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
import os
import websockets
import asyncio
import json
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "models/artifacts/model.joblib"
DATA_DIR   = Path("data/raw/netflow")
model      = None

# CICDDoS2019 feature columns — must match training order exactly
FEATURE_COLUMNS = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Avg Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init Fwd Win Bytes", "Init Bwd Win Bytes", "Fwd Act Data Packets", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


class Flow(BaseModel):
    srcIP:    str
    dstIP:    str
    srcPort:  int
    dstPort:  int
    protocol: int

    fwd_packets: int
    bwd_packets: int
    fwd_bytes:   int
    bwd_bytes:   int
    flow_duration_us: int           # microseconds

    fwd_pkt_len_max:  float = 0.0
    fwd_pkt_len_min:  float = 0.0
    fwd_pkt_len_mean: float = 0.0
    fwd_pkt_len_std:  float = 0.0
    bwd_pkt_len_max:  float = 0.0
    bwd_pkt_len_min:  float = 0.0
    bwd_pkt_len_mean: float = 0.0
    bwd_pkt_len_std:  float = 0.0

    fin_flag_count: int = 0
    syn_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 0
    urg_flag_count: int = 0
    cwe_flag_count: int = 0
    ece_flag_count: int = 0

    init_fwd_win_bytes:   int = 0
    init_bwd_win_bytes:   int = 0
    fwd_header_length:    int = 0
    bwd_header_length:    int = 0
    fwd_act_data_packets: int = 0


processed_files: dict[str, int] = {}


@app.on_event("startup")
async def startup_event():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"Model loaded from {MODEL_PATH}")
    else:
        print(f"Model not found at {MODEL_PATH}")

    await send_alert({
        "alert": "AI Inference Engine Online",
        "type": "info",
        "details": {"status": "ready", "model": "loaded" if model else "failed"},
    })
    asyncio.create_task(watcher_loop())


async def watcher_loop():
    print("Starting AI Watcher (JSONL)...")
    while True:
        try:
            files = sorted(DATA_DIR.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime)
            for file_path in files:
                str_path = str(file_path)
                offset = processed_files.get(str_path, 0)
                if file_path.stat().st_size > offset:
                    await process_file(file_path, offset)
        except Exception as e:
            print(f"Watcher error: {e}")
        await asyncio.sleep(1)


async def process_file(file_path: Path, offset: int):
    str_path = str(file_path)
    with open(file_path, "r", encoding="utf-8") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                flow_dict = json.loads(line)
                flow = Flow(**{k: flow_dict[k] for k in Flow.__fields__ if k in flow_dict})
                await infer_flow(flow)
            except Exception as e:
                print(f"Row parsing error: {e}")
        processed_files[str_path] = f.tell()


async def send_alert(alert_data: dict):
    uri = "ws://localhost:8000/ws/security"
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(alert_data))
    except Exception as e:
        print(f"Failed to send alert: {e}")


def map_flow_to_features(flow: Flow) -> pd.DataFrame:
    fwd_pkts  = flow.fwd_packets
    bwd_pkts  = flow.bwd_packets
    fwd_bytes = flow.fwd_bytes
    bwd_bytes = flow.bwd_bytes
    total_pkts  = fwd_pkts  + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    duration_us = max(flow.flow_duration_us, 1)
    duration_s  = duration_us / 1_000_000

    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0
    pkt_len_min  = min(flow.fwd_pkt_len_min, flow.bwd_pkt_len_min)
    pkt_len_max  = max(flow.fwd_pkt_len_max, flow.bwd_pkt_len_max)

    data = {
        "Protocol":               flow.protocol,
        "Flow Duration":          duration_us,
        "Total Fwd Packets":      fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Fwd Packets Length Total": fwd_bytes,
        "Bwd Packets Length Total": bwd_bytes,
        "Fwd Packet Length Max":  flow.fwd_pkt_len_max,
        "Fwd Packet Length Min":  flow.fwd_pkt_len_min,
        "Fwd Packet Length Mean": flow.fwd_pkt_len_mean,
        "Fwd Packet Length Std":  flow.fwd_pkt_len_std,
        "Bwd Packet Length Max":  flow.bwd_pkt_len_max,
        "Bwd Packet Length Min":  flow.bwd_pkt_len_min,
        "Bwd Packet Length Mean": flow.bwd_pkt_len_mean,
        "Bwd Packet Length Std":  flow.bwd_pkt_len_std,
        "Flow Bytes/s":    total_bytes / duration_s,
        "Flow Packets/s":  total_pkts  / duration_s,
        "Flow IAT Mean": 0.0, "Flow IAT Std": 0.0,
        "Flow IAT Max":  0.0, "Flow IAT Min": 0.0,
        "Fwd IAT Total": 0.0, "Fwd IAT Mean": 0.0,
        "Fwd IAT Std":   0.0, "Fwd IAT Max":  0.0, "Fwd IAT Min": 0.0,
        "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0,
        "Bwd IAT Std":   0.0, "Bwd IAT Max":  0.0, "Bwd IAT Min": 0.0,
        "Fwd PSH Flags": flow.psh_flag_count,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": flow.urg_flag_count,
        "Bwd URG Flags": 0,
        "Fwd Header Length": flow.fwd_header_length,
        "Bwd Header Length": flow.bwd_header_length,
        "Fwd Packets/s": fwd_pkts / duration_s,
        "Bwd Packets/s": bwd_pkts / duration_s,
        "Packet Length Min":      pkt_len_min,
        "Packet Length Max":      pkt_len_max,
        "Packet Length Mean":     avg_pkt_size,
        "Packet Length Std":      0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": flow.fin_flag_count,
        "SYN Flag Count": flow.syn_flag_count,
        "RST Flag Count": flow.rst_flag_count,
        "PSH Flag Count": flow.psh_flag_count,
        "ACK Flag Count": flow.ack_flag_count,
        "URG Flag Count": flow.urg_flag_count,
        "CWE Flag Count": flow.cwe_flag_count,
        "ECE Flag Count": flow.ece_flag_count,
        "Down/Up Ratio":        bwd_pkts  / fwd_pkts  if fwd_pkts  > 0 else 0.0,
        "Avg Packet Size":      avg_pkt_size,
        "Avg Fwd Segment Size": fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0.0,
        "Avg Bwd Segment Size": bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0.0,
        "Fwd Avg Bytes/Bulk":    0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk":    0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": fwd_pkts,
        "Subflow Fwd Bytes":   fwd_bytes,
        "Subflow Bwd Packets": bwd_pkts,
        "Subflow Bwd Bytes":   bwd_bytes,
        "Init Fwd Win Bytes":   flow.init_fwd_win_bytes,
        "Init Bwd Win Bytes":   flow.init_bwd_win_bytes,
        "Fwd Act Data Packets": flow.fwd_act_data_packets,
        "Fwd Seg Size Min":     flow.fwd_pkt_len_min,
        "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
        "Idle Mean":   0.0, "Idle Std":   0.0, "Idle Max":   0.0, "Idle Min":   0.0,
    }
    return pd.DataFrame([data], columns=FEATURE_COLUMNS)


@app.post("/infer/flow")
async def infer_flow(flow: Flow):
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        features = map_flow_to_features(flow)
        features = features.replace([np.inf, -np.inf], np.nan).fillna(0)

        total_pkts  = flow.fwd_packets + flow.bwd_packets
        duration_s  = max(flow.flow_duration_us, 1) / 1_000_000
        req_rate    = total_pkts / duration_s

        proba      = model.predict_proba(features)[0]
        p_attack   = float(1.0 - proba[list(model.classes_).index("Benign")] if "Benign" in list(model.classes_) else proba.max())
        prediction = model.classes_[np.argmax(proba)]

        if prediction != "Benign":
            alert = {
                "alert": f"Attack Detected: {prediction}",
                "type":  "critical",
                "details": {
                    **flow.dict(),
                    "p_attack": p_attack,
                    "req_rate": req_rate,
                },
            }
            await send_alert(alert)

        return {
            "status":     "processed",
            "prediction": prediction,
            "p_attack":   p_attack,
            "req_rate":   req_rate,
        }

    except Exception as e:
        print(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": model is not None}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
