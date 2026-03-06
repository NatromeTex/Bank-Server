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

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Add CORS middleware to allow dashboard polling
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, set to specific origins e.g. ["http://localhost:8000"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model
import csv

MODEL_PATH = "models/artifacts/model.joblib"
DATA_DIR = Path("data/raw/netflow")
model = None

class Flow(BaseModel):
    srcIP: str
    dstIP: str
    srcPort: int
    dstPort: int
    protocol: int
    bytes: int
    packets: int
    startTime: float
    endTime: float
    tcp_flags: str
    total_flows_exp: int # <--- Added missing feature

# Track processed lines for each file
processed_files = {} # {file_path_str: line_offset}

@app.on_event("startup")
async def startup_event():
    global model
    # Load model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"Model loaded from {MODEL_PATH}")
    else:
        print(f"Model not found at {MODEL_PATH}")
        
    # Send system online alert
    await send_alert({
        "alert": "AI Inference Engine Online",
        "type": "info",
        "details": {"status": "ready", "model": "loaded" if model else "failed"}
    })

    # Start watcher
    asyncio.create_task(watcher_loop())

async def watcher_loop():
    print("Starting AI Watcher...")
    while True:
        try:
            # Recursively find all CSV files
            files = sorted(DATA_DIR.rglob("*.csv"), key=lambda p: p.stat().st_mtime)
            
            for file_path in files:
                str_path = str(file_path)
                current_offset = processed_files.get(str_path, 0)
                
                # Check for new content
                if file_path.stat().st_size > current_offset:
                    await process_file(file_path, current_offset)
                    
        except Exception as e:
            print(f"Watcher error: {e}")
            
        await asyncio.sleep(1)

async def process_file(file_path: Path, offset: int):
    str_path = str(file_path)
    new_offset = offset
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            f.seek(offset)
            # If reading from start, skip header
            if offset == 0:
                header = f.readline()
                new_offset += len(header.encode('utf-8')) # Approximate
                
    except Exception as e:
        print(f"Error opening {file_path}: {e}")
        return

    # Let's try a simpler approach for text files: readlines()
    with open(file_path, "r", encoding="utf-8") as f:
        f.seek(offset)
        
        # Skip header if it's the very first read of a file
        if offset == 0:
            f.readline()
            
        reader = csv.DictReader(f, fieldnames=[
            'FLOW_ID', 'PROTOCOL_MAP', 'L4_SRC_PORT', 'IPV4_SRC_ADDR', 'L4_DST_PORT', 'IPV4_DST_ADDR',
            'FIRST_SWITCHED', 'FLOW_DURATION_MILLISECONDS', 'LAST_SWITCHED', 'PROTOCOL', 'TCP_FLAGS',
            'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'TCP_WIN_MIN_IN', 'TCP_WIN_MIN_OUT', 'TCP_WIN_MSS_IN',
            'TCP_WIN_SCALE_IN', 'TCP_WIN_SCALE_OUT', 'SRC_TOS', 'DST_TOS', 'TOTAL_FLOWS_EXP',
            'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'TOTAL_PKTS_EXP', 'TOTAL_BYTES_EXP', 'IN_BYTES',
            'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS', 'ANALYSIS_TIMESTAMP', 'ANOMALY', 'ID', 'ALERT'
        ])
        
        for row in reader:
            if not row['IPV4_SRC_ADDR']: continue # Skip empty lines
            
            try:
                # Convert CSV row to Flow object
                flow = Flow(
                    srcIP=row.get('IPV4_SRC_ADDR', '0.0.0.0'),
                    dstIP=row.get('IPV4_DST_ADDR', '0.0.0.0'),
                    srcPort=int(row.get('L4_SRC_PORT', 0)),
                    dstPort=int(row.get('L4_DST_PORT', 0)),
                    protocol=int(row.get('PROTOCOL', 0)),
                    bytes=int(row.get('IN_BYTES', 0)),
                    packets=int(row.get('IN_PKTS', 0)),
                    startTime=float(row.get('FIRST_SWITCHED', 0)),
                    endTime=float(row.get('LAST_SWITCHED', 0)),
                    tcp_flags=row.get('TCP_FLAGS', ""),
                    total_flows_exp=int(row.get('TOTAL_FLOWS_EXP', 0)) # <--- Extract feature
                )
                
                # Run inference
                await infer_flow(flow)
                
            except Exception as e:
                print(f"Row parsing error: {e}")
        
        new_offset = f.tell()
        
    processed_files[str_path] = new_offset

async def send_alert(alert_data):
    uri = "ws://localhost:8000/ws/security"
    try:
        async with websockets.connect(uri) as websocket:
            await websocket.send(json.dumps(alert_data))
    except Exception as e:
        print(f"Failed to send alert: {e}")

def map_flow_to_features(flow: Flow):
    # Map incoming flow to the features expected by the model
    
    data = {
        'L4_SRC_PORT': flow.srcPort,
        'L4_DST_PORT': flow.dstPort,
        'FIRST_SWITCHED': flow.startTime,
        'FLOW_DURATION_MILLISECONDS': (flow.endTime - flow.startTime) * 1000,
        'LAST_SWITCHED': flow.endTime,
        'PROTOCOL': flow.protocol,
        'TCP_FLAGS': 0, # Assuming 0 if we can't parse string easily here without logic
        'TCP_WIN_MAX_IN': 0,
        'TCP_WIN_MAX_OUT': 0,
        'TCP_WIN_MIN_IN': 0,
        'TCP_WIN_MIN_OUT': 0,
        'TCP_WIN_MSS_IN': 0,
        'TCP_WIN_SCALE_IN': 0,
        'TCP_WIN_SCALE_OUT': 0,
        'SRC_TOS': 0,
        'DST_TOS': 0,
        'TOTAL_FLOWS_EXP': flow.total_flows_exp, # <--- Added feature
        'IN_BYTES': flow.bytes,
        'IN_PKTS': flow.packets,
        'OUT_BYTES': 0, 
        'OUT_PKTS': 0,
        'ANOMALY': 0 
    }
    
    return pd.DataFrame([data])

@app.post("/infer/flow")
async def infer_flow(flow: Flow):
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        features = map_flow_to_features(flow)
        
        # Predict
        prediction = model.predict(features)[0]
        
        # If prediction is an attack (not 'None')
        if prediction != 'None':
            alert = {
                "alert": f"Attack Detected: {prediction}",
                "type": "critical",
                "details": flow.dict()
            }
            await send_alert(alert)
            
        return {"status": "processed", "prediction": prediction}
        
    except Exception as e:
        print(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "ok", "model_loaded": model is not None}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
