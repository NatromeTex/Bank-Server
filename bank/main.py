from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import asyncio
import time
import uuid
import json
from database import engine, Base
from worker import worker, transaction_queue, metrics
from schemas import AccountCreate, DepositRequest, WithdrawRequest, TransferRequest
import datetime
import sys
from pathlib import Path

# Add project root to sys.path to allow importing ingest
sys.path.append(str(Path(__file__).parent.parent))
from ingest import netflow_v9_parser

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.middleware("http")
async def netflow_logging_middleware(request: Request, call_next):
    start_time = time.time()

    # Extract client IP early (needed for mitigation block check)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_host = forwarded_for.split(",")[0].strip()
    else:
        client_host = request.client.host if request.client else "0.0.0.0"

    # Check mitigation block list (populated by mitigation controller via IPC file)
    blocked_ips = getattr(app.state, "mitigation_blocked_ips", {})
    if client_host in blocked_ips:
        if time.time() < blocked_ips[client_host].get("expiry", 0):
            return JSONResponse(
                {"detail": "Blocked by DDoS mitigation"},
                status_code=429,
            )

    # Process request
    response = await call_next(request)

    end_time = time.time()
    client_port = request.client.port if request.client else 0
    server_port = 8000 # Default/Assumed
    
    # Estimate bytes (content-length header)
    bytes_transferred = int(response.headers.get("content-length", 0))
    
    flow = {
        "srcIP": client_host,
        "dstIP": "127.0.0.1", # Localhost server
        "srcPort": client_port,
        "dstPort": server_port,
        "protocol": 6, # TCP
        "bytes": bytes_transferred,
        "packets": 1, # Minimal assumption
        "startTime": start_time,
        "endTime": end_time,
        "tcp_flags": "ACK" # Simplified
    }
    
    # Log flow
    netflow_v9_parser.write_flow_record(flow)
    
    return response

_MITIGATION_IPC = Path("/tmp/mitigation_state.json")

async def _load_mitigation_state():
    """Reload mitigation enforcement state from IPC file every 5 seconds."""
    app.state.mitigation_blocked_ips = {}
    while True:
        try:
            if _MITIGATION_IPC.exists():
                data = json.loads(_MITIGATION_IPC.read_text())
                app.state.mitigation_blocked_ips = data.get("blocked_ips", {})
        except Exception:
            pass
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(worker())
    asyncio.create_task(_load_mitigation_state())

async def process_request(type, data):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    tracking_id = str(uuid.uuid4())
    
    # Add pending transaction to metrics
    if type in ["deposit", "withdraw", "transfer"]:
        tx_entry = {
            "tracking_id": tracking_id,
            "type": type,
            "amount": data.amount if hasattr(data, 'amount') else 0,
            "timestamp": str(datetime.datetime.utcnow()),
            "status": "pending",
            "from": getattr(data, 'from_account_id', None) if type == 'transfer' else (getattr(data, 'account_id', None) if type == 'withdraw' else None),
            "to": getattr(data, 'to_account_id', None) if type == 'transfer' else (getattr(data, 'account_id', None) if type == 'deposit' else None)
        }
        metrics.last_50_transactions.append(tx_entry)

    await transaction_queue.put((type, data, future, time.time(), tracking_id))
    try:
        result = await future
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.websocket("/ws/stats")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            stats = {
                "total_funds": metrics.total_funds,
                "account_count": metrics.account_count,
                "avg_latency": metrics.get_avg_latency(),
                "tpm": metrics.get_tpm(),
                "completed_count": metrics.completed_count,
                "failed_count": metrics.failed_count,
                "queue_size": transaction_queue.qsize(),
                "last_50_transactions": list(metrics.last_50_transactions)
            }
            await websocket.send_text(json.dumps(stats))
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        print("Client disconnected")

@app.post("/accounts")
async def create_account(account: AccountCreate):
    return await process_request("create_account", account)

@app.delete("/accounts")
async def delete_account(account_id: int, pin: str):
    return await process_request("delete_account", {"account_id": account_id, "pin": pin})

@app.post("/deposit")
async def deposit(data: DepositRequest):
    return await process_request("deposit", data)

@app.post("/withdraw")
async def withdraw(data: WithdrawRequest):
    return await process_request("withdraw", data)

@app.post("/transfer")
async def transfer(data: TransferRequest):
    return await process_request("transfer", data)

@app.get("/admin/stats")
async def get_stats():
    return {
        "total_funds": metrics.total_funds,
        "account_count": metrics.account_count,
        "avg_latency": metrics.get_avg_latency(),
        "tpm": metrics.get_tpm(),
        "last_50_transactions": list(metrics.last_50_transactions)
    }

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass # Handle disconnected clients gracefully

manager = ConnectionManager()

@app.websocket("/ws/security")
async def websocket_security(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # If we receive a message (e.g. from inference service), broadcast it
            await manager.broadcast(data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)



class AlertInjection(BaseModel):
    alert: str
    type: str
    details: dict = {}

@app.post("/sys/admin/inject")
async def inject_alert(alert: AlertInjection):
    # Broadcast injected alert to all security dashboard clients
    await manager.broadcast(json.dumps(alert.dict()))
    return {"status": "injected", "alert": alert}

app.mount("/", StaticFiles(directory=str(Path(__file__).parent / "static"), html=True), name="static")
