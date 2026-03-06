
import sys
import os
import asyncio
import websockets
import json
import pandas as pd
import joblib
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from inference.app import Flow, map_flow_to_features, MODEL_PATH

async def test_inference():
    print("Testing Inference...")
    if not os.path.exists(MODEL_PATH):
        print(f"FAILED: Model not found at {MODEL_PATH}")
        return

    model = joblib.load(MODEL_PATH)
    
    # Create a dummy flow with the new feature
    flow = Flow(
        srcIP="192.168.1.1",
        dstIP="192.168.1.2",
        srcPort=12345,
        dstPort=80,
        protocol=6,
        bytes=1000,
        packets=10,
        startTime=100.0,
        endTime=101.0,
        tcp_flags="ACK",
        total_flows_exp=5 # Test value
    )
    
    try:
        features = map_flow_to_features(flow)
        print("Feature mapping successful.")
        print(f"Features columns: {features.columns.tolist()}")
        
        prediction = model.predict(features)[0]
        print(f"Prediction successful: {prediction}")
        
    except Exception as e:
        print(f"FAILED: Inference error: {e}")
        raise e

async def test_websocket():
    print("\nTesting Websocket...")
    uri = "ws://localhost:8000/ws/security"
    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to Security Websocket")
            
            # Send a test message (simulating inference app sending alert)
            test_alert = {
                "alert": "Test Alert",
                "type": "warning",
                "details": {"test": "data"}
            }
            await websocket.send(json.dumps(test_alert))
            print("Sent test alert")
            
            # Wait for echo/broadcast (since we are also a client, we should receive it if we were subscribed, 
            # but the bank server implementation broadcasts to *active connections*. 
            # Upon connecting, we are an active connection.
            # If we send a message, the server receives it and broadcasts to all.
            # So we should receive our own message if the server logic holds.)
            
            response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
            print(f"Received: {response}")
            assert "Test Alert" in response, "Did not receive broadcasted alert"
            print("Websocket test PASSED")
            
    except Exception as e:
        print(f"FAILED: Websocket error: {e}")
        # raise e # Don't raise, just report

async def main():
    await test_inference()
    await test_websocket()

if __name__ == "__main__":
    asyncio.run(main())
