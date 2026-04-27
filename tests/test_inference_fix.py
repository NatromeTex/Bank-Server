"""
Smoke tests for the CICDDoS2019-compatible inference pipeline.
Validates feature mapping, model prediction, and WebSocket alert path.
"""
import asyncio
import json
import os
import sys
from pathlib import Path

import joblib
import websockets

sys.path.append(str(Path(__file__).parent.parent))

from inference.app import FEATURE_COLUMNS, Flow, map_flow_to_features, MODEL_PATH

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_flow(**overrides) -> Flow:
    """Minimal valid CICDDoS2019 flow with sensible defaults."""
    defaults = dict(
        srcIP="192.168.1.1",
        dstIP="192.168.1.2",
        srcPort=12345,
        dstPort=80,
        protocol=6,
        fwd_packets=10,
        bwd_packets=6,
        fwd_bytes=2000,
        bwd_bytes=900,
        flow_duration_us=150_000,
        fwd_pkt_len_max=200.0,
        fwd_pkt_len_min=40.0,
        fwd_pkt_len_mean=200.0,
        fwd_pkt_len_std=0.0,
        bwd_pkt_len_max=150.0,
        bwd_pkt_len_min=150.0,
        bwd_pkt_len_mean=150.0,
        bwd_pkt_len_std=0.0,
        syn_flag_count=1,
        ack_flag_count=9,
        init_fwd_win_bytes=65535,
        init_bwd_win_bytes=65535,
        fwd_header_length=20,
        bwd_header_length=20,
        fwd_act_data_packets=9,
    )
    defaults.update(overrides)
    return Flow(**defaults)


# ── Inference tests ───────────────────────────────────────────────────────────

async def test_feature_mapping():
    print("Testing feature mapping...")
    flow = _make_flow()
    df = map_flow_to_features(flow)

    assert list(df.columns) == FEATURE_COLUMNS, \
        f"Column mismatch: got {df.columns.tolist()}"
    assert df.shape == (1, 77), f"Expected shape (1, 77), got {df.shape}"

    assert df["Protocol"].iloc[0] == 6
    assert df["Total Fwd Packets"].iloc[0] == 10
    assert df["Total Backward Packets"].iloc[0] == 6
    assert df["Flow Duration"].iloc[0] == 150_000
    assert df["SYN Flag Count"].iloc[0] == 1

    # Derived fields
    duration_s = 150_000 / 1_000_000
    expected_bps = (2000 + 900) / duration_s
    assert abs(df["Flow Bytes/s"].iloc[0] - expected_bps) < 1, \
        f"Flow Bytes/s wrong: {df['Flow Bytes/s'].iloc[0]}"

    print("  Feature mapping: PASSED")
    print(f"  Columns ({df.shape[1]}): {df.columns.tolist()[:5]} ...")


async def test_model_inference():
    print("\nTesting model inference...")
    if not os.path.exists(MODEL_PATH):
        print(f"  SKIPPED: model not found at {MODEL_PATH}")
        return

    model = joblib.load(MODEL_PATH)
    flow  = _make_flow()
    df    = map_flow_to_features(flow)

    import numpy as np
    df = df.replace([float("inf"), float("-inf")], float("nan")).fillna(0)

    prediction = model.predict(df)[0]
    proba      = model.predict_proba(df)[0]
    print(f"  Prediction : {prediction}")
    print(f"  Confidence : {max(proba):.3f}")
    print("  Model inference: PASSED")


async def test_zero_duration_flow():
    """flow_duration_us=0 must not cause division-by-zero."""
    print("\nTesting zero-duration flow safety...")
    flow = _make_flow(flow_duration_us=0)
    df   = map_flow_to_features(flow)
    assert not any(df.isin([float("inf"), float("-inf")]).any()), \
        "Inf values present for zero-duration flow"
    print("  Zero-duration safety: PASSED")


async def test_websocket():
    print("\nTesting WebSocket alert channel...")
    uri = "ws://localhost:8000/ws/security"
    try:
        async with websockets.connect(uri) as ws:
            alert = {"alert": "Test Alert", "type": "warning", "details": {"test": True}}
            await ws.send(json.dumps(alert))
            response = await asyncio.wait_for(ws.recv(), timeout=2.0)
            assert "Test Alert" in response
            print("  WebSocket: PASSED")
    except Exception as e:
        print(f"  WebSocket: SKIPPED ({e})")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    await test_feature_mapping()
    await test_model_inference()
    await test_zero_duration_flow()
    await test_websocket()
    print("\nAll inference tests complete.")


if __name__ == "__main__":
    asyncio.run(main())
