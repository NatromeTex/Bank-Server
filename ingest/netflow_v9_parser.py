"""
Flow extractor — CICDDoS2019-compatible output.

parse_packet()     : JSON bytes → canonical flow dict
map_to_cicdos_features() : canonical dict → 77-column CICFlowMeter feature dict
write_flow_record(): push to queue + append JSONL to rotating hourly file

Fields that require packet-level timestamps (IAT, Active/Idle, Bulk stats)
are zero-filled; everything derivable from bidirectional flow totals is computed.
"""
import datetime
import json
import queue
import time
from pathlib import Path

flow_stream: queue.Queue = queue.Queue()

DATA_DIR = Path("data/raw/netflow")

# ── Canonical flow field names (what callers must supply) ─────────────────────
CANONICAL_FIELDS = {
    # Identity
    "srcIP", "dstIP", "srcPort", "dstPort", "protocol",
    # Bidirectional volume
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    # Flow timing
    "flow_duration_us",          # microseconds
    # Per-direction packet length statistics
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    # TCP flag counts
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    # TCP window / header
    "init_fwd_win_bytes", "init_bwd_win_bytes",
    "fwd_header_length", "bwd_header_length",
    "fwd_act_data_packets",
}


def parse_packet(packet_bytes: bytes) -> dict:
    """
    Parse JSON-encoded packet bytes into the canonical flow dict.
    Missing optional fields default to 0 / 0.0.
    """
    try:
        data = json.loads(packet_bytes.decode("utf-8"))
        return {
            "srcIP":   data.get("srcIP",  "0.0.0.0"),
            "dstIP":   data.get("dstIP",  "0.0.0.0"),
            "srcPort": int(data.get("srcPort", 0)),
            "dstPort": int(data.get("dstPort", 0)),
            "protocol": int(data.get("protocol", 0)),

            "fwd_packets": int(data.get("fwd_packets", 0)),
            "bwd_packets": int(data.get("bwd_packets", 0)),
            "fwd_bytes":   int(data.get("fwd_bytes",   0)),
            "bwd_bytes":   int(data.get("bwd_bytes",   0)),
            "flow_duration_us": int(data.get("flow_duration_us", 0)),

            "fwd_pkt_len_max":  float(data.get("fwd_pkt_len_max",  0)),
            "fwd_pkt_len_min":  float(data.get("fwd_pkt_len_min",  0)),
            "fwd_pkt_len_mean": float(data.get("fwd_pkt_len_mean", 0)),
            "fwd_pkt_len_std":  float(data.get("fwd_pkt_len_std",  0)),
            "bwd_pkt_len_max":  float(data.get("bwd_pkt_len_max",  0)),
            "bwd_pkt_len_min":  float(data.get("bwd_pkt_len_min",  0)),
            "bwd_pkt_len_mean": float(data.get("bwd_pkt_len_mean", 0)),
            "bwd_pkt_len_std":  float(data.get("bwd_pkt_len_std",  0)),

            "fin_flag_count": int(data.get("fin_flag_count", 0)),
            "syn_flag_count": int(data.get("syn_flag_count", 0)),
            "rst_flag_count": int(data.get("rst_flag_count", 0)),
            "psh_flag_count": int(data.get("psh_flag_count", 0)),
            "ack_flag_count": int(data.get("ack_flag_count", 0)),
            "urg_flag_count": int(data.get("urg_flag_count", 0)),
            "cwe_flag_count": int(data.get("cwe_flag_count", 0)),
            "ece_flag_count": int(data.get("ece_flag_count", 0)),

            "init_fwd_win_bytes": int(data.get("init_fwd_win_bytes", 0)),
            "init_bwd_win_bytes": int(data.get("init_bwd_win_bytes", 0)),
            "fwd_header_length":  int(data.get("fwd_header_length",  0)),
            "bwd_header_length":  int(data.get("bwd_header_length",  0)),
            "fwd_act_data_packets": int(data.get("fwd_act_data_packets", 0)),
        }
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return {}


def map_to_cicdos_features(flow: dict) -> dict:
    """
    Map the canonical flow dict to the 77 CICFlowMeter feature columns used
    by CICDDoS2019-trained models.

    Fields requiring packet-level timestamps (all IAT, Active/Idle, Bulk)
    are zero-filled — they cannot be computed from flow-level summaries alone.
    """
    fwd_pkts  = flow.get("fwd_packets", 0)
    bwd_pkts  = flow.get("bwd_packets", 0)
    fwd_bytes = flow.get("fwd_bytes",   0)
    bwd_bytes = flow.get("bwd_bytes",   0)
    total_pkts  = fwd_pkts  + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    duration_us = max(flow.get("flow_duration_us", 1), 1)
    duration_s  = duration_us / 1_000_000

    avg_pkt_size  = total_bytes / total_pkts if total_pkts > 0 else 0.0
    pkt_len_min   = min(flow.get("fwd_pkt_len_min", 0.0), flow.get("bwd_pkt_len_min", 0.0))
    pkt_len_max   = max(flow.get("fwd_pkt_len_max", 0.0), flow.get("bwd_pkt_len_max", 0.0))

    return {
        "Protocol":               flow.get("protocol", 0),
        "Flow Duration":          duration_us,
        "Total Fwd Packets":      fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Fwd Packets Length Total": fwd_bytes,
        "Bwd Packets Length Total": bwd_bytes,

        "Fwd Packet Length Max":  flow.get("fwd_pkt_len_max",  0.0),
        "Fwd Packet Length Min":  flow.get("fwd_pkt_len_min",  0.0),
        "Fwd Packet Length Mean": flow.get("fwd_pkt_len_mean", 0.0),
        "Fwd Packet Length Std":  flow.get("fwd_pkt_len_std",  0.0),
        "Bwd Packet Length Max":  flow.get("bwd_pkt_len_max",  0.0),
        "Bwd Packet Length Min":  flow.get("bwd_pkt_len_min",  0.0),
        "Bwd Packet Length Mean": flow.get("bwd_pkt_len_mean", 0.0),
        "Bwd Packet Length Std":  flow.get("bwd_pkt_len_std",  0.0),

        "Flow Bytes/s":    total_bytes / duration_s,
        "Flow Packets/s":  total_pkts  / duration_s,

        # IAT — zero-filled (requires per-packet arrival timestamps)
        "Flow IAT Mean": 0.0, "Flow IAT Std": 0.0,
        "Flow IAT Max":  0.0, "Flow IAT Min": 0.0,
        "Fwd IAT Total": 0.0, "Fwd IAT Mean": 0.0,
        "Fwd IAT Std":   0.0, "Fwd IAT Max":  0.0, "Fwd IAT Min": 0.0,
        "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0,
        "Bwd IAT Std":   0.0, "Bwd IAT Max":  0.0, "Bwd IAT Min": 0.0,

        "Fwd PSH Flags": flow.get("psh_flag_count", 0),
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": flow.get("urg_flag_count", 0),
        "Bwd URG Flags": 0,

        "Fwd Header Length": flow.get("fwd_header_length", 0),
        "Bwd Header Length": flow.get("bwd_header_length", 0),
        "Fwd Packets/s":     fwd_pkts / duration_s,
        "Bwd Packets/s":     bwd_pkts / duration_s,

        "Packet Length Min":      pkt_len_min,
        "Packet Length Max":      pkt_len_max,
        "Packet Length Mean":     avg_pkt_size,
        "Packet Length Std":      0.0,   # requires individual packet sizes
        "Packet Length Variance": 0.0,

        "FIN Flag Count": flow.get("fin_flag_count", 0),
        "SYN Flag Count": flow.get("syn_flag_count", 0),
        "RST Flag Count": flow.get("rst_flag_count", 0),
        "PSH Flag Count": flow.get("psh_flag_count", 0),
        "ACK Flag Count": flow.get("ack_flag_count", 0),
        "URG Flag Count": flow.get("urg_flag_count", 0),
        "CWE Flag Count": flow.get("cwe_flag_count", 0),
        "ECE Flag Count": flow.get("ece_flag_count", 0),

        "Down/Up Ratio":       bwd_pkts  / fwd_pkts  if fwd_pkts  > 0 else 0.0,
        "Avg Packet Size":     avg_pkt_size,
        "Avg Fwd Segment Size": fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0.0,
        "Avg Bwd Segment Size": bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0.0,

        # Bulk — zero-filled (requires subflow segmentation)
        "Fwd Avg Bytes/Bulk":    0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk":    0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,

        # Subflow — approximate as single subflow
        "Subflow Fwd Packets": fwd_pkts,
        "Subflow Fwd Bytes":   fwd_bytes,
        "Subflow Bwd Packets": bwd_pkts,
        "Subflow Bwd Bytes":   bwd_bytes,

        "Init Fwd Win Bytes":   flow.get("init_fwd_win_bytes",   0),
        "Init Bwd Win Bytes":   flow.get("init_bwd_win_bytes",   0),
        "Fwd Act Data Packets": flow.get("fwd_act_data_packets", 0),
        "Fwd Seg Size Min":     flow.get("fwd_pkt_len_min",      0.0),

        # Active / Idle — zero-filled (requires subflow segmentation)
        "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
        "Idle Mean":   0.0, "Idle Std":   0.0, "Idle Max":   0.0, "Idle Min":   0.0,
    }


def get_log_file_path() -> Path:
    """Hourly rotating JSONL file: data/raw/netflow/YYYY/MM/DD/HH/flows_0.jsonl"""
    now = datetime.datetime.now()
    dir_path = DATA_DIR / now.strftime("%Y/%m/%d/%H")
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path / "flows_0.jsonl"


def write_flow_record(flow: dict):
    """Push canonical flow dict to queue and append as a JSONL record."""
    if not flow:
        return

    flow_stream.put(flow)

    file_path = get_log_file_path()
    try:
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(flow) + "\n")
    except Exception as e:
        print(f"Error writing flow record: {e}")


def main():
    print("Starting Flow Extractor Demo (CICDDoS2019-compatible)...")

    mock_packets = [
        json.dumps({
            "srcIP": "192.168.1.10", "dstIP": "10.0.0.1",
            "srcPort": 12345, "dstPort": 80, "protocol": 6,
            "fwd_packets": 5,  "bwd_packets": 3,
            "fwd_bytes": 1000, "bwd_bytes": 600,
            "flow_duration_us": 150_000,
            "fwd_pkt_len_max": 200.0, "fwd_pkt_len_min": 40.0,
            "fwd_pkt_len_mean": 200.0, "fwd_pkt_len_std": 0.0,
            "bwd_pkt_len_max": 200.0, "bwd_pkt_len_min": 200.0,
            "bwd_pkt_len_mean": 200.0, "bwd_pkt_len_std": 0.0,
            "syn_flag_count": 1, "ack_flag_count": 4,
            "init_fwd_win_bytes": 65535, "init_bwd_win_bytes": 65535,
            "fwd_header_length": 20, "bwd_header_length": 20,
            "fwd_act_data_packets": 4,
        }).encode(),
    ]

    for pkt in mock_packets:
        flow = parse_packet(pkt)
        write_flow_record(flow)
        features = map_to_cicdos_features(flow)
        print(f"Processed: {flow['srcIP']} → {flow['dstIP']}  "
              f"bytes/s={features['Flow Bytes/s']:.0f}  "
              f"pkts/s={features['Flow Packets/s']:.0f}")
        time.sleep(0.1)

    print("Demo complete.")


if __name__ == "__main__":
    main()
