import queue
import json
import time
import datetime
from pathlib import Path
import os
import csv

# Global queue for real-time streaming
flow_stream = queue.Queue()

# Base directory for data storage
DATA_DIR = Path("data/raw/netflow")

# Columns from train_net.csv
CSV_COLUMNS = [
    'FLOW_ID', 'PROTOCOL_MAP', 'L4_SRC_PORT', 'IPV4_SRC_ADDR', 'L4_DST_PORT', 'IPV4_DST_ADDR',
    'FIRST_SWITCHED', 'FLOW_DURATION_MILLISECONDS', 'LAST_SWITCHED', 'PROTOCOL', 'TCP_FLAGS',
    'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'TCP_WIN_MIN_IN', 'TCP_WIN_MIN_OUT', 'TCP_WIN_MSS_IN',
    'TCP_WIN_SCALE_IN', 'TCP_WIN_SCALE_OUT', 'SRC_TOS', 'DST_TOS', 'TOTAL_FLOWS_EXP',
    'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'TOTAL_PKTS_EXP', 'TOTAL_BYTES_EXP', 'IN_BYTES',
    'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS', 'ANALYSIS_TIMESTAMP', 'ANOMALY', 'ID', 'ALERT'
]

def parse_packet(packet_bytes: bytes) -> dict:
    """
    Parses a mock packet (JSON bytes) into the canonical schema.
    In a real scenario, this would parse NetFlow v9 binary data.
    """
    try:
        data = json.loads(packet_bytes.decode('utf-8'))
        
        # Ensure canonical schema
        canonical = {
            "srcIP": data.get("srcIP", "0.0.0.0"),
            "dstIP": data.get("dstIP", "0.0.0.0"),
            "srcPort": int(data.get("srcPort", 0)),
            "dstPort": int(data.get("dstPort", 0)),
            "protocol": int(data.get("protocol", 0)),
            "bytes": int(data.get("bytes", 0)),
            "packets": int(data.get("packets", 0)),
            "startTime": float(data.get("startTime", time.time())),
            "endTime": float(data.get("endTime", time.time())),
            "tcp_flags": str(data.get("tcp_flags", ""))
        }
        return canonical
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return {}

def get_log_file_path() -> Path:
    """
    Determines the current log file path based on the current hour.
    Structure: data/raw/netflow/YYYY/MM/DD/HH/flows_<increment>.csv
    """
    now = datetime.datetime.now()
    dir_path = DATA_DIR / now.strftime("%Y/%m/%d/%H")
    dir_path.mkdir(parents=True, exist_ok=True)
    
    # Simple increment logic: check existing files to find the next increment
    # For simplicity in this requirement, we can just use flows_0.csv or append to it.
    return dir_path / "flows_0.csv"

def map_to_csv_schema(flow: dict) -> dict:
    """
    Maps canonical flow dict to CSV schema.
    """
    row = {col: 0 for col in CSV_COLUMNS} # Default 0
    row.update({col: "" for col in ['FLOW_ID', 'PROTOCOL_MAP', 'IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'TCP_FLAGS', 'ALERT', 'ID']}) # Default empty string for strings
    
    # Map fields
    row['IPV4_SRC_ADDR'] = flow.get('srcIP', '0.0.0.0')
    row['IPV4_DST_ADDR'] = flow.get('dstIP', '0.0.0.0')
    row['L4_SRC_PORT'] = flow.get('srcPort', 0)
    row['L4_DST_PORT'] = flow.get('dstPort', 0)
    row['PROTOCOL'] = flow.get('protocol', 0)
    row['IN_BYTES'] = flow.get('bytes', 0)
    row['IN_PKTS'] = flow.get('packets', 0)
    row['FIRST_SWITCHED'] = flow.get('startTime', 0.0)
    row['LAST_SWITCHED'] = flow.get('endTime', 0.0)
    row['FLOW_DURATION_MILLISECONDS'] = (flow.get('endTime', 0) - flow.get('startTime', 0)) * 1000
    row['TCP_FLAGS'] = flow.get('tcp_flags', "")
    row['ANALYSIS_TIMESTAMP'] = time.time()
    
    # Fill others with reasonable defaults or leave as 0
    row['FLOW_ID'] = f"flow_{int(time.time()*1000)}"
    row['PROTOCOL_MAP'] = 'TCP' if row['PROTOCOL'] == 6 else ('UDP' if row['PROTOCOL'] == 17 else 'OTHER')
    
    return row

def write_flow_record(flow: dict):
    """
    Writes the flow record to the global queue and the rotating CSV file.
    """
    if not flow:
        return

    # 1. Push to queue
    flow_stream.put(flow)

    # 2. Write to file
    file_path = get_log_file_path()
    file_exists = file_path.exists()
    
    csv_row = map_to_csv_schema(flow)
    
    try:
        with open(file_path, "a", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(csv_row)
    except Exception as e:
        print(f"Error writing to file: {e}")

def main():
    """
    Demonstration loop.
    """
    print("Starting NetFlow Parser Demo...")
    
    # Mock data
    mock_packets = [
        json.dumps({
            "srcIP": "192.168.1.10", "dstIP": "10.0.0.1", "srcPort": 12345, "dstPort": 80,
            "protocol": 6, "bytes": 500, "packets": 5, "tcp_flags": "SYN"
        }).encode('utf-8'),
        json.dumps({
            "srcIP": "10.0.0.1", "dstIP": "192.168.1.10", "srcPort": 80, "dstPort": 12345,
            "protocol": 6, "bytes": 1200, "packets": 8, "tcp_flags": "ACK"
        }).encode('utf-8')
    ]

    for pkt in mock_packets:
        flow = parse_packet(pkt)
        write_flow_record(flow)
        print(f"Processed flow: {flow['srcIP']} -> {flow['dstIP']}")
        time.sleep(0.1)

    print("Demo complete.")

if __name__ == "__main__":
    main()
