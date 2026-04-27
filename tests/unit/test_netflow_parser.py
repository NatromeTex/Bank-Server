"""
Unit tests for ingest/netflow_v9_parser.py (CICDDoS2019-compatible output).

Validates:
- parse_packet produces the correct canonical schema
- write_flow_record pushes to queue and writes JSONL
- Hourly directory rotation
- map_to_cicdos_features produces all 77 CICFlowMeter columns
- Derived fields (Flow Bytes/s, Down/Up Ratio, etc.) are computed correctly
- Zero-duration flows are handled without division-by-zero
"""
import datetime
import json
import math
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from ingest import netflow_v9_parser
from ingest.netflow_v9_parser import map_to_cicdos_features, parse_packet

CICDOS_COLUMNS = [
    "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packets Length Total", "Bwd Packets Length Total",
    "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
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

_SAMPLE_FLOW = {
    "srcIP": "192.168.1.10", "dstIP": "10.0.0.1",
    "srcPort": 12345, "dstPort": 80, "protocol": 6,
    "fwd_packets": 5,  "bwd_packets": 3,
    "fwd_bytes": 1000, "bwd_bytes": 600,
    "flow_duration_us": 200_000,
    "fwd_pkt_len_max": 200.0, "fwd_pkt_len_min": 40.0,
    "fwd_pkt_len_mean": 200.0, "fwd_pkt_len_std": 0.0,
    "bwd_pkt_len_max": 200.0, "bwd_pkt_len_min": 200.0,
    "bwd_pkt_len_mean": 200.0, "bwd_pkt_len_std": 0.0,
    "fin_flag_count": 0, "syn_flag_count": 1, "rst_flag_count": 0,
    "psh_flag_count": 0, "ack_flag_count": 4, "urg_flag_count": 0,
    "cwe_flag_count": 0, "ece_flag_count": 0,
    "init_fwd_win_bytes": 65535, "init_bwd_win_bytes": 65535,
    "fwd_header_length": 20, "bwd_header_length": 20,
    "fwd_act_data_packets": 4,
}


class TestParsePacket(unittest.TestCase):

    def test_canonical_schema_keys(self):
        packet = json.dumps(_SAMPLE_FLOW).encode()
        parsed = parse_packet(packet)
        self.assertEqual(set(parsed.keys()), netflow_v9_parser.CANONICAL_FIELDS)

    def test_field_types(self):
        packet = json.dumps(_SAMPLE_FLOW).encode()
        parsed = parse_packet(packet)
        self.assertIsInstance(parsed["srcIP"], str)
        self.assertIsInstance(parsed["protocol"], int)
        self.assertIsInstance(parsed["fwd_packets"], int)
        self.assertIsInstance(parsed["fwd_pkt_len_max"], float)
        self.assertIsInstance(parsed["syn_flag_count"], int)

    def test_values_round_trip(self):
        packet = json.dumps(_SAMPLE_FLOW).encode()
        parsed = parse_packet(packet)
        self.assertEqual(parsed["srcIP"],         "192.168.1.10")
        self.assertEqual(parsed["protocol"],      6)
        self.assertEqual(parsed["fwd_packets"],   5)
        self.assertEqual(parsed["bwd_bytes"],     600)
        self.assertEqual(parsed["syn_flag_count"], 1)
        self.assertEqual(parsed["flow_duration_us"], 200_000)

    def test_missing_optional_fields_default_to_zero(self):
        minimal = {"srcIP": "1.2.3.4", "dstIP": "5.6.7.8",
                   "srcPort": 1, "dstPort": 2, "protocol": 17}
        parsed = parse_packet(json.dumps(minimal).encode())
        self.assertEqual(parsed["fwd_packets"], 0)
        self.assertEqual(parsed["syn_flag_count"], 0)
        self.assertEqual(parsed["flow_duration_us"], 0)

    def test_invalid_json_returns_empty(self):
        result = parse_packet(b"not valid json{{")
        self.assertEqual(result, {})


class TestMapToCicddosFeatures(unittest.TestCase):

    def test_all_77_columns_present(self):
        features = map_to_cicdos_features(_SAMPLE_FLOW)
        self.assertEqual(set(features.keys()), set(CICDOS_COLUMNS))
        self.assertEqual(len(features), 77)

    def test_direct_mappings(self):
        f = map_to_cicdos_features(_SAMPLE_FLOW)
        self.assertEqual(f["Protocol"],               6)
        self.assertEqual(f["Flow Duration"],          200_000)
        self.assertEqual(f["Total Fwd Packets"],      5)
        self.assertEqual(f["Total Backward Packets"], 3)
        self.assertEqual(f["Fwd Packets Length Total"], 1000)
        self.assertEqual(f["Bwd Packets Length Total"], 600)
        self.assertEqual(f["SYN Flag Count"], 1)
        self.assertEqual(f["ACK Flag Count"], 4)
        self.assertEqual(f["Init Fwd Win Bytes"], 65535)

    def test_derived_rates(self):
        f = map_to_cicdos_features(_SAMPLE_FLOW)
        duration_s = 200_000 / 1_000_000   # 0.2 s
        self.assertAlmostEqual(f["Flow Bytes/s"],   (1000 + 600) / duration_s,  places=1)
        self.assertAlmostEqual(f["Flow Packets/s"], (5 + 3)      / duration_s,  places=1)
        self.assertAlmostEqual(f["Fwd Packets/s"],  5            / duration_s,  places=1)
        self.assertAlmostEqual(f["Bwd Packets/s"],  3            / duration_s,  places=1)

    def test_derived_ratios_and_sizes(self):
        f = map_to_cicdos_features(_SAMPLE_FLOW)
        self.assertAlmostEqual(f["Down/Up Ratio"],        3 / 5,         places=5)
        self.assertAlmostEqual(f["Avg Fwd Segment Size"], 1000 / 5,      places=5)
        self.assertAlmostEqual(f["Avg Bwd Segment Size"], 600  / 3,      places=5)
        self.assertAlmostEqual(f["Avg Packet Size"],      1600 / 8,      places=5)

    def test_subflow_equals_total(self):
        f = map_to_cicdos_features(_SAMPLE_FLOW)
        self.assertEqual(f["Subflow Fwd Packets"], 5)
        self.assertEqual(f["Subflow Fwd Bytes"],   1000)
        self.assertEqual(f["Subflow Bwd Packets"], 3)
        self.assertEqual(f["Subflow Bwd Bytes"],   600)

    def test_iat_and_active_idle_are_zero(self):
        f = map_to_cicdos_features(_SAMPLE_FLOW)
        for col in ["Flow IAT Mean", "Fwd IAT Total", "Bwd IAT Max",
                    "Active Mean", "Idle Std"]:
            self.assertEqual(f[col], 0.0, f"{col} should be zero-filled")

    def test_zero_duration_no_division_error(self):
        flow = dict(_SAMPLE_FLOW, flow_duration_us=0)
        try:
            f = map_to_cicdos_features(flow)
        except ZeroDivisionError:
            self.fail("map_to_cicdos_features raised ZeroDivisionError on zero duration")
        self.assertFalse(math.isinf(f["Flow Bytes/s"]), "Flow Bytes/s should not be inf")

    def test_zero_fwd_packets_no_division_error(self):
        flow = dict(_SAMPLE_FLOW, fwd_packets=0, fwd_bytes=0)
        f = map_to_cicdos_features(flow)
        self.assertEqual(f["Down/Up Ratio"],        0.0)
        self.assertEqual(f["Avg Fwd Segment Size"], 0.0)


class TestWriteFlowRecord(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        netflow_v9_parser.DATA_DIR = Path(self.test_dir)
        while not netflow_v9_parser.flow_stream.empty():
            netflow_v9_parser.flow_stream.get()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_directory_creation(self):
        netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
        now = datetime.datetime.now()
        expected_dir = Path(self.test_dir) / now.strftime("%Y/%m/%d/%H")
        self.assertTrue(expected_dir.exists())
        self.assertTrue((expected_dir / "flows_0.jsonl").exists())

    def test_queue_output(self):
        netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
        self.assertEqual(netflow_v9_parser.flow_stream.qsize(), 1)
        queued = netflow_v9_parser.flow_stream.get()
        self.assertEqual(queued, _SAMPLE_FLOW)

    def test_jsonl_format(self):
        netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
        now = datetime.datetime.now()
        jsonl_path = Path(self.test_dir) / now.strftime("%Y/%m/%d/%H") / "flows_0.jsonl"
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual(record["srcIP"],       "192.168.1.10")
        self.assertEqual(record["fwd_packets"], 5)

    def test_multiple_records_appended(self):
        netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
        netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
        now = datetime.datetime.now()
        jsonl_path = Path(self.test_dir) / now.strftime("%Y/%m/%d/%H") / "flows_0.jsonl"
        lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)

    def test_file_rotation_by_hour(self):
        with patch("ingest.netflow_v9_parser.datetime") as mock_dt:
            mock_dt.datetime.now.return_value = datetime.datetime(2024, 6, 1, 10, 0, 0)
            netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
            path_10 = Path(self.test_dir) / "2024/06/01/10/flows_0.jsonl"
            self.assertTrue(path_10.exists())

            mock_dt.datetime.now.return_value = datetime.datetime(2024, 6, 1, 11, 0, 0)
            netflow_v9_parser.write_flow_record(_SAMPLE_FLOW)
            path_11 = Path(self.test_dir) / "2024/06/01/11/flows_0.jsonl"
            self.assertTrue(path_11.exists())

        self.assertTrue(path_10.exists())
        self.assertTrue(path_11.exists())

    def test_empty_flow_not_written(self):
        netflow_v9_parser.write_flow_record({})
        self.assertEqual(netflow_v9_parser.flow_stream.qsize(), 0)


if __name__ == "__main__":
    unittest.main()
