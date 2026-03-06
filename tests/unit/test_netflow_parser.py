import unittest
import json
import shutil
import tempfile
import queue
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import datetime

# Import the module to be tested
# We need to adjust sys.path or use relative import if running as a script
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from ingest import netflow_v9_parser

class TestNetFlowParser(unittest.TestCase):

    def setUp(self):
        # Create a temporary directory for data
        self.test_dir = tempfile.mkdtemp()
        netflow_v9_parser.DATA_DIR = Path(self.test_dir)
        
        # Clear the queue
        while not netflow_v9_parser.flow_stream.empty():
            netflow_v9_parser.flow_stream.get()

    def tearDown(self):
        # Remove the temporary directory
        shutil.rmtree(self.test_dir)

    def test_directory_creation(self):
        """Test that directories are created correctly."""
        flow = {
            "srcIP": "1.1.1.1", "dstIP": "2.2.2.2", "srcPort": 10, "dstPort": 20,
            "protocol": 6, "bytes": 100, "packets": 1, "startTime": 1.0, "endTime": 2.0,
            "tcp_flags": "SYN"
        }
        netflow_v9_parser.write_flow_record(flow)
        
        now = datetime.datetime.now()
        expected_dir = Path(self.test_dir) / now.strftime("%Y/%m/%d/%H")
        self.assertTrue(expected_dir.exists())
        self.assertTrue((expected_dir / "flows_0.jsonl").exists())

    def test_queue_output(self):
        """Test that records are pushed to the queue."""
        flow = {
            "srcIP": "1.1.1.1", "dstIP": "2.2.2.2", "srcPort": 10, "dstPort": 20,
            "protocol": 6, "bytes": 100, "packets": 1, "startTime": 1.0, "endTime": 2.0,
            "tcp_flags": "SYN"
        }
        netflow_v9_parser.write_flow_record(flow)
        
        self.assertEqual(netflow_v9_parser.flow_stream.qsize(), 1)
        queued_flow = netflow_v9_parser.flow_stream.get()
        self.assertEqual(queued_flow, flow)

    def test_schema_validation(self):
        """Test that parse_packet produces the correct schema."""
        raw_data = {
            "srcIP": "1.2.3.4",
            "dstIP": "5.6.7.8",
            "srcPort": 80,
            "dstPort": 443,
            "protocol": 6,
            "bytes": 1024,
            "packets": 10,
            "startTime": 1000.0,
            "endTime": 1001.0,
            "tcp_flags": "ACK"
        }
        packet_bytes = json.dumps(raw_data).encode('utf-8')
        parsed = netflow_v9_parser.parse_packet(packet_bytes)
        
        expected_keys = {
            "srcIP", "dstIP", "srcPort", "dstPort", "protocol",
            "bytes", "packets", "startTime", "endTime", "tcp_flags"
        }
        self.assertEqual(set(parsed.keys()), expected_keys)
        self.assertEqual(parsed["srcIP"], "1.2.3.4")
        self.assertEqual(parsed["srcPort"], 80)

    def test_file_rotation(self):
        """Test that files rotate based on time (mocked)."""
        flow = {
            "srcIP": "1.1.1.1", "dstIP": "2.2.2.2", "srcPort": 10, "dstPort": 20,
            "protocol": 6, "bytes": 100, "packets": 1, "startTime": 1.0, "endTime": 2.0,
            "tcp_flags": "SYN"
        }

        # Mock datetime in the parser module
        # We need to mock the 'datetime' module imported in netflow_v9_parser
        with patch('ingest.netflow_v9_parser.datetime') as mock_datetime_module:
            # Setup the mock to behave like datetime.datetime
            # We need mock_datetime_module.datetime.now() to return our fixed time
            
            # First time: Hour 10
            fixed_dt_10 = datetime.datetime(2023, 1, 1, 10, 0, 0)
            mock_datetime_module.datetime.now.return_value = fixed_dt_10
            
            netflow_v9_parser.write_flow_record(flow)
            path_10 = Path(self.test_dir) / "2023/01/01/10/flows_0.jsonl"
            self.assertTrue(path_10.exists())

            # Second time: Hour 11
            fixed_dt_11 = datetime.datetime(2023, 1, 1, 11, 0, 0)
            mock_datetime_module.datetime.now.return_value = fixed_dt_11
            
            netflow_v9_parser.write_flow_record(flow)
            path_11 = Path(self.test_dir) / "2023/01/01/11/flows_0.jsonl"
            self.assertTrue(path_11.exists())
            
        # Verify both files exist
        self.assertTrue(path_10.exists())
        self.assertTrue(path_11.exists())

if __name__ == '__main__':
    unittest.main()
