import unittest
from features.window_agg import WindowAggregator

class TestWindowAggregator(unittest.TestCase):
    def setUp(self):
        self.aggregator = WindowAggregator()
        self.flows = [
            {
                "srcIP": "10.0.0.1", "dstIP": "192.168.1.1", "srcPort": 12345, "dstPort": 80,
                "protocol": 6, "bytes": 100, "packets": 2, "startTime": 10.0, "endTime": 11.0,
                "tcp_flags": "SYN"
            },
            {
                "srcIP": "10.0.0.2", "dstIP": "192.168.1.1", "srcPort": 54321, "dstPort": 80,
                "protocol": 6, "bytes": 200, "packets": 4, "startTime": 12.0, "endTime": 13.0,
                "tcp_flags": "ACK"
            },
            {
                "srcIP": "10.0.0.1", "dstIP": "192.168.1.2", "srcPort": 12345, "dstPort": 443,
                "protocol": 17, "bytes": 50, "packets": 1, "startTime": 15.0, "endTime": 15.5,
                "tcp_flags": ""
            }
        ]
        for flow in self.flows:
            self.aggregator.add_flow(flow)

    def test_volume_metrics(self):
        # Window covering all flows
        metrics = self.aggregator.compute_window(0, 20)
        
        self.assertEqual(metrics['flow_count'], 3)
        self.assertEqual(metrics['total_bytes'], 350)
        self.assertEqual(metrics['total_packets'], 7)
        self.assertAlmostEqual(metrics['avg_bytes_per_flow'], 350/3)

    def test_unique_metrics(self):
        metrics = self.aggregator.compute_window(0, 20)
        
        self.assertEqual(metrics['unique_src_ips'], 2) # 10.0.0.1, 10.0.0.2
        self.assertEqual(metrics['unique_dst_ips'], 2) # 192.168.1.1, 192.168.1.2
        self.assertEqual(metrics['unique_protocols'], 2) # 6, 17

    def test_entropy_metrics(self):
        metrics = self.aggregator.compute_window(0, 20)
        
        # srcIPs: 10.0.0.1 (2), 10.0.0.2 (1). Total 3.
        # p1 = 2/3, p2 = 1/3
        # Entropy = -(2/3 log2(2/3) + 1/3 log2(1/3))
        import math
        p1 = 2/3
        p2 = 1/3
        expected_entropy = -(p1 * math.log2(p1) + p2 * math.log2(p2))
        self.assertAlmostEqual(metrics['src_ip_entropy'], expected_entropy)

    def test_tcp_flags(self):
        metrics = self.aggregator.compute_window(0, 20)
        self.assertEqual(metrics['syn_count'], 1)
        self.assertEqual(metrics['ack_count'], 1)
        self.assertEqual(metrics['syn_ratio'], 1/3)

    def test_deltas(self):
        # First window: only first flow
        self.aggregator.compute_window(9, 11.5) 
        # Stats stored. flow_count=1
        
        # Second window: all flows
        metrics = self.aggregator.compute_window(0, 20)
        # Current flow_count=3. Previous=1. Delta=2
        self.assertEqual(metrics['delta_flows'], 2)

    def test_empty_window(self):
        metrics = self.aggregator.compute_window(100, 200)
        self.assertEqual(metrics['flow_count'], 0)
        self.assertEqual(metrics['total_bytes'], 0)
        self.assertEqual(metrics['src_ip_entropy'], 0.0)

if __name__ == '__main__':
    unittest.main()
