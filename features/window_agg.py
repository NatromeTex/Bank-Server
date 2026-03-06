import math
import statistics
from collections import Counter, defaultdict
from typing import List, Dict, Any, Set

class WindowAggregator:
    def __init__(self):
        self.flows: List[Dict[str, Any]] = []
        self.previous_window_stats: Dict[str, Any] = {}

    def add_flow(self, flow: Dict[str, Any]):
        """Adds a flow to the current internal buffer."""
        self.flows.append(flow)

    def reset_window(self):
        """Clears the current flow buffer."""
        self.flows = []

    def _calculate_entropy(self, values: List[Any]) -> float:
        """Computes Shannon entropy for a list of values."""
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def compute_window(self, window_start: float, window_end: float) -> Dict[str, Any]:
        """
        Computes metrics for flows within the specified time window.
        """
        # Filter flows within the window
        # Assuming flow['startTime'] is the relevant timestamp
        current_flows = [
            f for f in self.flows 
            if window_start <= f.get('startTime', 0) <= window_end
        ]

        duration_seconds = window_end - window_start
        if duration_seconds <= 0:
            duration_seconds = 1e-9 # Avoid division by zero

        # Initialize metrics
        metrics = {}

        # --- Volume Metrics ---
        flow_count = len(current_flows)
        total_bytes = sum(f.get('bytes', 0) for f in current_flows)
        total_packets = sum(f.get('packets', 0) for f in current_flows)

        metrics['flow_count'] = flow_count
        metrics['total_bytes'] = total_bytes
        metrics['total_packets'] = total_packets
        metrics['bytes_per_second'] = total_bytes / duration_seconds
        metrics['packets_per_second'] = total_packets / duration_seconds
        metrics['flows_per_second'] = flow_count / duration_seconds
        metrics['avg_bytes_per_flow'] = total_bytes / flow_count if flow_count > 0 else 0
        metrics['avg_packets_per_flow'] = total_packets / flow_count if flow_count > 0 else 0

        # --- Unique / Diversity Metrics ---
        src_ips = [f.get('srcIP') for f in current_flows]
        dst_ips = [f.get('dstIP') for f in current_flows]
        src_ports = [f.get('srcPort') for f in current_flows]
        dst_ports = [f.get('dstPort') for f in current_flows]
        protocols = [f.get('protocol') for f in current_flows]
        tcp_flags = [f.get('tcp_flags') for f in current_flows]

        metrics['unique_src_ips'] = len(set(src_ips))
        metrics['unique_dst_ips'] = len(set(dst_ips))
        metrics['unique_src_ports'] = len(set(src_ports))
        metrics['unique_dst_ports'] = len(set(dst_ports))
        metrics['unique_protocols'] = len(set(protocols))
        metrics['unique_tcp_flag_patterns'] = len(set(tcp_flags))

        # --- Entropy Metrics ---
        metrics['src_ip_entropy'] = self._calculate_entropy(src_ips)
        metrics['dst_ip_entropy'] = self._calculate_entropy(dst_ips)
        metrics['src_port_entropy'] = self._calculate_entropy(src_ports)
        metrics['dst_port_entropy'] = self._calculate_entropy(dst_ports)
        metrics['protocol_entropy'] = self._calculate_entropy(protocols)

        # --- Duration Metrics ---
        durations = [f.get('endTime', 0) - f.get('startTime', 0) for f in current_flows]
        if durations:
            metrics['avg_flow_duration'] = statistics.mean(durations)
            metrics['max_flow_duration'] = max(durations)
            metrics['min_flow_duration'] = min(durations)
            metrics['std_flow_duration'] = statistics.stdev(durations) if len(durations) > 1 else 0.0
        else:
            metrics['avg_flow_duration'] = 0.0
            metrics['max_flow_duration'] = 0.0
            metrics['min_flow_duration'] = 0.0
            metrics['std_flow_duration'] = 0.0

        # --- TCP Flag / Protocol Metrics ---
        # Simple string check for flags. Assumes 'tcp_flags' is a string like "SYN", "ACK", "SYN-ACK"
        # or a raw int. Requirement said "tcp_flags": str.
        syn_count = sum(1 for f in tcp_flags if 'SYN' in str(f.upper()))
        ack_count = sum(1 for f in tcp_flags if 'ACK' in str(f.upper()))
        rst_count = sum(1 for f in tcp_flags if 'RST' in str(f.upper()))
        fin_count = sum(1 for f in tcp_flags if 'FIN' in str(f.upper()))
        psh_count = sum(1 for f in tcp_flags if 'PSH' in str(f.upper()))
        urg_count = sum(1 for f in tcp_flags if 'URG' in str(f.upper()))

        metrics['syn_count'] = syn_count
        metrics['ack_count'] = ack_count
        metrics['rst_count'] = rst_count
        metrics['fin_count'] = fin_count
        metrics['psh_count'] = psh_count
        metrics['urg_count'] = urg_count
        
        metrics['syn_ratio'] = syn_count / flow_count if flow_count > 0 else 0
        metrics['rst_ratio'] = rst_count / flow_count if flow_count > 0 else 0

        # --- Behavioral Ratios ---
        metrics['bytes_per_packet'] = total_bytes / total_packets if total_packets > 0 else 0
        metrics['packets_per_flow'] = metrics['avg_packets_per_flow'] # Same as avg
        
        one_packet_flows = sum(1 for f in current_flows if f.get('packets', 0) == 1)
        metrics['one_packet_flow_ratio'] = one_packet_flows / flow_count if flow_count > 0 else 0
        
        small_flows = sum(1 for f in current_flows if f.get('bytes', 0) < 100)
        metrics['small_flow_ratio'] = small_flows / flow_count if flow_count > 0 else 0
        
        # Configurable threshold for large flows, let's say 10KB for now
        large_flow_threshold = 10000 
        large_flows = sum(1 for f in current_flows if f.get('bytes', 0) > large_flow_threshold)
        metrics['large_flow_ratio'] = large_flows / flow_count if flow_count > 0 else 0

        # --- Rate-of-Change Metrics (Deltas) ---
        prev = self.previous_window_stats
        metrics['delta_flows'] = flow_count - prev.get('flow_count', 0)
        metrics['delta_bytes'] = total_bytes - prev.get('total_bytes', 0)
        metrics['delta_packets'] = total_packets - prev.get('total_packets', 0)
        metrics['delta_entropy_src_ip'] = metrics['src_ip_entropy'] - prev.get('src_ip_entropy', 0.0)
        metrics['delta_entropy_dst_ip'] = metrics['dst_ip_entropy'] - prev.get('dst_ip_entropy', 0.0)

        # Update previous stats
        self.previous_window_stats = metrics.copy()

        return metrics
