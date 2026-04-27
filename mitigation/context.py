import sys
import time
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from features.window_agg import WindowAggregator


class Baseline:
    def __init__(self):
        self.tpm: float = 0.0
        self.latency: float = 0.001
        self.flows_per_second: float = 0.0
        self.src_ip_entropy: float = 3.0  # healthy diversity default
        self.is_ready: bool = False
        self._samples: list = []

    def add_sample(self, stats: dict, window: dict):
        self._samples.append({
            "tpm": stats.get("tpm", 0),
            "latency": max(stats.get("avg_latency", 0.001), 0.001),
            "fps": window.get("flows_per_second", 0),
            "entropy": window.get("src_ip_entropy", 3.0),
        })

    def finalize(self):
        if not self._samples:
            # No samples yet — use safe defaults so FSM can still operate
            self.is_ready = True
            return
        n = len(self._samples)
        self.tpm = sum(s["tpm"] for s in self._samples) / n
        self.latency = max(sum(s["latency"] for s in self._samples) / n, 0.001)
        self.flows_per_second = sum(s["fps"] for s in self._samples) / n
        self.src_ip_entropy = sum(s["entropy"] for s in self._samples) / n
        self.is_ready = True

    def update_ema(self, stats: dict, window: dict, alpha: float = 0.05):
        if not self.is_ready:
            return
        self.tpm = (1 - alpha) * self.tpm + alpha * stats.get("tpm", self.tpm)
        self.latency = (1 - alpha) * self.latency + alpha * max(stats.get("avg_latency", self.latency), 0.001)
        self.flows_per_second = (1 - alpha) * self.flows_per_second + alpha * window.get("flows_per_second", self.flows_per_second)
        self.src_ip_entropy = (1 - alpha) * self.src_ip_entropy + alpha * window.get("src_ip_entropy", self.src_ip_entropy)


class ContextLayer:
    def __init__(self, config):
        self.config = config
        self.baseline = Baseline()
        self._baseline_start = time.time()
        self._aggregator = WindowAggregator()
        self._talker_windows: dict[str, deque] = {}     # ip → deque of event timestamps
        self._alert_history: deque = deque(maxlen=200)
        self._latest_stats: dict = {}
        self._last_window_metrics: dict = {}

    def ingest_flow(self, flow: dict):
        # Adapt CICFlowMeter canonical dict to the schema WindowAggregator expects
        total_bytes   = flow.get("fwd_bytes",   0) + flow.get("bwd_bytes",   0)
        total_packets = flow.get("fwd_packets", 0) + flow.get("bwd_packets", 0)
        duration_s    = flow.get("flow_duration_us", 0) / 1_000_000
        now           = time.time()

        flags = []
        if flow.get("syn_flag_count", 0): flags.append("SYN")
        if flow.get("ack_flag_count", 0): flags.append("ACK")
        if flow.get("fin_flag_count", 0): flags.append("FIN")
        if flow.get("rst_flag_count", 0): flags.append("RST")
        if flow.get("psh_flag_count", 0): flags.append("PSH")
        if flow.get("urg_flag_count", 0): flags.append("URG")

        adapted = {
            "srcIP":     flow.get("srcIP",    ""),
            "dstIP":     flow.get("dstIP",    ""),
            "srcPort":   flow.get("srcPort",   0),
            "dstPort":   flow.get("dstPort",   0),
            "protocol":  flow.get("protocol",  0),
            "bytes":     total_bytes,
            "packets":   total_packets,
            "startTime": now - duration_s,
            "endTime":   now,
            "tcp_flags": "-".join(flags),
        }
        self._aggregator.add_flow(adapted)

        ip = flow.get("srcIP", "")
        if ip:
            if ip not in self._talker_windows:
                self._talker_windows[ip] = deque()
            self._talker_windows[ip].append(now)

    def ingest_stats(self, stats: dict):
        self._latest_stats = stats
        elapsed = time.time() - self._baseline_start
        warmup_secs = self.config.baseline_window_minutes * 60

        if not self.baseline.is_ready:
            if elapsed >= warmup_secs:
                self.baseline.finalize()
            elif self._last_window_metrics:
                self.baseline.add_sample(stats, self._last_window_metrics)
        else:
            self.baseline.update_ema(stats, self._last_window_metrics, self.config.baseline_ema_alpha)

    def ingest_alert(self, alert: dict):
        alert["_received_at"] = time.time()
        self._alert_history.append(alert)

    def get_top_talkers(self, n: int = 10) -> list[tuple[str, float]]:
        now = time.time()
        window = self.config.talker_window_seconds
        rates = []
        for ip, timestamps in self._talker_windows.items():
            # Prune timestamps outside the window
            while timestamps and timestamps[0] < now - window:
                timestamps.popleft()
            rate = len(timestamps) / window
            if rate > 0:
                rates.append((ip, rate))
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]

    def get_recent_alerts(self, window_secs: float = 10.0) -> list[dict]:
        cutoff = time.time() - window_secs
        return [a for a in self._alert_history if a.get("_received_at", 0) >= cutoff]

    def get_window_metrics(self) -> dict:
        now = time.time()
        metrics = self._aggregator.compute_window(now - 30, now)
        self._last_window_metrics = metrics
        return metrics

    def get_latest_stats(self) -> dict:
        return self._latest_stats

    def prune_old_flows(self):
        """Drop old flows from the aggregator to bound memory usage."""
        cutoff = time.time() - self.config.flow_prune_age_secs
        self._aggregator.flows = [
            f for f in self._aggregator.flows
            if f.get("startTime", 0) >= cutoff
        ]
