import time
from dataclasses import dataclass, field

from mitigation.fsm import State


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _sigmoid_clamp(x: float, low: float, high: float) -> float:
    """Linearly map x from [low, high] → [0, 1], clamped at both ends."""
    if high <= low:
        return 0.0
    return _clamp((x - low) / (high - low), 0.0, 1.0)


@dataclass
class DecisionScore:
    ml_confidence: float
    composite: float
    flows_per_second: float
    src_ip_entropy: float
    syn_ratio: float
    tpm: float
    avg_latency: float
    queue_size: int
    top_talkers: list
    baseline_ready: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ml_confidence": round(self.ml_confidence, 3),
            "composite": round(self.composite, 3),
            "flows_per_second": round(self.flows_per_second, 2),
            "src_ip_entropy": round(self.src_ip_entropy, 3),
            "syn_ratio": round(self.syn_ratio, 3),
            "tpm": self.tpm,
            "avg_latency_ms": round(self.avg_latency * 1000, 2),
            "queue_size": self.queue_size,
            "baseline_ready": self.baseline_ready,
            "top_talkers": [(ip, round(r, 2)) for ip, r in self.top_talkers[:5]],
        }


class DecisionEngine:
    def __init__(self, config, context, logger):
        self.config = config
        self.context = context
        self.logger = logger

    def evaluate(self) -> DecisionScore:
        c = self.config
        ctx = self.context

        window = ctx.get_window_metrics()
        stats = ctx.get_latest_stats()
        recent_alerts = ctx.get_recent_alerts(c.ml_confidence_window_secs)
        baseline = ctx.baseline

        # ── ML confidence from alert frequency ────────────────────────────────
        critical_alerts = [a for a in recent_alerts if a.get("type") == "critical"]
        ml_confidence = min(len(critical_alerts) / c.ml_confidence_saturation_count, 1.0)
        # Floor at 0.65 when an explicit DDoS detection is present
        if any("Attack Detected" in a.get("alert", "") for a in critical_alerts):
            ml_confidence = max(ml_confidence, 0.65)

        # ── Traffic volume signal [0..1] ──────────────────────────────────────
        fps = window.get("flows_per_second", 0.0)
        volume_signal = _sigmoid_clamp(fps, c.flows_per_sec_suspicious, c.flows_per_sec_attack)

        # ── Entropy signal (inverted: low entropy = fewer unique IPs = suspicious) ──
        entropy = window.get("src_ip_entropy", 3.0)
        entropy_signal = 1.0 - _clamp(entropy / 4.0, 0.0, 1.0)

        # ── System health signal ──────────────────────────────────────────────
        tpm = stats.get("tpm", 0)
        avg_latency = max(stats.get("avg_latency", 0.0), 0.0)
        queue_size = stats.get("queue_size", 0)

        if baseline.is_ready and baseline.tpm > 0:
            tpm_ratio = tpm / baseline.tpm
            lat_ratio = avg_latency / baseline.latency
        else:
            tpm_ratio = 1.0
            lat_ratio = 1.0

        health_signal = (
            _sigmoid_clamp(tpm_ratio - 1, 0, 4) * 0.5 +
            _sigmoid_clamp(lat_ratio - 1, 0, 4) * 0.5
        )

        # ── Weighted composite score ──────────────────────────────────────────
        composite = (
            c.weight_ml * ml_confidence +
            c.weight_volume * volume_signal +
            c.weight_entropy * entropy_signal +
            c.weight_health * health_signal
        )

        syn_ratio = window.get("syn_ratio", 0.0)
        top_talkers = ctx.get_top_talkers(c.top_n_talkers)

        return DecisionScore(
            ml_confidence=ml_confidence,
            composite=composite,
            flows_per_second=fps,
            src_ip_entropy=entropy,
            syn_ratio=syn_ratio,
            tpm=tpm,
            avg_latency=avg_latency,
            queue_size=queue_size,
            top_talkers=top_talkers,
            baseline_ready=baseline.is_ready,
        )

    def recommend_actions(self, score: DecisionScore, state: State) -> list[dict]:
        """
        Returns a list of action specs ordered from least to most aggressive.
        Each spec is a dict: {action, ip?, rps_cap?, ttl?, delay_ms?}
        """
        c = self.config
        actions = []
        whitelist = set(c.ip_whitelist)
        talkers = score.top_talkers

        if state == State.SUSPICIOUS:
            for ip, rps in talkers[:5]:
                if ip not in whitelist and rps > 0:
                    actions.append({"action": "rate_limit", "ip": ip, "rps_cap": c.rate_limit_rps_suspicious})

        elif state in (State.UNDER_ATTACK, State.MITIGATING):
            # SYN flood protection
            if score.syn_ratio > 0.7:
                actions.append({"action": "enable_syn_cookies"})

            # Traffic shaping on heavy load
            if score.composite > 0.70:
                actions.append({"action": "shape_traffic", "delay_ms": c.traffic_shape_delay_ms})

            # Block top attackers
            for ip, rps in talkers[:3]:
                if ip not in whitelist:
                    actions.append({"action": "block_ip", "ip": ip, "ttl": c.block_ttl_seconds})

            # Rate-limit the next tier of talkers
            for ip, rps in talkers[3:8]:
                if ip not in whitelist:
                    actions.append({"action": "rate_limit", "ip": ip, "rps_cap": c.rate_limit_rps_attack})

        return actions
