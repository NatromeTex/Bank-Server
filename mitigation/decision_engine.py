import math
import time
from dataclasses import dataclass, field
from enum import Enum

from mitigation.fsm import State

BASELINE_REQ_RATE: float = 50.0


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _sigmoid_clamp(x: float, low: float, high: float) -> float:
    """Linearly map x from [low, high] → [0, 1], clamped at both ends."""
    if high <= low:
        return 0.0
    return _clamp((x - low) / (high - low), 0.0, 1.0)


class RiskTier(Enum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


def compute_risk_score(p_attack: float, req_rate: float, baseline_rate: float = BASELINE_REQ_RATE) -> float:
    """Weighted risk: 60% ML attack probability + 40% log-scaled traffic intensity vs baseline."""
    rate_component = math.log(1 + req_rate) / math.log(1 + baseline_rate)
    return min(0.6 * p_attack + 0.4 * rate_component, 1.0)


def _classify_risk(risk_score: float) -> RiskTier:
    if risk_score >= 0.70:
        return RiskTier.HIGH
    if risk_score >= 0.35:
        return RiskTier.MODERATE
    return RiskTier.LOW


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


_RISK_EMA_ALPHA: float = 0.7
_HIGH_RISK_CONSECUTIVE_REQUIRED: int = 3


class DecisionEngine:
    def __init__(self, config, context, logger):
        self.config = config
        self.context = context
        self.logger = logger
        self._smoothed_risks: dict[str, float] = {}   # ip → EMA-smoothed risk score
        self._high_risk_counts: dict[str, int] = {}   # ip → consecutive HIGH evaluations

    def evaluate(self) -> DecisionScore:
        c = self.config
        ctx = self.context

        window = ctx.get_window_metrics()
        stats = ctx.get_latest_stats()
        recent_alerts = ctx.get_recent_alerts(c.ml_confidence_window_secs)
        baseline = ctx.baseline

        # ── ML confidence from per-alert risk scores ──────────────────────────
        critical_alerts = [a for a in recent_alerts if a.get("type") == "critical"]
        alert_risks = []
        for a in critical_alerts:
            details = a.get("details", {})
            p_atk = float(details.get("p_attack", 0.0))
            r_rate = float(details.get("req_rate", 0.0))
            alert_risks.append(compute_risk_score(p_atk, r_rate))

        if alert_risks:
            peak = max(alert_risks)
            mean = sum(alert_risks) / len(alert_risks)
            ml_confidence = peak * 0.7 + mean * 0.3
            # Floor at 0.65 when an explicit DDoS detection is present
            if any("Attack Detected" in a.get("alert", "") for a in critical_alerts):
                ml_confidence = max(ml_confidence, 0.65)
        else:
            ml_confidence = 0.0

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

        # ── Per-IP risk-tiered decisions from recent ML alert data ────────────
        recent_alerts = self.context.get_recent_alerts(c.ml_confidence_window_secs)
        for a in recent_alerts:
            if a.get("type") != "critical":
                continue
            details = a.get("details", {})
            src_ip = details.get("srcIP", "")
            if not src_ip or src_ip in whitelist:
                continue
            p_atk = float(details.get("p_attack", 0.0))
            r_rate = float(details.get("req_rate", 0.0))
            current_risk = compute_risk_score(p_atk, r_rate)
            prev = self._smoothed_risks.get(src_ip, current_risk)
            self._smoothed_risks[src_ip] = _RISK_EMA_ALPHA * current_risk + (1 - _RISK_EMA_ALPHA) * prev

        for ip, risk in self._smoothed_risks.items():
            tier = _classify_risk(risk)
            if tier == RiskTier.HIGH:
                self._high_risk_counts[ip] = self._high_risk_counts.get(ip, 0) + 1
            else:
                self._high_risk_counts[ip] = 0

            count = self._high_risk_counts.get(ip, 0)

            if tier == RiskTier.LOW:
                self.logger.risk_decision(ip, risk, tier.value, "allow", count)
            elif tier == RiskTier.MODERATE:
                self.logger.risk_decision(ip, risk, tier.value, "rate_limit", count)
                actions.append({"action": "rate_limit", "ip": ip, "rps_cap": c.rate_limit_rps_suspicious})
            else:
                if count >= _HIGH_RISK_CONSECUTIVE_REQUIRED:
                    self.logger.risk_decision(ip, risk, tier.value, "block_ip", count)
                    actions.append({"action": "block_ip", "ip": ip, "ttl": c.block_ttl_seconds})
                else:
                    # HIGH but not yet sustained — rate-limit as intermediate response
                    self.logger.risk_decision(ip, risk, tier.value, "rate_limit_pending_block", count)
                    actions.append({"action": "rate_limit", "ip": ip, "rps_cap": c.rate_limit_rps_attack})

        # ── State-level global mitigations ────────────────────────────────────
        if state in (State.UNDER_ATTACK, State.MITIGATING):
            if score.syn_ratio > 0.7:
                actions.append({"action": "enable_syn_cookies"})
            if score.composite > 0.70:
                actions.append({"action": "shape_traffic", "delay_ms": c.traffic_shape_delay_ms})

        return actions
