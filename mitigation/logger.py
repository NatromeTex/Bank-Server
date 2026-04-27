import json
from datetime import datetime, timezone
from pathlib import Path


# ── ANSI colours ──────────────────────────────────────────────────────────────
_R  = "\033[31m"   # red
_Y  = "\033[33m"   # yellow
_G  = "\033[32m"   # green
_C  = "\033[36m"   # cyan
_M  = "\033[35m"   # magenta
_W  = "\033[37m"   # white
_B  = "\033[1m"    # bold
_DIM = "\033[2m"   # dim
_RST = "\033[0m"   # reset

_TIER_COLOUR = {"low": _G, "moderate": _Y, "high": _R}

_ACTION_COLOUR = {
    "allow":                  _G,
    "rate_limit":             _Y,
    "rate_limit_pending_block": _Y,
    "block_ip":               _R,
}

_STATE_COLOUR = {
    "NORMAL":      _G,
    "SUSPICIOUS":  _Y,
    "UNDER_ATTACK": _R,
    "MITIGATING":  _M,
    "STABILIZING": _C,
}

_ACTION_LABEL = {
    "rate_limit":               "RATE LIMIT",
    "rate_limit_pending_block": "RATE LIMIT  [escalation pending]",
    "block_ip":                 "BLOCK",
    "allow":                    "ALLOW",
    "enable_syn_cookies":       "SYN COOKIES ON",
    "shape_traffic":            "SHAPE TRAFFIC",
    "unblock_ip":               "UNBLOCK",
    "remove_rate_limit":        "REMOVE RATE LIMIT",
    "disable_shaping":          "DISABLE SHAPING",
    "disable_syn_cookies":      "SYN COOKIES OFF",
}


def _ts() -> str:
    """HH:MM:SS.mmm timestamp for terminal."""
    now = datetime.now()
    return f"{_DIM}{now.strftime('%H:%M:%S')}.{now.microsecond // 1000:03d}{_RST}"


def _risk_bar(score: float, width: int = 20) -> str:
    filled = round(score * width)
    empty  = width - filled
    colour = _G if score < 0.35 else (_Y if score < 0.70 else _R)
    return f"{colour}{'█' * filled}{'░' * empty}{_RST} {score:.3f}"


class StructuredLogger:
    def __init__(self, log_dir: str = "mitigation/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _write_jsonl(self, event: dict):
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        line = json.dumps(event)
        log_file = self.log_dir / f"controller_{datetime.now().strftime('%Y%m%d')}.jsonl"
        try:
            with open(log_file, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def _emit(self, event: dict):
        """Write to JSONL file only. Terminal output is handled per method."""
        self._write_jsonl(event)

    def _print(self, *lines: str):
        print("\n".join(lines), flush=True)

    # ── Public logging methods ────────────────────────────────────────────────

    def state_transition(self, from_state: str, to_state: str, score: dict):
        self._write_jsonl({"event": "state_transition", "from": from_state, "to": to_state, "score": score})

        fc = _STATE_COLOUR.get(from_state, _W)
        tc = _STATE_COLOUR.get(to_state,   _W)
        composite = score.get("composite", 0.0)

        self._print(
            f"{_ts()}  {_B}STATE CHANGE{_RST}",
            f"  {fc}{from_state}{_RST}  →  {tc}{_B}{to_state}{_RST}",
            f"  Composite score : {_risk_bar(composite)}",
            f"  ML confidence   : {score.get('ml_confidence', 0.0):.3f}",
            f"  Flows/sec       : {score.get('flows_per_second', 0.0):.1f}",
            f"  SYN ratio       : {score.get('syn_ratio', 0.0):.3f}",
            f"  Avg latency     : {score.get('avg_latency_ms', 0.0):.1f} ms",
        )

    def action(self, result: dict):
        self._write_jsonl({"event": "action", **result})

        act    = result.get("action", "unknown")
        target = result.get("target", "?")
        status = result.get("result", "?")
        reason = result.get("reason", "")

        label  = _ACTION_LABEL.get(act, act.upper())
        colour = _ACTION_COLOUR.get(act, _W)
        status_str = f"{_G}✓{_RST}" if status == "applied" else f"{_Y}–{_RST}"

        self._print(
            f"{_ts()}  {status_str} {colour}{_B}{label}{_RST}"
            f"  {_C}{target}{_RST}"
            + (f"  {_DIM}({reason}){_RST}" if reason else "")
        )

    def risk_decision(self, ip: str, risk_score: float, tier: str, action: str, consecutive: int = 0):
        self._write_jsonl({
            "event": "risk_decision",
            "ip": ip,
            "risk_score": round(risk_score, 3),
            "tier": tier,
            "action": action,
            "consecutive_high": consecutive,
        })

        tc = _TIER_COLOUR.get(tier, _W)
        ac = _ACTION_COLOUR.get(action, _W)
        label = _ACTION_LABEL.get(action, action.upper())

        streak = (
            f"  {_DIM}streak {consecutive}/{3}{_RST}"
            if tier == "high" and action != "block_ip"
            else (f"  {_R}streak {consecutive}{_RST}" if tier == "high" else "")
        )

        self._print(
            f"{_ts()}  {_DIM}RISK DECISION{_RST}",
            f"  IP     : {_C}{ip}{_RST}",
            f"  Risk   : {_risk_bar(risk_score)}",
            f"  Tier   : {tc}{_B}{tier.upper()}{_RST}",
            f"  Action : {ac}{_B}{label}{_RST}{streak}",
        )

    def feedback(self, action: str, target: str, effective: bool, delta_tpm: float, delta_latency: float):
        self._write_jsonl({
            "event": "feedback",
            "action": action,
            "target": target,
            "effective": effective,
            "delta_tpm": round(delta_tpm, 2),
            "delta_latency_ms": round(delta_latency * 1000, 2),
        })

        icon   = f"{_G}✓ effective{_RST}" if effective else f"{_Y}✗ no effect{_RST}"
        d_tpm  = f"{_G}+{delta_tpm:.1f}{_RST}" if delta_tpm >= 0 else f"{_R}{delta_tpm:.1f}{_RST}"
        d_lat  = f"{_G}{delta_latency*1000:.1f} ms{_RST}" if delta_latency <= 0 else f"{_R}+{delta_latency*1000:.1f} ms{_RST}"

        self._print(
            f"{_ts()}  {_DIM}FEEDBACK{_RST}  {_C}{target}{_RST}  [{action}]  {icon}",
            f"  ΔTPM: {d_tpm}   ΔLatency: {d_lat}",
        )

    def escalation(self, from_action: str, to_action: str):
        self._write_jsonl({"event": "escalation", "from": from_action, "to": to_action})
        fa = _ACTION_LABEL.get(from_action, from_action.upper())
        ta = _ACTION_LABEL.get(to_action,   to_action.upper())
        self._print(f"{_ts()}  {_Y}{_B}ESCALATION{_RST}  {fa}  →  {_R}{ta}{_RST}")

    def de_escalation(self, action: str, target: str):
        self._write_jsonl({"event": "de_escalation", "action": action, "target": target})
        label = _ACTION_LABEL.get(action, action.upper())
        self._print(f"{_ts()}  {_G}DE-ESCALATION{_RST}  {label}  {_C}{target}{_RST}")

    def incident_report(self, report: str):
        self._write_jsonl({"event": "incident_report", "report": report})
        border = "─" * 60
        self._print(
            f"{_ts()}  {_M}{_B}INCIDENT REPORT{_RST}",
            f"  {_DIM}{border}{_RST}",
            *[f"  {line}" for line in report.splitlines()],
            f"  {_DIM}{border}{_RST}",
        )

    def info(self, message: str, **kwargs):
        self._write_jsonl({"event": "info", "message": message, **kwargs})
        extras = "  ".join(f"{_DIM}{k}={v}{_RST}" for k, v in kwargs.items())
        self._print(f"{_ts()}  {_C}INFO{_RST}  {message}" + (f"  {extras}" if extras else ""))

    def error(self, context: str, error: str):
        self._write_jsonl({"event": "error", "context": context, "error": error})
        self._print(f"{_ts()}  {_R}{_B}ERROR{_RST}  [{context}]  {error}")
