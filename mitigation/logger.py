import json
import sys
from datetime import datetime, timezone
from pathlib import Path


class StructuredLogger:
    def __init__(self, log_dir: str = "mitigation/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _emit(self, event: dict):
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        line = json.dumps(event)
        print(f"[MITIGATION] {line}", flush=True)
        log_file = self.log_dir / f"controller_{datetime.now().strftime('%Y%m%d')}.jsonl"
        try:
            with open(log_file, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def state_transition(self, from_state: str, to_state: str, score: dict):
        self._emit({"event": "state_transition", "from": from_state, "to": to_state, "score": score})

    def action(self, result: dict):
        self._emit({"event": "action", **result})

    def feedback(self, action: str, target: str, effective: bool, delta_tpm: float, delta_latency: float):
        self._emit({
            "event": "feedback",
            "action": action,
            "target": target,
            "effective": effective,
            "delta_tpm": round(delta_tpm, 2),
            "delta_latency_ms": round(delta_latency * 1000, 2),
        })

    def escalation(self, from_action: str, to_action: str):
        self._emit({"event": "escalation", "from": from_action, "to": to_action})

    def de_escalation(self, action: str, target: str):
        self._emit({"event": "de_escalation", "action": action, "target": target})

    def incident_report(self, report: str):
        self._emit({"event": "incident_report", "report": report})

    def info(self, message: str, **kwargs):
        self._emit({"event": "info", "message": message, **kwargs})

    def error(self, context: str, error: str):
        self._emit({"event": "error", "context": context, "error": error})
