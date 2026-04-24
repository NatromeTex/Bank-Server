import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class ActionRecord:
    action: str
    target: str
    pre_tpm: float
    pre_latency: float
    applied_at: float = field(default_factory=time.time)
    post_tpm: float | None = None
    post_latency: float | None = None
    effective: bool | None = None


class FeedbackLoop:
    def __init__(self, config, context, actions, ipc, logger):
        self.config = config
        self.context = context
        self.actions = actions
        self.ipc = ipc
        self.logger = logger
        self._records: list[ActionRecord] = []

    def record_action(self, action: str, target: str):
        """Log an applied action and schedule a delayed effectiveness measurement."""
        stats = self.context.get_latest_stats()
        record = ActionRecord(
            action=action,
            target=target,
            pre_tpm=stats.get("tpm", 0),
            pre_latency=stats.get("avg_latency", 0.0),
        )
        self._records.append(record)
        asyncio.create_task(self._measure_delayed(record))

    async def _measure_delayed(self, record: ActionRecord):
        await asyncio.sleep(self.config.feedback_measure_delay_secs)
        stats = self.context.get_latest_stats()
        record.post_tpm = stats.get("tpm", 0)
        record.post_latency = stats.get("avg_latency", 0.0)
        delta_tpm = record.post_tpm - record.pre_tpm
        delta_lat = record.post_latency - record.pre_latency
        # Effective if TPM dropped or latency improved
        record.effective = delta_tpm <= 0 or delta_lat <= 0
        self.logger.feedback(record.action, record.target, record.effective, delta_tpm, delta_lat)

    async def de_escalate(self, blocked_ips: dict, rate_limited_ips: dict):
        """
        Progressively lift restrictions in reverse order of aggressiveness.
        Called when the FSM is in STABILIZING state.
        """
        changed = False

        # 1. Disable SYN cookie mode
        if self.actions._syn_cookie_mode:
            self.actions.disable_syn_cookies()
            self.logger.de_escalation("syn_cookies", "global")
            changed = True

        # 2. Disable traffic shaping
        if self.actions._shape_delay_ms > 0:
            self.actions.disable_shaping()
            self.logger.de_escalation("shape_traffic", "global")
            changed = True

        # 3. Lift oldest IP blocks (up to 5 per STABILIZING cycle)
        for ip in list(blocked_ips.keys())[:5]:
            self.actions.unblock_ip(ip)
            changed = True

        # 4. Remove rate limits (up to 10 per cycle)
        for ip in list(rate_limited_ips.keys())[:10]:
            self.actions.remove_rate_limit(ip)
            changed = True

        if changed and self.config.enforcement_mode:
            await self.ipc.write_state(self.actions.get_state_snapshot())

    def get_action_trace(self) -> list[ActionRecord]:
        return list(self._records)

    def clear(self):
        self._records.clear()
