import time
from dataclasses import dataclass
from typing import Literal


@dataclass
class ActionResult:
    action: str
    target: str
    result: Literal["applied", "failed", "skipped"]
    reason: str
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


class MitigationActions:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        # Enforcement state — synced to IPC file for bank middleware
        self._blocked_ips: dict[str, dict] = {}    # ip → {expiry, reason}
        self._rate_limits: dict[str, int] = {}      # ip → rps_cap
        self._syn_cookie_mode: bool = False
        self._shape_delay_ms: float = 0.0

        # Safeguard trackers
        self._blocks_this_minute: list[float] = []  # timestamps of recent blocks
        self._cooldowns: dict[str, float] = {}       # "action:target" → last_applied_at

    # ── Safeguard helpers ─────────────────────────────────────────────────────

    def _check_cooldown(self, action: str, target: str) -> bool:
        key = f"{action}:{target}"
        last = self._cooldowns.get(key, 0.0)
        return (time.time() - last) >= self.config.cooldown_seconds

    def _record_cooldown(self, action: str, target: str):
        self._cooldowns[f"{action}:{target}"] = time.time()

    def _can_block_more(self) -> bool:
        now = time.time()
        self._blocks_this_minute = [t for t in self._blocks_this_minute if now - t < 60]
        return len(self._blocks_this_minute) < self.config.max_blocks_per_minute

    # ── Mitigation tools ──────────────────────────────────────────────────────

    def rate_limit(self, ip: str, rps_cap: int) -> ActionResult:
        if ip in self.config.ip_whitelist:
            return ActionResult("rate_limit", ip, "skipped", "whitelisted")
        if not self._check_cooldown("rate_limit", ip):
            return ActionResult("rate_limit", ip, "skipped", "cooldown active")
        self._rate_limits[ip] = rps_cap
        self._record_cooldown("rate_limit", ip)
        result = ActionResult("rate_limit", ip, "applied", f"rps_cap={rps_cap}")
        self.logger.action(result.to_dict())
        return result

    def remove_rate_limit(self, ip: str) -> ActionResult:
        self._rate_limits.pop(ip, None)
        result = ActionResult("remove_rate_limit", ip, "applied", "de-escalation")
        self.logger.action(result.to_dict())
        return result

    def block_ip(self, ip: str, ttl: int | None = None) -> ActionResult:
        if ip in self.config.ip_whitelist:
            return ActionResult("block_ip", ip, "skipped", "whitelisted")
        if not self._can_block_more():
            return ActionResult("block_ip", ip, "skipped", "max block rate exceeded")
        if not self._check_cooldown("block_ip", ip):
            return ActionResult("block_ip", ip, "skipped", "cooldown active")
        ttl = ttl or self.config.block_ttl_seconds
        self._blocked_ips[ip] = {"expiry": time.time() + ttl, "reason": "DDoS mitigation"}
        self._blocks_this_minute.append(time.time())
        self._record_cooldown("block_ip", ip)
        result = ActionResult("block_ip", ip, "applied", f"ttl={ttl}s")
        self.logger.action(result.to_dict())
        return result

    def unblock_ip(self, ip: str) -> ActionResult:
        self._blocked_ips.pop(ip, None)
        result = ActionResult("unblock_ip", ip, "applied", "de-escalation")
        self.logger.action(result.to_dict())
        return result

    def shape_traffic(self, delay_ms: float | None = None) -> ActionResult:
        if not self._check_cooldown("shape_traffic", "global"):
            return ActionResult("shape_traffic", "global", "skipped", "cooldown active")
        self._shape_delay_ms = delay_ms if delay_ms is not None else self.config.traffic_shape_delay_ms
        self._record_cooldown("shape_traffic", "global")
        result = ActionResult("shape_traffic", "global", "applied", f"delay={self._shape_delay_ms:.0f}ms")
        self.logger.action(result.to_dict())
        return result

    def disable_shaping(self) -> ActionResult:
        self._shape_delay_ms = 0.0
        result = ActionResult("disable_shaping", "global", "applied", "de-escalation")
        self.logger.action(result.to_dict())
        return result

    def enable_syn_cookies(self) -> ActionResult:
        if not self._check_cooldown("enable_syn_cookies", "global"):
            return ActionResult("enable_syn_cookies", "global", "skipped", "cooldown active")
        self._syn_cookie_mode = True
        self._record_cooldown("enable_syn_cookies", "global")
        result = ActionResult("enable_syn_cookies", "global", "applied", "SYN flood protection")
        self.logger.action(result.to_dict())
        return result

    def disable_syn_cookies(self) -> ActionResult:
        self._syn_cookie_mode = False
        result = ActionResult("disable_syn_cookies", "global", "applied", "de-escalation")
        self.logger.action(result.to_dict())
        return result

    def cleanup_expired_blocks(self):
        now = time.time()
        expired = [ip for ip, info in self._blocked_ips.items() if info["expiry"] <= now]
        for ip in expired:
            del self._blocked_ips[ip]
        if expired:
            self.logger.info(f"Auto-expired {len(expired)} block(s)", ips=expired)

    # ── State accessors ───────────────────────────────────────────────────────

    def get_state_snapshot(self) -> dict:
        return {
            "blocked_ips": dict(self._blocked_ips),
            "rate_limits": {ip: {"rps_cap": cap} for ip, cap in self._rate_limits.items()},
            "syn_cookie_mode": self._syn_cookie_mode,
            "traffic_shape_delay_ms": self._shape_delay_ms,
            "updated_at": time.time(),
        }

    def get_blocked_ips(self) -> dict:
        return dict(self._blocked_ips)

    def get_rate_limits(self) -> dict:
        return dict(self._rate_limits)
