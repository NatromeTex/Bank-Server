import asyncio
import csv
import json
import time
from pathlib import Path

import websockets

from mitigation.actions import ActionResult, MitigationActions
from mitigation.config import MitigationConfig
from mitigation.context import ContextLayer
from mitigation.decision_engine import DecisionEngine, DecisionScore
from mitigation.feedback import FeedbackLoop
from mitigation.fsm import FSM, State
from mitigation.ipc import IPCBridge
from mitigation.llm_agent import LLMAgent
from mitigation.logger import StructuredLogger


_CSV_FIELDNAMES = [
    'FLOW_ID', 'PROTOCOL_MAP', 'L4_SRC_PORT', 'IPV4_SRC_ADDR', 'L4_DST_PORT', 'IPV4_DST_ADDR',
    'FIRST_SWITCHED', 'FLOW_DURATION_MILLISECONDS', 'LAST_SWITCHED', 'PROTOCOL', 'TCP_FLAGS',
    'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'TCP_WIN_MIN_IN', 'TCP_WIN_MIN_OUT', 'TCP_WIN_MSS_IN',
    'TCP_WIN_SCALE_IN', 'TCP_WIN_SCALE_OUT', 'SRC_TOS', 'DST_TOS', 'TOTAL_FLOWS_EXP',
    'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'TOTAL_PKTS_EXP', 'TOTAL_BYTES_EXP', 'IN_BYTES',
    'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS', 'ANALYSIS_TIMESTAMP', 'ANOMALY', 'ID', 'ALERT',
]


class MitigationController:
    def __init__(self, config: MitigationConfig | None = None):
        self.config = config or MitigationConfig()
        c = self.config

        self.logger = StructuredLogger(c.log_dir)
        self.fsm = FSM(c, self.logger)
        self.context = ContextLayer(c)
        self.ipc = IPCBridge(c)
        self.actions = MitigationActions(c, self.logger)
        self.engine = DecisionEngine(c, self.context, self.logger)
        self.agent = LLMAgent(c, self.actions, self.context, self.ipc, self.logger)
        self.feedback = FeedbackLoop(c, self.context, self.actions, self.ipc, self.logger)

        self._project_root = Path(__file__).parent.parent
        self._data_dir = self._project_root / "data" / "raw" / "netflow"
        self._csv_offsets: dict[str, int] = {}

        # Incident tracking — reset after each resolved incident
        self._fsm_transitions: list[str] = []
        self._peak_tpm: float = 0.0
        self._peak_latency: float = 0.0
        self._agent_spawned_for_current_incident: bool = False
        self.suspicious_agent_trigger_secs: float = 20.0

    # ── Entry point ───────────────────────────────────────────────────────────

    async def run(self):
        mode = "ENFORCEMENT" if self.config.enforcement_mode else "SHADOW (log-only)"
        self.logger.info("Mitigation controller starting", mode=mode)
        await asyncio.gather(
            self._security_ws_listener(),
            self._stats_ws_listener(),
            self._flow_file_watcher(),
            self._evaluation_loop(),
            self._janitor_loop(),
        )

    # ── WebSocket listeners ───────────────────────────────────────────────────

    async def _security_ws_listener(self):
        backoff = 1.0
        while True:
            try:
                async with websockets.connect(self.config.security_ws_url) as ws:
                    self.logger.info("Connected to /ws/security")
                    backoff = 1.0
                    async for message in ws:
                        try:
                            self.context.ingest_alert(json.loads(message))
                        except Exception:
                            pass
            except Exception as e:
                self.logger.error("security_ws_listener", str(e))
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _stats_ws_listener(self):
        backoff = 1.0
        while True:
            try:
                async with websockets.connect(self.config.stats_ws_url) as ws:
                    self.logger.info("Connected to /ws/stats")
                    backoff = 1.0
                    async for message in ws:
                        try:
                            stats = json.loads(message)
                            self.context.ingest_stats(stats)
                            tpm = stats.get("tpm", 0)
                            lat = stats.get("avg_latency", 0.0)
                            if tpm > self._peak_tpm:
                                self._peak_tpm = tpm
                            if lat > self._peak_latency:
                                self._peak_latency = lat
                        except Exception:
                            pass
            except Exception as e:
                self.logger.error("stats_ws_listener", str(e))
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    # ── Flow file watcher ─────────────────────────────────────────────────────

    async def _flow_file_watcher(self):
        while True:
            try:
                if self._data_dir.exists():
                    files = sorted(
                        self._data_dir.rglob("*.csv"),
                        key=lambda p: p.stat().st_mtime,
                    )
                    for fp in files:
                        key = str(fp)
                        offset = self._csv_offsets.get(key, 0)
                        if fp.stat().st_size > offset:
                            new_offset = await asyncio.to_thread(self._read_csv_flows, fp, offset)
                            self._csv_offsets[key] = new_offset
            except Exception as e:
                self.logger.error("flow_file_watcher", str(e))
            await asyncio.sleep(self.config.flow_watcher_interval_secs)

    def _read_csv_flows(self, fp: Path, offset: int) -> int:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                f.seek(offset)
                if offset == 0:
                    f.readline()  # skip header
                reader = csv.DictReader(f, fieldnames=_CSV_FIELDNAMES)
                for row in reader:
                    src_ip = row.get("IPV4_SRC_ADDR", "")
                    if not src_ip:
                        continue
                    try:
                        self.context.ingest_flow({
                            "srcIP": src_ip,
                            "dstIP": row.get("IPV4_DST_ADDR", ""),
                            "srcPort": int(row.get("L4_SRC_PORT", 0) or 0),
                            "dstPort": int(row.get("L4_DST_PORT", 0) or 0),
                            "protocol": int(row.get("PROTOCOL", 0) or 0),
                            "bytes": int(row.get("IN_BYTES", 0) or 0),
                            "packets": int(row.get("IN_PKTS", 0) or 0),
                            "startTime": float(row.get("FIRST_SWITCHED", 0) or 0),
                            "endTime": float(row.get("LAST_SWITCHED", 0) or 0),
                            "tcp_flags": row.get("TCP_FLAGS", ""),
                        })
                    except Exception:
                        pass
                return f.tell()
        except Exception as e:
            self.logger.error("read_csv_flows", str(e))
            return offset

    # ── Main evaluation loop ──────────────────────────────────────────────────

    async def _evaluation_loop(self):
        await asyncio.sleep(self.config.startup_grace_secs)
        while True:
            try:
                await self._evaluate()
            except Exception as e:
                self.logger.error("evaluation_loop", str(e))
            await asyncio.sleep(self.config.evaluation_interval_secs)

    async def _evaluate(self):
        score = self.engine.evaluate()
        prev_state = self.fsm.state
        new_state = self.fsm.transition(score.to_dict())

        if new_state is not None:
            self._fsm_transitions.append(f"{prev_state.value}→{new_state.value}")
            if new_state == State.NORMAL and prev_state == State.STABILIZING:
                await self._on_incident_resolved()
            elif new_state == State.NORMAL and prev_state == State.SUSPICIOUS:
                # False alarm — reset so agent can spawn fresh next time
                self._agent_spawned_for_current_incident = False

        current_state = self.fsm.state

        if current_state in (State.SUSPICIOUS, State.UNDER_ATTACK, State.MITIGATING):
            # ── Step 1: Rule engine applies immediate first-responder actions ──
            specs = self.engine.recommend_actions(score, current_state)
            initial_actions = []
            for spec in specs:
                result = self._apply_action(spec)
                if result.result == "applied":
                    self.feedback.record_action(result.action, result.target)
                    initial_actions.append({
                        "action": result.action,
                        "ip": spec.get("ip", "global"),
                        "result": result.result,
                        "reason": result.reason,
                    })

            if self.config.enforcement_mode:
                await self.ipc.write_state(self.actions.get_state_snapshot())

            # ── Step 2: Spawn LLM agent if not already running ──────────────
            # Triggers on MITIGATING entry (immediate), or after 20s in SUSPICIOUS.
            spawn_agent = False
            if new_state == State.MITIGATING:
                spawn_agent = True
            elif (
                current_state == State.SUSPICIOUS
                and self.fsm.state_duration() >= self.suspicious_agent_trigger_secs
                and not self._agent_spawned_for_current_incident
            ):
                spawn_agent = True

            if spawn_agent and not self.agent.is_running:
                self._agent_spawned_for_current_incident = True
                asyncio.create_task(self._run_agent(score, initial_actions))

        elif current_state == State.STABILIZING:
            await self.feedback.de_escalate(
                self.actions.get_blocked_ips(),
                self.actions.get_rate_limits(),
            )

        self.context.prune_old_flows()

    def _apply_action(self, spec: dict) -> ActionResult:
        action = spec["action"]
        if action == "rate_limit":
            return self.actions.rate_limit(spec["ip"], spec.get("rps_cap", self.config.rate_limit_rps_attack))
        elif action == "block_ip":
            return self.actions.block_ip(spec["ip"], spec.get("ttl"))
        elif action == "shape_traffic":
            return self.actions.shape_traffic(spec.get("delay_ms"))
        elif action == "enable_syn_cookies":
            return self.actions.enable_syn_cookies()
        else:
            return ActionResult(action, "unknown", "failed", "unknown action type")

    # ── Report file writer ────────────────────────────────────────────────────

    def _save_report(self, report: str, label: str = "report") -> Path:
        """Write a report to mitigation/reports/YYYYMMDD_HHMMSS_<label>.md"""
        from datetime import datetime
        reports_dir = self._project_root / "mitigation" / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = reports_dir / f"{timestamp}_{label}.md"
        path.write_text(report)
        self.logger.info("Report saved", path=str(path))
        return path

    # ── LLM agent task ────────────────────────────────────────────────────────

    async def _run_agent(self, score: DecisionScore, initial_actions: list[dict]):
        """Background task: hand the situation to the LLM agent after first-responder actions."""
        self.logger.info(
            "Handing off to LLM agent",
            initial_actions_count=len(initial_actions),
            threat_score=round(score.composite, 3),
        )
        summary = await self.agent.run(score, initial_actions)
        if summary:
            self.logger.incident_report(summary)
            self._save_report(summary, label="agent_summary")

    # ── Janitor: TTL expiry + IPC sync ───────────────────────────────────────

    async def _janitor_loop(self):
        while True:
            await asyncio.sleep(self.config.janitor_interval_secs)
            try:
                self.actions.cleanup_expired_blocks()
                if self.config.enforcement_mode:
                    await self.ipc.write_state(self.actions.get_state_snapshot())
            except Exception as e:
                self.logger.error("janitor_loop", str(e))

    # ── Incident resolution ───────────────────────────────────────────────────

    async def _on_incident_resolved(self):
        self.logger.info("Incident resolved — system returned to NORMAL")
        trace = self.feedback.get_action_trace()
        report = await self.agent.generate_incident_report(
            action_trace=trace,
            fsm_transitions=self._fsm_transitions,
            baseline=self.context.baseline,
            peak_tpm=self._peak_tpm,
            peak_latency=self._peak_latency,
        )
        if report:
            self.logger.incident_report(report)
            self._save_report(report, label="incident_report")
            await self._post_report(report)

        # Clear enforcement state and reset trackers
        await self.ipc.write_state(self.actions.get_state_snapshot())
        self._fsm_transitions.clear()
        self._peak_tpm = 0.0
        self._peak_latency = 0.0
        self._agent_spawned_for_current_incident = False
        self.feedback.clear()

    async def _post_report(self, report: str):
        try:
            import aiohttp
            payload = {
                "alert": "Incident Report: Attack Resolved",
                "type": "info",
                "details": {"report": report, "generated_by": "mitigation_controller"},
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.inject_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as _:
                    pass
        except Exception as e:
            self.logger.error("_post_report", str(e))
