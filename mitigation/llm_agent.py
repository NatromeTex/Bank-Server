"""
LLM Agent — tool-calling Claude agent that takes over after the rule engine's
initial actions. Runs an agentic loop: assess → act → verify → report.
"""
import json
import time

try:
    import anthropic
    _anthropic_available = True
except ImportError:
    _anthropic_available = False

try:
    import aiohttp as _aiohttp
    _aiohttp_available = True
except ImportError:
    _aiohttp_available = False


_SYSTEM_PROMPT = """You are a cybersecurity AI first responder for a banking system.

A DDoS attack has been detected and an automated rule engine has already applied initial mitigations. \
Your job is to take over and handle the situation further.

Your responsibilities:
1. Check current metrics to understand the state of the attack
2. Take targeted additional actions: block attacking IPs, rate limit, shape traffic, enable SYN cookies
3. Verify that your actions are having an effect by re-checking metrics
4. Alert human security staff with a clear, plain-English summary of what happened and what was done
5. When satisfied that the situation is stabilising, stop calling tools and write your final assessment

Constraints:
- Never block whitelisted IPs: {whitelist}
- Prefer targeted actions (block specific IPs) over broad ones (shape all traffic)
- Call get_current_metrics after taking actions to confirm improvement
- Always finish with a send_alert to notify human staff"""

_TOOLS = [
    {
        "name": "get_current_metrics",
        "description": "Get live system metrics: TPM, latency, queue size, flows/sec, entropy, blocked/rate-limited IP counts.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_top_talkers",
        "description": "Get the top N IP addresses by current request rate (requests/sec).",
        "input_schema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "description": "Number of IPs to return (default 10)"}
            },
        },
    },
    {
        "name": "block_ip",
        "description": "Block an IP address for a given duration. Best for the highest-volume attacking IPs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to block"},
                "ttl_seconds": {"type": "integer", "description": "Block duration in seconds (default 300)"},
            },
            "required": ["ip"],
        },
    },
    {
        "name": "rate_limit",
        "description": "Cap requests per second for a specific IP. Use for moderate-volume IPs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to rate limit"},
                "rps_cap": {"type": "integer", "description": "Max requests per second (e.g. 5, 10, 50)"},
            },
            "required": ["ip", "rps_cap"],
        },
    },
    {
        "name": "unblock_ip",
        "description": "Remove an IP from the block list. Use if a block was mistaken or should be lifted early.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to unblock"}
            },
            "required": ["ip"],
        },
    },
    {
        "name": "remove_rate_limit",
        "description": "Remove the rate limit from an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP to remove rate limit from"}
            },
            "required": ["ip"],
        },
    },
    {
        "name": "shape_traffic",
        "description": (
            "Add artificial response delay to throttle all traffic. "
            "Use as a broad measure when many IPs are attacking simultaneously."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "delay_ms": {
                    "type": "number",
                    "description": "Milliseconds of delay to add to every response (e.g. 50, 100, 200)",
                }
            },
            "required": ["delay_ms"],
        },
    },
    {
        "name": "enable_syn_cookies",
        "description": "Enable SYN cookie protection to defend against SYN flood attacks. Use when syn_ratio is high.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "send_alert",
        "description": "Send an alert message to the security dashboard for human operators.",
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Alert message for human operators"},
                "level": {
                    "type": "string",
                    "enum": ["critical", "warning", "info"],
                    "description": "Alert severity",
                },
            },
            "required": ["message", "level"],
        },
    },
]


class LLMAgent:
    MAX_ITERATIONS = 10

    def __init__(self, config, actions, context, ipc, logger):
        self.config = config
        self.actions = actions
        self.context = context
        self.ipc = ipc
        self.logger = logger
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running

    # ── Main agentic loop ─────────────────────────────────────────────────────

    async def run(self, score, initial_actions: list[dict]) -> str | None:
        """
        Spawn after the rule engine's first actions. Runs a tool-calling loop
        until Claude decides the situation is handled. Returns final text or None.
        """
        if not _anthropic_available:
            self.logger.error("LLMAgent", "anthropic package not installed — pip install anthropic")
            return None

        self._is_running = True
        try:
            return await self._agent_loop(score, initial_actions)
        except Exception as e:
            self.logger.error("LLMAgent.run", str(e))
            return None
        finally:
            self._is_running = False

    async def _agent_loop(self, score, initial_actions: list[dict]) -> str:
        client = anthropic.AsyncAnthropic()
        baseline = self.context.baseline

        # Snapshot current situation for the initial prompt
        metrics = self.context.get_latest_stats()
        window = self.context.get_window_metrics()
        top_talkers = self.context.get_top_talkers(10)

        situation = {
            "threat_score": round(score.composite, 3),
            "ml_confidence": round(score.ml_confidence, 3),
            "current_tpm": metrics.get("tpm", 0),
            "baseline_tpm": round(baseline.tpm, 1) if baseline.is_ready else "establishing",
            "avg_latency_ms": round(metrics.get("avg_latency", 0) * 1000, 2),
            "queue_size": metrics.get("queue_size", 0),
            "failed_transactions": metrics.get("failed_count", 0),
            "flows_per_second": round(score.flows_per_second, 2),
            "src_ip_entropy": round(score.src_ip_entropy, 3),
            "syn_ratio": round(score.syn_ratio, 3),
            "top_talkers_rps": [(ip, round(r, 2)) for ip, r in top_talkers],
        }

        initial_summary = (
            [f"{a['action']} {a.get('ip', 'global')} → {a.get('result', '?')}" for a in initial_actions]
            if initial_actions else ["none"]
        )

        user_message = (
            f"A DDoS attack is underway on the banking server.\n\n"
            f"Automated first-responder actions already taken:\n"
            + "\n".join(f"  - {s}" for s in initial_summary)
            + f"\n\nCurrent situation snapshot:\n{json.dumps(situation, indent=2)}\n\n"
            f"Take over from here. Assess, act, verify, and alert human staff."
        )

        messages = [{"role": "user", "content": user_message}]
        system = _SYSTEM_PROMPT.format(whitelist=self.config.ip_whitelist)

        self.logger.info(
            "LLM agent starting tool-calling loop",
            threat_score=round(score.composite, 3),
            initial_actions=len(initial_actions),
        )

        final_text = ""

        for iteration in range(self.MAX_ITERATIONS):
            response = await client.messages.create(
                model=self.config.llm_model,
                max_tokens=1024,
                system=system,
                tools=_TOOLS,
                messages=messages,
            )

            tool_calls = [b for b in response.content if b.type == "tool_use"]
            text_blocks = [b for b in response.content if b.type == "text"]

            if text_blocks:
                final_text = text_blocks[-1].text

            messages.append({"role": "assistant", "content": response.content})

            # No tool calls → agent is done
            if not tool_calls or response.stop_reason == "end_turn":
                self.logger.info("LLM agent finished", iterations=iteration + 1)
                break

            # Execute each tool call and feed results back
            tool_results = []
            for tc in tool_calls:
                result_str = await self._execute_tool(tc.name, tc.input)
                self.logger.info("LLM tool call", tool=tc.name, input=tc.input, result=result_str[:120])
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": result_str,
                })
                # Sync enforcement state after any action that modifies it
                if tc.name in {
                    "block_ip", "rate_limit", "unblock_ip",
                    "remove_rate_limit", "shape_traffic", "enable_syn_cookies",
                }:
                    if self.config.enforcement_mode:
                        await self.ipc.write_state(self.actions.get_state_snapshot())

            messages.append({"role": "user", "content": tool_results})

        return final_text

    # ── Tool dispatcher ───────────────────────────────────────────────────────

    async def _execute_tool(self, name: str, inp: dict) -> str:
        if name == "get_current_metrics":
            stats = self.context.get_latest_stats()
            window = self.context.get_window_metrics()
            baseline = self.context.baseline
            return json.dumps({
                "tpm": stats.get("tpm", 0),
                "baseline_tpm": round(baseline.tpm, 1),
                "avg_latency_ms": round(stats.get("avg_latency", 0) * 1000, 2),
                "queue_size": stats.get("queue_size", 0),
                "failed_count": stats.get("failed_count", 0),
                "flows_per_second": round(window.get("flows_per_second", 0), 2),
                "src_ip_entropy": round(window.get("src_ip_entropy", 0), 3),
                "syn_ratio": round(window.get("syn_ratio", 0), 3),
                "currently_blocked_ips": len(self.actions.get_blocked_ips()),
                "currently_rate_limited_ips": len(self.actions.get_rate_limits()),
                "syn_cookie_mode": self.actions._syn_cookie_mode,
                "traffic_shape_delay_ms": self.actions._shape_delay_ms,
            })

        elif name == "get_top_talkers":
            n = inp.get("n", 10)
            talkers = self.context.get_top_talkers(n)
            return json.dumps([(ip, round(r, 2)) for ip, r in talkers])

        elif name == "block_ip":
            result = self.actions.block_ip(inp["ip"], inp.get("ttl_seconds"))
            return json.dumps(result.to_dict())

        elif name == "rate_limit":
            result = self.actions.rate_limit(inp["ip"], inp["rps_cap"])
            return json.dumps(result.to_dict())

        elif name == "unblock_ip":
            result = self.actions.unblock_ip(inp["ip"])
            return json.dumps(result.to_dict())

        elif name == "remove_rate_limit":
            result = self.actions.remove_rate_limit(inp["ip"])
            return json.dumps(result.to_dict())

        elif name == "shape_traffic":
            result = self.actions.shape_traffic(inp.get("delay_ms"))
            return json.dumps(result.to_dict())

        elif name == "enable_syn_cookies":
            result = self.actions.enable_syn_cookies()
            return json.dumps(result.to_dict())

        elif name == "send_alert":
            await self._post_alert(inp["message"], inp.get("level", "warning"))
            return json.dumps({"result": "alert sent to security dashboard"})

        else:
            return json.dumps({"error": f"unknown tool: {name}"})

    async def _post_alert(self, message: str, level: str):
        if not _aiohttp_available:
            self.logger.error("LLMAgent._post_alert", "aiohttp not installed")
            return
        payload = {
            "alert": message,
            "type": level,
            "details": {"source": "mitigation_agent"},
        }
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.inject_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as _:
                    pass
        except Exception as e:
            self.logger.error("LLMAgent._post_alert", str(e))

    # ── Post-incident report (no tool use, just text) ─────────────────────────

    async def generate_incident_report(
        self,
        action_trace,
        fsm_transitions: list,
        baseline,
        peak_tpm: float,
        peak_latency: float,
    ) -> str | None:
        if not _anthropic_available:
            return None
        if len(action_trace) < self.config.llm_min_actions:
            self.logger.info("Incident report skipped: too few actions", count=len(action_trace))
            return None

        actions_summary = [
            {"action": r.action, "target": r.target, "effective": r.effective}
            for r in action_trace
        ]
        blocked_ips = list({r.target for r in action_trace if r.action == "block_ip"})

        prompt = (
            "Write a concise post-incident report (under 200 words) for a bank operations team.\n\n"
            f"INCIDENT TIMELINE:\n"
            f"- State sequence: {' → '.join(fsm_transitions) if fsm_transitions else 'N/A'}\n"
            f"- Baseline TPM: {baseline.tpm:.0f}, Peak TPM: {peak_tpm:.0f}\n"
            f"- Baseline latency: {baseline.latency * 1000:.1f}ms, Peak: {peak_latency * 1000:.1f}ms\n"
            f"- Total actions taken: {len(action_trace)}\n"
            f"- Actions: {json.dumps(actions_summary)}\n"
            f"- IPs blocked: {blocked_ips[:10]}\n\n"
            "Cover: what happened, how the system responded, outcome, and recommended follow-up. Plain English."
        )

        try:
            client = anthropic.AsyncAnthropic()
            msg = await client.messages.create(
                model=self.config.llm_model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as e:
            self.logger.error("LLMAgent.generate_incident_report", str(e))
            return None
