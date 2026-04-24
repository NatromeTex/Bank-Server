from dataclasses import dataclass, field


@dataclass
class MitigationConfig:
    # ── Service URLs ──────────────────────────────────────────────────────────
    security_ws_url: str = "ws://localhost:8000/ws/security"
    stats_ws_url: str = "ws://localhost:8000/ws/stats"
    inject_url: str = "http://localhost:8000/sys/admin/inject"

    # ── IPC enforcement file (read by bank middleware) ─────────────────────────
    ipc_file_path: str = "/tmp/mitigation_state.json"
    enforcement_mode: bool = True   # False = shadow/log-only, no actual blocking

    # ── FSM composite score thresholds ────────────────────────────────────────
    suspicious_threshold: float = 0.40
    attack_threshold: float = 0.80
    # SUSPICIOUS → UNDER_ATTACK: sustained high score
    suspicious_sustained_attack_threshold: float = 0.75
    suspicious_sustained_secs: float = 15.0
    # SUSPICIOUS → NORMAL: false-alarm decay
    suspicious_to_normal_threshold: float = 0.30
    suspicious_to_normal_secs: float = 30.0
    # MITIGATING → STABILIZING
    mitigating_to_stabilizing_threshold: float = 0.35
    mitigating_to_stabilizing_secs: float = 30.0
    # STABILIZING → UNDER_ATTACK re-escalation
    stabilizing_to_attack_threshold: float = 0.70
    # STABILIZING → NORMAL
    stabilizing_to_normal_threshold: float = 0.25
    stabilizing_to_normal_secs: float = 60.0

    # ── Composite score signal weights (must sum to 1.0) ───────────────────────
    weight_ml: float = 0.40
    weight_volume: float = 0.25
    weight_entropy: float = 0.20
    weight_health: float = 0.15

    # ── ML confidence derivation from alert frequency ─────────────────────────
    ml_confidence_window_secs: float = 10.0
    ml_confidence_saturation_count: int = 10  # N alerts in window → confidence 1.0

    # ── Traffic signal thresholds ──────────────────────────────────────────────
    flows_per_sec_suspicious: float = 500.0
    flows_per_sec_attack: float = 1500.0
    tpm_spike_suspicious: float = 3.0    # tpm > baseline * N → suspicious
    tpm_spike_attack: float = 5.0
    latency_spike_suspicious: float = 2.5
    src_ip_entropy_low: float = 2.0      # below this = suspicious (few source IPs)

    # ── Mitigation action parameters ──────────────────────────────────────────
    rate_limit_rps_suspicious: int = 50   # per-IP rate cap in SUSPICIOUS
    rate_limit_rps_attack: int = 10       # per-IP rate cap in UNDER_ATTACK/MITIGATING
    block_ttl_seconds: int = 300          # auto-expiry for blocked IPs (5 min)
    max_blocks_per_minute: int = 20       # safeguard: cap IP blocks/min
    cooldown_seconds: float = 30.0        # min gap between same action on same target
    traffic_shape_delay_ms: float = 100.0 # artificial response delay when shaping

    # ── Context / baseline ────────────────────────────────────────────────────
    top_n_talkers: int = 10
    baseline_window_minutes: float = 3.0  # warmup period before baseline is ready
    baseline_ema_alpha: float = 0.05      # post-warmup exponential moving average
    talker_window_seconds: float = 30.0   # sliding window for per-IP rate counting
    flow_prune_age_secs: float = 60.0     # drop flows older than this from aggregator

    # ── Feedback loop ─────────────────────────────────────────────────────────
    feedback_measure_delay_secs: float = 15.0  # wait before measuring action effect

    # ── Timing ────────────────────────────────────────────────────────────────
    evaluation_interval_secs: float = 2.0
    flow_watcher_interval_secs: float = 2.0
    janitor_interval_secs: float = 10.0
    startup_grace_secs: float = 5.0

    # ── Safeguards ────────────────────────────────────────────────────────────
    ip_whitelist: list = field(default_factory=lambda: ["127.0.0.1", "::1", "localhost"])

    # ── LLM incident report ───────────────────────────────────────────────────
    llm_enabled: bool = True
    llm_model: str = "claude-haiku-4-5-20251001"
    llm_min_actions: int = 3   # only generate report if >= N actions were applied

    # ── Logging ───────────────────────────────────────────────────────────────
    log_dir: str = "mitigation/logs"
