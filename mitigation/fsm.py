import time
from enum import Enum


class State(Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    UNDER_ATTACK = "UNDER_ATTACK"
    MITIGATING = "MITIGATING"
    STABILIZING = "STABILIZING"


class FSM:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.state = State.NORMAL
        self.state_entered_at = time.time()

        # Timers for sustained-condition transitions
        self._suspicious_elevated_since: float | None = None
        self._suspicious_normal_since: float | None = None
        self._mitigating_recovering_since: float | None = None
        self._stabilizing_since: float | None = None

    def state_duration(self) -> float:
        return time.time() - self.state_entered_at

    def transition(self, score: dict) -> State | None:
        """
        Evaluate score and apply FSM transition rules.
        Returns the new State if a transition occurred, else None.
        """
        c = self.config
        composite = score["composite"]
        now = time.time()
        new_state = None

        if self.state == State.NORMAL:
            if composite >= c.attack_threshold:
                new_state = State.UNDER_ATTACK
            elif composite >= c.suspicious_threshold:
                new_state = State.SUSPICIOUS

        elif self.state == State.SUSPICIOUS:
            # Fast-track to UNDER_ATTACK on very high score
            if composite >= c.attack_threshold:
                new_state = State.UNDER_ATTACK
            # Sustained elevated score → UNDER_ATTACK
            elif composite >= c.suspicious_sustained_attack_threshold:
                if self._suspicious_elevated_since is None:
                    self._suspicious_elevated_since = now
                elif now - self._suspicious_elevated_since >= c.suspicious_sustained_secs:
                    new_state = State.UNDER_ATTACK
            else:
                self._suspicious_elevated_since = None

            # False-alarm decay → NORMAL
            if new_state is None:
                if composite < c.suspicious_to_normal_threshold:
                    if self._suspicious_normal_since is None:
                        self._suspicious_normal_since = now
                    elif now - self._suspicious_normal_since >= c.suspicious_to_normal_secs:
                        new_state = State.NORMAL
                else:
                    self._suspicious_normal_since = None

        elif self.state == State.UNDER_ATTACK:
            # Automatically move to MITIGATING — actions begin
            new_state = State.MITIGATING

        elif self.state == State.MITIGATING:
            # Re-escalate if situation worsens
            if composite >= c.stabilizing_to_attack_threshold:
                new_state = State.UNDER_ATTACK
                self._mitigating_recovering_since = None
            # Sustained recovery → STABILIZING
            elif composite < c.mitigating_to_stabilizing_threshold:
                if self._mitigating_recovering_since is None:
                    self._mitigating_recovering_since = now
                elif now - self._mitigating_recovering_since >= c.mitigating_to_stabilizing_secs:
                    new_state = State.STABILIZING
                    self._mitigating_recovering_since = None
            else:
                self._mitigating_recovering_since = None

        elif self.state == State.STABILIZING:
            # Re-escalate on fresh spike
            if composite >= c.stabilizing_to_attack_threshold:
                new_state = State.UNDER_ATTACK
                self._stabilizing_since = None
            # Sustained calm → NORMAL (triggers incident report)
            elif composite < c.stabilizing_to_normal_threshold:
                if self._stabilizing_since is None:
                    self._stabilizing_since = now
                elif now - self._stabilizing_since >= c.stabilizing_to_normal_secs:
                    new_state = State.NORMAL
                    self._stabilizing_since = None
            else:
                self._stabilizing_since = None

        if new_state is not None and new_state != self.state:
            self.logger.state_transition(self.state.value, new_state.value, score)
            self.state = new_state
            self.state_entered_at = now
            # Clear all sustained-condition timers on any transition
            self._suspicious_elevated_since = None
            self._suspicious_normal_since = None
            self._mitigating_recovering_since = None
            return new_state

        return None
