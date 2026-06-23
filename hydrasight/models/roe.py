"""
Rules of Engagement model.

Defines safety boundaries for an engagement.
Generic by design — works for any target type (Linux, Windows,
web applications, containers, mixed services).

The ROE is loaded from `hydrasight.roe.json` alongside `hydrasight.json`.
If no ROE file exists, a permissive default is used.
"""

import ipaddress
import time
from dataclasses import dataclass, field


@dataclass
class RulesOfEngagement:
    """
    Safety envelope for an engagement.

    All engine actions are checked against this model before execution.
    kill_switch=True stops all further execution immediately.
    """

    # ── scope ─────────────────────────────────────────────────────────────────
    allowed_targets: list[str] = field(default_factory=lambda: ["*"])
    blocked_ports: list[int] = field(default_factory=list)
    blocked_modules: list[str] = field(default_factory=list)

    # ── approval gates ────────────────────────────────────────────────────────
    require_approval_for: list[str] = field(default_factory=lambda: ["EXPLOIT", "POST_EXPLOIT"])

    # ── limits ────────────────────────────────────────────────────────────────
    max_runtime_minutes: int = 120
    max_threads: int = 1

    # ── kill switch ───────────────────────────────────────────────────────────
    kill_switch: bool = False

    # ── runtime tracking (not serialised) ────────────────────────────────────
    _start_time: float | None = field(default=None, init=False, repr=False)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start_timer(self) -> None:
        """Call at engagement start to enable runtime checks."""
        self._start_time = time.time()

    # ── target validation ─────────────────────────────────────────────────────

    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        """
        Return (allowed, reason) for the given IP string.
        Accepts wildcard "*", exact IPs, and CIDR ranges.
        """
        if self.kill_switch:
            return False, "kill_switch is active"
        if "*" in self.allowed_targets:
            return True, "wildcard allows all targets"
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False, f"not a valid IP address: {target}"
        for rule in self.allowed_targets:
            try:
                if "/" in rule:
                    net = ipaddress.ip_network(rule, strict=False)
                    if ip in net:
                        return True, f"within allowed range {rule}"
                elif str(ip) == rule:
                    return True, f"exact match for {rule}"
            except ValueError:
                continue
        return False, f"{target} not in allowed_targets"

    # ── port / module checks ──────────────────────────────────────────────────

    def is_port_blocked(self, port: int) -> bool:
        return port in self.blocked_ports

    def is_module_blocked(self, module: str) -> bool:
        """True if *module* substring-matches any entry in blocked_modules."""
        return any(m in module for m in self.blocked_modules)

    # ── approval gates ────────────────────────────────────────────────────────

    def requires_approval(self, phase_id: str) -> bool:
        """True if the operator must explicitly approve this phase."""
        if self.kill_switch:
            return True
        return phase_id in self.require_approval_for

    # ── runtime limits ────────────────────────────────────────────────────────

    def is_runtime_exceeded(self) -> bool:
        if self._start_time is None:
            return False
        elapsed_min = (time.time() - self._start_time) / 60
        return elapsed_min >= self.max_runtime_minutes

    def runtime_remaining_minutes(self) -> float:
        if self._start_time is None:
            return float(self.max_runtime_minutes)
        elapsed_min = (time.time() - self._start_time) / 60
        return max(0.0, self.max_runtime_minutes - elapsed_min)

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "allowed_targets": self.allowed_targets,
            "blocked_ports": self.blocked_ports,
            "blocked_modules": self.blocked_modules,
            "require_approval_for": self.require_approval_for,
            "max_runtime_minutes": self.max_runtime_minutes,
            "max_threads": self.max_threads,
            "kill_switch": self.kill_switch,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RulesOfEngagement":
        roe = cls()
        if "allowed_targets" in data:
            roe.allowed_targets = [str(t) for t in data["allowed_targets"]]
        if "blocked_ports" in data:
            roe.blocked_ports = [int(p) for p in data["blocked_ports"]]
        if "blocked_modules" in data:
            roe.blocked_modules = [str(m) for m in data["blocked_modules"]]
        if "require_approval_for" in data:
            roe.require_approval_for = [str(p) for p in data["require_approval_for"]]
        if "max_runtime_minutes" in data:
            roe.max_runtime_minutes = int(data["max_runtime_minutes"])
        if "max_threads" in data:
            roe.max_threads = int(data["max_threads"])
        if "kill_switch" in data:
            roe.kill_switch = bool(data["kill_switch"])
        return roe

    @classmethod
    def permissive(cls) -> "RulesOfEngagement":
        """Default ROE — allows all, no approval gates, 2-hour limit."""
        return cls(
            allowed_targets=["*"],
            blocked_ports=[],
            blocked_modules=[],
            require_approval_for=[],
            max_runtime_minutes=120,
            max_threads=1,
            kill_switch=False,
        )

    # ── display ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        parts: list[str] = []
        if "*" in self.allowed_targets:
            parts.append("scope: any target")
        else:
            parts.append(f"scope: {', '.join(self.allowed_targets)}")
        if self.blocked_ports:
            parts.append(f"blocked ports: {self.blocked_ports}")
        if self.blocked_modules:
            parts.append(f"blocked modules: {len(self.blocked_modules)}")
        if self.require_approval_for:
            parts.append(f"approval required: {', '.join(self.require_approval_for)}")
        parts.append(f"max runtime: {self.max_runtime_minutes}m")
        if self.kill_switch:
            parts.append("⚠ KILL SWITCH ACTIVE")
        return "  │  ".join(parts)
