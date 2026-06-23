"""
Planner state — per-engagement memory that prevents the engine from
wasting retries on known-bad paths and records what worked.

Generic by design: tracks phases, tools, credentials, and explored ports
for any engagement type (recon-only, web, Linux, Windows, mixed).
"""

import time
from dataclasses import dataclass, field


@dataclass
class PhaseResult:
    """Outcome record for one engine phase."""

    phase_id: str
    success: bool
    reason: str = ""
    tools_used: list[str] = field(default_factory=list)
    tool_outcomes: dict[str, bool] = field(default_factory=dict)
    bytes_returned: int = 0
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time.time)


class PlannerState:
    """
    Per-engagement planner memory.

    The engine should:
    - call ``record_phase()`` after every phase execution
    - call ``should_skip_phase()`` before each phase to avoid repeated failures
    - call ``record_tool_outcome()`` after each tool dispatch
    """

    def __init__(self, max_retries: int = 2) -> None:
        self.max_retries: int = max_retries
        self.phase_results: dict[str, PhaseResult] = {}
        self.blocked_phases: set[str] = set()
        self.working_tools: set[str] = set()
        self.empty_tools: set[str] = set()
        self.explored_ports: set[int] = set()
        self.tried_credentials: set[tuple[str, str]] = set()
        self.retry_counts: dict[str, int] = {}
        self._start_time: float = time.time()

    # ── phase recording ───────────────────────────────────────────────────────

    def record_phase(
        self,
        phase_id: str,
        success: bool,
        reason: str = "",
        tools_used: list[str] | None = None,
        tool_outcomes: dict[str, bool] | None = None,
        bytes_out: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        self.phase_results[phase_id] = PhaseResult(
            phase_id=phase_id,
            success=success,
            reason=reason,
            tools_used=tools_used or [],
            tool_outcomes=tool_outcomes or {},
            bytes_returned=bytes_out,
            duration_s=duration_s,
        )
        self.retry_counts[phase_id] = self.retry_counts.get(phase_id, 0) + 1

    # ── phase skip logic ──────────────────────────────────────────────────────

    def should_skip_phase(self, phase_id: str) -> tuple[bool, str]:
        """Return (should_skip, reason)."""
        if phase_id in self.blocked_phases:
            return True, f"{phase_id} is blocked"
        result = self.phase_results.get(phase_id)
        if result and not result.success:
            retries = self.retry_counts.get(phase_id, 0)
            if retries >= self.max_retries:
                return True, (
                    f"{phase_id} failed {retries}× (max {self.max_retries}): {result.reason}"
                )
        return False, ""

    def block_phase(self, phase_id: str) -> None:
        self.blocked_phases.add(phase_id)

    def phase_succeeded(self, phase_id: str) -> bool:
        r = self.phase_results.get(phase_id)
        return r.success if r else False

    def phase_attempted(self, phase_id: str) -> bool:
        return phase_id in self.phase_results

    def all_succeeded_phases(self) -> list[str]:
        return [k for k, v in self.phase_results.items() if v.success]

    def all_failed_phases(self) -> list[str]:
        return [k for k, v in self.phase_results.items() if not v.success]

    # ── tool tracking ─────────────────────────────────────────────────────────

    def record_tool_outcome(self, tool: str, success: bool, bytes_out: int = 0) -> None:
        if success and bytes_out > 50:
            self.working_tools.add(tool)
            self.empty_tools.discard(tool)
        elif bytes_out < 50:
            self.empty_tools.add(tool)

    def is_tool_known_empty(self, tool: str) -> bool:
        return tool in self.empty_tools and tool not in self.working_tools

    # ── credential tracking ───────────────────────────────────────────────────

    def record_credential_attempt(self, username: str, secret: str) -> None:
        self.tried_credentials.add((username.lower(), secret))

    def credential_already_tried(self, username: str, secret: str) -> bool:
        return (username.lower(), secret) in self.tried_credentials

    # ── port tracking ─────────────────────────────────────────────────────────

    def mark_port_explored(self, port: int) -> None:
        self.explored_ports.add(port)

    def is_port_explored(self, port: int) -> bool:
        return port in self.explored_ports

    # ── timing ────────────────────────────────────────────────────────────────

    def elapsed_minutes(self) -> float:
        return (time.time() - self._start_time) / 60

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        return {
            "elapsed_minutes": round(self.elapsed_minutes(), 1),
            "phases_attempted": len(self.phase_results),
            "phases_succeeded": len(self.all_succeeded_phases()),
            "phases_failed": len(self.all_failed_phases()),
            "blocked_phases": sorted(self.blocked_phases),
            "working_tools": sorted(self.working_tools),
            "empty_tools": sorted(self.empty_tools),
            "credentials_tried": len(self.tried_credentials),
            "ports_explored": sorted(self.explored_ports),
        }

    def to_dict(self) -> dict:
        """Serialize PlannerState for persistence."""
        from dataclasses import asdict
        return {
            "max_retries": self.max_retries,
            "phase_results": {k: asdict(v) for k, v in self.phase_results.items()},
            "blocked_phases": list(self.blocked_phases),
            "working_tools": list(self.working_tools),
            "empty_tools": list(self.empty_tools),
            "explored_ports": list(self.explored_ports),
            "tried_credentials": list(self.tried_credentials),
            "retry_counts": self.retry_counts,
            "_start_time": self._start_time,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PlannerState":
        """Deserialize PlannerState from persistence."""
        state = cls(max_retries=data.get("max_retries", 2))

        pr_data = data.get("phase_results", {})
        for k, v in pr_data.items():
            state.phase_results[k] = PhaseResult(**v)

        state.blocked_phases = set(data.get("blocked_phases", []))
        state.working_tools = set(data.get("working_tools", []))
        state.empty_tools = set(data.get("empty_tools", []))
        state.explored_ports = set(data.get("explored_ports", []))
        state.tried_credentials = {tuple(c) for c in data.get("tried_credentials", [])}
        state.retry_counts = data.get("retry_counts", {})
        state._start_time = data.get("_start_time", time.time())
        return state
