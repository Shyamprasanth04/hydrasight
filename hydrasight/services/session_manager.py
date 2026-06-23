import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from hydrasight.models.findings import Findings
from hydrasight.models.planner_state import PlannerState


@dataclass
class SessionSummary:
    """Read-only presentation model for the session list."""
    session_id: str
    target: str
    started_at: str
    completed_at: str
    risk: str
    findings_count: int
    verified_count: int
    exploited_count: int
    state: str  # e.g., "in progress", "completed", "compromised"
    last_activity: float


class SessionManager:
    """Manages persistence of engagements (Findings + PlannerState)."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir) / "sessions"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_id(self, target: str, started_at: str) -> str:
        """Stable ID based on target and start time, or a random UUID."""
        if not target or not started_at:
            return f"sess_{uuid.uuid4().hex[:8]}"
        m = hashlib.md5(f"{target}_{started_at}".encode())
        return f"sess_{m.hexdigest()[:8]}"

    def save_session(
        self,
        findings: Findings,
        state: PlannerState | None = None,
        status: str = "in progress",
    ) -> str:
        """Serialize Findings and PlannerState to disk."""
        target = findings.target
        started_at = findings.started_at

        # We need an ID. Since this gets called multiple times, we generate it deterministically
        # or store it on the findings object. For simplicity, deterministic hash works since
        # `started_at` is set precisely once at autopwn start.
        session_id = self._generate_id(target, started_at)

        path = self.output_dir / f"{session_id}.json"

        payload = {
            "session_id": session_id,
            "state": status,
            "last_activity": time.time(),
            "findings": findings.to_dict(),
            "planner_state": state.to_dict() if state else None,
        }

        # Write atomically
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        tmp_path.replace(path)

        return session_id

    def list_sessions(self) -> list[SessionSummary]:
        """Load all available sessions and return lightweight summaries."""
        summaries = []

        for file_path in self.output_dir.glob("*.json"):
            try:
                with open(file_path, encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            f_dict = data.get("findings", {})
            f_meta = f_dict.get("meta", {})
            f_summary = f_dict.get("summary", {})

            summary = SessionSummary(
                session_id=data.get("session_id", file_path.stem),
                target=f_meta.get("target", "unknown"),
                started_at=f_meta.get("started", ""),
                completed_at=f_meta.get("completed", ""),
                risk=f_meta.get("risk", "NONE"),
                findings_count=f_summary.get("vulns", 0),
                verified_count=f_summary.get("verified", 0),
                exploited_count=len(f_dict.get("sessions", [])),
                state=data.get("state", "unknown"),
                last_activity=data.get("last_activity", 0.0),
            )
            summaries.append(summary)

        # Sort by most recent activity
        summaries.sort(key=lambda s: s.last_activity, reverse=True)
        return summaries

    def load_session(self, session_id: str) -> tuple[Findings, PlannerState | None] | None:
        """Rehydrate Findings and PlannerState for resumption."""
        path = self.output_dir / f"{session_id}.json"
        if not path.exists():
            return None

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None

        findings = Findings.from_dict(data.get("findings", {}))

        state = None
        ps_data = data.get("planner_state")
        if ps_data:
            state = PlannerState.from_dict(ps_data)

        return findings, state
