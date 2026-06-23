from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class TimelineEvent:
    command_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float | None = None
    phase: str = "UNKNOWN"
    action_id: str = "unknown"
    target: str | None = None

    # Command Details
    rendered_command: str | None = None
    was_dry_run: bool = False
    exit_status: int | None = None
    api_status: str | None = None
    bytes_received: int = 0
    was_truncated: bool = False
    error_text: str | None = None

    # Output and Parsing
    raw_output_ref: str | None = None  # Path to saved artifact
    parser_outcome: str = "pending"
    parser_summary: dict[str, Any] = field(default_factory=dict)
    finding_delta: dict[str, int] = field(default_factory=dict)

    # Notes
    operator_note: str | None = None
    tags: list[str] = field(default_factory=list)
