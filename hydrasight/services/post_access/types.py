"""Shared types for the post-access handler package."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class AccessType(str, Enum):
    """How a foothold was obtained on a target."""

    METERPRETER = "meterpreter"
    SHELL = "shell"
    SSH = "ssh"
    FTP = "ftp"
    WEB_ADMIN = "web_admin"
    API_TOKEN = "api_token"
    UNKNOWN = "unknown"


@dataclass
class PostAccessResult:
    """Outcome of a post-access handler execution."""

    access_type: AccessType
    success: bool
    output: str
    hashes: list[dict] = field(default_factory=list)  # [{username, lm, ntlm}]
    credentials: list[dict] = field(default_factory=list)  # [{username, secret, kind}]
    artifacts: list[str] = field(default_factory=list)  # file paths, ssh keys, etc.
    notes: str = ""

    @classmethod
    def failure(
        cls,
        access_type: AccessType,
        reason: str = "",
    ) -> PostAccessResult:
        """Construct an unsuccessful result carrying a reason in ``notes``."""
        return cls(
            access_type=access_type,
            success=False,
            output="",
            hashes=[],
            credentials=[],
            artifacts=[],
            notes=reason,
        )
