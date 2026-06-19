"""
Typed finding record with confidence scoring, evidence tracking,
and verifier state.

Replaces loose dict-based finding storage with an explicit model.
Designed to support any finding origin: scanner output, manual notes,
AI analysis, or direct tool verification.

Backward compatible with existing Findings dict lists — both coexist
in the Findings collection during Phase 2.
"""
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from hydrasight.utils.time_utils import ts


class FindingSeverity(str, Enum):
    """Severity levels with integer ranking for sorting."""

    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[
            self.value
        ]

    @classmethod
    def from_str(cls, s: str) -> "FindingSeverity":
        try:
            return cls(s.upper())
        except ValueError:
            return cls.INFO


@dataclass
class FindingRecord:
    """
    A single, typed, evidence-backed security finding.

    confidence:
        0.0 – scanner output only, completely unverified
        0.5 – plausible from parser heuristics (default)
        0.8 – corroborated by multiple signals
        0.9 – independently verified by targeted probe
        1.0 – directly exploited / proof obtained
    """

    # ── required ──────────────────────────────────────────────────────────────
    name        : str
    severity    : FindingSeverity
    description : str

    # ── optional metadata ─────────────────────────────────────────────────────
    id          : str       = field(
        default_factory=lambda: str(uuid.uuid4())[:8]
    )
    cve         : str       = ""
    port        : int       = 0
    service     : str       = ""
    phase       : str       = ""
    source_tool : str       = ""
    remediation : str       = ""
    timestamp   : str       = field(default_factory=ts)

    # ── evidence list ─────────────────────────────────────────────────────────
    evidence    : list[str] = field(default_factory=list)

    # ── verification state ────────────────────────────────────────────────────
    verified                : bool  = False
    confidence              : float = 0.5
    verification_attempted  : bool  = False
    verification_command    : str   = ""
    verification_output     : str   = ""

    # ── mutations ─────────────────────────────────────────────────────────────

    def mark_verified(
        self,
        confidence : float = 0.9,
        output     : str   = "",
        command    : str   = "",
    ) -> None:
        """Mark finding as independently verified."""
        self.verified               = True
        self.confidence             = min(1.0, max(0.0, confidence))
        self.verification_attempted = True
        if output:
            self.verification_output = output[:500]
        if command:
            self.verification_command = command

    def mark_unverified(self, reason: str = "") -> None:
        """
        Mark finding as failed verification.
        Reduces confidence by 0.2 (floor 0.0) — does NOT delete the finding.
        """
        self.verified               = False
        self.confidence             = max(0.0, self.confidence - 0.2)
        self.verification_attempted = True
        if reason:
            self.evidence.append(f"[UNVERIFIED] {reason}")

    def mark_proven(self, evidence_text: str = "") -> None:
        """Mark finding as fully proven (exploitation / proof obtained)."""
        self.verified   = True
        self.confidence = 1.0
        self.verification_attempted = True
        if evidence_text:
            self.evidence.append(f"[PROVEN] {evidence_text}")

    def add_evidence(self, text: str) -> None:
        if text and len(text.strip()) > 0:
            self.evidence.append(text[:500])

    def boost_confidence(self, delta: float = 0.1) -> None:
        """Corroborate the finding from an additional signal."""
        self.confidence = min(1.0, self.confidence + delta)

    # ── computed properties ───────────────────────────────────────────────────

    @property
    def severity_rank(self) -> int:
        return self.severity.rank

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.9:
            return "VERIFIED"
        if self.confidence >= 0.7:
            return "HIGH"
        if self.confidence >= 0.5:
            return "MEDIUM"
        if self.confidence >= 0.3:
            return "LOW"
        return "UNCONFIRMED"

    # ── serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id"                    : self.id,
            "name"                  : self.name,
            "severity"              : self.severity.value,
            "description"           : self.description,
            "cve"                   : self.cve,
            "port"                  : self.port,
            "service"               : self.service,
            "phase"                 : self.phase,
            "source_tool"           : self.source_tool,
            "evidence"              : self.evidence,
            "verified"              : self.verified,
            "confidence"            : round(self.confidence, 3),
            "confidence_label"      : self.confidence_label,
            "remediation"           : self.remediation,
            "timestamp"             : self.timestamp,
            "verification_attempted": self.verification_attempted,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindingRecord":
        sev = FindingSeverity.from_str(data.get("severity", "INFO"))
        rec = cls(
            name        = data.get("name", ""),
            severity    = sev,
            description = data.get("description", ""),
        )
        rec.id                     = data.get("id", rec.id)
        rec.cve                    = data.get("cve", "")
        rec.port                   = int(data.get("port", 0))
        rec.service                = data.get("service", "")
        rec.phase                  = data.get("phase", "")
        rec.source_tool            = data.get("source_tool", "")
        rec.evidence               = list(data.get("evidence", []))
        rec.verified               = bool(data.get("verified", False))
        rec.confidence             = float(data.get("confidence", 0.5))
        rec.remediation            = data.get("remediation", "")
        rec.timestamp              = data.get("timestamp", ts())
        rec.verification_attempted = bool(
            data.get("verification_attempted", False)
        )
        return rec

    @classmethod
    def from_vuln_dict(cls, vuln: dict, phase: str = "") -> "FindingRecord":
        """Create from existing Findings.vulns dict entry (backward compat)."""
        return cls(
            name        = vuln.get("name", ""),
            severity    = FindingSeverity.from_str(vuln.get("severity", "INFO")),
            description = vuln.get("description", ""),
            cve         = vuln.get("cve", ""),
            port        = int(vuln.get("port", 0)),
            phase       = phase,
            confidence  = 0.5,
        )
