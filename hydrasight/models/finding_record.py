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

from hydrasight.utils.time_utils import ts


class FindingSeverity(str, Enum):
    """Severity levels with integer ranking for sorting."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    @classmethod
    def from_str(cls, s: str) -> "FindingSeverity":
        try:
            return cls(s.upper())
        except ValueError:
            return cls.INFO


class FindingStage(str, Enum):
    """Lifecycle stage of a finding. Decoupled from numeric confidence."""

    CANDIDATE = "CANDIDATE"
    OBSERVED = "OBSERVED"
    PLAUSIBLE = "PLAUSIBLE"
    VERIFIED = "VERIFIED"
    EXPLOITED = "EXPLOITED"

    @property
    def rank(self) -> int:
        return {"EXPLOITED": 0, "VERIFIED": 1, "PLAUSIBLE": 2, "OBSERVED": 3, "CANDIDATE": 4}[self.value]


class VerificationState(str, Enum):
    """Strict canonical reporting vocabulary."""
    EXPLOITED = "EXPLOITED"
    VERIFIED = "VERIFIED"
    SUPPORTED_CANDIDATE = "SUPPORTED_CANDIDATE"
    NO_STRATEGY_CANDIDATE = "NO_STRATEGY_CANDIDATE"
    ATTEMPTED_NOT_CONFIRMED = "ATTEMPTED_NOT_CONFIRMED"
    PENDING = "PENDING"


@dataclass
class FindingRecord:
    """
    A single, typed, evidence-backed security finding.
    """

    # ── required ──────────────────────────────────────────────────────────────
    name: str
    severity: FindingSeverity
    description: str

    # ── canonical reporting state ─────────────────────────────────────────────
    verification_state: VerificationState = VerificationState.PENDING
    verification_reason_code: str = "pending_verification"

    # ── lifecycle & confidence ────────────────────────────────────────────────
    stage: FindingStage = FindingStage.PLAUSIBLE
    confidence: float = 0.5  # 0.0 to 1.0 numeric score

    # ── optional metadata ─────────────────────────────────────────────────────
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cve: str = ""
    port: int = 0
    service: str = ""
    phase: str = ""
    source_tool: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=ts)

    # ── evidence list ─────────────────────────────────────────────────────────
    evidence: list[str] = field(default_factory=list)

    # ── verification state ────────────────────────────────────────────────────
    verification_attempted: bool = False
    verification_outcome: str = ""  # "VERIFIED", "FAILED", "NOT_APPLICABLE", "NO_STRATEGY", "ERROR"
    verification_rationale: str = ""
    verification_evidence: str = ""
    verification_strategy: str = ""

    # Legacy fields mapping
    verified: bool = False
    verification_command: str = ""
    verification_output: str = ""

    # ── reporting state ───────────────────────────────────────────────────────
    reported: bool = False
    reported_section: str = ""

    # ── computed canonical properties ─────────────────────────────────────────

    @property
    def is_exploited(self) -> bool:
        return self.verification_state == VerificationState.EXPLOITED

    @property
    def is_verified(self) -> bool:
        return self.verification_state == VerificationState.VERIFIED

    @property
    def is_supported_candidate(self) -> bool:
        return self.verification_state == VerificationState.SUPPORTED_CANDIDATE

    @property
    def is_no_strategy_candidate(self) -> bool:
        return self.verification_state == VerificationState.NO_STRATEGY_CANDIDATE

    @property
    def is_attempted_not_confirmed(self) -> bool:
        return self.verification_state == VerificationState.ATTEMPTED_NOT_CONFIRMED

    @property
    def is_pending(self) -> bool:
        return self.verification_state == VerificationState.PENDING

    @property
    def is_validated(self) -> bool:
        return self.is_exploited or self.is_verified

    @property
    def is_candidate(self) -> bool:
        return self.is_supported_candidate or self.is_no_strategy_candidate

    @property
    def is_appendix_only(self) -> bool:
        # Pushing low-value findings to the appendix
        return self.is_no_strategy_candidate or self.is_attempted_not_confirmed

    def _assert_invariants(self) -> None:
        states = [
            self.is_exploited,
            self.is_verified,
            self.is_supported_candidate,
            self.is_no_strategy_candidate,
            self.is_attempted_not_confirmed,
            self.is_pending,
        ]
        if sum(states) != 1:
            raise RuntimeError(f"Invariant violation: exactly_one_of failed for states: {states} on {self.name}")

    # ── mutations ─────────────────────────────────────────────────────────────

    def mark_candidate(self, reason: str = "") -> None:
        self.stage = FindingStage.CANDIDATE
        self.confidence = 0.1
        self.verification_state = VerificationState.SUPPORTED_CANDIDATE
        self.verification_reason_code = "supported_candidate"
        if reason:
            self.evidence.append(f"[CANDIDATE] {reason}")
        self._assert_invariants()

    def mark_observed(self, reason: str = "") -> None:
        self.stage = FindingStage.OBSERVED
        self.confidence = 0.3
        self.verification_state = VerificationState.SUPPORTED_CANDIDATE
        self.verification_reason_code = "supported_candidate"
        if reason:
            self.evidence.append(f"[OBSERVED] {reason}")
        self._assert_invariants()

    def mark_plausible(self, reason: str = "") -> None:
        self.stage = FindingStage.PLAUSIBLE
        self.confidence = 0.5
        self.verification_state = VerificationState.SUPPORTED_CANDIDATE
        self.verification_reason_code = "supported_candidate"
        if reason:
            self.evidence.append(f"[PLAUSIBLE] {reason}")
        self._assert_invariants()

    def demote_to_plausible(self, reason: str = "") -> None:
        """Intentional downgrade path, e.g., parser correction."""
        self.stage = FindingStage.PLAUSIBLE
        self.confidence = min(0.5, self.confidence)
        self.verified = False
        self.verification_state = VerificationState.SUPPORTED_CANDIDATE
        self.verification_reason_code = "supported_candidate"
        if reason:
            self.evidence.append(f"[DEMOTED] {reason}")
        self._assert_invariants()

    def mark_verified(
        self,
        confidence: float = 0.9,
        output: str = "",
        command: str = "",
        rationale: str = "",
        strategy: str = ""
    ) -> None:
        """Mark finding as independently verified with evidence."""
        self.stage = FindingStage.VERIFIED
        self.verified = True
        self.confidence = min(1.0, max(0.0, confidence))
        self.verification_attempted = True
        self.verification_outcome = "VERIFIED"

        self.verification_state = VerificationState.VERIFIED
        self.verification_reason_code = "verified_by_strategy"

        if rationale:
            self.verification_rationale = rationale
        if strategy:
            self.verification_strategy = strategy
        if output:
            self.verification_output = output[:500]
            self.verification_evidence = output[:500]
        if command:
            self.verification_command = command
        self._assert_invariants()

    def mark_exploited(self, evidence_text: str = "", command: str = "") -> None:
        """Mark finding as fully proven (exploitation / session obtained)."""
        self.stage = FindingStage.EXPLOITED
        self.verified = True
        self.confidence = 1.0
        self.verification_attempted = True
        self.verification_outcome = "VERIFIED"
        self.verification_rationale = "Exploited successfully"

        self.verification_state = VerificationState.EXPLOITED
        self.verification_reason_code = "session_opened"

        if command:
            self.verification_command = command

        if evidence_text:
            self.evidence.append(f"[EXPLOITED] {evidence_text}")
            self.verification_evidence = evidence_text
        self._assert_invariants()

    def mark_unverified(self, reason: str = "", outcome: str = "FAILED") -> None:
        """
        Mark finding as failed verification or no strategy.
        """
        self.verified = False

        if outcome == "NO_STRATEGY":
            self.verification_attempted = False
            self.verification_outcome = outcome
            self.verification_state = VerificationState.NO_STRATEGY_CANDIDATE
            self.verification_reason_code = "no_strategy_registered"
        else:
            self.verification_attempted = True
            self.verification_outcome = outcome
            if outcome == "FAILED":
                self.confidence = max(0.0, self.confidence - 0.2)
                self.verification_state = VerificationState.ATTEMPTED_NOT_CONFIRMED
                self.verification_reason_code = "negative_result"
            elif outcome == "ERROR":
                self.verification_state = VerificationState.ATTEMPTED_NOT_CONFIRMED
                self.verification_reason_code = "tool_error"
            else:
                self.verification_state = VerificationState.ATTEMPTED_NOT_CONFIRMED
                self.verification_reason_code = "negative_result"

        self.verification_rationale = reason
        if reason and outcome == "FAILED":
            self.evidence.append(f"[UNVERIFIED] {reason}")
        self._assert_invariants()

    def mark_proven(self, evidence_text: str = "") -> None:
        """Legacy compatibility wrapper for mark_exploited."""
        self.mark_exploited(evidence_text)

    def add_evidence(self, text: str) -> None:
        if text and len(text.strip()) > 0:
            self.evidence.append(text[:500])

    def boost_confidence(self, delta: float = 0.1) -> None:
        """Corroborate the finding from an additional signal. Does NOT change stage."""
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
        # Decoupled from stage, just reflects the numeric range for legacy reasons
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
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "stage": self.stage.value,
            "cve": self.cve,
            "port": self.port,
            "service": self.service,
            "phase": self.phase,
            "source_tool": self.source_tool,
            "evidence": self.evidence,
            "verified": self.verified,
            "confidence": round(self.confidence, 3),
            "confidence_label": self.confidence_label,
            "remediation": self.remediation,
            "timestamp": self.timestamp,
            "verification_attempted": self.verification_attempted,
            "verification_outcome": self.verification_outcome,
            "verification_rationale": self.verification_rationale,
            "verification_evidence": self.verification_evidence,
            "verification_strategy": self.verification_strategy,
            "verification_state": self.verification_state.value,
            "verification_reason_code": self.verification_reason_code,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FindingRecord":
        sev = FindingSeverity.from_str(data.get("severity", "INFO"))
        rec = cls(
            name=data.get("name", ""),
            severity=sev,
            description=data.get("description", ""),
        )
        rec.id = data.get("id", rec.id)

        # Safe stage loading
        stage_str = data.get("stage")
        if stage_str:
            try:
                rec.stage = FindingStage(stage_str)
            except ValueError:
                rec.stage = FindingStage.PLAUSIBLE

        rec.cve = data.get("cve", "")
        rec.port = int(data.get("port", 0))
        rec.service = data.get("service", "")
        rec.phase = data.get("phase", "")
        rec.source_tool = data.get("source_tool", "")
        rec.evidence = list(data.get("evidence", []))
        rec.verified = bool(data.get("verified", False))
        rec.confidence = float(data.get("confidence", 0.5))
        rec.remediation = data.get("remediation", "")
        rec.timestamp = data.get("timestamp", ts())

        rec.verification_attempted = bool(data.get("verification_attempted", False))
        rec.verification_outcome = data.get("verification_outcome", "")
        rec.verification_rationale = data.get("verification_rationale", "")
        rec.verification_evidence = data.get("verification_evidence", "")
        rec.verification_strategy = data.get("verification_strategy", "")

        v_state = data.get("verification_state")
        if v_state:
            try:
                rec.verification_state = VerificationState(v_state)
            except ValueError:
                pass
        rec.verification_reason_code = data.get("verification_reason_code", rec.verification_reason_code)

        return rec

    @classmethod
    def from_vuln_dict(cls, vuln: dict, phase: str = "") -> "FindingRecord":
        """Create from existing Findings.vulns dict entry (backward compat)."""
        return cls(
            name=vuln.get("name", ""),
            severity=FindingSeverity.from_str(vuln.get("severity", "INFO")),
            description=vuln.get("description", ""),
            stage=FindingStage.PLAUSIBLE,
            cve=vuln.get("cve", ""),
            port=int(vuln.get("port", 0)),
            phase=phase,
            confidence=0.5,
        )
