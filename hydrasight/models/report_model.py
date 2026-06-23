from dataclasses import dataclass, field
from typing import Any

from hydrasight.models.finding_record import FindingRecord
from hydrasight.models.findings import Findings


@dataclass
class VerificationCoverage:
    total: int = 0
    attempted: int = 0
    verified: int = 0
    exploited: int = 0
    failed: int = 0
    no_strategy: int = 0
    error: int = 0
    not_applicable: int = 0
    supported: int = 0
    unsupported: int = 0

@dataclass
class ReportItem:
    """Normalized presentation-safe finding record for all renderers."""

    canonical_status: str
    status_label: str

    display_title: str
    display_summary: str
    display_evidence: str
    display_remediation: str
    verification_reason_code: str

    severity: str
    priority_rank: int
    severity_rank: int

    appendix_only: bool

    # Core identifiers for correlation
    id: str
    cve: str
    port: int
    service: str
    source_tool: str
    phase: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.display_title,
            "severity": self.severity,
            "canonical_status": self.canonical_status,
            "status_label": self.status_label,
            "verification_reason_code": self.verification_reason_code,
            "display_summary": self.display_summary,
            "display_evidence": self.display_evidence,
            "display_remediation": self.display_remediation,
            "port": self.port,
            "service": self.service,
            "source_tool": self.source_tool,
            "phase": self.phase,
            "cve": self.cve,
            "timestamp": self.timestamp,
            "appendix_only": self.appendix_only,
        }

@dataclass
class ReportModel:
    """Single source of truth for canonical reporting semantics."""

    # Meta
    target: str = ""
    started_at: str = ""
    completed_at: str = ""

    # Risk
    confirmed_risk: str = "NONE"
    potential_risk: str = "NONE"
    overall_risk: str = "NONE"

    # Coverage
    verification_coverage: VerificationCoverage = field(default_factory=VerificationCoverage)

    # Canonical Collections
    exploited_findings: list[ReportItem] = field(default_factory=list)
    verified_findings: list[ReportItem] = field(default_factory=list)
    supported_candidates: list[ReportItem] = field(default_factory=list)
    no_strategy_candidates: list[ReportItem] = field(default_factory=list)
    attempted_not_confirmed_findings: list[ReportItem] = field(default_factory=list)
    appendix_findings: list[ReportItem] = field(default_factory=list)

    # Counters
    exploited_count: int = 0
    verified_count: int = 0
    supported_candidate_count: int = 0
    no_strategy_candidate_count: int = 0
    attempted_not_confirmed_count: int = 0
    pending_count: int = 0

    credential_count: int = 0
    session_count: int = 0

    # Legacy / Other Data
    ports: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    dirs: list[dict[str, Any]] = field(default_factory=list)
    host_info: dict[str, Any] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: Findings) -> "ReportModel":
        from hydrasight.utils.time_utils import ts

        model = cls(
            target=findings.target,
            started_at=findings.started_at,
            completed_at=ts(),
            confirmed_risk=findings.confirmed_risk,
            potential_risk=findings.potential_risk,
            overall_risk=findings.overall_risk,
            ports=findings.ports,
            credentials=findings.credentials,
            sessions=findings.sessions,
            dirs=findings.dirs,
            host_info=findings.host_info,
            timeline=findings.timeline,
            credential_count=len(findings.credentials),
            session_count=len(findings.sessions),
        )

        for rec in findings.finding_records:
            item = cls._map_to_report_item(rec)

            # Map to canonical collection
            if item.canonical_status == "EXPLOITED":
                model.exploited_findings.append(item)
                model.exploited_count += 1
            elif item.canonical_status == "VERIFIED":
                model.verified_findings.append(item)
                model.verified_count += 1
            elif item.canonical_status == "SUPPORTED_CANDIDATE":
                model.supported_candidates.append(item)
                model.supported_candidate_count += 1
            elif item.canonical_status == "NO_STRATEGY_CANDIDATE":
                model.no_strategy_candidates.append(item)
                model.no_strategy_candidate_count += 1
            elif item.canonical_status == "ATTEMPTED_NOT_CONFIRMED":
                model.attempted_not_confirmed_findings.append(item)
                model.attempted_not_confirmed_count += 1
            else:
                model.pending_count += 1

            if item.appendix_only:
                model.appendix_findings.append(item)

        # Sort collections
        model.exploited_findings.sort(key=lambda x: x.severity_rank)
        model.verified_findings.sort(key=lambda x: x.severity_rank)
        model.supported_candidates.sort(key=lambda x: x.severity_rank)
        model.no_strategy_candidates.sort(key=lambda x: x.severity_rank)
        model.attempted_not_confirmed_findings.sort(key=lambda x: x.severity_rank)
        model.appendix_findings.sort(key=lambda x: x.severity_rank)

        records = findings.finding_records
        model.verification_coverage = VerificationCoverage(
            total=len(records),
            attempted=sum(1 for r in records if r.verification_attempted),
            verified=model.verified_count,
            exploited=model.exploited_count,
            failed=model.attempted_not_confirmed_count,
            no_strategy=model.no_strategy_candidate_count,
            error=sum(1 for r in records if r.verification_outcome == "ERROR"),
            not_applicable=sum(1 for r in records if r.verification_outcome == "NOT_APPLICABLE"),
            supported=len(records) - model.no_strategy_candidate_count,
            unsupported=model.no_strategy_candidate_count
        )

        return model

    @staticmethod
    def _map_to_report_item(rec: FindingRecord) -> ReportItem:
        if rec.is_exploited:
            canonical_status = "EXPLOITED"
            status_label = "PROVEN"
            priority_rank = 0
        elif rec.is_verified:
            canonical_status = "VERIFIED"
            status_label = "VERIFIED"
            priority_rank = 1
        elif rec.is_supported_candidate:
            canonical_status = "SUPPORTED_CANDIDATE"
            status_label = "SUPPORTED CANDIDATE"
            priority_rank = 2
        elif rec.is_no_strategy_candidate:
            canonical_status = "NO_STRATEGY_CANDIDATE"
            status_label = "NO STRATEGY"
            priority_rank = 3
        elif rec.is_attempted_not_confirmed:
            canonical_status = "ATTEMPTED_NOT_CONFIRMED"
            status_label = "NOT CONFIRMED"
            priority_rank = 4
        else:
            canonical_status = "PENDING"
            status_label = "PENDING"
            priority_rank = 5

        # Format remediation block
        rem = rec.remediation.strip()
        if not rem:
            rem = f"Review best practices for {rec.name}."

        evidence_text = "\n".join(rec.evidence) if rec.evidence else rec.verification_evidence

        return ReportItem(
            canonical_status=canonical_status,
            status_label=status_label,
            display_title=f"{rec.name}{' (' + rec.cve + ')' if rec.cve else ''}",
            display_summary=rec.description,
            display_evidence=evidence_text,
            display_remediation=rem,
            verification_reason_code=rec.verification_reason_code,
            severity=rec.severity.value,
            priority_rank=priority_rank,
            severity_rank=rec.severity_rank,
            appendix_only=rec.is_appendix_only,
            id=rec.id,
            cve=rec.cve,
            port=rec.port,
            service=rec.service,
            source_tool=rec.source_tool,
            phase=rec.phase,
            timestamp=rec.timestamp,
        )

    def to_dict(self) -> dict:
        return {
            "meta": {
                "target": self.target,
                "started": self.started_at,
                "completed": self.completed_at,
                "confirmed_risk": self.confirmed_risk,
                "potential_risk": self.potential_risk,
                "overall_risk": self.overall_risk,
            },
            "summary": {
                "exploited_count": self.exploited_count,
                "verified_count": self.verified_count,
                "supported_candidate_count": self.supported_candidate_count,
                "no_strategy_candidate_count": self.no_strategy_candidate_count,
                "attempted_not_confirmed_count": self.attempted_not_confirmed_count,
                "pending_count": self.pending_count,
                "credential_count": self.credential_count,
                "session_count": self.session_count,
            },
            "verification_coverage": self.verification_coverage.__dict__,
            "findings": {
                "exploited": [r.to_dict() for r in self.exploited_findings],
                "verified": [r.to_dict() for r in self.verified_findings],
                "supported_candidates": [r.to_dict() for r in self.supported_candidates],
                "no_strategy_candidates": [r.to_dict() for r in self.no_strategy_candidates],
                "attempted_not_confirmed": [r.to_dict() for r in self.attempted_not_confirmed_findings],
                "appendix_findings": [r.to_dict() for r in self.appendix_findings],
            },
            "environment": {
                "ports": self.ports,
                "credentials": self.credentials,
                "sessions": self.sessions,
                "dirs": self.dirs,
                "host_info": self.host_info,
                "timeline": self.timeline,
            }
        }
