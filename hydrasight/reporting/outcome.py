"""Engagement-outcome classification.

Extracted from the shell renderer so the decision logic is pure and testable.
The renderer owns only the colour/label mapping for an outcome key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hydrasight.models.report_model import ReportModel


@dataclass(frozen=True)
class EngagementOutcome:
    """An immutable classification of how an engagement concluded."""

    key: str
    label: str
    description: str


# Ordered by significance (most decisive first). The first matching outcome
# wins in :func:`classify_outcome`.
POST_ACCESS = EngagementOutcome("POST_ACCESS", "POST-ACCESS", "Active session(s) established")
CREDENTIAL_LED = EngagementOutcome(
    "CREDENTIAL_LED", "CREDENTIAL-LED", "Credentials recovered without session"
)
EXPLOIT_CONFIRMED = EngagementOutcome(
    "EXPLOIT_CONFIRMED", "EXPLOIT-CONFIRMED", "Vulnerabilities explicitly exploited"
)
VALIDATION = EngagementOutcome("VALIDATION", "VALIDATION", "Vulnerabilities independently verified")
VULN_CANDIDATES = EngagementOutcome(
    "VULN_CANDIDATES", "VULNERABILITY-CANDIDATES", "Candidate vulnerabilities identified"
)
RECON_ONLY = EngagementOutcome("RECON_ONLY", "RECON-ONLY", "Port/service discovery completed")
NO_FINDINGS = EngagementOutcome("NO_FINDINGS", "NO-FINDINGS", "No actionable data collected")

#: Outcome lookup by key (used by the renderer for colour mapping).
OUTCOMES: dict[str, EngagementOutcome] = {
    o.key: o
    for o in (
        POST_ACCESS,
        CREDENTIAL_LED,
        EXPLOIT_CONFIRMED,
        VALIDATION,
        VULN_CANDIDATES,
        RECON_ONLY,
        NO_FINDINGS,
    )
}


def classify_outcome(report: ReportModel) -> EngagementOutcome:
    """Classify an engagement from its normalized report.

    Priority: POST_ACCESS > CREDENTIAL_LED > EXPLOIT_CONFIRMED > VALIDATION >
    VULN_CANDIDATES > RECON_ONLY > NO_FINDINGS.
    """
    if report.sessions:
        return POST_ACCESS
    if report.credentials:
        return CREDENTIAL_LED
    if report.exploited_findings:
        return EXPLOIT_CONFIRMED
    if report.verified_findings:
        return VALIDATION
    if (
        report.supported_candidates
        or report.no_strategy_candidates
        or report.attempted_not_confirmed_findings
    ):
        return VULN_CANDIDATES
    if report.ports:
        return RECON_ONLY
    return NO_FINDINGS
