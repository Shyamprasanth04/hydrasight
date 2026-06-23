
from hydrasight.models.finding_record import FindingRecord, FindingSeverity, FindingStage
from hydrasight.models.findings import Findings
from hydrasight.models.report_model import ReportModel
from hydrasight.services.verifier import VerificationOutcome


def test_finding_lifecycle_transitions():
    """Test explicit lifecycle state transitions."""
    rec = FindingRecord(name="TestVuln", severity=FindingSeverity.HIGH, description="Test")

    # Defaults to PLAUSIBLE if no stage passed
    assert rec.stage == FindingStage.PLAUSIBLE
    assert rec.confidence == 0.5

    # Demote to CANDIDATE
    rec.mark_candidate(reason="Parser noise")
    assert rec.stage == FindingStage.CANDIDATE
    assert rec.confidence == 0.1
    assert "[CANDIDATE] Parser noise" in rec.evidence[0]

    # Observe
    rec.mark_observed()
    assert rec.stage == FindingStage.OBSERVED
    assert rec.confidence == 0.3

    # Plausible
    rec.mark_plausible()
    assert rec.stage == FindingStage.PLAUSIBLE
    assert rec.confidence == 0.5

    # Verify
    rec.mark_verified(confidence=0.9, rationale="Found pattern", strategy="nmap")
    assert rec.stage == FindingStage.VERIFIED
    assert rec.confidence == 0.9
    assert rec.verified
    assert rec.verification_outcome == VerificationOutcome.VERIFIED.value

    # Exploit
    rec.mark_exploited(evidence_text="uid=0(root)")
    assert rec.stage == FindingStage.EXPLOITED
    assert rec.confidence == 1.0
    assert rec.verified
    assert "[EXPLOITED] uid=0(root)" in rec.evidence[-1]


def test_high_confidence_does_not_imply_verified():
    """High confidence alone must NEVER imply VERIFIED."""
    rec = FindingRecord(name="TestVuln", severity=FindingSeverity.HIGH, description="Test")
    rec.boost_confidence(0.4)
    assert rec.confidence == 0.9
    assert rec.stage == FindingStage.PLAUSIBLE  # still plausible
    assert not rec.verified


def test_demote_to_plausible():
    """demote_to_plausible() behavior."""
    rec = FindingRecord(name="Test", severity=FindingSeverity.HIGH, description="Test")
    rec.mark_verified()
    assert rec.stage == FindingStage.VERIFIED
    assert rec.verified

    rec.demote_to_plausible("Correction")
    assert rec.stage == FindingStage.PLAUSIBLE
    assert not rec.verified
    assert rec.confidence == 0.5


def test_findings_container_separation():
    """Test verified vs candidate separation in Findings using VerificationState."""
    f = Findings()

    # Exploit
    r1 = FindingRecord(name="Exploited", severity=FindingSeverity.CRITICAL, description="")
    r1.mark_exploited()
    f.add_finding_record(r1)

    # Verified
    r2 = FindingRecord(name="Verified", severity=FindingSeverity.HIGH, description="")
    r2.mark_verified()
    f.add_finding_record(r2)

    # Plausible (Supported Candidate)
    r3 = FindingRecord(name="Plausible", severity=FindingSeverity.MEDIUM, description="")
    f.add_finding_record(r3)

    # Candidate (Supported Candidate)
    r4 = FindingRecord(name="Candidate", severity=FindingSeverity.LOW, description="")
    r4.mark_candidate()
    f.add_finding_record(r4)

    assert len(f.exploited_findings()) == 1
    assert len(f.verified_findings()) == 1
    assert len(f.plausible_findings()) == 1
    assert len(f.candidate_findings()) == 1
    assert f.verified_count == 2


def test_report_model_normalization():
    """ReportModel normalization test for canonical buckets."""
    f = Findings()
    f.target = "10.0.0.1"

    r1 = FindingRecord(name="Ver", severity=FindingSeverity.CRITICAL, description="")
    r1.mark_verified()
    f.add_finding_record(r1)

    r2 = FindingRecord(name="NoStrat", severity=FindingSeverity.HIGH, description="")
    r2.mark_unverified("No strategy", outcome=VerificationOutcome.NO_STRATEGY.value)
    f.add_finding_record(r2)

    r3 = FindingRecord(name="Failed", severity=FindingSeverity.HIGH, description="")
    r3.mark_unverified("Pattern not found", outcome=VerificationOutcome.FAILED.value)
    f.add_finding_record(r3)

    model = ReportModel.from_findings(f)
    assert model.target == "10.0.0.1"
    assert model.confirmed_risk == "CRITICAL"
    assert len(model.verified_findings) == 1
    assert len(model.no_strategy_candidates) == 1
    assert len(model.attempted_not_confirmed_findings) == 1

    assert model.verification_coverage.total == 3
    assert model.verification_coverage.verified == 1
    assert model.verification_coverage.no_strategy == 1
    assert model.verification_coverage.unsupported == 1
    assert model.verification_coverage.supported == 2
    assert model.verification_coverage.failed == 1
