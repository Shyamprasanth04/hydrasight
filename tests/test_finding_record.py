"""Tests for FindingRecord and FindingSeverity."""
import pytest
from hydrasight.models.finding_record import FindingRecord, FindingSeverity


@pytest.fixture
def basic() -> FindingRecord:
    return FindingRecord(
        name        = "MS17-010 EternalBlue",
        severity    = FindingSeverity.CRITICAL,
        description = "SMBv1 unauthenticated RCE",
        cve         = "CVE-2017-0144",
        port        = 445,
    )


class TestFindingSeverity:
    def test_rank_ordering(self):
        assert FindingSeverity.CRITICAL.rank < FindingSeverity.HIGH.rank
        assert FindingSeverity.HIGH.rank    < FindingSeverity.MEDIUM.rank
        assert FindingSeverity.MEDIUM.rank  < FindingSeverity.LOW.rank
        assert FindingSeverity.LOW.rank     < FindingSeverity.INFO.rank

    def test_from_str_valid(self):
        assert FindingSeverity.from_str("critical") == FindingSeverity.CRITICAL
        assert FindingSeverity.from_str("HIGH")     == FindingSeverity.HIGH

    def test_from_str_invalid_defaults_info(self):
        assert FindingSeverity.from_str("BOGUS") == FindingSeverity.INFO

    def test_string_value(self):
        assert FindingSeverity.CRITICAL.value == "CRITICAL"


class TestFindingRecordCreation:
    def test_id_auto_generated(self, basic):
        assert len(basic.id) == 8

    def test_unique_ids(self):
        a = FindingRecord("A", FindingSeverity.HIGH, "desc")
        b = FindingRecord("A", FindingSeverity.HIGH, "desc")
        assert a.id != b.id

    def test_default_confidence(self, basic):
        assert basic.confidence == 0.5

    def test_default_not_verified(self, basic):
        assert basic.verified is False

    def test_timestamp_set(self, basic):
        assert basic.timestamp != ""

    def test_all_fields(self, basic):
        assert basic.name == "MS17-010 EternalBlue"
        assert basic.severity == FindingSeverity.CRITICAL
        assert basic.cve == "CVE-2017-0144"
        assert basic.port == 445


class TestVerificationMutations:
    def test_mark_verified(self, basic):
        basic.mark_verified(confidence=0.9, output="VULNERABLE found")
        assert basic.verified is True
        assert basic.confidence == 0.9
        assert basic.verification_attempted is True

    def test_mark_verified_clamps_high(self, basic):
        basic.mark_verified(confidence=1.5)
        assert basic.confidence == 1.0

    def test_mark_verified_clamps_low(self, basic):
        basic.mark_verified(confidence=-0.5)
        assert basic.confidence == 0.0

    def test_mark_unverified_reduces_confidence(self, basic):
        original = basic.confidence
        basic.mark_unverified("pattern not found")
        assert basic.confidence == pytest.approx(max(0.0, original - 0.2))
        assert basic.verified is False
        assert basic.verification_attempted is True

    def test_mark_unverified_adds_evidence(self, basic):
        basic.mark_unverified("reason here")
        assert any("reason here" in e for e in basic.evidence)

    def test_mark_unverified_floors_at_zero(self, basic):
        basic.confidence = 0.1
        basic.mark_unverified()
        basic.mark_unverified()
        assert basic.confidence >= 0.0

    def test_mark_proven(self, basic):
        basic.mark_proven("session opened as root")
        assert basic.verified is True
        assert basic.confidence == 1.0

    def test_add_evidence(self, basic):
        basic.add_evidence("nmap output line")
        assert "nmap output line" in basic.evidence

    def test_boost_confidence(self, basic):
        before = basic.confidence
        basic.boost_confidence(0.1)
        assert basic.confidence == pytest.approx(before + 0.1)

    def test_boost_confidence_caps_at_one(self, basic):
        basic.confidence = 0.95
        basic.boost_confidence(0.5)
        assert basic.confidence == 1.0


class TestComputedProperties:
    def test_severity_rank(self, basic):
        assert basic.severity_rank == 0  # CRITICAL

    def test_is_high_confidence_true(self, basic):
        basic.confidence = 0.8
        assert basic.is_high_confidence is True

    def test_is_high_confidence_false(self, basic):
        basic.confidence = 0.4
        assert basic.is_high_confidence is False

    def test_confidence_label_verified(self, basic):
        basic.confidence = 0.95
        assert basic.confidence_label == "VERIFIED"

    def test_confidence_label_medium(self, basic):
        basic.confidence = 0.5
        assert basic.confidence_label == "MEDIUM"

    def test_confidence_label_unconfirmed(self, basic):
        basic.confidence = 0.1
        assert basic.confidence_label == "UNCONFIRMED"


class TestSerialisation:
    def test_to_dict_has_required_keys(self, basic):
        d = basic.to_dict()
        assert "id" in d
        assert "name" in d
        assert "severity" in d
        assert "verified" in d
        assert "confidence" in d
        assert "confidence_label" in d
        assert "evidence" in d

    def test_to_dict_severity_is_string(self, basic):
        d = basic.to_dict()
        assert isinstance(d["severity"], str)
        assert d["severity"] == "CRITICAL"

    def test_from_dict_roundtrip(self, basic):
        d   = basic.to_dict()
        rec = FindingRecord.from_dict(d)
        assert rec.name       == basic.name
        assert rec.severity   == basic.severity
        assert rec.cve        == basic.cve
        assert rec.port       == basic.port
        assert rec.confidence == basic.confidence
        assert rec.verified   == basic.verified

    def test_from_vuln_dict(self):
        vuln = {
            "name"       : "Anonymous FTP Access",
            "severity"   : "MEDIUM",
            "description": "Anon FTP allowed",
            "cve"        : "",
            "port"       : 21,
            "ts"         : "2024-01-01 00:00:00",
        }
        rec = FindingRecord.from_vuln_dict(vuln, phase="FTP_CHECK")
        assert rec.name     == "Anonymous FTP Access"
        assert rec.severity == FindingSeverity.MEDIUM
        assert rec.port     == 21
        assert rec.phase    == "FTP_CHECK"
