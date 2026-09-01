"""Tests for mandatory operator authorization (deny-by-default)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from hydrasight.security.authorization import (
    ATTEST_PHRASE,
    AuthorizationAttestation,
    AuthorizationManager,
    scope_is_valid,
)

# ── attestation dataclass ─────────────────────────────────────────────────────


def test_covers_exact_ip_and_cidr():
    att = AuthorizationAttestation(operator="op", scope=["10.0.0.5", "192.168.0.0/16"])
    assert att.covers("10.0.0.5")
    assert att.covers("192.168.1.20")
    assert not att.covers("10.0.0.6")
    assert not att.covers("8.8.8.8")


def test_covers_rejects_garbage():
    att = AuthorizationAttestation(operator="op", scope=["10.0.0.0/8"])
    assert not att.covers("not-an-ip")


def test_is_expired():
    fresh = AuthorizationAttestation(operator="op", scope=["10.0.0.0/8"], expires_after_minutes=60)
    assert not fresh.is_expired()

    stale = AuthorizationAttestation(
        operator="op",
        scope=["10.0.0.0/8"],
        expires_after_minutes=60,
        granted_at=datetime.now(timezone.utc) - timedelta(minutes=61),
    )
    assert stale.is_expired()

    never = AuthorizationAttestation(operator="op", scope=["10.0.0.0/8"], expires_after_minutes=0)
    assert not never.is_expired()


def test_authorization_id_is_stable_and_unique_by_scope():
    a = AuthorizationAttestation(operator="op", scope=["10.0.0.0/8"])
    b = AuthorizationAttestation(operator="op", scope=["10.0.0.0/8"])
    assert a.authorization_id == b.authorization_id
    c = AuthorizationAttestation(operator="op", scope=["192.168.0.0/16"])
    assert c.authorization_id != a.authorization_id


def test_scope_is_valid():
    assert scope_is_valid(["10.0.0.1", "192.168.0.0/16"])
    assert not scope_is_valid([])
    assert not scope_is_valid(["10.0.0.1", "not-a-network"])
    assert not scope_is_valid(["999.1.1.1"])


# ── manager: interactive ──────────────────────────────────────────────────────


def test_deny_by_default():
    mgr = AuthorizationManager()
    assert mgr.attestation is None
    assert mgr.is_active is False
    allowed, reason = mgr.check("10.0.0.1")
    assert not allowed
    assert "no authorization" in reason


def test_record_interactive_requires_exact_phrase():
    mgr = AuthorizationManager()
    for wrong in ("i authorize", "I AUTHORIZE ", " I AUTHORIZE", "I authorize", ""):
        ok, _ = mgr.record_interactive("op", ["10.0.0.0/8"], wrong)
        assert not ok, f"phrase {wrong!r} must be rejected"
        assert mgr.attestation is None
        assert mgr.is_active is False

    ok, msg = mgr.record_interactive("op", ["10.0.0.0/8"], ATTEST_PHRASE)
    assert ok, msg
    assert mgr.is_active
    allowed, reason = mgr.check("10.0.0.5")
    assert allowed, reason
    denied, dreason = mgr.check("8.8.8.8")
    assert not denied
    assert "outside" in dreason


def test_record_interactive_rejects_bad_scope():
    mgr = AuthorizationManager()
    ok, reason = mgr.record_interactive("op", ["bogus"], ATTEST_PHRASE)
    assert not ok
    assert "invalid scope" in reason
    assert mgr.attestation is None


def test_attestation_covers_cidr_membership():
    mgr = AuthorizationManager()
    mgr.record_interactive("op", ["172.16.0.0/12"], ATTEST_PHRASE)
    assert mgr.check("172.20.5.5")[0]
    assert not mgr.check("172.32.0.1")[0]


# ── manager: expiry ───────────────────────────────────────────────────────────


def test_expired_attestation_is_denied():
    mgr = AuthorizationManager()
    mgr.record_interactive("op", ["10.0.0.0/8"], ATTEST_PHRASE, expires_after_minutes=1)
    assert mgr.is_active
    mgr.attestation.granted_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    assert not mgr.is_active
    allowed, reason = mgr.check("10.0.0.1")
    assert not allowed
    assert "expired" in reason


def test_check_rejects_invalid_target_ip():
    mgr = AuthorizationManager()
    mgr.record_interactive("op", ["10.0.0.0/8"], ATTEST_PHRASE)
    allowed, reason = mgr.check("not-an-ip")
    assert not allowed
    assert "not a valid IP" in reason


def test_reset_clears_attestation():
    mgr = AuthorizationManager()
    mgr.record_interactive("op", ["10.0.0.0/8"], ATTEST_PHRASE)
    assert mgr.is_active
    mgr.reset()
    assert not mgr.is_active
    assert mgr.check("10.0.0.1")[0] is False


# ── manager: file loading ─────────────────────────────────────────────────────


def _write_auth(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")


def test_load_file_grants_valid_attestation(tmp_path):
    f = tmp_path / "auth.json"
    _write_auth(
        f,
        {
            "operator": "ci-bot",
            "scope": ["10.0.0.0/8", "192.168.1.10"],
            "reference": "ticket-123",
            "phrase_confirmed": True,
            "expires_after_minutes": 60,
        },
    )
    mgr = AuthorizationManager()
    ok, msg = mgr.load_file(str(f))
    assert ok, msg
    assert mgr.is_active
    assert mgr.check("10.5.5.5")[0]
    assert mgr.check("192.168.1.10")[0]
    assert not mgr.check("192.168.2.1")[0]
    assert mgr.attestation.operator == "ci-bot"


def test_load_file_missing_denies(tmp_path):
    mgr = AuthorizationManager()
    ok, msg = mgr.load_file(str(tmp_path / "nope.json"))
    assert not ok
    assert "no authorization file" in msg
    assert mgr.attestation is None


def test_load_file_malformed_json_denies(tmp_path):
    f = tmp_path / "auth.json"
    f.write_text("{ this is not json", encoding="utf-8")
    mgr = AuthorizationManager()
    ok, _ = mgr.load_file(str(f))
    assert not ok
    assert not mgr.is_active


def test_load_file_phrase_not_confirmed_denies(tmp_path):
    f = tmp_path / "auth.json"
    _write_auth(f, {"operator": "x", "scope": ["10.0.0.0/8"], "phrase_confirmed": False})
    mgr = AuthorizationManager()
    ok, reason = mgr.load_file(str(f))
    assert not ok
    assert "phrase_confirmed" in reason
    assert not mgr.is_active


def test_load_file_bad_scope_denies(tmp_path):
    f = tmp_path / "auth.json"
    _write_auth(f, {"operator": "x", "scope": ["nonsense"], "phrase_confirmed": True})
    mgr = AuthorizationManager()
    ok, _ = mgr.load_file(str(f))
    assert not ok


def test_load_file_empty_scope_denies(tmp_path):
    f = tmp_path / "auth.json"
    _write_auth(f, {"operator": "x", "scope": [], "phrase_confirmed": True})
    mgr = AuthorizationManager()
    ok, _ = mgr.load_file(str(f))
    assert not ok
