"""Tests for the tamper-evident, hash-chained audit trail."""

from __future__ import annotations

import json

import pytest

from hydrasight.security.audit import (
    GENESIS_HASH,
    REDACTED,
    AuditAction,
    AuditLogger,
    redact_secrets,
)


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "audit", operator="alice", session_id="sess-1")


# ── redaction ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text,sensitive",
    [
        ("sshpass -p 'hunter2' ssh root@10.0.0.1", "hunter2"),
        ("sshpass -p hunter2 ssh root@10.0.0.1", "hunter2"),
        ('sshpass -p "p@ss w0rd!" ssh host', "p@ss"),
        ("curl http://admin:s3cr3t@10.0.0.5/x", "s3cr3t"),
        ("export password=Sup3rSecret echo done", "Sup3rSecret"),
        ("token='abc.def.ghi' curl host", "abc.def.ghi"),
        ("API_KEY=zzz123 ./run", "zzz123"),
    ],
)
def test_redact_secrets_scrubs_sensitive_values(text, sensitive):
    out = redact_secrets(text)
    assert sensitive not in out
    assert REDACTED in out


def test_redact_secrets_keeps_benign_text():
    assert redact_secrets("nmap -sV 10.0.0.1") == "nmap -sV 10.0.0.1"


def test_redact_secrets_handles_none_and_non_string():
    assert redact_secrets(None) == ""
    assert redact_secrets(12345) == "12345"


# ── chain structure ───────────────────────────────────────────────────────────


def test_first_record_chains_from_genesis(audit):
    rec = audit.command_allowed(tool="nmap_scan", target="10.0.0.1", command="nmap 10.0.0.1")
    assert rec is not None
    assert rec["sequence"] == 1
    assert rec["prev_hash"] == GENESIS_HASH
    assert len(rec["hash"]) == 64
    assert rec["action"] == AuditAction.COMMAND_ALLOWED.value
    assert rec["operator"] == "alice"
    assert rec["session_id"] == "sess-1"


def test_records_are_sequential_and_chained(audit):
    audit.command_allowed(tool="a", target="10.0.0.1")
    audit.command_blocked(tool="b", target="10.1.1.1", reason="outside scope")
    audit.authorization_granted(target="10.0.0.0/8")
    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    records = [json.loads(line) for line in lines]
    assert [r["sequence"] for r in records] == [1, 2, 3]
    assert records[1]["prev_hash"] == records[0]["hash"]
    assert records[2]["prev_hash"] == records[1]["hash"]


def test_command_field_is_redacted_on_disk(audit):
    audit.command_allowed(
        tool="run_command", target="10.0.0.1", command="sshpass -p 'toor' ssh root@x"
    )
    raw = audit.path.read_text(encoding="utf-8")
    assert "toor" not in raw
    assert REDACTED in raw


# ── verification ──────────────────────────────────────────────────────────────


def test_verify_clean_chain(audit):
    audit.command_allowed(tool="a", target="10.0.0.1")
    audit.command_blocked(tool="b", target="10.0.0.2", reason="ROE")
    audit.authorization_denied(target="10.0.0.3", reason="no auth")
    audit.authorization_granted(target="10.0.0.4")
    audit.engagement_start(target="10.0.0.1")
    audit.engagement_end(target="10.0.0.1")
    ok, msg = audit.verify()
    assert ok, msg
    assert "6 record" in msg


def test_verify_detects_tampered_line(audit):
    audit.command_allowed(tool="a", target="10.0.0.1")
    audit.command_allowed(tool="b", target="10.0.0.2")
    # Tamper: change the target of the first record without recomputing hash.
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["target"] = "10.9.9.9"
    lines[0] = json.dumps(rec)
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = audit.verify()
    assert not ok
    assert "tampered" in msg or "hash mismatch" in msg


def test_verify_detects_deleted_line(audit):
    audit.command_allowed(tool="a", target="10.0.0.1")
    audit.command_allowed(tool="b", target="10.0.0.2")
    audit.command_allowed(tool="c", target="10.0.0.3")
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    # Delete the middle record.
    del lines[1]
    audit.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = audit.verify()
    assert not ok
    assert "chain broken" in msg or "prev_hash" in msg


def test_verify_detects_malformed_json(audit):
    audit.command_allowed(tool="a", target="10.0.0.1")
    with open(audit.path, "a", encoding="utf-8") as fh:
        fh.write("{not valid json\n")
    ok, msg = audit.verify()
    assert not ok
    assert "malformed JSON" in msg


def test_verify_missing_log_is_ok(tmp_path):
    audit = AuditLogger(tmp_path / "nope")
    ok, msg = audit.verify()
    assert ok
    assert "no audit log" in msg


# ── resume ────────────────────────────────────────────────────────────────────


def test_chain_resumes_from_existing_log(tmp_path):
    out = tmp_path / "audit"
    a1 = AuditLogger(out, operator="alice")
    a1.command_allowed(tool="a", target="10.0.0.1")
    a1.command_allowed(tool="b", target="10.0.0.2")

    # New logger over the same file resumes sequence and chain.
    a2 = AuditLogger(out, operator="alice")
    rec = a2.command_allowed(tool="c", target="10.0.0.3")
    assert rec is not None
    assert rec["sequence"] == 3
    ok, msg = a2.verify()
    assert ok, msg


def test_disabled_logger_is_noop(tmp_path):
    audit = AuditLogger(tmp_path / "audit", enabled=False)
    assert audit.log(AuditAction.COMMAND_ALLOWED, tool="a", target="10.0.0.1") is None
    assert not audit.path.exists()
    ok, _ = audit.verify()
    assert ok


def test_audit_write_never_raises_on_bad_dir(monkeypatch, tmp_path):
    audit = AuditLogger(tmp_path / "audit")

    # Force the open() to blow up; log() must swallow it and return None.
    def _boom(*_a, **_k):
        raise OSError("disk on fire")

    monkeypatch.setattr("builtins.open", _boom)
    assert audit.command_allowed(tool="a", target="10.0.0.1") is None
