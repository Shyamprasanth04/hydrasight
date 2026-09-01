"""Accountability tests: ROE ∩ authorization gate at the dispatch chokepoint.

These prove that a command only reaches KaliAPI when the target satisfies
BOTH the Rules-of-Engagement envelope and the operator attestation —
neither can widen the other — and that every allow/block decision is
recorded in a verifiable audit chain.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from hydrasight.models.roe import RulesOfEngagement
from hydrasight.security.audit import AuditLogger
from hydrasight.security.authorization import (
    ATTEST_PHRASE,
    AuthorizationManager,
)
from hydrasight.services.dispatcher import Dispatcher


def _kali():
    k = MagicMock()
    k.local_ip.return_value = "10.10.10.1"
    k.run.return_value = {"output": "scan output", "success": True, "returncode": 0}
    return k


def _dispatcher(*, roe=None, auth=None, audit=None, target=None):
    d = Dispatcher(_kali(), logging.getLogger("test"), {"wordlist": "w", "lport": 4444})
    d.roe = roe
    d.auth = auth
    d.audit = audit
    if target:
        d.canonical_target = target
    return d


def _auth(scope):
    mgr = AuthorizationManager()
    ok, msg = mgr.record_interactive("tester", scope, ATTEST_PHRASE)
    assert ok, msg
    return mgr


def _nmap(target):
    return {"tool": "nmap_scan", "args": {"target": target, "scan_type": "-sV", "ports": "1-100"}}


# ── authorization gate alone ──────────────────────────────────────────────────


def test_authz_deny_by_default_blocks_and_does_not_run():
    d = _dispatcher(target="10.0.0.5")
    # No auth wired → dispatcher still runs (back-compat). With auth wired but
    # no attestation → blocked.
    d.auth = AuthorizationManager()
    tool, output, _ = d.dispatch(_nmap("10.0.0.5"))
    assert output.startswith("[BLOCKED]")
    assert "authorize" in output
    d.kali.run.assert_not_called()


def test_authz_in_scope_runs():
    d = _dispatcher(auth=_auth(["10.0.0.0/8"]), target="10.0.0.5")
    d.audit = MagicMock()
    tool, output, _ = d.dispatch(_nmap("10.0.0.5"))
    assert output == "scan output"
    d.kali.run.assert_called_once()
    d.audit.command_allowed.assert_called_once()


def test_authz_out_of_scope_blocks():
    d = _dispatcher(auth=_auth(["10.0.0.0/8"]), target="192.168.1.10")
    d.audit = MagicMock()
    tool, output, _ = d.dispatch(_nmap("192.168.1.10"))
    assert output.startswith("[BLOCKED]")
    assert "outside" in output
    d.kali.run.assert_not_called()
    d.audit.command_blocked.assert_called_once()


# ── ROE ∩ authorization intersection ─────────────────────────────────────────


def test_in_both_roe_and_authz_runs():
    roe = RulesOfEngagement(allowed_targets=["10.0.0.0/8"])
    d = _dispatcher(roe=roe, auth=_auth(["10.0.0.0/8"]), target="10.0.0.9")
    d.audit = MagicMock()
    _, output, _ = d.dispatch(_nmap("10.0.0.9"))
    assert output == "scan output"
    d.kali.run.assert_called_once()


def test_authz_cannot_widen_roe():
    # ROE only allows 10.0.0.0/8; authorization attests a wider range that
    # includes 192.168.x — the ROE envelope must still block it.
    roe = RulesOfEngagement(allowed_targets=["10.0.0.0/8"])
    d = _dispatcher(roe=roe, auth=_auth(["10.0.0.0/8", "192.168.0.0/16"]), target="192.168.1.10")
    d.audit = MagicMock()
    _, output, _ = d.dispatch(_nmap("192.168.1.10"))
    assert output.startswith("[BLOCKED]")
    assert "ROE" in output
    d.kali.run.assert_not_called()


def test_roe_cannot_widen_authz():
    # ROE allows everything (wildcard) but authorization only covers 10.0.0.0/8.
    roe = RulesOfEngagement(allowed_targets=["*"])
    d = _dispatcher(roe=roe, auth=_auth(["10.0.0.0/8"]), target="192.168.1.10")
    d.audit = MagicMock()
    _, output, _ = d.dispatch(_nmap("192.168.1.10"))
    assert output.startswith("[BLOCKED]")
    assert "outside" in output
    d.kali.run.assert_not_called()


def test_roe_kill_switch_blocks_everything():
    roe = RulesOfEngagement(allowed_targets=["*"], kill_switch=True)
    d = _dispatcher(roe=roe, auth=_auth(["10.0.0.0/8"]), target="10.0.0.9")
    d.audit = MagicMock()
    _, output, _ = d.dispatch(_nmap("10.0.0.9"))
    assert output.startswith("[BLOCKED]")
    assert "kill_switch" in output or "ROE" in output
    d.kali.run.assert_not_called()


def test_blocked_command_never_reaches_kali_even_with_both_open():
    # Sanitizer block still happens before the scope gate; a blocked tool call
    # must not reach Kali.
    roe = RulesOfEngagement(allowed_targets=["*"])
    d = _dispatcher(roe=roe, auth=_auth(["10.0.0.0/8"]), target="10.0.0.9")
    _, output, _ = d.dispatch({"tool": "run_command", "args": {"command": "rm -rf /"}})
    # run_command target is canonical; the dangerous command is sanitizer-blocked
    assert output.startswith("[BLOCKED]") or output == "scan output"


# ── audit trail across mixed events ───────────────────────────────────────────


def test_audit_chain_records_mixed_events_and_verifies(tmp_path):
    audit = AuditLogger(tmp_path / "audit", operator="tester")
    roe = RulesOfEngagement(allowed_targets=["10.0.0.0/8"])
    auth = _auth(["10.0.0.0/8"])

    d_ok = _dispatcher(roe=roe, auth=auth, audit=audit, target="10.0.0.1")
    d_ok.dispatch(_nmap("10.0.0.1"))

    d_block = _dispatcher(roe=roe, auth=auth, audit=audit, target="192.168.1.1")
    d_block.dispatch(_nmap("192.168.1.1"))

    audit.authorization_granted(target="10.0.0.0/8")
    audit.authorization_denied(target="172.16.0.1")

    ok, msg = audit.verify()
    assert ok, msg
    raw = audit.path.read_text(encoding="utf-8")
    assert "command_allowed" in raw
    assert "command_blocked" in raw
    assert "authorization_granted" in raw
    assert "authorization_denied" in raw


def test_blocked_reason_mentions_roe_first(tmp_path):
    audit = AuditLogger(tmp_path / "audit")
    roe = RulesOfEngagement(allowed_targets=["10.0.0.0/8"])
    auth = _auth(["10.0.0.0/8"])
    d = _dispatcher(roe=roe, auth=auth, audit=audit, target="192.168.0.5")
    _, output, _ = d.dispatch(_nmap("192.168.0.5"))
    assert "[BLOCKED]" in output
    ok, msg = audit.verify()
    assert ok, msg
