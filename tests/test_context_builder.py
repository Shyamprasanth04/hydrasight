"""
Tests for ContextBuilder — compact engagement context assembly.

All tests are offline — no network, no Ollama.
"""

from __future__ import annotations

from hydrasight.models.findings import Findings
from hydrasight.models.planner_state import PlannerState
from hydrasight.services.context_builder import _MAX_CONTEXT_CHARS, ContextBuilder


def _cfg(mode: str = "confirm") -> dict:
    return {"execution_mode": mode}


def _findings_empty() -> Findings:
    return Findings()


def _findings_with_ports() -> Findings:
    f = Findings()
    f.target = "10.10.10.5"
    f.add_port(22, "tcp", "ssh", "OpenSSH 8.9")
    f.add_port(80, "tcp", "http", "Apache 2.4")
    f.add_port(445, "tcp", "microsoft-ds", "")
    return f


def _findings_with_vulns() -> Findings:
    f = _findings_with_ports()
    f.add_vuln(
        name="MS17-010 EternalBlue",
        severity="CRITICAL",
        description="SMBv1 RCE",
        cve="CVE-2017-0144",
        port=445,
        phase="SMB_CHECK",
        source_tool="nmap",
        confidence=0.9,
    )
    f.add_vuln(
        name="Anonymous FTP",
        severity="MEDIUM",
        description="FTP anon login allowed",
        port=21,
        phase="FTP_CHECK",
        source_tool="nmap",
        confidence=0.8,
    )
    return f


# ── basic structure ────────────────────────────────────────────────────────────


class TestContextBuilderBasic:
    def test_empty_findings_no_target(self):
        ctx = ContextBuilder.build(_findings_empty(), None, _cfg())
        assert "Target     : none" in ctx
        assert "Open ports : none" in ctx
        assert "Vulns      : none" in ctx

    def test_target_appears_in_context(self):
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "10.10.10.5" in ctx

    def test_execution_mode_appears(self):
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, None, _cfg(mode="never"))
        assert "Mode: never" in ctx

    def test_auto_mode_appears(self):
        ctx = ContextBuilder.build(_findings_empty(), None, _cfg(mode="auto"))
        assert "Mode: auto" in ctx

    def test_ports_listed(self):
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "22/ssh" in ctx
        assert "80/http" in ctx

    def test_ports_truncated_after_max(self):
        f = Findings()
        f.target = "10.0.0.1"
        for i in range(1, 15):  # 14 ports
            f.add_port(8000 + i, "tcp", "http", "")
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "..." in ctx

    def test_safety_rules_always_present(self):
        ctx = ContextBuilder.build(_findings_empty(), None, _cfg())
        assert "NEVER invent scan output" in ctx
        assert "Supported commands" in ctx


# ── vuln / finding records ────────────────────────────────────────────────────


class TestContextBuilderVulns:
    def test_vuln_count_and_name(self):
        f = _findings_with_vulns()
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "MS17-010 EternalBlue" in ctx
        assert "CRITICAL" in ctx

    def test_verified_note_shown(self):
        f = _findings_with_vulns()
        # Mark the FindingRecord as verified
        for rec in f.finding_records:
            if rec.name == "MS17-010 EternalBlue":
                rec.mark_verified(confidence=0.95)
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "verified" in ctx

    def test_high_confidence_section(self):
        f = _findings_with_vulns()
        # Both findings have confidence >= 0.75 so should appear in high-conf
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "High-conf" in ctx
        assert "MS17-010" in ctx

    def test_verified_count_shown(self):
        f = _findings_with_vulns()
        for rec in f.finding_records:
            rec.mark_verified()
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "confirmed" in ctx

    def test_low_confidence_finding_not_in_high_conf(self):
        f = Findings()
        f.target = "10.0.0.1"
        f.add_vuln("Low Conf Finding", "INFO", "desc", confidence=0.3)
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "High-conf" not in ctx

    def test_credentials_shown(self):
        f = _findings_with_ports()
        f.add_cred("admin", "password123")
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "Credentials: 1" in ctx

    def test_sessions_shown(self):
        f = _findings_with_ports()
        f.add_session(uid="root", exploit="test")
        ctx = ContextBuilder.build(f, None, _cfg())
        assert "Sessions" in ctx


# ── PlannerState dead paths ───────────────────────────────────────────────────


class TestContextBuilderPlannerState:
    def test_no_state_no_dead_paths_section(self):
        ctx = ContextBuilder.build(_findings_with_ports(), None, _cfg())
        assert "Dead paths" not in ctx

    def test_failed_phase_appears(self):
        state = PlannerState(max_retries=1)
        state.record_phase("SSH_CHECK", False, reason="connection refused")
        # Record it twice to exceed max_retries
        state.record_phase("SSH_CHECK", False, reason="connection refused")
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, state, _cfg())
        assert "SSH_CHECK" in ctx
        assert "Dead paths" in ctx

    def test_empty_tool_appears(self):
        state = PlannerState()
        state.record_tool_outcome("ftp_brute", success=False, bytes_out=0)
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, state, _cfg())
        assert "ftp_brute" in ctx

    def test_tried_credentials_shown(self):
        state = PlannerState()
        state.record_credential_attempt("admin", "pass1")
        state.record_credential_attempt("root", "pass2")
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, state, _cfg())
        assert "credential pair" in ctx

    def test_empty_state_no_dead_paths(self):
        """Fresh PlannerState with no failures should not add dead paths section."""
        state = PlannerState()
        f = _findings_with_ports()
        ctx = ContextBuilder.build(f, state, _cfg())
        assert "Dead paths" not in ctx


# ── context size cap ──────────────────────────────────────────────────────────


class TestContextBuilderCap:
    def test_context_never_exceeds_max_chars(self):
        f = Findings()
        f.target = "10.0.0.1"
        # Add many findings to force a long context
        for i in range(30):
            f.add_port(8000 + i, "tcp", f"service-{i}", "version 1.2.3.4.5.6.7.8.9.0-long-name")
        for i in range(20):
            f.add_vuln(f"Very Long Vulnerability Name Number {i}", "HIGH", "desc " * 20)
        state = PlannerState()
        for i in range(10):
            state.record_phase(f"PHASE_{i}", False, reason="failed " * 10)
        ctx = ContextBuilder.build(f, state, _cfg())
        assert len(ctx) <= _MAX_CONTEXT_CHARS + len("\n[context truncated]")

    def test_truncation_marker_present_when_capped(self):
        f = Findings()
        f.target = "10.0.0.1"
        for i in range(30):
            f.add_vuln(f"Vuln {i} with extra long name and lots of detail", "CRITICAL", "d" * 100)
        ctx = ContextBuilder.build(f, None, _cfg())
        if len(ctx) > _MAX_CONTEXT_CHARS:
            assert "[context truncated]" in ctx


# ── canonical_target fallback ─────────────────────────────────────────────────


class TestContextBuilderCanonicalTarget:
    def test_canonical_target_used_when_no_findings_target(self):
        f = Findings()  # target is ""
        ctx = ContextBuilder.build(f, None, _cfg(), canonical_target="192.168.1.10")
        assert "192.168.1.10" in ctx

    def test_findings_target_takes_precedence(self):
        f = Findings()
        f.target = "10.10.10.5"
        ctx = ContextBuilder.build(f, None, _cfg(), canonical_target="192.168.1.10")
        assert "10.10.10.5" in ctx
        assert "192.168.1.10" not in ctx
