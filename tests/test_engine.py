"""Tests for the engagement orchestration Engine (core/engine.py).

These exercises run fully offline: AIClient, KaliAPI and Dispatcher are
mocked, and Rich console output is suppressed. They target the parts of
the engine that previously had almost no coverage: phase planning,
recon/deep-scan flow, exploitation dispatch, hash cracking, ROE gates and
the lifecycle early-returns.
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from hydrasight.core.engine import Engine
from hydrasight.integrations.exploit_suggestion import (
    ExecutionMode,
    ExploitSuggestion,
)
from hydrasight.models.findings import Findings
from hydrasight.models.roe import RulesOfEngagement

TARGET = "10.10.10.10"


class _NullProgress:
    """Stand-in for a Rich spinner context manager that does nothing."""

    def __enter__(self):
        prog = MagicMock()
        prog.add_task.return_value = None
        return prog

    def __exit__(self, *exc):
        return False


def _null_spinner(_msg: str = ""):
    return _NullProgress()


@pytest.fixture(autouse=True)
def _silence_engine_output():
    """Replace the engine's Rich display helpers with no-ops for the whole test."""
    import hydrasight.core.engine as engine_mod

    silent = MagicMock()
    saved: dict = {}
    names = [
        "console",
        "div",
        "info",
        "ok",
        "warn",
        "err",
        "hit",
        "label",
        "task_line",
        "result_line",
        "stats_line",
        "raw_output",
        "analysis_panel",
        "phase_header",
        "spinner",
    ]
    for name in names:
        saved[name] = getattr(engine_mod, name)
        setattr(engine_mod, name, _null_spinner if name == "spinner" else silent)
    yield
    for name, value in saved.items():
        setattr(engine_mod, name, value)


# ── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def cfg() -> dict:
    return {
        "scan_range": "1-1000",
        "deep_scan_range": "1-65535",
        "wordlist": "/usr/share/wordlists/dirb/common.txt",
        "rockyou_path": "/usr/share/wordlists/rockyou.txt",
        "lport": 4444,
        "verbosity": 0,
        "max_retries": 2,
    }


@pytest.fixture
def log() -> logging.Logger:
    return logging.getLogger("test-engine")


def _make_engine(
    cfg, log, roe=None, findings=None
) -> tuple[Engine, MagicMock, MagicMock, MagicMock]:
    """Build an Engine with mocked ai / kali / dispatcher. Rich output is
    silenced by the autouse ``_silence_engine_output`` fixture."""
    ai = MagicMock()
    # A non-empty reply is required for _ask_and_run to proceed to parsing.
    ai.ask.return_value = "model reply"
    ai.extract_tool_call.return_value = None

    kali = MagicMock()
    kali.check_target.return_value = {"reachable": True, "output": "0% packet loss"}
    kali.local_ip.return_value = "10.10.10.1"

    dispatcher = MagicMock()
    dispatcher.canonical_target = None
    dispatcher.dispatch.return_value = ("nmap_scan", "", 0.0)

    findings = findings or Findings()
    engine = Engine(
        ai=ai,
        kali=kali,
        dispatcher=dispatcher,
        findings=findings,
        cfg=cfg,
        log=log,
        roe=roe or RulesOfEngagement.permissive(),
    )
    return engine, ai, kali, dispatcher


# A realistic nmap service-scan output used for recon ingestion.
NMAP_OUTPUT = (
    "Starting Nmap\n"
    "22/tcp open  ssh     OpenSSH 8.2\n"
    "80/tcp open  http    nginx 1.18\n"
    "445/tcp open  microsoft-ds Windows\n"
    "Service Info: OS: Windows\n"
)


# ── lifecycle / ROE gates ────────────────────────────────────────────────────


class TestLifecycleAndRoe:
    def test_target_outside_roe_returns_early(self, cfg, log):
        roe = RulesOfEngagement.from_dict({"allowed_targets": ["192.168.0.0/16"]})
        engine, ai, kali, dispatcher = _make_engine(cfg, log, roe=roe)
        engine.run("10.10.10.10")
        # No dispatch should happen when the ROE blocks the target.
        dispatcher.dispatch.assert_not_called()
        assert dispatcher.canonical_target is None

    def test_kill_switch_blocks_engagement(self, cfg, log):
        roe = RulesOfEngagement.from_dict({"kill_switch": True})
        engine, ai, kali, dispatcher = _make_engine(cfg, log, roe=roe)
        engine.run(TARGET)
        dispatcher.dispatch.assert_not_called()

    def test_abort_sets_flag(self, cfg, log):
        engine, *_ = _make_engine(cfg, log)
        assert engine.aborted is False
        engine.abort()
        assert engine.aborted is True

    def test_reachability_failure_continues_with_pn(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        kali.check_target.return_value = {"reachable": False, "output": "100% packet loss"}
        ai.extract_tool_call.return_value = {"tool": "nmap_scan", "args": {"target": TARGET}}
        dispatcher.dispatch.return_value = ("nmap_scan", NMAP_OUTPUT, 1.0)
        engine.run(TARGET)
        # Reachability warning must not abort the engagement.
        assert engine.findings.target == TARGET
        assert dispatcher.dispatch.called


# ── recon flow ───────────────────────────────────────────────────────────────


class TestReconFlow:
    def test_recon_ingests_ports(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        ai.extract_tool_call.return_value = {"tool": "nmap_scan", "args": {"target": TARGET}}
        dispatcher.dispatch.return_value = ("nmap_scan", NMAP_OUTPUT, 1.0)
        engine.run(TARGET)
        ports = {p["port"] for p in engine.findings.ports}
        assert {22, 80, 445}.issubset(ports)

    def test_no_ports_triggers_deep_scan(self, cfg, log):
        import itertools

        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        ai.extract_tool_call.return_value = {"tool": "nmap_scan", "args": {"target": TARGET}}
        # First recon returns nothing; second (deep) scan returns ports;
        # later phases (vuln scan) cycle to an empty response.
        dispatcher.dispatch.side_effect = itertools.chain(
            [
                ("nmap_scan", "all 1000 ports filtered", 0.5),
                ("nmap_scan", NMAP_OUTPUT, 2.0),
            ],
            itertools.repeat(("nmap_scan", "", 0.1)),
        )
        engine.run(TARGET)
        # Deep scan ran (at least two dispatch calls).
        assert dispatcher.dispatch.call_count >= 2
        assert {22, 80, 445}.issubset({p["port"] for p in engine.findings.ports})

    def test_no_ports_after_deep_scan_concludes_cleanly(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        ai.extract_tool_call.return_value = None  # model returns no tool call
        dispatcher.dispatch.return_value = ("nmap_scan", "host down", 0.1)
        engine.run(TARGET)
        assert engine.findings.ports == []
        # canonical target is reset after engagement
        assert dispatcher.canonical_target is None

    def test_ms17_finding_ingested(self, cfg, log):
        out = NMAP_OUTPUT + "\nHost is VULNERABLE to MS17-010 (EternalBlue)\n"
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        ai.extract_tool_call.return_value = {"tool": "smb_check", "args": {"target": TARGET}}
        dispatcher.dispatch.return_value = ("smb_check", out, 1.0)
        engine._ingest(out, "SMB_CHECK")
        names = [v["name"] for v in engine.findings.vulns]
        assert any("MS17-010" in n for n in names)


# ── adaptive phase planner ───────────────────────────────────────────────────


class TestPlanPhases:
    def _engine_with_services(self, cfg, log, *services):
        findings = Findings()
        for port, service in services:
            findings.add_port(port, "tcp", service)
        engine, *_ = _make_engine(cfg, log, findings=findings)
        engine._state = None
        return engine

    def test_ftp_service_adds_ftp_check(self, cfg, log):
        engine = self._engine_with_services(cfg, log, (21, "ftp"))
        plan = engine._plan_phases()
        assert "FTP_CHECK" in plan
        assert "VULN_SCAN" in plan

    def test_smb_service_adds_smb_check(self, cfg, log):
        engine = self._engine_with_services(cfg, log, (445, "microsoft-ds"))
        plan = engine._plan_phases()
        assert "SMB_CHECK" in plan

    def test_ssh_service_adds_ssh_check(self, cfg, log):
        engine = self._engine_with_services(cfg, log, (22, "ssh"))
        plan = engine._plan_phases()
        assert "SSH_CHECK" in plan

    def test_web_services_add_web_phases(self, cfg, log):
        engine = self._engine_with_services(cfg, log, (80, "http"))
        plan = engine._plan_phases()
        assert "WEB_FINGER" in plan
        assert "WEB_DIR" in plan
        assert "WEB_VULN" in plan

    def test_credentials_trigger_exploit_and_post(self, cfg, log):
        findings = Findings()
        findings.add_port(22, "tcp", "ssh")
        findings.add_cred("admin", "pass123", kind="bruteforce", source="hydra-ssh")
        engine, *_ = _make_engine(cfg, log, findings=findings)
        plan = engine._plan_phases()
        assert "EXPLOIT" in plan
        assert "POST_EXPLOIT" in plan

    def test_recon_only_when_nothing_actionable(self, cfg, log):
        engine = self._engine_with_services(cfg, log)
        plan = engine._plan_phases()
        # No creds, no vulns → no exploitation phases.
        assert "EXPLOIT" not in plan
        assert "POST_EXPLOIT" not in plan


# ── exploitation ─────────────────────────────────────────────────────────────


def _suggestion(mode: ExecutionMode, **kw) -> ExploitSuggestion:
    defaults = dict(
        id="s1",
        title="Test Suggestion",
        category="smb",
        target_service="smb",
        execution_mode=mode,
        confidence=0.9,
        rationale="test",
        msf_module="exploit/windows/smb/ms17_010_eternalblue",
        rport=445,
        msf_payload="windows/meterpreter/reverse_tcp",
        cve="CVE-2017-0144",
    )
    defaults.update(kw)
    return ExploitSuggestion(**defaults)


class TestExploitation:
    def test_manual_check_returns_false(self, cfg, log):
        engine, *_ = _make_engine(cfg, log)
        sug = _suggestion(ExecutionMode.MANUAL_CHECK)
        ok, uid = engine._run_exploit(sug, TARGET)
        assert ok is False
        assert uid == ""

    def test_metasploit_success_records_session(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        dispatcher.dispatch.return_value = (
            "post_exploit",
            "Meterpreter session 1 opened\n[*] uid=NT AUTHORITY\\SYSTEM",
            5.0,
        )
        sug = _suggestion(ExecutionMode.METASPLOIT)
        ok, uid = engine._run_exploit(sug, TARGET)
        assert ok is True
        assert engine.findings.sessions  # a session was recorded
        assert engine.findings.host_info.get("compromised") is not False

    def test_metasploit_blocked_module_skipped(self, cfg, log):
        roe = RulesOfEngagement.from_dict({"blocked_modules": ["ms17_010_eternalblue"]})
        engine, ai, kali, dispatcher = _make_engine(cfg, log, roe=roe)
        sug = _suggestion(ExecutionMode.METASPLOIT)
        ok, _ = engine._run_exploit(sug, TARGET)
        assert ok is False
        dispatcher.dispatch.assert_not_called()

    def test_blocked_port_skips_exploit(self, cfg, log):
        roe = RulesOfEngagement.from_dict({"blocked_ports": [445]})
        engine, ai, kali, dispatcher = _make_engine(cfg, log, roe=roe)
        sug = _suggestion(ExecutionMode.METASPLOIT, rport=445)
        ok, _ = engine._run_exploit(sug, TARGET)
        assert ok is False

    def test_brute_force_dispatch(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        sug = _suggestion(ExecutionMode.BRUTE_FORCE, target_service="ssh", msf_module="")
        dispatcher.dispatch.return_value = ("ssh_brute", "login: admin pass: x", 3.0)
        ok, _ = engine._run_auxiliary(sug, TARGET)
        assert ok is True
        called_tool = dispatcher.dispatch.call_args[0][0]["tool"]
        assert called_tool == "ssh_brute"

    def test_ssh_access_without_creds_returns_false(self, cfg, log):
        engine, *_ = _make_engine(cfg, log)
        sug = _suggestion(ExecutionMode.SSH_ACCESS)
        ok, _ = engine._run_ssh_access(sug, TARGET)
        assert ok is False

    def test_ftp_access_without_creds_returns_false(self, cfg, log):
        engine, *_ = _make_engine(cfg, log)
        sug = _suggestion(ExecutionMode.FTP_ACCESS)
        ok, _ = engine._run_ftp_access(sug, TARGET)
        assert ok is False

    def test_cred_reuse_is_manual_placeholder(self, cfg, log):
        engine, *_ = _make_engine(cfg, log)
        sug = _suggestion(ExecutionMode.CREDENTIAL_REUSE)
        ok, _ = engine._run_cred_reuse(sug, TARGET)
        assert ok is False


# ── hash cracking ────────────────────────────────────────────────────────────


class TestHashCracking:
    def test_no_hashes_skips(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        engine._crack_hashes()
        dispatcher.dispatch.assert_not_called()

    def test_missing_rockyou_skips(self, cfg, log):
        findings = Findings()
        findings.add_hash("admin", "lmhash", "ntlmhash")
        engine, ai, kali, dispatcher = _make_engine(cfg, log, findings=findings)
        with patch("hydrasight.core.engine.Path.exists", return_value=False):
            engine._crack_hashes()
        dispatcher.dispatch.assert_not_called()

    def test_cracked_passwords_become_credentials(self, cfg, log):
        findings = Findings()
        findings.add_hash(
            "admin", "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        engine, ai, kali, dispatcher = _make_engine(cfg, log, findings=findings)

        john_output = "Using default input encoding\n---CRACKED---\nadmin:Password123:500:abc:::\n"
        dispatcher.dispatch.return_value = ("run_command", john_output, 4.0)
        with patch("hydrasight.core.engine.Path.exists", return_value=True):
            engine._crack_hashes()

        creds = [(c["username"], c["secret"]) for c in findings.credentials]
        assert any(u == "admin" and s == "Password123" for u, s in creds)
        # hash marked cracked
        assert findings.hashes[0]["cracked"] == "Password123"


# ── post-exploitation ────────────────────────────────────────────────────────


class TestPostExploit:
    def test_no_session_skips_post_exploit(self, cfg, log):
        engine, ai, kali, dispatcher = _make_engine(cfg, log)
        engine._post_exploit_phase(TARGET)
        dispatcher.dispatch.assert_not_called()

    def test_session_triggers_post_access_handler(self, cfg, log):
        findings = Findings()
        findings.add_session(id="1", uid="root", exploit="test", payload="ssh", target=TARGET)
        engine, ai, kali, dispatcher = _make_engine(cfg, log, findings=findings)
        engine._post_exploit_phase(TARGET)
        # The handler dispatches at least one command (or attempts access).
        assert dispatcher.dispatch.called or ai.ask.called
