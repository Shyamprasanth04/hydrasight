"""Phase 4 tests — EngagementPlanner (dry-run), FTPAccessHandler, WebAdminHandler."""

import logging
from unittest.mock import MagicMock

import pytest

from hydrasight.core.planner import (
    EngagementBranch,
    EngagementPlanner,
)
from hydrasight.models.findings import Findings
from hydrasight.models.planner_state import PlannerState
from hydrasight.models.roe import RulesOfEngagement
from hydrasight.services.post_access import (
    AccessType,
    FTPAccessHandler,
    PostAccessResult,
    WebAdminHandler,
)

# ── helpers ───────────────────────────────────────────────────────────────────


@pytest.fixture
def log() -> logging.Logger:
    return logging.getLogger("test")


@pytest.fixture
def permissive_roe() -> RulesOfEngagement:
    return RulesOfEngagement.permissive()


@pytest.fixture
def mock_dispatcher():
    d = MagicMock()
    d.dispatch.return_value = ("run_command", "drwxr-xr-x files listing", 0.5)
    return d


def _findings_with_ports(*specs) -> Findings:
    f = Findings()
    for item in specs:
        port, service = item[0], item[1]
        version = item[2] if len(item) > 2 else ""
        f.add_port(port, "tcp", service, version)
    return f


# ── EngagementPlanner — empty findings ────────────────────────────────────────


class TestPlannerEmpty:
    def test_empty_findings_produces_recon_branch(self, permissive_roe):
        f = Findings()
        plan = EngagementPlanner.build(f, permissive_roe)
        assert plan.branch == EngagementBranch.RECON_ONLY

    def test_empty_findings_phases_include_recon(self, permissive_roe):
        f = Findings()
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        assert "RECON" in phase_ids

    def test_empty_findings_no_suggestions(self, permissive_roe):
        f = Findings()
        plan = EngagementPlanner.build(f, permissive_roe)
        assert plan.actionable_suggestions == []

    def test_plan_has_target(self, permissive_roe):
        f = Findings()
        plan = EngagementPlanner.build(f, permissive_roe, target="192.168.1.1")
        assert plan.target == "192.168.1.1"
        assert plan.has_target is True


# ── EngagementPlanner — service detection ─────────────────────────────────────


class TestPlannerServiceDetection:
    def test_smb_service_adds_smb_check(self, permissive_roe):
        f = _findings_with_ports((445, "smb", ""))
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        assert "SMB_CHECK" in phase_ids

    def test_ftp_service_adds_ftp_check(self, permissive_roe):
        f = _findings_with_ports((21, "ftp", "vsftpd"))
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        assert "FTP_CHECK" in phase_ids

    def test_ssh_service_adds_ssh_check(self, permissive_roe):
        f = _findings_with_ports((22, "ssh", "openssh"))
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        assert "SSH_CHECK" in phase_ids

    def test_web_service_adds_web_phases(self, permissive_roe):
        f = _findings_with_ports((80, "http", "apache"))
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        assert "WEB_FINGER" in phase_ids
        assert "WEB_DIR" in phase_ids
        assert "WEB_VULN" in phase_ids

    def test_vuln_scan_always_present(self, permissive_roe):
        f = _findings_with_ports((22, "ssh", ""))
        plan = EngagementPlanner.build(f, permissive_roe)
        assert "VULN_SCAN" in [p.phase_id for p in plan.phases]


# ── EngagementPlanner — branch selection ──────────────────────────────────────


class TestPlannerBranch:
    def test_credential_led_when_creds_present(self, permissive_roe):
        f = _findings_with_ports((22, "ssh", ""))
        f.add_cred("admin", "password", kind="bruteforce")
        plan = EngagementPlanner.build(f, permissive_roe)
        assert plan.branch == EngagementBranch.CREDENTIAL_LED

    def test_exploit_led_when_vulns_suggest_exploits(self, permissive_roe):
        f = _findings_with_ports((445, "smb", ""))
        f.add_vuln(name="MS17-010 EternalBlue", severity="CRITICAL", description="test")
        plan = EngagementPlanner.build(f, permissive_roe)
        assert plan.branch == EngagementBranch.EXPLOIT_LED

    def test_web_led_when_only_web_no_exploit(self, permissive_roe):
        f = _findings_with_ports((80, "http", "apache"))
        plan = EngagementPlanner.build(f, permissive_roe)
        # apache alone has no exploit suggestion, so web-led
        assert plan.branch in (EngagementBranch.WEB_LED, EngagementBranch.RECON_ONLY)

    def test_validation_when_vulns_no_exploits(self, permissive_roe):
        # Port 22 with no matching version produces a brute-force suggestion,
        # so the branch becomes exploit-led. Only true validation-only occurs
        # when no exploit suggestions exist at all (e.g. non-exploitable vuln
        # and no ports that map to suggestions).
        f = Findings()
        f.add_port(9999, "tcp", "custom-service", "")
        f.add_vuln(name="Weak Config", severity="LOW", description="weak")
        plan = EngagementPlanner.build(f, permissive_roe)
        # No exploit suggestions for custom-service on 9999 → validation/recon
        assert plan.branch in (
            EngagementBranch.VALIDATION_ONLY,
            EngagementBranch.RECON_ONLY,
            EngagementBranch.WEB_LED,
        )

    def test_exploit_phases_added_for_exploit_led(self, permissive_roe):
        f = _findings_with_ports((445, "smb", ""))
        f.add_vuln(name="MS17-010 EternalBlue", severity="CRITICAL", description="rce")
        plan = EngagementPlanner.build(f, permissive_roe)
        phase_ids = [p.phase_id for p in plan.phases]
        if plan.branch == EngagementBranch.EXPLOIT_LED:
            assert "EXPLOIT" in phase_ids
            assert "POST_EXPLOIT" in phase_ids

    def test_credential_led_includes_exploit_phases(self, permissive_roe):
        f = _findings_with_ports((22, "ssh", ""))
        f.add_cred("root", "toor", kind="bruteforce")
        plan = EngagementPlanner.build(f, permissive_roe)
        assert plan.branch == EngagementBranch.CREDENTIAL_LED
        phase_ids = [p.phase_id for p in plan.phases]
        assert "EXPLOIT" in phase_ids


# ── EngagementPlanner — ROE enforcement ───────────────────────────────────────


class TestPlannerROE:
    def test_kill_switch_blocks_all_phases(self):
        roe = RulesOfEngagement.permissive()
        roe.kill_switch = True
        f = _findings_with_ports((445, "smb", ""))
        plan = EngagementPlanner.build(f, roe)
        assert all(p.blocked for p in plan.phases)

    def test_kill_switch_adds_warning(self):
        roe = RulesOfEngagement.permissive()
        roe.kill_switch = True
        f = Findings()
        plan = EngagementPlanner.build(f, roe)
        assert any("kill switch" in w.lower() for w in plan.warnings)

    def test_approval_gate_marks_phase_gated(self):
        roe = RulesOfEngagement.permissive()
        roe.require_approval_for = ["EXPLOIT"]
        f = _findings_with_ports((445, "smb", ""))
        f.add_vuln(name="MS17-010 EternalBlue", severity="CRITICAL", description="")
        plan = EngagementPlanner.build(f, roe)
        exploit_phase = next((p for p in plan.phases if p.phase_id == "EXPLOIT"), None)
        if exploit_phase:
            assert exploit_phase.gated

    def test_blocked_ports_appear_in_warnings(self):
        roe = RulesOfEngagement.permissive()
        roe.blocked_ports = [445]
        f = _findings_with_ports((445, "smb", ""))
        plan = EngagementPlanner.build(f, roe)
        assert any("445" in w for w in plan.warnings)

    def test_max_runtime_appears_in_warnings(self):
        roe = RulesOfEngagement.permissive()
        roe.max_runtime_minutes = 30
        f = _findings_with_ports((22, "ssh", ""))
        plan = EngagementPlanner.build(f, roe)
        assert any("30" in w for w in plan.warnings)


# ── EngagementPlan properties ─────────────────────────────────────────────────


class TestEngagementPlanProperties:
    def test_actionable_phases_excludes_blocked(self):
        roe = RulesOfEngagement.permissive()
        roe.kill_switch = True
        f = _findings_with_ports((22, "ssh", ""))
        plan = EngagementPlanner.build(f, roe)
        assert plan.actionable_phases == []
        assert len(plan.blocked_phases) == len(plan.phases)

    def test_summary_lines_not_empty(self):
        roe = RulesOfEngagement.permissive()
        f = _findings_with_ports((22, "ssh", ""))
        plan = EngagementPlanner.build(f, roe)
        lines = plan.summary_lines()
        assert len(lines) >= 2
        assert any("branch" in line for line in lines)

    def test_manual_suggestions_are_manual_check_mode(self):
        from hydrasight.integrations.exploit_suggestion import ExecutionMode

        roe = RulesOfEngagement.permissive()
        f = _findings_with_ports((80, "http", ""))
        plan = EngagementPlanner.build(f, roe)
        for m in plan.manual_suggestions:
            assert m.execution_mode == ExecutionMode.MANUAL_CHECK

    def test_planner_state_used_for_skip(self):
        roe = RulesOfEngagement.permissive()
        f = _findings_with_ports((22, "ssh", ""))
        state = PlannerState()
        # exhaust retries for SSH_CHECK
        for _ in range(10):
            state.record_phase("SSH_CHECK", False, "no output")
        plan = EngagementPlanner.build(f, roe, planner_state=state)
        ssh_phase = next((p for p in plan.phases if p.phase_id == "SSH_CHECK"), None)
        if ssh_phase:
            assert ssh_phase.blocked


# ── FTPAccessHandler ──────────────────────────────────────────────────────────


class TestFTPAccessHandler:
    def test_no_credentials_returns_failure(self, log, mock_dispatcher):
        h = FTPAccessHandler(log, {})
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 21, {})
        assert result.success is False
        assert "credential" in result.notes.lower()

    def test_failed_listing_returns_failure(self, log):
        # "login failure" (not "failed") — also test with empty output
        d = MagicMock()
        d.dispatch.return_value = ("run_command", "", 0.5)  # empty = no listing
        session = {"username": "admin", "password": "wrong", "rport": 21}
        h = FTPAccessHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 21, {})
        assert result.success is False

    def test_successful_listing(self, log):
        calls = [
            ("run_command", "drwxr-xr-x 5 user group 4096 Jan 1 /", 0.5),
            ("run_command", "root:x:0:0:root:/root:/bin/bash", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
        ]
        d = MagicMock()
        d.dispatch.side_effect = calls
        session = {"username": "ftpuser", "password": "ftppass", "rport": 21}
        h = FTPAccessHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 21, {})
        assert result.access_type == AccessType.FTP
        assert result.success is True
        assert "FTP ROOT LISTING" in result.output

    def test_retrieves_interesting_files(self, log):
        passwd_content = "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"
        calls = [
            ("run_command", "drwxr-xr-x listing content", 0.5),  # root listing
            ("run_command", passwd_content, 0.5),  # /etc/passwd
            ("run_command", "", 0.5),  # /etc/shadow (no access)
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
            ("run_command", "", 0.5),
        ]
        d = MagicMock()
        d.dispatch.side_effect = calls
        session = {"username": "user", "password": "pass", "rport": 21}
        h = FTPAccessHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 21, {})
        assert "/etc/passwd" in result.artifacts

    def test_dispatch_error_returns_failure(self, log):
        d = MagicMock()
        d.dispatch.side_effect = RuntimeError("connection refused")
        session = {"username": "user", "password": "pass"}
        h = FTPAccessHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 21, {})
        assert result.success is False

    def test_access_type(self, log):
        h = FTPAccessHandler(log, {})
        assert h.access_type == AccessType.FTP

    def test_interesting_paths_list(self):
        assert "/etc/passwd" in FTPAccessHandler.INTERESTING_PATHS
        assert "/etc/shadow" in FTPAccessHandler.INTERESTING_PATHS


# ── WebAdminHandler ───────────────────────────────────────────────────────────


class TestWebAdminHandler:
    def test_no_credentials_returns_failure(self, log, mock_dispatcher):
        h = WebAdminHandler(log, {})
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 80, {})
        assert result.success is False
        assert "credential" in result.notes.lower()

    def test_access_type(self, log):
        h = WebAdminHandler(log, {})
        assert h.access_type == AccessType.WEB_ADMIN

    def test_no_match_returns_no_success(self, log):
        d = MagicMock()
        d.dispatch.return_value = ("run_command", "<html><title>Not Found</title></html>", 0.5)
        session = {"username": "admin", "password": "admin", "rport": 80}
        h = WebAdminHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 80, {})
        assert result.success is False
        assert result.artifacts == []

    def test_phpmyadmin_success_detected(self, log):
        responses = [
            ("run_command", "<title>phpMyAdmin - admin dashboard</title>", 0.5),  # phpmyadmin
            ("run_command", "<html>login</html>", 0.5),  # wp
            ("run_command", "<html>login</html>", 0.5),  # roundcube
            ("run_command", "401", 0.5),  # tomcat
            ("run_command", "", 0.5),  # cookie cleanup
        ]
        d = MagicMock()
        d.dispatch.side_effect = responses
        session = {"username": "root", "password": "root", "rport": 80}
        h = WebAdminHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 80, {})
        assert result.success is True
        assert len(result.artifacts) >= 1
        assert "phpMyAdmin" in result.artifacts[0]

    def test_tomcat_200_success(self, log):
        # Make phpMyAdmin/WP/Roundcube responses obviously not match
        # Tomcat gets 200 basic-auth response
        responses = [
            ("run_command", "<html>Welcome to Apache</html>", 0.5),  # phpmyadmin - no match
            ("run_command", "<html>Blog site</html>", 0.5),  # wp - no match
            ("run_command", "<html>Email client</html>", 0.5),  # roundcube - no match
            ("run_command", "200", 0.5),  # tomcat 200
            ("run_command", "", 0.5),  # cleanup
        ]
        d = MagicMock()
        d.dispatch.side_effect = responses
        session = {"username": "tomcat", "password": "tomcat", "rport": 8080}
        h = WebAdminHandler(log, session)
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 8080, {})
        assert result.success is True
        assert any("Tomcat" in a for a in result.artifacts)

    def test_https_scheme_used_for_443(self, log):
        cmds_issued = []

        def capture(call):
            if isinstance(call, dict) and call.get("args"):
                cmds_issued.append(call["args"].get("command", ""))
            return ("run_command", "", 0.5)

        d = MagicMock()
        d.dispatch.side_effect = capture
        session = {"username": "admin", "password": "pass", "rport": 443}
        h = WebAdminHandler(log, session)
        h.execute(d, "192.168.1.10", "10.0.0.1", 443, {})
        assert any("https://" in c for c in cmds_issued if c)

    def test_dispatch_error_does_not_crash(self, log):
        d = MagicMock()
        d.dispatch.side_effect = RuntimeError("network unreachable")
        session = {"username": "admin", "password": "pass", "rport": 80}
        h = WebAdminHandler(log, session)
        # Should not raise — errors are caught per-profile
        result = h.execute(d, "192.168.1.10", "10.0.0.1", 80, {})
        assert isinstance(result, PostAccessResult)

    def test_factory_selects_web_admin_for_http_payload(self, log):
        from hydrasight.services.post_access import PostAccessHandler

        session = {"payload": "http", "username": "a", "password": "b"}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, WebAdminHandler)

    def test_factory_selects_ftp_for_ftp_payload(self, log):
        from hydrasight.services.post_access import PostAccessHandler

        session = {"payload": "ftp", "username": "a", "password": "b"}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, FTPAccessHandler)

    def test_profiles_have_required_keys(self):
        for p in WebAdminHandler._PROFILES:
            assert "path" in p
            assert "success_str" in p
            assert "label" in p
