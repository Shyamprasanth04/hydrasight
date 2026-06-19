"""Tests for PlannerState and PhaseResult."""
import time
import pytest
from hydrasight.models.planner_state import PlannerState, PhaseResult


@pytest.fixture
def state() -> PlannerState:
    return PlannerState(max_retries=2)


class TestPhaseRecording:
    def test_record_phase_success(self, state):
        state.record_phase("RECON", True, "ports found")
        assert state.phase_attempted("RECON") is True
        assert state.phase_succeeded("RECON") is True

    def test_record_phase_failure(self, state):
        state.record_phase("SMB_CHECK", False, "no smb service")
        assert state.phase_attempted("SMB_CHECK") is True
        assert state.phase_succeeded("SMB_CHECK") is False

    def test_retry_count_increments(self, state):
        state.record_phase("EXPLOIT", False, "no session")
        assert state.retry_counts["EXPLOIT"] == 1
        state.record_phase("EXPLOIT", False, "no session")
        assert state.retry_counts["EXPLOIT"] == 2

    def test_unattempted_phase_not_succeeded(self, state):
        assert state.phase_succeeded("NEVER_RUN") is False

    def test_all_succeeded_phases(self, state):
        state.record_phase("RECON", True)
        state.record_phase("FTP_CHECK", False)
        state.record_phase("SMB_CHECK", True)
        succeeded = state.all_succeeded_phases()
        assert "RECON" in succeeded
        assert "SMB_CHECK" in succeeded
        assert "FTP_CHECK" not in succeeded

    def test_all_failed_phases(self, state):
        state.record_phase("EXPLOIT", False)
        failed = state.all_failed_phases()
        assert "EXPLOIT" in failed


class TestSkipLogic:
    def test_no_skip_for_unattempted(self, state):
        skip, _ = state.should_skip_phase("RECON")
        assert skip is False

    def test_no_skip_after_success(self, state):
        state.record_phase("RECON", True)
        skip, _ = state.should_skip_phase("RECON")
        assert skip is False

    def test_no_skip_after_first_failure(self, state):
        state.record_phase("SMB_CHECK", False, "reason")
        skip, _ = state.should_skip_phase("SMB_CHECK")
        assert skip is False  # max_retries=2, only 1 attempt

    def test_skip_after_max_retries(self, state):
        state.record_phase("EXPLOIT", False, "no session")
        state.record_phase("EXPLOIT", False, "no session")
        skip, reason = state.should_skip_phase("EXPLOIT")
        assert skip is True
        assert "2" in reason  # mentions retry count

    def test_skip_blocked_phase(self, state):
        state.block_phase("POST_EXPLOIT")
        skip, reason = state.should_skip_phase("POST_EXPLOIT")
        assert skip is True
        assert "blocked" in reason.lower()

    def test_block_then_record_still_skipped(self, state):
        state.block_phase("HASH_CRACK")
        state.record_phase("HASH_CRACK", True)
        skip, _ = state.should_skip_phase("HASH_CRACK")
        assert skip is True


class TestToolTracking:
    def test_working_tool(self, state):
        state.record_tool_outcome("nmap_scan", True, bytes_out=5000)
        assert "nmap_scan" in state.working_tools

    def test_empty_tool(self, state):
        state.record_tool_outcome("nikto_scan", False, bytes_out=0)
        assert "nikto_scan" in state.empty_tools

    def test_is_tool_known_empty(self, state):
        state.record_tool_outcome("gobuster_scan", False, bytes_out=10)
        assert state.is_tool_known_empty("gobuster_scan") is True

    def test_working_tool_removed_from_empty(self, state):
        state.record_tool_outcome("nmap_scan", False, bytes_out=0)
        assert "nmap_scan" in state.empty_tools
        state.record_tool_outcome("nmap_scan", True, bytes_out=2000)
        assert "nmap_scan" not in state.empty_tools


class TestCredentialTracking:
    def test_record_and_check_credential(self, state):
        state.record_credential_attempt("admin", "password123")
        assert state.credential_already_tried("admin", "password123") is True

    def test_case_insensitive_username(self, state):
        state.record_credential_attempt("Admin", "pass")
        assert state.credential_already_tried("admin", "pass") is True

    def test_untried_credential(self, state):
        assert state.credential_already_tried("root", "toor") is False

    def test_different_password_not_tried(self, state):
        state.record_credential_attempt("admin", "password1")
        assert state.credential_already_tried("admin", "password2") is False


class TestPortTracking:
    def test_mark_and_check_explored(self, state):
        state.mark_port_explored(445)
        assert state.is_port_explored(445) is True

    def test_unexplored_port(self, state):
        assert state.is_port_explored(80) is False

    def test_multiple_ports(self, state):
        for p in (21, 22, 80, 443):
            state.mark_port_explored(p)
        assert all(state.is_port_explored(p) for p in (21, 22, 80, 443))


class TestSummary:
    def test_summary_keys(self, state):
        summary = state.summary()
        assert "elapsed_minutes"   in summary
        assert "phases_attempted"  in summary
        assert "phases_succeeded"  in summary
        assert "phases_failed"     in summary
        assert "working_tools"     in summary
        assert "empty_tools"       in summary

    def test_summary_counts(self, state):
        state.record_phase("RECON", True)
        state.record_phase("EXPLOIT", False)
        summary = state.summary()
        assert summary["phases_attempted"] == 2
        assert summary["phases_succeeded"] == 1
        assert summary["phases_failed"]    == 1

    def test_elapsed_minutes_positive(self, state):
        assert state.elapsed_minutes() >= 0.0


class TestPhaseResultDataclass:
    def test_phase_result_fields(self):
        r = PhaseResult(
            phase_id     = "RECON",
            success      = True,
            reason       = "found 5 ports",
            tools_used   = ["nmap_scan"],
            bytes_returned = 4096,
        )
        assert r.phase_id      == "RECON"
        assert r.success       is True
        assert r.tools_used    == ["nmap_scan"]
        assert r.bytes_returned == 4096

    def test_phase_result_timestamp_set(self):
        r = PhaseResult("X", True)
        assert r.timestamp > 0
