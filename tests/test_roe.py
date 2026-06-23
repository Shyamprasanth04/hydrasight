"""Tests for RulesOfEngagement."""

import pytest

from hydrasight.models.roe import RulesOfEngagement


@pytest.fixture
def default_roe() -> RulesOfEngagement:
    return RulesOfEngagement.permissive()


@pytest.fixture
def strict_roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        allowed_targets=["192.168.1.10", "10.0.0.0/24"],
        blocked_ports=[23, 25, 110],
        blocked_modules=["exploit/windows/smb/ms17_010"],
        require_approval_for=["EXPLOIT", "POST_EXPLOIT"],
        max_runtime_minutes=30,
        max_threads=2,
        kill_switch=False,
    )


class TestTargetValidation:
    def test_wildcard_allows_any_ip(self, default_roe):
        ok, reason = default_roe.is_target_allowed("192.168.99.1")
        assert ok
        assert "wildcard" in reason

    def test_exact_ip_match(self, strict_roe):
        ok, _ = strict_roe.is_target_allowed("192.168.1.10")
        assert ok

    def test_exact_ip_denied(self, strict_roe):
        ok, _ = strict_roe.is_target_allowed("192.168.1.99")
        assert not ok

    def test_cidr_allows_in_range(self, strict_roe):
        ok, _ = strict_roe.is_target_allowed("10.0.0.50")
        assert ok

    def test_cidr_denies_out_of_range(self, strict_roe):
        ok, _ = strict_roe.is_target_allowed("10.0.1.1")
        assert not ok

    def test_invalid_ip_denied(self, strict_roe):
        ok, reason = strict_roe.is_target_allowed("not-an-ip")
        assert not ok
        assert "valid" in reason.lower()

    def test_kill_switch_blocks_any_target(self):
        roe = RulesOfEngagement(kill_switch=True)
        ok, reason = roe.is_target_allowed("192.168.1.1")
        assert not ok
        assert "kill" in reason.lower()


class TestPortBlocking:
    def test_blocked_port(self, strict_roe):
        assert strict_roe.is_port_blocked(23) is True
        assert strict_roe.is_port_blocked(25) is True

    def test_allowed_port(self, strict_roe):
        assert strict_roe.is_port_blocked(80) is False
        assert strict_roe.is_port_blocked(443) is False

    def test_unblocked_default(self, default_roe):
        assert default_roe.is_port_blocked(445) is False


class TestModuleBlocking:
    def test_blocked_module_substring(self, strict_roe):
        assert strict_roe.is_module_blocked("exploit/windows/smb/ms17_010_eternalblue") is True

    def test_allowed_module(self, strict_roe):
        assert strict_roe.is_module_blocked("auxiliary/scanner/ssh") is False

    def test_no_blocked_modules(self, default_roe):
        assert default_roe.is_module_blocked("anything") is False


class TestApprovalGates:
    def test_requires_approval_for_exploit(self, strict_roe):
        assert strict_roe.requires_approval("EXPLOIT") is True

    def test_no_approval_for_recon(self, strict_roe):
        assert strict_roe.requires_approval("RECON") is False

    def test_permissive_requires_no_approval(self, default_roe):
        assert default_roe.requires_approval("EXPLOIT") is False

    def test_kill_switch_forces_approval(self):
        roe = RulesOfEngagement(kill_switch=True)
        assert roe.requires_approval("RECON") is True


class TestRuntimeLimits:
    def test_no_start_time_never_exceeded(self, strict_roe):
        assert strict_roe.is_runtime_exceeded() is False

    def test_runtime_remaining_before_start(self, strict_roe):
        remaining = strict_roe.runtime_remaining_minutes()
        assert remaining == float(strict_roe.max_runtime_minutes)

    def test_start_timer_sets_time(self, strict_roe):
        strict_roe.start_timer()
        assert strict_roe._start_time is not None

    def test_not_exceeded_right_after_start(self, strict_roe):
        strict_roe.start_timer()
        assert strict_roe.is_runtime_exceeded() is False

    def test_runtime_remaining_decreases(self, strict_roe):
        import time as _time

        strict_roe.start_timer()
        _time.sleep(0.05)  # ensure at least some time elapses
        remaining = strict_roe.runtime_remaining_minutes()
        assert remaining < float(strict_roe.max_runtime_minutes)
        assert remaining > 0.0


class TestSerialisation:
    def test_to_dict_keys(self, strict_roe):
        d = strict_roe.to_dict()
        assert "allowed_targets" in d
        assert "blocked_ports" in d
        assert "require_approval_for" in d
        assert "kill_switch" in d

    def test_from_dict_roundtrip(self, strict_roe):
        d = strict_roe.to_dict()
        roe = RulesOfEngagement.from_dict(d)
        assert roe.allowed_targets == strict_roe.allowed_targets
        assert roe.blocked_ports == strict_roe.blocked_ports
        assert roe.blocked_modules == strict_roe.blocked_modules
        assert roe.require_approval_for == strict_roe.require_approval_for
        assert roe.max_runtime_minutes == strict_roe.max_runtime_minutes
        assert roe.kill_switch == strict_roe.kill_switch

    def test_from_dict_partial(self):
        roe = RulesOfEngagement.from_dict({"max_runtime_minutes": 60})
        assert roe.max_runtime_minutes == 60
        assert roe.kill_switch is False

    def test_from_dict_empty(self):
        roe = RulesOfEngagement.from_dict({})
        assert roe.allowed_targets == ["*"]

    def test_permissive_factory(self):
        roe = RulesOfEngagement.permissive()
        assert "*" in roe.allowed_targets
        assert roe.kill_switch is False
        assert roe.require_approval_for == []


class TestSummary:
    def test_summary_includes_scope(self, default_roe):
        s = default_roe.summary()
        assert "any" in s.lower() or "*" in s

    def test_summary_includes_runtime(self, strict_roe):
        s = strict_roe.summary()
        assert "30m" in s

    def test_summary_mentions_kill_switch(self):
        roe = RulesOfEngagement(kill_switch=True)
        s = roe.summary()
        assert "KILL" in s or "kill" in s.lower()
