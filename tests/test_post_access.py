"""Tests for PostAccessHandler abstraction."""

import logging
from unittest.mock import MagicMock

import pytest

from hydrasight.services.post_access import (
    AccessType,
    BasePostAccessHandler,
    MeterpreterHandler,
    PostAccessHandler,
    PostAccessResult,
    ShellHandler,
    SSHAccessHandler,
)


@pytest.fixture
def log() -> logging.Logger:
    return logging.getLogger("test")


@pytest.fixture
def mock_dispatcher():
    d = MagicMock()
    d.dispatch.return_value = ("run_command", "uid=0(root)", 1.5)
    return d


# ── PostAccessResult ──────────────────────────────────────────────────────────


class TestPostAccessResult:
    def test_failure_factory(self):
        r = PostAccessResult.failure(AccessType.METERPRETER, "test reason")
        assert r.success is False
        assert r.output == ""
        assert r.hashes == []
        assert r.credentials == []
        assert r.artifacts == []
        assert "test reason" in r.notes

    def test_success_fields(self):
        r = PostAccessResult(
            access_type=AccessType.SHELL,
            success=True,
            output="uid=0(root)",
            hashes=[],
            credentials=[],
            artifacts=["/tmp/shadow"],
        )
        assert r.success is True
        assert r.access_type == AccessType.SHELL
        assert "/tmp/shadow" in r.artifacts


# ── AccessType ────────────────────────────────────────────────────────────────


class TestAccessType:
    def test_all_types_are_strings(self):
        for t in AccessType:
            assert isinstance(t.value, str)

    def test_known_values(self):
        assert AccessType.METERPRETER.value == "meterpreter"
        assert AccessType.SSH.value == "ssh"
        assert AccessType.SHELL.value == "shell"


# ── Handler factory ───────────────────────────────────────────────────────────


class TestPostAccessHandlerFactory:
    def test_meterpreter_payload_selects_meterpreter(self, log):
        session = {"payload": "windows/x64/meterpreter/reverse_tcp"}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, MeterpreterHandler)
        assert h.access_type == AccessType.METERPRETER

    def test_cmd_unix_payload_selects_shell(self, log):
        session = {"payload": "cmd/unix/reverse"}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, ShellHandler)
        assert h.access_type == AccessType.SHELL

    def test_shell_payload_keyword(self, log):
        session = {"payload": "generic/shell_reverse_tcp"}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, ShellHandler)

    def test_username_in_session_selects_ssh(self, log):
        session = {"username": "admin", "password": "secret", "payload": ""}
        h = PostAccessHandler.for_session(session, log)
        assert isinstance(h, SSHAccessHandler)

    def test_empty_session_defaults_to_meterpreter(self, log):
        h = PostAccessHandler.for_session({}, log)
        assert isinstance(h, MeterpreterHandler)

    def test_explicit_access_type_overrides(self, log):
        session = {"payload": "meterpreter_payload"}
        h = PostAccessHandler.for_session(session, log, access_type=AccessType.SHELL)
        assert isinstance(h, ShellHandler)


# ── MeterpreterHandler ────────────────────────────────────────────────────────


class TestMeterpreterHandler:
    def test_execute_returns_result(self, log, mock_dispatcher):
        session = {
            "payload": "windows/x64/meterpreter/reverse_tcp",
            "module": "exploit/windows/smb/ms17_010_eternalblue",
            "rport": 445,
        }
        h = MeterpreterHandler(log, session)
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 4445, {})
        assert isinstance(result, PostAccessResult)
        assert result.access_type == AccessType.METERPRETER

    def test_execute_dispatch_called(self, log, mock_dispatcher):
        session = {"payload": "windows/x64/meterpreter/reverse_tcp"}
        h = MeterpreterHandler(log, session)
        h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 4445, {})
        assert mock_dispatcher.dispatch.called

    def test_failure_on_dispatch_error(self, log):
        session = {}
        bad_dispatcher = MagicMock()
        bad_dispatcher.dispatch.side_effect = RuntimeError("connection refused")
        h = MeterpreterHandler(log, session)
        result = h.execute(bad_dispatcher, "192.168.1.10", "10.0.0.1", 4445, {})
        assert result.success is False
        assert "connection refused" in result.notes

    def test_default_commands_windows(self, log):
        h = MeterpreterHandler(log, {})
        cmds = h._default_commands(is_windows=True)
        assert "hashdump" in cmds

    def test_default_commands_linux(self, log):
        h = MeterpreterHandler(log, {})
        cmds = h._default_commands(is_windows=False)
        assert "/etc/shadow" in cmds


# ── ShellHandler ──────────────────────────────────────────────────────────────


class TestShellHandler:
    def test_execute_returns_result(self, log, mock_dispatcher):
        h = ShellHandler(log, {"payload": "cmd/unix/reverse"})
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 4446, {})
        assert isinstance(result, PostAccessResult)
        assert result.access_type == AccessType.SHELL

    def test_dispatch_called(self, log, mock_dispatcher):
        h = ShellHandler(log, {})
        h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 4446, {})
        assert mock_dispatcher.dispatch.called

    def test_failure_on_error(self, log):
        bad = MagicMock()
        bad.dispatch.side_effect = OSError("timeout")
        h = ShellHandler(log, {})
        result = h.execute(bad, "192.168.1.10", "10.0.0.1", 4446, {})
        assert result.success is False


# ── SSHAccessHandler ──────────────────────────────────────────────────────────


class TestSSHAccessHandler:
    def test_no_credentials_returns_failure(self, log, mock_dispatcher):
        h = SSHAccessHandler(log, {})
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 22, {})
        assert result.success is False
        assert "credential" in result.notes.lower()

    def test_with_credentials_dispatches(self, log, mock_dispatcher):
        session = {"username": "admin", "password": "secret"}
        h = SSHAccessHandler(log, session)
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 22, {})
        assert mock_dispatcher.dispatch.called
        assert result.access_type == AccessType.SSH

    def test_success_on_output(self, log, mock_dispatcher):
        mock_dispatcher.dispatch.return_value = ("run_command", "uid=0(root) groups=0(root)", 0.5)
        session = {"username": "root", "password": "toor"}
        h = SSHAccessHandler(log, session)
        result = h.execute(mock_dispatcher, "192.168.1.10", "10.0.0.1", 22, {})
        assert result.success is True


# ── Registry ──────────────────────────────────────────────────────────────────


class TestRegistry:
    def test_register_custom_handler(self, log):
        class FTPHandler(BasePostAccessHandler):
            access_type = AccessType.FTP

            def execute(self, dispatcher, target, lhost, lport, cfg):
                return PostAccessResult.failure(self.access_type, "stub")

        PostAccessHandler.register(AccessType.FTP, FTPHandler)
        h = PostAccessHandler.for_session({}, log, access_type=AccessType.FTP)
        assert isinstance(h, FTPHandler)

    def test_default_registry_has_core_types(self):
        assert AccessType.METERPRETER in PostAccessHandler._REGISTRY
        assert AccessType.SHELL in PostAccessHandler._REGISTRY
        assert AccessType.SSH in PostAccessHandler._REGISTRY
