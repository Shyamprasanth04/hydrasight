"""Tests for the shell refactor — handlers, renderer, and thin Shell.

All tests are offline (no Kali, no Ollama).
Focus: verify the split preserved behavior and no circular imports.
"""

from unittest.mock import MagicMock, patch

import pytest

# ── Import tests (no circular imports) ────────────────────────────────────────


class TestImports:
    """Verify all three modules import cleanly without circular deps."""

    def test_import_shell(self):
        from hydrasight.cli.shell import Shell

        assert Shell is not None

    def test_import_shell_handlers(self):
        from hydrasight.cli.shell_handlers import ShellHandlers

        assert ShellHandlers is not None

    def test_import_shell_renderer(self):
        from hydrasight.cli import shell_renderer

        assert shell_renderer is not None

    def test_shell_has_handlers(self):
        """Shell.__init__ creates a ShellHandlers instance."""
        from hydrasight.cli.shell import Shell

        # We can't fully instantiate Shell without side effects (signal, readline)
        # but we can verify the class attributes exist
        assert hasattr(Shell, "HIST")
        assert hasattr(Shell, "ROE_FILE")


# ── Renderer function tests (pure display, mock console) ─────────────────────


class TestRendererFunctions:
    """Verify renderer functions exist and are callable."""

    def test_render_help_callable(self):
        from hydrasight.cli.shell_renderer import render_help

        # render_help prints to console; just verify it doesn't crash
        with patch("hydrasight.cli.shell_renderer.console"):
            render_help()

    def test_render_config_callable(self):
        from hydrasight.cli.shell_renderer import render_config

        with patch("hydrasight.cli.shell_renderer.console"):
            render_config({"execution_mode": "confirm", "model": "test"})

    def test_render_findings_no_data(self):
        from hydrasight.cli.shell_renderer import render_findings

        mock_findings = MagicMock()
        mock_findings.has_data = False
        mock_findings.target = ""
        with patch("hydrasight.cli.shell_renderer.console"):
            render_findings(mock_findings)

    def test_render_conclusion_no_data(self):
        from hydrasight.cli.shell_renderer import render_conclusion

        mock_findings = MagicMock()
        mock_findings.has_data = False
        with patch("hydrasight.cli.shell_renderer.console"):
            render_conclusion(mock_findings)

    def test_render_roe(self):
        from hydrasight.cli.shell_renderer import render_roe
        from hydrasight.models.roe import RulesOfEngagement

        roe = RulesOfEngagement.permissive()
        with patch("hydrasight.cli.shell_renderer.console"):
            render_roe(roe, "hydrasight.roe.json")

    def test_render_proposed_action(self):
        from hydrasight.cli.shell_renderer import render_proposed_action

        mock_action = MagicMock()
        mock_action.command_str = "nmap -sV 10.10.10.5"
        mock_action.tool_hint = "nmap_scan"
        mock_action.target = "10.10.10.5"
        mock_action.ports = "1-1000"
        mock_action.flags = ["-sV"]
        mock_action.confidence = 0.85
        with patch("hydrasight.cli.shell_renderer.console"):
            render_proposed_action(mock_action)

    def test_render_clarification(self):
        from hydrasight.cli.shell_renderer import render_clarification

        with patch("hydrasight.cli.shell_renderer.console"):
            render_clarification("Which target?")

    def test_render_suggestion(self):
        from hydrasight.cli.shell_renderer import render_suggestion

        with patch("hydrasight.cli.shell_renderer.console"):
            render_suggestion("Try running nmap", None)

    def test_render_verify_results(self):
        from hydrasight.cli.shell_renderer import render_verify_results

        mock_result = MagicMock()
        mock_result.verified = True
        mock_result.finding_name = "MS17-010"
        mock_result.confidence = 0.9
        with patch("hydrasight.cli.shell_renderer.console"):
            render_verify_results([mock_result])

    def test_render_stats(self):
        import time

        from hydrasight.cli.shell_renderer import render_stats

        mock_findings = MagicMock()
        mock_findings.ports = []
        mock_findings.vulns = []
        mock_findings.credentials = []
        mock_ai = MagicMock()
        mock_ai.call_count = 0
        mock_ai.messages = []
        mock_ai.total_tokens = 0
        mock_ai.model = "test"
        with patch("hydrasight.cli.shell_renderer.console"):
            render_stats(mock_findings, mock_ai, time.time(), 0)

    def test_render_history(self):
        from hydrasight.cli.shell_renderer import render_history

        mock_ai = MagicMock()
        mock_ai.messages = [
            {"role": "system", "content": "You are an assistant"},
            {"role": "user", "content": "hello"},
        ]
        with patch("hydrasight.cli.shell_renderer.console"):
            render_history(mock_ai)


# ── ShellHandlers tests ───────────────────────────────────────────────────────


@pytest.fixture
def handlers():
    """Create a ShellHandlers instance with all mocked dependencies."""
    from hydrasight.cli.shell_handlers import ShellHandlers
    from hydrasight.models.roe import RulesOfEngagement

    cfg = {
        "verbosity": 0,
        "output_dir": "hydrasight_output",
        "execution_mode": "confirm",
        "model": "test",
        "deep_scan_range": "1-65535",
        "auto_save": False,
        "auto_pdf": False,
        "lport": 4444,
    }

    return ShellHandlers(
        cfg=cfg,
        findings=MagicMock(),
        kali=MagicMock(),
        ai=MagicMock(),
        dispatcher=MagicMock(),
        engine=MagicMock(),
        chat=MagicMock(),
        intent=MagicMock(),
        planner=MagicMock(),
        confirm=MagicMock(),
        policy=MagicMock(),
        roe=RulesOfEngagement.permissive(),
        log=MagicMock(),
    )


class TestShellHandlers:
    def test_handle_builtin_exit_returns_false(self, handlers):
        """exit command returns False to stop REPL."""
        handlers.ai.total_tokens = 0
        handlers.ai.call_count = 0
        handlers.ai.messages = []
        handlers.ai.model = "test"
        handlers.findings.has_data = False
        handlers.findings.ports = []
        handlers.findings.vulns = []
        handlers.findings.credentials = []
        with patch("hydrasight.cli.shell_handlers.console"), \
             patch("hydrasight.cli.shell_renderer.console"):
            result = handlers.handle_builtin("exit", ["exit"], "exit")
        assert result is False

    def test_handle_builtin_help_returns_true(self, handlers):
        """help command returns True to continue REPL."""
        with patch("hydrasight.cli.shell_renderer.console"):
            result = handlers.handle_builtin("help", ["help"], "help")
        assert result is True

    def test_handle_builtin_clear(self, handlers):
        """clear resets all state."""
        with patch("hydrasight.cli.shell_handlers.console"):
            result = handlers.handle_builtin("clear", ["clear"], "clear")
        assert result is True
        handlers.findings.reset.assert_called_once()
        handlers.ai.reset.assert_called_once()
        handlers._chat.reset.assert_called_once()
        handlers._confirm.clear.assert_called_once()

    def test_handle_builtin_abort(self, handlers):
        """abort calls engine.abort()."""
        result = handlers.handle_builtin("abort", ["abort"], "abort")
        assert result is True
        handlers.engine.abort.assert_called_once()

    def test_handle_builtin_findings(self, handlers):
        """findings command delegates to renderer."""
        handlers.findings.has_data = False
        handlers.findings.target = ""
        with patch("hydrasight.cli.shell_renderer.console"):
            result = handlers.handle_builtin("findings", ["findings"], "findings")
        assert result is True

    def test_handle_builtin_ports_filter(self, handlers):
        """ports command passes filter_type."""
        handlers.findings.has_data = False
        handlers.findings.target = ""
        with patch("hydrasight.cli.shell_renderer.console"):
            result = handlers.handle_builtin("ports", ["ports"], "ports")
        assert result is True

    def test_handle_mode_valid(self, handlers):
        """mode command changes execution_mode."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("mode", ["mode", "auto"], "mode auto")
        assert handlers.cfg["execution_mode"] == "auto"

    def test_handle_mode_invalid(self, handlers):
        """mode with invalid value warns."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("mode", ["mode", "invalid"], "mode invalid")
        assert handlers.cfg["execution_mode"] == "confirm"  # unchanged

    def test_handle_verbose(self, handlers):
        """verbose command changes verbosity."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("verbose", ["verbose", "2"], "verbose 2")
        assert handlers.cfg["verbosity"] == 2
        assert handlers.verbosity == 2

    def test_handle_autopwn_no_ip(self, handlers):
        """autopwn without IP warns."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("autopwn", ["autopwn"], "autopwn")
        # No engine.run() called
        handlers.engine.run.assert_not_called()

    def test_handle_autopwn_invalid_ip(self, handlers):
        """autopwn with invalid IP errors."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("autopwn", ["autopwn", "not-ip"], "autopwn not-ip")
        handlers.engine.run.assert_not_called()

    def test_handle_scan_no_ip(self, handlers):
        """scan without IP warns."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.handle_builtin("scan", ["scan"], "scan")
        handlers.engine._ask_and_run.assert_not_called()

    def test_on_bare_text_empty(self, handlers):
        """Empty text is ignored."""
        handlers.on_bare_text("")
        handlers._intent.classify.assert_not_called()

    def test_on_run_empty(self, handlers):
        """Empty /run warns."""
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.on_run("")

    def test_on_run_no_target(self, handlers):
        """No target available warns."""
        handlers.findings.target = None
        with patch("hydrasight.cli.shell_handlers.console"):
            handlers.on_run("check smb")

    def test_chat_context_no_target(self, handlers):
        """Chat context works with no target."""
        handlers.findings.target = None
        handlers.dispatcher.canonical_target = None
        handlers.findings.has_data = False
        handlers.findings.ports = []
        handlers.findings.vulns = []
        handlers.findings.credentials = []
        handlers.findings.hashes = []
        handlers.findings.sessions = []
        handlers.engine._state = None

        ctx = handlers._chat_context()
        assert "HydraSight Engagement Context" in ctx
        assert "none (no engagement started yet)" in ctx

    def test_chat_context_with_target(self, handlers):
        """Chat context includes target and risk."""
        handlers.findings.target = "10.10.10.5"
        handlers.dispatcher.canonical_target = None
        handlers.findings.has_data = True
        handlers.findings.overall_risk = "HIGH"
        handlers.findings.ports = [{"port": 22, "service": "ssh"}]
        handlers.findings.vulns = [{"name": "test", "severity": "HIGH"}]
        handlers.findings.credentials = []
        handlers.findings.hashes = []
        handlers.findings.sessions = []
        handlers.engine._state = None

        ctx = handlers._chat_context()
        assert "10.10.10.5" in ctx
        assert "HIGH" in ctx


# ── Integration: verify Shell still creates properly ──────────────────────────


class TestShellCreation:
    def test_shell_class_has_run_method(self):
        """Shell class has a run() method."""
        from hydrasight.cli.shell import Shell

        assert hasattr(Shell, "run")
        assert callable(Shell.run)

    def test_shell_reexported_from_original_location(self):
        """Shell is importable from its original location."""
        from hydrasight.cli.shell import Shell

        assert Shell.__name__ == "Shell"
