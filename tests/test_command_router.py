"""
Tests for the safety-critical mode separation refactor.

Tests prove that:
  - No conversational input ever triggers tool execution
  - plan is a built-in dry-run command and never calls tools
  - /ask always stays in chat mode
  - /run is the only path that may route to tools
  - stale canonical_target cannot infect chat messages
  - JSON-looking conversational AI output is never parsed as a tool call
  - CommandRouter classifies all inputs correctly
"""

import logging
from unittest.mock import MagicMock, patch

import pytest

from hydrasight.config.defaults import CHAT_SYSTEM_PROMPT
from hydrasight.services.command_router import (
    BUILTIN_COMMANDS,
    CommandRouter,
    InputClass,
)
from hydrasight.services.intent_router import is_conversational, route_intent

# ── CommandRouter tests ───────────────────────────────────────────────────────


class TestCommandRouter:
    """Pure classification — no AI, no side effects."""

    @pytest.fixture
    def router(self):
        return CommandRouter()

    # chat inputs
    @pytest.mark.parametrize(
        "text",
        [
            "hey",
            "hello",
            "what can you do",
            "explain smb signing",
            "why no ports found",
            "how should I approach this target",
            "summarize findings",
            "what happened",
            "yo",
            "tell me about ms17-010",
            "why did the last scan fail",
            "is port 445 dangerous",
            "what is meterpreter",
            "what does CVE-2017-0144 mean",
            "",  # empty → chat
            "   ",  # whitespace → chat
            "/unknowncommand foo",
        ],
    )
    def test_bare_text_classified_as_chat(self, router, text):
        ci = router.classify(text)
        assert ci.cls == InputClass.CHAT, f"'{text}' should be CHAT but got {ci.cls}"
        assert ci.is_safe is True

    # /ask inputs
    @pytest.mark.parametrize(
        "text,tail",
        [
            ("/ask explain smb signing", "explain smb signing"),
            ("/Ask what is ms17-010", "what is ms17-010"),
            ("/ASK", ""),
            ("/ask", ""),
        ],
    )
    def test_ask_prefix_classified_as_ask(self, router, text, tail):
        ci = router.classify(text)
        assert ci.cls == InputClass.ASK
        assert ci.tail == tail
        assert ci.is_safe is True

    # /run inputs
    @pytest.mark.parametrize(
        "text,tail",
        [
            ("/run check smb on 192.168.1.10", "check smb on 192.168.1.10"),
            ("/Run vuln scan on 10.0.2.5", "vuln scan on 10.0.2.5"),
            ("/run", ""),
        ],
    )
    def test_run_prefix_classified_as_run(self, router, text, tail):
        ci = router.classify(text)
        assert ci.cls == InputClass.RUN
        assert ci.tail == tail
        assert ci.is_safe is False

    # builtin commands
    @pytest.mark.parametrize(
        "text,cmd",
        [
            ("autopwn 192.168.1.10", "autopwn"),
            ("scan 192.168.1.10", "scan"),
            ("plan", "plan"),
            ("help", "help"),
            ("findings", "findings"),
            ("status", "status"),
            ("clear", "clear"),
            ("exit", "exit"),
            ("quit", "quit"),
            ("verbose 2", "verbose"),
            ("report 10.0.2.5", "report"),
            ("suggest", "suggest"),
            ("conclusion", "conclusion"),
            ("roe", "roe"),
            ("verify", "verify"),
            ("ports", "ports"),
            ("vulns", "vulns"),
            ("creds", "creds"),
            ("hashes", "hashes"),
            ("sessions", "sessions"),
        ],
    )
    def test_builtin_commands_classified_correctly(self, router, text, cmd):
        ci = router.classify(text)
        assert ci.cls == InputClass.BUILTIN, f"'{text}' should be BUILTIN but got {ci.cls}"
        assert ci.command == cmd

    def test_plan_is_builtin_not_chat(self, router):
        """'plan' must never fall through to chat or tool dispatch."""
        ci = router.classify("plan")
        assert ci.cls == InputClass.BUILTIN
        assert ci.command == "plan"

    def test_scan_with_ip_is_builtin(self, router):
        ci = router.classify("scan 192.168.1.10")
        assert ci.cls == InputClass.BUILTIN
        assert ci.command == "scan"
        assert ci.tail == "192.168.1.10"

    def test_autopwn_with_ip_is_builtin(self, router):
        ci = router.classify("autopwn 10.0.2.5")
        assert ci.cls == InputClass.BUILTIN
        assert ci.command == "autopwn"

    def test_smb_question_is_chat_not_builtin(self, router):
        """'check smb' without /run prefix must NEVER trigger a tool."""
        ci = router.classify("check smb on 192.168.1.10")
        assert ci.cls == InputClass.CHAT

    def test_ssh_question_is_chat(self, router):
        ci = router.classify("check ssh authentication on 192.168.1.10")
        assert ci.cls == InputClass.CHAT

    def test_vuln_question_is_chat(self, router):
        ci = router.classify("run vuln scan on 10.0.2.5")
        # "run" != "/run" — no slash prefix means CHAT
        assert ci.cls == InputClass.CHAT

    def test_smb_explain_is_chat(self, router):
        ci = router.classify("explain eternal blue vulnerability")
        assert ci.cls == InputClass.CHAT

    def test_json_looking_input_is_chat(self, router):
        """JSON-looking text must never be treated as a command."""
        ci = router.classify('{"tool": "nmap_scan", "args": {"target": "1.2.3.4"}}')
        assert ci.cls == InputClass.CHAT

    def test_all_builtins_in_registry(self):
        assert "autopwn" in BUILTIN_COMMANDS
        assert "plan" in BUILTIN_COMMANDS
        assert "suggest" in BUILTIN_COMMANDS
        assert "scan" in BUILTIN_COMMANDS
        assert "findings" in BUILTIN_COMMANDS
        assert "help" in BUILTIN_COMMANDS
        assert "clear" in BUILTIN_COMMANDS


# ── intent_router tests ───────────────────────────────────────────────────────


class TestIntentRouterSafetyBoundary:
    """
    route_intent() is only called from _on_run() (via /run prefix).
    These tests verify it never fires without a target.
    """

    def test_no_target_returns_none(self):
        """Without a target, route_intent must return None regardless of text."""
        assert route_intent("check smb", None) is None
        assert route_intent("smb vuln ms17-010", None) is None
        assert route_intent("hey", None) is None

    def test_no_target_empty_string_returns_none(self):
        assert route_intent("smb vuln", "") is None

    def test_smb_with_target_matches(self):
        result = route_intent("ms17-010 eternalblue", "192.168.1.10")
        assert result is not None
        assert result["tool"] == "smb_check"
        assert result["args"]["target"] == "192.168.1.10"

    def test_ssh_with_target_matches(self):
        result = route_intent("check ssh auth methods", "10.0.2.5")
        assert result is not None
        assert result["tool"] == "ssh_check"
        assert result["args"]["target"] == "10.0.2.5"

    def test_conversational_text_with_target_no_match(self):
        """Greetings / generic questions must not match, even with a target."""
        assert route_intent("hey", "192.168.1.10") is None
        assert route_intent("what is smb", "192.168.1.10") is None
        # 'explain' + general phrasing must not match
        assert route_intent("explain the vulnerability", "192.168.1.10") is None
        assert route_intent("hello", "192.168.1.10") is None
        # NOTE: 'eternal blue' deliberately matches the SMB-vuln pattern —
        # that is why it requires the /run prefix to be safe. The CommandRouter
        # ensures bare text never reaches route_intent at all.


# ── is_conversational tests (legacy — kept for reference) ────────────────────


class TestIsConversational:
    """
    is_conversational() is no longer used in the REPL (replaced by
    CommandRouter), but tested here to document its limitations.
    """

    def test_known_phrases_return_true(self):
        assert is_conversational("hey") is True
        assert is_conversational("hello") is True
        assert is_conversational("what can you do") is True

    def test_natural_question_returns_false(self):
        # This is the core limitation that triggered the refactor —
        # 'explain smb' would return False and enter freeform/tool routing.
        assert is_conversational("explain smb signing") is False
        assert is_conversational("why no ports found") is False

    def test_smb_question_returns_false(self):
        # Demonstrates the bug: this text would have hit route_intent
        assert is_conversational("check smb on 192.168.1.10") is False


# ── CHAT_SYSTEM_PROMPT contract tests ─────────────────────────────────────────


class TestChatSystemPrompt:
    def test_no_json_instruction(self):
        """Chat system prompt must never instruct the model to produce JSON tool calls."""
        lower = CHAT_SYSTEM_PROMPT.lower()
        # Must not contain the orchestration tool-call instruction
        assert "respond with one valid json" not in lower
        assert "raw json only" not in lower
        # The prompt may mention {"tool": ...} as a NEGATIVE example only
        # — the key constraint is the absence of the orchestration instruction.
        assert "nmap_scan" not in CHAT_SYSTEM_PROMPT
        assert "gobuster_scan" not in CHAT_SYSTEM_PROMPT

    def test_explicitly_forbids_json(self):
        assert (
            "NEVER produce JSON" in CHAT_SYSTEM_PROMPT
            or "never produce json" in CHAT_SYSTEM_PROMPT.lower()
        )

    def test_conversation_mode_declared(self):
        assert (
            "CONVERSATION MODE" in CHAT_SYSTEM_PROMPT
            or "conversation mode" in CHAT_SYSTEM_PROMPT.lower()
        )

    def test_no_tool_list(self):
        """Chat prompt must not describe the available tools."""
        assert "nmap_scan" not in CHAT_SYSTEM_PROMPT
        assert "gobuster_scan" not in CHAT_SYSTEM_PROMPT
        assert "post_exploit" not in CHAT_SYSTEM_PROMPT


# ── ChatAIClient contract tests ───────────────────────────────────────────────


class TestChatAIClientContract:
    def test_no_extract_tool_call_method(self):
        """ChatAIClient must not expose extract_tool_call — prevent accidental tool dispatch."""
        from hydrasight.services.chat_ai_client import ChatAIClient

        assert not hasattr(ChatAIClient, "extract_tool_call"), (
            "ChatAIClient must NOT have extract_tool_call() — "
            "adding this method is a safety violation"
        )

    def test_uses_chat_system_prompt(self):
        import inspect

        from hydrasight.services.chat_ai_client import ChatAIClient

        source = inspect.getsource(ChatAIClient.__init__)
        assert "CHAT_SYSTEM_PROMPT" in source

    def test_separate_from_ai_client(self):
        """ChatAIClient and AIClient must be separate classes."""
        from hydrasight.services.ai_client import AIClient
        from hydrasight.services.chat_ai_client import ChatAIClient

        assert ChatAIClient is not AIClient

    def test_chat_context_smaller_than_orchestration(self):
        """Chat uses smaller context to enforce separation."""
        import logging

        from hydrasight.services.chat_ai_client import ChatAIClient

        log = logging.getLogger("test")
        c = ChatAIClient("http://localhost:11434", "qwen2.5:7b", 8192, log)
        assert c.context <= 4096


# ── Shell integration tests (mocked) ─────────────────────────────────────────


class TestShellSafety:
    """
    Test that Shell correctly routes inputs without executing real tools.
    Dispatcher.dispatch and ChatController.chat are mocked.
    """

    @pytest.fixture
    def shell(self):
        """Build a minimal Shell with all network/IO mocked."""
        from hydrasight.config.defaults import DEFAULT_CONFIG

        cfg = dict(DEFAULT_CONFIG)
        cfg["verbosity"] = 0
        cfg["log_file"] = "test.log"

        with (
            patch("hydrasight.cli.shell.KaliAPI"),
            patch("hydrasight.cli.shell.AIClient"),
            patch("hydrasight.cli.shell.Dispatcher"),
            patch("hydrasight.cli.shell.Engine"),
            patch("hydrasight.cli.shell.ChatController"),
            patch("hydrasight.cli.shell._setup_log", return_value=logging.getLogger("test")),
        ):
            from hydrasight.cli.shell import Shell

            sh = Shell(cfg)
        return sh

    def _dispatch_called(self, shell) -> bool:
        return bool(shell.dispatcher.dispatch.called)

    def test_hey_does_not_dispatch(self, shell):
        shell._on_bare_text("hey")
        assert not self._dispatch_called(shell)

    def test_what_can_you_do_does_not_dispatch(self, shell):
        shell._on_bare_text("what can you do")
        assert not self._dispatch_called(shell)

    def test_explain_smb_does_not_dispatch(self, shell):
        shell._on_bare_text("explain smb signing")
        assert not self._dispatch_called(shell)

    def test_why_no_ports_does_not_dispatch(self, shell):
        shell._on_bare_text("why no ports found")
        assert not self._dispatch_called(shell)

    def test_bare_text_delegates_to_chat_controller(self, shell):
        shell._on_bare_text("hello")
        shell._chat.chat.assert_called_once()

    def test_ask_prefix_delegates_to_chat_controller(self, shell):
        """_on_bare_text is called for /ask — must delegate to chat, never dispatch."""
        shell._on_bare_text("explain eternal blue")
        shell._chat.chat.assert_called_once()
        assert not self._dispatch_called(shell)

    def test_on_run_no_target_no_dispatch(self, shell):
        """_on_run without a target must fail safely, not dispatch."""
        shell.findings.target = None
        shell.dispatcher.canonical_target = None
        shell._on_run("check smb on the host")
        # No IP in text and no findings target → should not dispatch
        assert not self._dispatch_called(shell)

    def test_on_run_with_ip_and_match_dispatches(self, shell):
        """_on_run with explicit IP and matching pattern SHOULD dispatch."""
        shell.dispatcher.dispatch.return_value = ("run_command", "nmap output here", 1.5)
        shell.ai.ask.return_value = "PORTS: 445\nVULNS: none\nNOTES: ok"
        shell.engine._ingest = MagicMock()
        shell._on_run("check smb vuln ms17-010 on 192.168.1.10")
        assert self._dispatch_called(shell)

    def test_on_run_no_match_no_dispatch(self, shell):
        """_on_run with no matching pattern must not dispatch, not fall through to AI."""
        shell.findings.target = "192.168.1.10"
        shell._on_run("make me a cup of tea")
        assert not self._dispatch_called(shell)

    def test_canonical_target_not_leaked_after_run(self, shell):
        """canonical_target must be restored after _on_run, even on error."""
        shell.dispatcher.dispatch.return_value = ("run_command", "output", 1.0)
        shell.ai.ask.return_value = "NOTES: ok"
        shell.engine._ingest = MagicMock()
        shell.dispatcher.canonical_target = "OLD_TARGET"
        shell._on_run("check smb on 192.168.1.10")
        # After the call, canonical_target must be restored to OLD_TARGET
        assert shell.dispatcher.canonical_target == "OLD_TARGET"

    def test_json_looking_text_goes_to_chat_not_dispatch(self, shell):
        """If a user types raw JSON, it must go to chat, not tool dispatch."""
        json_text = '{"tool": "nmap_scan", "args": {"target": "192.168.1.10"}}'
        router = shell._router
        ci = router.classify(json_text)
        assert ci.cls == InputClass.CHAT
        # The REPL would call _on_bare_text, not _on_run or dispatcher
        shell._on_bare_text(json_text)
        assert not self._dispatch_called(shell)

    def test_plan_classified_as_builtin(self, shell):
        ci = shell._router.classify("plan")
        assert ci.cls == InputClass.BUILTIN
        assert ci.command == "plan"

    def test_scan_classified_as_builtin(self, shell):
        ci = shell._router.classify("scan 192.168.1.10")
        assert ci.cls == InputClass.BUILTIN

    def test_autopwn_classified_as_builtin(self, shell):
        ci = shell._router.classify("autopwn 192.168.1.10")
        assert ci.cls == InputClass.BUILTIN

    def test_stale_target_not_used_in_bare_text(self, shell):
        """
        After a previous engagement sets canonical_target,
        bare text must not use that target for tool routing.
        """
        # Simulate stale state from previous engagement
        shell.dispatcher.canonical_target = "10.0.0.1"
        # Bare text must go to chat, not tool routing
        shell._on_bare_text("explain what you found")
        assert not self._dispatch_called(shell)
        shell._chat.chat.assert_called_once()
