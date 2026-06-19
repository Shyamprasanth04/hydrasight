"""
Tests for the natural-language intent and confirmation pipeline.

These tests prove that:
- chat/explain/plan intents never execute tools.
- operational intents require confirmation by default.
- the confirmation manager respects yes/no and clears state.
- execution mode (confirm/auto/never) behaves as expected.
- ambiguous intents safely request clarification.
- explicit builtins bypass ambiguity.
"""
import pytest
from unittest.mock import MagicMock, patch

from hydrasight.services.intent_classifier import IntentClassifier, Intent
from hydrasight.services.action_planner import ActionPlanner
from hydrasight.services.confirmation_manager import ConfirmationManager
from hydrasight.services.execution_policy import ExecutionPolicy
from hydrasight.services.command_router import CommandRouter, InputClass


# ── Component tests ──────────────────────────────────────────────────────────

def test_intent_classifier_chat_and_explain():
    classifier = IntentClassifier()
    assert classifier.classify("hey").intent == Intent.CHAT
    assert classifier.classify("what is smb signing").intent == Intent.EXPLAIN
    assert classifier.classify('{"tool": "nmap_scan"}').intent == Intent.CHAT


def test_intent_classifier_operational():
    classifier = IntentClassifier()
    res = classifier.classify("run an nmap scan on 192.168.100.131 ports 1-500 with -sS -sV -O")
    assert res.intent == Intent.EXECUTE_ACTION
    assert res.extracted_ip == "192.168.100.131"
    assert res.extracted_ports == "1-500"
    assert "-sS" in res.extracted_flags
    assert res.tool_hint == "nmap_scan"


def test_intent_classifier_ambiguous():
    classifier = IntentClassifier()
    res = classifier.classify("check smb on 192.168.100.131")
    # 'check' is an enum verb, so this is high confidence execute
    assert res.intent == Intent.EXECUTE_ACTION
    assert res.tool_hint == "smb_check"

    # Truly ambiguous (no IP, no verb)
    res2 = classifier.classify("look at smb")
    assert res2.intent == Intent.CLARIFY


def test_intent_classifier_smb_routing():
    classifier = IntentClassifier()
    res1 = classifier.classify("check smb shares on 10.129.72.237")
    assert res1.intent == Intent.EXECUTE_ACTION
    assert res1.tool_hint == "smb_enum"

    res2 = classifier.classify("check ms17-010 on 10.129.72.237")
    assert res2.intent == Intent.EXECUTE_ACTION
    assert res2.tool_hint == "smb_check"

    res3 = classifier.classify("enumerate smb on 10.129.72.237")
    assert res3.intent == Intent.EXECUTE_ACTION
    assert res3.tool_hint == "smb_enum"

def test_intent_classifier_smbclient_routing():
    classifier = IntentClassifier()
    res = classifier.classify("enumerate SMB shares using smbclient on 10.129.74.47")
    assert res.intent == Intent.EXECUTE_ACTION
    assert res.tool_hint == "smbclient_enum"
    assert res.extracted_ip == "10.129.74.47"

def test_intent_classifier_run_command_guardrail():
    classifier = IntentClassifier()
    res1 = classifier.classify("run command: smbclient -L //10.129.74.47 -N")
    # Matches a known tool (smbclient), so allows execution
    assert res1.intent == Intent.EXECUTE_ACTION
    assert res1.tool_hint == "smbclient_enum"

    res2 = classifier.classify("run command: arbitrary_shell_command 1.1.1.1")
    # No known tool hint, should trigger clarify
    assert res2.intent == Intent.CLARIFY
    assert "To actually execute commands" in res2.clarify_question


def test_confirmation_manager_lifecycle():
    from hydrasight.services.action_planner import PendingAction
    mgr = ConfirmationManager()
    assert not mgr.has_pending

    action = PendingAction(
        tool_hint="test", target="1.1.1.1", ports=None, flags=[],
        command_str="cmd", tool_call={}, reason="", confidence=1.0
    )
    mgr.set(action)
    assert mgr.has_pending
    assert mgr.pending == action

    # "no" cancels
    resolution, act = mgr.try_resolve("no")
    assert resolution == "no"
    assert act is None
    assert not mgr.has_pending

    # "yes" confirms
    mgr.set(action)
    resolution, act = mgr.try_resolve("yes")
    assert resolution == "yes"
    assert act == action
    assert not mgr.has_pending

    # unrelated input clears
    mgr.set(action)
    resolution, act = mgr.try_resolve("what is smb")
    assert resolution is None
    assert act is None
    # the caller (shell) is responsible for calling clear() on unrelated input, 
    # but the try_resolve itself doesn't clear it unless it's a valid yes/no.
    mgr.clear()
    assert not mgr.has_pending


def test_execution_policy_modes():
    policy = ExecutionPolicy()
    
    # 1. Safe intent
    from hydrasight.services.intent_classifier import IntentResult
    safe_res = IntentResult(intent=Intent.EXPLAIN, confidence=0.9)
    assert policy.decide(safe_res, None, "confirm").action == "chat"
    assert policy.decide(safe_res, None, "auto").action == "chat"
    
    # 2. Execute intent
    from hydrasight.services.action_planner import PendingAction
    exec_res = IntentResult(intent=Intent.EXECUTE_ACTION, confidence=0.9, extracted_ip="1.1.1.1")
    pending = PendingAction(
        tool_hint="test", target="1.1.1.1", ports=None, flags=[],
        command_str="cmd", tool_call={}, reason="", confidence=0.9
    )
    
    # confirm mode
    assert policy.decide(exec_res, pending, "confirm").action == "confirm"
    
    # auto mode (high confidence)
    assert policy.decide(exec_res, pending, "auto").action == "execute"
    
    # auto mode (low confidence) -> drops to confirm
    low_res = IntentResult(intent=Intent.EXECUTE_ACTION, confidence=0.5, extracted_ip="1.1.1.1")
    pending.confidence = 0.5
    assert policy.decide(low_res, pending, "auto").action == "confirm"
    
    # never mode
    assert policy.decide(exec_res, pending, "never").action == "suggest"


# ── Shell Integration Mock Tests ─────────────────────────────────────────────

@pytest.fixture
def shell():
    from hydrasight.config.defaults import DEFAULT_CONFIG
    cfg = dict(DEFAULT_CONFIG)
    cfg["verbosity"] = 0
    cfg["log_file"]  = "test.log"
    cfg["execution_mode"] = "confirm"

    with (
        patch("hydrasight.cli.shell.KaliAPI"),
        patch("hydrasight.cli.shell.AIClient"),
        patch("hydrasight.cli.shell.Dispatcher"),
        patch("hydrasight.cli.shell.Engine"),
        patch("hydrasight.cli.shell.ChatController"),
        patch("hydrasight.cli.shell._setup_log")
    ):
        from hydrasight.cli.shell import Shell
        sh = Shell(cfg)
        # Mock the dispatch functions directly to test routing
        sh._chat.chat = MagicMock()
        sh._dispatch_pending_action = MagicMock()
        sh._show_plan = MagicMock()
        return sh

def test_shell_chat_only(shell):
    shell._on_bare_text("what is smb signing")
    shell._chat.chat.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()

def test_chat_controller_sanitizer():
    from hydrasight.services.chat_controller import ChatController
    import logging
    
    class FakeAI:
        def __init__(self, *a, **k): self.call_count = 1; self.messages = []
        def ask(self, p): return "I cannot directly execute commands for you."
        def reset(self): pass

    cc = ChatController("http", "model", 4000, logging.getLogger())
    cc._ai = FakeAI()
    
    with patch("hydrasight.services.chat_controller.console.print") as mock_print:
        cc.chat("execute it against a target 10.129.72.237")
        
    args_str = " ".join(str(call.args) for call in mock_print.call_args_list)
    assert "cannot directly execute commands" not in args_str.lower()
    assert "no action has been launched" in args_str.lower()

def test_shell_model_json_is_chat(shell):
    # Model accidentally emitted JSON in chat path
    shell._on_bare_text('{"tool": "nmap_scan"}')
    shell._chat.chat.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()

def test_shell_nl_execute_confirm_mode(shell):
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    shell._dispatch_pending_action.assert_not_called()
    assert shell._confirm.has_pending

    # Confirm
    shell._on_bare_text("yes")
    shell._dispatch_pending_action.assert_called_once()
    assert not shell._confirm.has_pending

def test_shell_nl_execute_cancel(shell):
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    assert shell._confirm.has_pending

    # Cancel
    shell._on_bare_text("no")
    shell._dispatch_pending_action.assert_not_called()
    assert not shell._confirm.has_pending

def test_shell_unrelated_clears_pending(shell):
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    assert shell._confirm.has_pending

    # Ask for a different action entirely
    shell._on_bare_text("enumerate ftp on 10.0.0.5")
    # The new action becomes the pending one!
    assert shell._confirm.has_pending
    assert shell._confirm.pending.tool_hint == "ftp_check"
    shell._dispatch_pending_action.assert_not_called()

def test_shell_explain_preserves_pending(shell):
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    assert shell._confirm.has_pending
    
    # Ask for explanation of what the command does
    shell._on_bare_text("what does an nmap scan do?")
    assert shell._confirm.has_pending
    shell._chat.chat.assert_called_once()

def test_shell_never_mode(shell):
    shell.cfg["execution_mode"] = "never"
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    # Will print suggestion, not propose
    shell._dispatch_pending_action.assert_not_called()

def test_shell_auto_mode(shell):
    shell.cfg["execution_mode"] = "auto"
    shell._on_bare_text("run an nmap scan on 192.168.100.131")
    # High confidence exec verb + tool word + IP -> exec directly
    shell._dispatch_pending_action.assert_called_once()

def test_shell_plan_dry_run(shell):
    shell._on_bare_text("plan")
    shell._show_plan.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()

def test_shell_scan_builtin(shell):
    # Builtins go through the loop, bypassing _on_bare_text.
    # We test the router.
    ci = shell._router.classify("scan 192.168.1.1")
    assert ci.cls == InputClass.BUILTIN
    assert ci.command == "scan"


# ── Goal 2: Operational meta-intent classification ────────────────────────────

def test_intent_execute_plan_variants():
    """do all planned stuff / run the plan → EXECUTE_PLAN intent."""
    classifier = IntentClassifier()
    for phrase in [
        "do all planned stuff",
        "run the plan",
        "execute the plan",
        "continue engagement",
        "run all planned",
    ]:
        res = classifier.classify(phrase)
        assert res.intent == Intent.EXECUTE_PLAN, (
            f"'{phrase}' expected EXECUTE_PLAN, got {res.intent}"
        )


def test_intent_verify_findings_variants():
    """verify findings / verify vulns → VERIFY_FINDINGS intent."""
    classifier = IntentClassifier()
    for phrase in [
        "verify findings",
        "verify vulnerabilities",
        "check confirmations",
        "validate findings",
    ]:
        res = classifier.classify(phrase)
        assert res.intent == Intent.VERIFY_FINDINGS, (
            f"'{phrase}' expected VERIFY_FINDINGS, got {res.intent}"
        )


def test_intent_show_suggestions_variants():
    """suggest next step / next move → SHOW_SUGGESTIONS intent."""
    classifier = IntentClassifier()
    for phrase in [
        "suggest next step",
        "next move",
        "next step",
        "what should i do next",
        "what next",
    ]:
        res = classifier.classify(phrase)
        assert res.intent == Intent.SHOW_SUGGESTIONS, (
            f"'{phrase}' expected SHOW_SUGGESTIONS, got {res.intent}"
        )


def test_intent_show_conclusion_variants():
    """conclusion / summarize outcome → SHOW_CONCLUSION intent."""
    classifier = IntentClassifier()
    for phrase in [
        "conclusion",
        "show conclusion",
        "summarize outcome",
        "engagement result",
        "what did we find",
        "what have we found",
    ]:
        res = classifier.classify(phrase)
        assert res.intent == Intent.SHOW_CONCLUSION, (
            f"'{phrase}' expected SHOW_CONCLUSION, got {res.intent}"
        )


# ── Goal 4: SMB enumeration phrase priority ───────────────────────────────────

def test_smb_enum_prioritized_over_smb_check():
    """'smb enumeration scan' must route to smb_enum not smb_check."""
    classifier = IntentClassifier()
    for phrase in [
        "enumerate SMB shares on 10.10.10.10",
        "run an SMB enumeration scan on 10.10.10.10",
        "smb enumeration 10.10.10.10",
        "list smb shares on 10.10.10.10",
        "enum4linux 10.10.10.10",
    ]:
        res = classifier.classify(phrase)
        assert res.intent == Intent.EXECUTE_ACTION, f"'{phrase}' expected EXECUTE_ACTION"
        assert res.tool_hint == "smb_enum", (
            f"'{phrase}' expected smb_enum, got {res.tool_hint}"
        )


def test_smb_check_still_works():
    """ms17-010 / eternalblue patterns still route to smb_check."""
    classifier = IntentClassifier()
    res = classifier.classify("check ms17-010 on 10.10.10.10")
    assert res.tool_hint == "smb_check"


# ── Goal 2 + shell: meta-intents route to internal methods ────────────────────

def test_shell_verify_findings_routes_to_run_verify(shell):
    shell._run_verify = MagicMock()
    shell._on_bare_text("verify findings")
    shell._run_verify.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()


def test_shell_show_suggestions_routes_to_show_suggest(shell):
    shell._show_suggest = MagicMock()
    shell._on_bare_text("suggest next step")
    shell._show_suggest.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()


def test_shell_show_conclusion_routes_to_show_conclusion(shell):
    shell._show_conclusion = MagicMock()
    shell._on_bare_text("conclusion")
    shell._show_conclusion.assert_called_once()
    shell._dispatch_pending_action.assert_not_called()


def test_shell_execute_plan_no_target_warns(shell):
    """Without a target, execute_plan must warn instead of calling engine."""
    shell.findings.target = None
    shell.dispatcher.canonical_target = None
    shell._on_bare_text("do all planned stuff")
    shell._dispatch_pending_action.assert_not_called()
    # engine.run should not have been called with no target
    shell.engine.run.assert_not_called()


# ── Goal 3: fake-execution guard in ChatController ────────────────────────────

def test_chat_controller_blocks_fake_exec_claims():
    """Responses claiming 'I will begin' / 'Starting now' must be intercepted."""
    from hydrasight.services.chat_controller import ChatController
    import logging

    FAKE_REPLIES = [
        "I will begin the SMB enumeration now.",
        "Starting now: running enum4linux against the target.",
        "Let's proceed with the scan.",
        "I'll enumerate the shares for you.",
        "I am starting the vulnerability scan.",
        "I'm starting nmap on 192.168.1.1.",
    ]

    for fake_reply in FAKE_REPLIES:
        class FakeAI:
            def __init__(self, *a, **k):
                self.call_count = 0
                self.messages = []
            def ask(self, p):
                return fake_reply
            def reset(self): pass

        cc = ChatController("http", "model", 4000, logging.getLogger("test"))
        cc._ai = FakeAI()

        printed = []
        with patch("hydrasight.services.chat_controller.console.print") as mp:
            cc.chat("check smb")
            printed = [str(c) for c in mp.call_args_list]

        output = " ".join(printed).lower()
        assert "no action has been launched" in output, (
            f"Guard failed for reply: '{fake_reply}'\nPrinted: {output}"
        )
        assert fake_reply.lower()[:20] not in output, (
            f"Fake reply leaked through for: '{fake_reply}'"
        )


# ── Goal 1: _chat_context() provides state context ────────────────────────────

def test_shell_chat_context_returns_state_block(shell):
    """_chat_context() must always return a string with context headers."""
    # Without findings
    ctx = shell._chat_context()
    assert ctx is not None
    assert "HydraSight Engagement Context" in ctx
    assert "RULES:" in ctx
    assert "NEVER invent" in ctx
