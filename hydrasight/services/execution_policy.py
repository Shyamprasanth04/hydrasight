"""
ExecutionPolicy — deterministic policy layer for natural-language execution.

Applies the execution_mode configuration to decide what happens when an
EXECUTE_ACTION intent is detected.

Modes
-----
  confirm (default)
    All natural-language execution requests require operator confirmation.
    Shows a preview, waits for yes/no.

  auto
    High-confidence requests (>= AUTO_CONFIDENCE_THRESHOLD) run immediately.
    Lower-confidence requests still ask for confirmation.

  never
    Never execute from natural language.
    Prints what would be run, directs operator to use explicit commands.

Safety invariants
-----------------
  - CHAT and EXPLAIN intents NEVER execute regardless of mode
  - plan NEVER executes
  - Ambiguous (CLARIFY) intents NEVER execute — ask first
  - mode='never' guarantees no NL execution under any circumstance
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hydrasight.services.action_planner import PendingAction
from hydrasight.services.intent_classifier import Intent, IntentResult

# Minimum confidence to auto-execute in 'auto' mode
AUTO_CONFIDENCE_THRESHOLD = 0.80

# Valid mode values
ExecutionMode = Literal["confirm", "auto", "never"]
VALID_MODES: frozenset[str] = frozenset({"confirm", "auto", "never"})


@dataclass
class PolicyDecision:
    """The outcome of applying ExecutionPolicy to an IntentResult."""

    action: Literal[
        "execute",  # run the action immediately
        "confirm",  # propose action + wait for confirmation
        "suggest",  # explain what would be run, guide to explicit command
        "clarify",  # ask a follow-up question
        "chat",  # safe chat / explanation — no tool involvement
        "plan",  # show dry-run plan
    ]
    message: str | None = None  # extra message to show operator
    pending: PendingAction | None = None

    @property
    def is_safe(self) -> bool:
        """True if this decision cannot produce tool execution right now."""
        return self.action in ("suggest", "clarify", "chat", "plan")


class ExecutionPolicy:
    """
    Map an IntentResult + PendingAction to a PolicyDecision.

    *mode* is read from config at decision time (supports runtime changes).
    """

    def decide(
        self,
        result: IntentResult,
        pending: PendingAction | None,
        mode: ExecutionMode = "confirm",
    ) -> PolicyDecision:
        """
        Apply execution policy.

        Args:
            result:  Classified intent
            pending: Planned action (from ActionPlanner.plan())
            mode:    'confirm' | 'auto' | 'never'
        """
        mode = mode if mode in VALID_MODES else "confirm"

        # ── safe intents — never execute ──────────────────────────────────────
        if result.intent in (Intent.CHAT, Intent.EXPLAIN):
            return PolicyDecision(action="chat")

        if result.intent == Intent.PLAN:
            return PolicyDecision(action="plan")

        if result.intent == Intent.CLARIFY:
            return PolicyDecision(
                action="clarify",
                message=result.clarify_question,
            )

        # ── operational meta-intents — passed through to shell for dispatch ────
        # Shell._on_bare_text handles these before checking policy decisions.
        # Return a safe "chat" sentinel so the policy layer doesn't block them.
        if result.intent in (
            Intent.EXECUTE_PLAN,
            Intent.VERIFY_FINDINGS,
            Intent.SHOW_SUGGESTIONS,
            Intent.SHOW_CONCLUSION,
        ):
            return PolicyDecision(action="chat")

        # ── SUGGEST_ACTION ────────────────────────────────────────────────────
        if result.intent == Intent.SUGGEST_ACTION:
            return PolicyDecision(action="suggest")

        # ── EXECUTE_ACTION ────────────────────────────────────────────────────
        if result.intent != Intent.EXECUTE_ACTION:
            # Unknown intent — fail safe
            return PolicyDecision(action="chat")

        # mode=never: always explain, never execute
        if mode == "never":
            msg = (
                "I understand you want to run a tool, but I'm configured "
                "to never execute from natural language.\n"
            )
            if pending:
                msg += (
                    f"What I would run:\n  {pending.command_str}\n\n"
                    f"To execute it, use:\n  scan {pending.target}\n"
                    f"  or:  autopwn {pending.target}"
                )
            return PolicyDecision(action="suggest", message=msg, pending=pending)

        # No action plan possible (no target etc.)
        if pending is None:
            return PolicyDecision(
                action="clarify",
                message=(
                    "I understood an action request but couldn't determine "
                    "a target or tool.\n"
                    "Please include an IP address, e.g.:\n"
                    "  'run an nmap scan on 192.168.1.10'"
                ),
            )

        # mode=auto + high confidence: execute immediately
        if mode == "auto" and result.confidence >= AUTO_CONFIDENCE_THRESHOLD:
            return PolicyDecision(action="execute", pending=pending)

        # mode=confirm (or auto + low confidence): propose + confirm
        return PolicyDecision(action="confirm", pending=pending)
