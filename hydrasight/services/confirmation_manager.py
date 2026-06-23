"""
ConfirmationManager — manages one pending action awaiting operator approval.

Lifecycle:
  1. Shell proposes an action → manager.set(pending_action)
  2. Shell shows confirmation prompt to operator
  3. Next input arrives → manager.try_resolve(user_input)
     - returns ("yes", action) if user confirmed
     - returns ("no", None)   if user cancelled
     - returns (None, None)   if this is not a yes/no reply
  4. If an unrelated request arrives → manager.clear() is called

Only ONE pending action is stored at a time.

SAFETY: pending actions never survive context boundaries.
clear() is called when:
  - a builtin command is dispatched
  - a new /run is issued
  - a CHAT or EXPLAIN response is sent that replaces the context
"""

from __future__ import annotations

import time
from typing import Literal

from hydrasight.services.action_planner import PendingAction

# Words the operator can use to confirm or cancel
_YES_WORDS = frozenset(
    {
        "yes",
        "y",
        "confirm",
        "ok",
        "okay",
        "sure",
        "run",
        "run it",
        "go",
        "go ahead",
        "do it",
        "execute",
        "execute it",
        "proceed",
        "yep",
        "yup",
        "aye",
        "affirmative",
        "confirmed",
    }
)
_NO_WORDS = frozenset(
    {
        "no",
        "n",
        "cancel",
        "stop",
        "abort",
        "skip",
        "nope",
        "nah",
        "forget it",
        "never mind",
        "nevermind",
        "pass",
        "decline",
        "negative",
        "denied",
    }
)

# A pending action expires after this many seconds if the operator ignores it
_PENDING_TTL = 300  # 5 minutes


class ConfirmationManager:
    """Thread-unsafe but REPL-safe — single-user, single-thread only."""

    def __init__(self) -> None:
        self._pending: PendingAction | None = None
        self._set_at: float = 0.0

    # ── state ──────────────────────────────────────────────────────────────────

    @property
    def has_pending(self) -> bool:
        if not self._pending:
            return False
        if time.time() - self._set_at > _PENDING_TTL:
            self.clear()
            return False
        return True

    @property
    def pending(self) -> PendingAction | None:
        if not self.has_pending:
            return None
        return self._pending

    def set(self, action: PendingAction) -> None:
        """Store a new pending action (replaces any previous one)."""
        self._pending = action
        self._set_at = time.time()

    def clear(self) -> None:
        """Discard the pending action."""
        self._pending = None
        self._set_at = 0.0

    # ── resolution ────────────────────────────────────────────────────────────

    def try_resolve(
        self, user_input: str
    ) -> tuple[Literal["yes", "no"] | None, PendingAction | None]:
        """
        Attempt to resolve the pending action from operator input.

        Returns:
          ("yes", action) — confirmed
          ("no",  None)   — cancelled
          (None,  None)   — not a yes/no answer
        """
        if not self.has_pending:
            return None, None

        normalized = user_input.strip().lower().rstrip("!?.")

        if normalized in _YES_WORDS:
            action = self._pending
            self.clear()
            return "yes", action

        if normalized in _NO_WORDS:
            self.clear()
            return "no", None

        return None, None

    def is_yes_no(self, user_input: str) -> bool:
        """Return True if this input looks like a confirmation reply."""
        n = user_input.strip().lower().rstrip("!?.")
        return n in _YES_WORDS or n in _NO_WORDS
