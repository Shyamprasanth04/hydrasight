"""
CommandRouter — deterministic REPL input classifier.

STRICT MODE SEPARATION
======================
Every raw input string is classified into exactly one of four cases:

  BUILTIN   — matches a known command keyword (autopwn, scan, help, ...)
              → Shell dispatches to the built-in handler, no AI involved.

  ASK       — starts with /ask (case-insensitive)
              → ChatController handles it; tools are NEVER executed.

  RUN       — starts with /run (case-insensitive)
              → Shell._on_run() handles it; tool routing is allowed.

  CHAT      — everything else (bare text, questions, greetings)
              → ChatController handles it; tools are NEVER executed.

This module is intentionally free of AI calls, network access,
and side effects — it is a pure classifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class InputClass(Enum):
    BUILTIN = auto()  # explicit shell command
    ASK = auto()  # /ask prefix  → chat, no tools
    RUN = auto()  # /run prefix  → tool routing allowed
    CHAT = auto()  # bare text    → chat, no tools


# ── set of all built-in command tokens ───────────────────────────────────────

BUILTIN_COMMANDS: frozenset[str] = frozenset(
    {
        "autopwn",
        "scan",
        "findings",
        "ports",
        "vulns",
        "creds",
        "hashes",
        "sessions",
        "save",
        "report",
        "status",
        "stats",
        "config",
        "history",
        "roe",
        "verify",
        "suggest",
        "plan",
        "conclusion",
        "verbose",
        "clear",
        "mode",
        "help",
        "exit",
        "quit",
        "abort",
    }
)


@dataclass(frozen=True)
class ClassifiedInput:
    cls: InputClass
    command: str  # lower-cased first token (for BUILTIN) or ""
    args: list[str]  # remaining tokens / words
    raw: str  # original input, stripped

    @property
    def tail(self) -> str:
        """Everything after the first token, preserving spaces."""
        parts = self.raw.split(None, 1)
        return parts[1].strip() if len(parts) > 1 else ""

    @property
    def is_safe(self) -> bool:
        """True if this input can NEVER trigger a tool execution."""
        return self.cls in (InputClass.CHAT, InputClass.ASK)


class CommandRouter:
    """
    Classifies a raw REPL input string without any side effects.

    Usage
    -----
        router = CommandRouter()
        ci = router.classify(raw_input)
        if ci.cls == InputClass.BUILTIN:
            ...
    """

    def classify(self, raw: str) -> ClassifiedInput:
        """Return a ClassifiedInput for *raw*. Never raises."""
        text = raw.strip()
        if not text:
            return ClassifiedInput(InputClass.CHAT, "", [], text)

        lower = text.lower()

        # /ask prefix — always chat, never tools
        if lower.startswith("/ask"):
            tail = text[4:].strip()
            parts = tail.split()
            return ClassifiedInput(InputClass.ASK, "/ask", parts, text)

        # /run prefix — tool routing allowed
        if lower.startswith("/run"):
            tail = text[4:].strip()
            parts = tail.split()
            return ClassifiedInput(InputClass.RUN, "/run", parts, text)

        # Any other / prefix is treated as chat (unknown slash command)
        if text.startswith("/"):
            return ClassifiedInput(InputClass.CHAT, "", [], text)

        # Check first token against known built-in commands
        parts = text.split()
        first = parts[0].lower()
        if first in BUILTIN_COMMANDS:
            return ClassifiedInput(InputClass.BUILTIN, first, parts[1:], text)

        # Everything else — bare text — is CHAT (safe, no tools)
        return ClassifiedInput(InputClass.CHAT, "", parts, text)
