"""
ChatController — safe conversational AI path.

GUARANTEE: this module NEVER dispatches tools, NEVER calls Kali,
NEVER inspects AI output for JSON tool calls.

Uses a dedicated ChatAIClient with a system prompt that explicitly
forbids JSON tool-call output.

The orchestration AIClient (used by Engine) has its own separate
message history and is never touched here.
"""
from __future__ import annotations

import logging
from typing import Optional

from hydrasight.services.chat_ai_client import ChatAIClient
from hydrasight.cli.display import (
    console, div, info, warn,
)
from hydrasight.config.defaults import P


class ChatController:
    """
    Handles all conversational input safely.

    Wraps a ChatAIClient and guarantees that no tool execution
    can result from any input passed to this class.
    """

    def __init__(
        self,
        ollama_url  : str,
        model       : str,
        context_size: int,
        log         : logging.Logger,
    ) -> None:
        self._ai  = ChatAIClient(ollama_url, model, context_size, log)
        self._log = log

    # ── public API ────────────────────────────────────────────────────────────

    def chat(
        self,
        user_input : str,
        context    : Optional[str] = None,
    ) -> None:
        """
        Send *user_input* to the chat model and print the reply.

        *context* is an optional findings summary injected as a
        one-shot system note (not persisted to history).

        SAFETY CONTRACT: this method NEVER calls dispatcher.dispatch(),
        NEVER calls kali.*, and NEVER parses AI output for tool calls.
        """
        prompt = user_input.strip()
        if not prompt:
            return

        # Optionally inject a brief context note (findings summary)
        if context:
            prompt = (
                f"[Current engagement context — for reference only]:\n"
                f"{context}\n\n"
                f"User question: {user_input}"
            )

        response = self._ai.ask(prompt)
        if not response:
            warn("no response from chat model")
            return

        # ── lightweight sanitizer / filter ───────────────────────────────────
        # Block any response that CLAIMS to start an action but no tool was
        # dispatched (since ChatController NEVER dispatches tools).
        _FAKE_EXEC_PHRASES = (
            "i will begin",
            "i will run",
            "i'll begin",
            "i'll run",
            "i'll enumerate",
            "starting now",
            "let's proceed",
            "i am starting",
            "i'm starting",
            "beginning the",
            "i will start",
            "i'll start",
            "initiating the",
            "launching the",
        )
        _DISALLOWED_TOOLS = (
            "nessus",
            "openvas",
            "as an ai",
            "i cannot directly execute commands",
        )
        lower_resp = response.lower()
        if any(p in lower_resp for p in _FAKE_EXEC_PHRASES + _DISALLOWED_TOOLS):
            response = (
                "No action has been launched yet. HydraSight has not executed any tools "
                "from this conversation.\n\n"
                "Supported actions you can trigger:\n"
                "  run the plan          -- resume full planned engagement\n"
                "  verify findings       -- check discovered vulnerabilities\n"
                "  suggest               -- show ranked exploit/access candidates\n"
                "  smb enumeration       -- enumerate SMB shares (enum4linux -S)\n"
                "  smbclient enumeration -- list shares via smbclient\n"
                "  autopwn <ip>          -- full adaptive engagement\n"
            )

        console.print()
        div("assistant")
        console.print()
        for line in response.splitlines():
            if line.strip():
                console.print(f"  [{P.TEXT}]{line}[/]")
        console.print()
        div()

    def reset(self) -> None:
        """Reset chat history (e.g. on `clear` command)."""
        self._ai.reset()

    @property
    def call_count(self) -> int:
        return self._ai.call_count

    @property
    def messages(self) -> list[dict]:
        return self._ai.messages
