"""
ChatAIClient — isolated conversational AI client.

CRITICAL DIFFERENCE from AIClient (the orchestration client):
  - Uses CHAT_SYSTEM_PROMPT — explicitly forbids JSON tool calls
  - Has NO extract_tool_call() method — callers cannot accidentally parse tools
  - Has completely separate message history from the orchestration client
  - Low temperature (0.3) for cleaner prose answers
  - Shorter context budget — chat doesn't need long history

This client must ONLY be used by ChatController.
The Engine and Shell orchestration path must ONLY use AIClient.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import requests

from hydrasight.config.defaults import CHAT_SYSTEM_PROMPT


class ChatAIClient:
    """
    Conversational-only Ollama wrapper.

    Contract:
    - Never returns or stores JSON tool-call dicts
    - Never parses model output for tool calls
    - Never exposes extract_tool_call()
    """

    def __init__(
        self,
        base_url    : str,
        model       : str,
        context_size: int,
        log         : logging.Logger,
    ) -> None:
        self.base        = base_url.rstrip("/")
        self.model       = model
        self.context     = min(context_size, 4096)   # chat doesn't need huge ctx
        self.log         = log
        self.sess        = requests.Session()
        self.call_count  = 0
        self.messages: list[dict] = [
            {"role": "system", "content": CHAT_SYSTEM_PROMPT}
        ]

    def reset(self) -> None:
        self.messages    = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
        self.call_count  = 0

    def _trim(self, budget: int = 3000) -> None:
        sys_msgs = [m for m in self.messages if m["role"] == "system"]
        other    = [m for m in self.messages if m["role"] != "system"]
        while other:
            total = sum(len(str(m["content"])) for m in sys_msgs + other) // 4
            if total <= budget:
                break
            other.pop(0)
        self.messages = sys_msgs + other

    def ask(self, content: str, retries: int = 2, delay: float = 1.5) -> str:
        """Send a message; return plain-text reply. Never returns JSON tool calls."""
        self.messages.append({"role": "user", "content": content})
        self._trim()
        self.call_count += 1

        for attempt in range(1, retries + 1):
            try:
                r = self.sess.post(
                    f"{self.base}/api/chat",
                    json={
                        "model"   : self.model,
                        "messages": self.messages,
                        "stream"  : False,
                        "options" : {
                            "num_ctx"    : self.context,
                            "temperature": 0.3,
                            "top_p"      : 0.95,
                            "num_predict": 800,
                        },
                    },
                    timeout=120,
                )
                r.raise_for_status()
                data  = r.json()
                reply = (
                    data.get("message", {}).get("content", "")
                    or data.get("response", "")
                ).strip()

                if not reply:
                    self.log.warning("chat: empty response attempt %d", attempt)
                    if attempt < retries:
                        time.sleep(delay)
                    continue

                # SAFETY: strip any JSON-looking content the model might emit
                # despite the system prompt. We do NOT parse it — we just
                # return it as plain text, which is harmless.
                self.messages.append({"role": "assistant", "content": reply})
                return reply

            except requests.Timeout:
                self.log.error("chat timeout attempt %d", attempt)
            except requests.ConnectionError:
                self.log.error("chat connection lost attempt %d", attempt)
            except Exception as exc:  # noqa: BLE001
                self.log.error("chat error attempt %d: %s", attempt, exc)
            if attempt < retries:
                time.sleep(delay)

        return ""

    # ── intentionally no extract_tool_call() ──────────────────────────────────
    # Adding this method here would be a safety violation.
    # Any caller that needs tool calls must use AIClient, not ChatAIClient.
