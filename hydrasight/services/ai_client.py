"""Ollama /api/chat wrapper with context-window management."""
import json
import logging
import time
import re
from typing import Optional

import requests

from hydrasight.config.defaults import SYSTEM_PROMPT


class AIClient:
    """Manages conversation history and communicates with Ollama."""

    def __init__(
        self,
        base_url : str,
        model    : str,
        context  : int,
        log      : logging.Logger,
    ) -> None:
        self.base         = base_url.rstrip("/")
        self.model        = model
        self.context      = context
        self.log          = log
        self.sess         = requests.Session()
        self.total_tokens = 0
        self.call_count   = 0
        self.messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

    # ── health ────────────────────────────────────────────────────────────────

    def health(self) -> tuple[bool, str]:
        try:
            r = self.sess.get(f"{self.base}/api/tags", timeout=5)
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}"
            models = [m["name"] for m in r.json().get("models", [])]
            match  = next(
                (m for m in models
                 if m == self.model
                 or m.startswith(self.model.split(":")[0])),
                None,
            )
            if match:
                return True, match
            avail = ", ".join(models[:3]) if models else "none"
            return (
                False,
                f"model missing — run: ollama pull {self.model}"
                f" (available: {avail})",
            )
        except requests.ConnectionError:
            return False, "ollama not running — run: ollama serve"
        except requests.Timeout:
            return False, "ollama timeout"
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    # ── context management ────────────────────────────────────────────────────

    def _trim(self, budget: int = 6000) -> None:
        """Remove oldest non-system messages to stay under token budget."""
        sys_msgs = [m for m in self.messages if m["role"] == "system"]
        other    = [m for m in self.messages if m["role"] != "system"]
        while other:
            total = (
                sum(len(str(m["content"])) for m in sys_msgs + other) // 4
            )
            if total <= budget:
                break
            other.pop(0)
        self.messages = sys_msgs + other

    def reset_for_engagement(self) -> None:
        """Hard-reset context before autopwn to prevent context bleed."""
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.log.info("context reset for new engagement")

    def reset(self) -> None:
        """Full reset including counters."""
        self.messages     = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.total_tokens = 0
        self.call_count   = 0

    # ── inference ─────────────────────────────────────────────────────────────

    def ask(
        self,
        content : str,
        retries : int   = 3,
        delay   : float = 2.0,
    ) -> str:
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
                            "temperature": 0.1,
                            "top_p"      : 0.9,
                            "num_predict": 1024,
                        },
                    },
                    timeout=180,
                )
                r.raise_for_status()
                data  = r.json()
                reply = (
                    data.get("message", {}).get("content", "")
                    or data.get("response", "")
                ).strip()
                self.total_tokens += (
                    data.get("usage", {}).get("total_tokens", 0)
                    or data.get("eval_count", 0)
                    + data.get("prompt_eval_count", 0)
                )
                if not reply:
                    self.log.warning("empty response attempt %d", attempt)
                    if attempt < retries:
                        time.sleep(delay)
                    continue
                self.messages.append(
                    {"role": "assistant", "content": reply}
                )
                return reply
            except requests.Timeout:
                self.log.error("ai timeout attempt %d", attempt)
            except requests.ConnectionError:
                self.log.error("ai connection lost attempt %d", attempt)
            except Exception as exc:  # noqa: BLE001
                self.log.error("ai error attempt %d: %s", attempt, exc)
            if attempt < retries:
                time.sleep(delay)
        return ""

    def extract_tool_call(self, text: str) -> Optional[dict]:
        """Extract a JSON tool-call dict from model response text."""
        if not text:
            return None
        text = re.sub(r"```(?:json)?|```", "", text).strip()
        try:
            d = json.loads(text)
            if isinstance(d, dict) and "tool" in d:
                return d
        except json.JSONDecodeError:
            pass
        for m in re.finditer(
            r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL
        ):
            try:
                d = json.loads(m.group())
                if isinstance(d, dict) and "tool" in d:
                    return d
            except json.JSONDecodeError:
                continue
        return None
