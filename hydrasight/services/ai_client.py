"""Ollama /api/chat wrapper with context-window management."""

import json
import logging
import re
import time

import requests

from hydrasight.config.defaults import (
    _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR,
    SYSTEM_PROMPT,
)


def _model_base(model: str) -> str:
    """Return lowercase base name, stripping namespace prefix and :tag suffix.

    Examples:
      'qcwind/qwen3-8b-instruct-Q4-K-M:latest' -> 'qwen3-8b-instruct-q4-k-m'
      'qwen2.5:7b'                              -> 'qwen2.5'
      'llama3.1:8b-instruct-q4_k_m'            -> 'llama3.1'
    """
    base = model.split(":")[0]   # strip :tag
    base = base.split("/")[-1]   # strip namespace/
    return base.lower()


class AIClient:
    """Manages conversation history and communicates with Ollama (orchestration path)."""

    def __init__(
        self,
        base_url: str,
        model: str,
        context: int,
        log: logging.Logger,
        options: dict | None = None,
    ) -> None:
        self.base = base_url.rstrip("/")
        self.model = model
        self.context = context
        self.log = log
        # Merge caller-supplied options over the built-in defaults
        self._options: dict = dict(_DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR)
        if options:
            self._options.update(options)
        # Ensure num_ctx reflects the context arg (config may override)
        self._options.setdefault("num_ctx", context)
        self.sess = requests.Session()
        self.total_tokens = 0
        self.call_count = 0
        self.messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

    # ── health ────────────────────────────────────────────────────────────────

    def health(self) -> tuple[bool, str]:
        try:
            r = self.sess.get(f"{self.base}/api/tags", timeout=5)
            if r.status_code != 200:
                return False, f"HTTP {r.status_code}"
            models = [m["name"] for m in r.json().get("models", [])]
            # Exact match first; then loose base-name match to handle namespaced tags
            match = next(
                (
                    m
                    for m in models
                    if m == self.model or _model_base(m) == _model_base(self.model)
                ),
                None,
            )
            if match:
                return True, match
            avail = ", ".join(models[:3]) if models else "none"
            return (
                False,
                f"model missing — run: ollama pull {self.model} (available: {avail})",
            )
        except requests.ConnectionError:
            return False, "ollama not running — run: ollama serve"
        except requests.Timeout:
            return False, "ollama timeout"
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    # ── context management ────────────────────────────────────────────────────

    def _trim(self, budget: int | None = None) -> None:
        """Remove oldest non-system messages to stay under token budget."""
        effective_budget = budget if budget is not None else self._options.get("num_predict", 6000)
        sys_msgs = [m for m in self.messages if m["role"] == "system"]
        other = [m for m in self.messages if m["role"] != "system"]
        while other:
            total = sum(len(str(m["content"])) for m in sys_msgs + other) // 4
            if total <= effective_budget:
                break
            other.pop(0)
        self.messages = sys_msgs + other

    def reset_for_engagement(self) -> None:
        """Hard-reset context before autopwn to prevent context bleed."""
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.log.info("context reset for new engagement")

    def reset(self) -> None:
        """Full reset including counters."""
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.total_tokens = 0
        self.call_count = 0

    # ── inference ─────────────────────────────────────────────────────────────

    def ask(
        self,
        content: str,
        retries: int = 3,
        delay: float = 2.0,
        token_budget: int | None = None,
    ) -> str:
        self.messages.append({"role": "user", "content": content})
        self._trim(token_budget)
        self.call_count += 1
        for attempt in range(1, retries + 1):
            try:
                r = self.sess.post(
                    f"{self.base}/api/chat",
                    json={
                        "model": self.model,
                        "messages": self.messages,
                        "stream": False,
                        "options": self._options,
                    },
                    timeout=180,
                )
                r.raise_for_status()
                data = r.json()
                reply = (
                    data.get("message", {}).get("content", "") or data.get("response", "")
                ).strip()
                self.total_tokens += data.get("usage", {}).get("total_tokens", 0) or (
                    data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
                )
                if not reply:
                    self.log.warning("empty response attempt %d", attempt)
                    if attempt < retries:
                        time.sleep(delay)
                    continue
                self.messages.append({"role": "assistant", "content": reply})
                return str(reply)
            except requests.Timeout:
                self.log.error("ai timeout attempt %d", attempt)
            except requests.ConnectionError:
                self.log.error("ai connection lost attempt %d", attempt)
            except Exception as exc:  # noqa: BLE001
                self.log.error("ai error attempt %d: %s", attempt, exc)
            if attempt < retries:
                time.sleep(delay)
        return ""

    def extract_tool_call(self, text: str) -> dict | None:
        """Extract a JSON tool-call dict from model response text.

        Handles:
          - <think>...</think> blocks (Qwen3 chain-of-thought leakage)
          - ```json ... ``` markdown fences
          - Extra prose before/after a JSON object
          - Partial structured responses (fails closed — returns None)
        """
        if not text:
            return None

        # 1. Strip <think>...</think> blocks (Qwen3 thinking mode leakage)
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        # 2. Strip markdown code fences
        text = re.sub(r"```(?:json)?|```", "", text).strip()

        # 3. Try the whole remaining text as JSON
        try:
            d = json.loads(text)
            if isinstance(d, dict) and "tool" in d:
                return d
        except json.JSONDecodeError:
            pass

        # 4. Extract first JSON object from mixed text
        for m in re.finditer(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL):
            try:
                d = json.loads(m.group())
                if isinstance(d, dict) and "tool" in d:
                    return d
            except json.JSONDecodeError:
                continue

        return None
