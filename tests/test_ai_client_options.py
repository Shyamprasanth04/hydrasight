"""
Tests for AIClient / ChatAIClient options injection, model matching, and
<think> tag stripping in extract_tool_call().

All tests are offline — no live Ollama or network required.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from hydrasight.config.defaults import (
    _DEFAULT_OLLAMA_OPTIONS_CHAT,
    _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR,
)
from hydrasight.services.ai_client import AIClient, _model_base
from hydrasight.services.chat_ai_client import ChatAIClient

_LOG = logging.getLogger("test")


# ── _model_base() ─────────────────────────────────────────────────────────────


class TestModelBase:
    def test_strips_tag(self):
        assert _model_base("qwen2.5:7b") == "qwen2.5"

    def test_strips_namespace_and_tag(self):
        result = _model_base("qcwind/qwen3-8b-instruct-Q4-K-M:latest")
        assert result == "qwen3-8b-instruct-q4-k-m"

    def test_no_tag_no_namespace(self):
        assert _model_base("llama3") == "llama3"

    def test_namespace_only_no_tag(self):
        assert _model_base("ns/mymodel") == "mymodel"

    def test_case_insensitive(self):
        assert _model_base("NS/MyModel:Latest") == "mymodel"


# ── AIClient health() model matching ─────────────────────────────────────────


def _make_client(model: str, options: dict | None = None) -> AIClient:
    return AIClient("http://localhost:11434", model, 8192, _LOG, options=options)


class TestHealthModelMatching:
    def _mock_tags(self, models: list[str]):
        """Return a mock requests response for /api/tags."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"models": [{"name": m} for m in models]}
        return resp

    def test_exact_match(self):
        client = _make_client("qwen2.5:7b")
        with patch.object(client.sess, "get", return_value=self._mock_tags(["qwen2.5:7b"])):
            ok, match = client.health()
        assert ok is True
        assert match == "qwen2.5:7b"

    def test_namespaced_model_matches_base(self):
        """qcwind/qwen3-8b-instruct-Q4-K-M:latest should match even if Ollama
        returns the model without the qcwind/ prefix in its tag list."""
        client = _make_client("qcwind/qwen3-8b-instruct-Q4-K-M:latest")
        ollama_name = "qwen3-8b-instruct-q4-k-m:latest"
        with patch.object(client.sess, "get", return_value=self._mock_tags([ollama_name])):
            ok, match = client.health()
        assert ok is True
        assert match == ollama_name

    def test_model_missing(self):
        client = _make_client("missing-model:latest")
        with patch.object(client.sess, "get", return_value=self._mock_tags(["qwen2.5:7b"])):
            ok, msg = client.health()
        assert ok is False
        assert "model missing" in msg

    def test_connection_error(self):
        import requests

        client = _make_client("any:model")
        with patch.object(client.sess, "get", side_effect=requests.ConnectionError):
            ok, msg = client.health()
        assert ok is False
        assert "ollama not running" in msg


# ── AIClient options injection ────────────────────────────────────────────────


class TestAIClientOptions:
    def _make_ask_response(self, content: str):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "message": {"content": content},
            "eval_count": 10,
            "prompt_eval_count": 5,
        }
        resp.raise_for_status = MagicMock()
        return resp

    def test_default_options_in_payload(self):
        client = _make_client("test:model")
        resp = self._make_ask_response('{"tool":"nmap_scan","args":{}}')
        with patch.object(client.sess, "post", return_value=resp) as mock_post:
            client.ask("scan 192.168.1.1")
        payload = mock_post.call_args[1]["json"]
        assert payload["options"]["temperature"] == _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR["temperature"]
        assert payload["options"]["repeat_penalty"] == _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR["repeat_penalty"]
        assert payload["options"]["think"] is False

    def test_custom_options_override_defaults(self):
        custom = {"temperature": 0.99, "num_predict": 42}
        client = _make_client("test:model", options=custom)
        resp = self._make_ask_response("hello")
        with patch.object(client.sess, "post", return_value=resp) as mock_post:
            client.ask("hi")
        payload = mock_post.call_args[1]["json"]
        assert payload["options"]["temperature"] == 0.99
        assert payload["options"]["num_predict"] == 42
        # think=False should still be there from defaults
        assert payload["options"]["think"] is False

    def test_think_false_in_orchestrator_defaults(self):
        assert _DEFAULT_OLLAMA_OPTIONS_ORCHESTRATOR.get("think") is False

    def test_think_not_in_chat_defaults(self):
        # Chat path doesn't need think=False (it's not sending tool calls)
        assert "think" not in _DEFAULT_OLLAMA_OPTIONS_CHAT


# ── ChatAIClient options injection ────────────────────────────────────────────


class TestChatAIClientOptions:
    def _make_client(self, options: dict | None = None) -> ChatAIClient:
        return ChatAIClient("http://localhost:11434", "test:model", 8192, _LOG, options=options)

    def _make_ask_response(self, content: str):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"message": {"content": content}}
        resp.raise_for_status = MagicMock()
        return resp

    def test_default_options_in_payload(self):
        client = self._make_client()
        resp = self._make_ask_response("hello")
        with patch.object(client.sess, "post", return_value=resp) as mock_post:
            client.ask("hi")
        payload = mock_post.call_args[1]["json"]
        assert payload["options"]["temperature"] == _DEFAULT_OLLAMA_OPTIONS_CHAT["temperature"]
        assert payload["options"]["repeat_penalty"] == _DEFAULT_OLLAMA_OPTIONS_CHAT["repeat_penalty"]

    def test_custom_options_override_defaults(self):
        client = self._make_client(options={"temperature": 0.5})
        resp = self._make_ask_response("hello")
        with patch.object(client.sess, "post", return_value=resp) as mock_post:
            client.ask("hi")
        payload = mock_post.call_args[1]["json"]
        assert payload["options"]["temperature"] == 0.5

    def test_num_ctx_from_options(self):
        client = self._make_client(options={"num_ctx": 4096})
        assert client._options["num_ctx"] == 4096

    def test_num_ctx_falls_back_to_context_size_arg(self):
        """If options dict doesn't specify num_ctx, use context_size arg."""
        client = ChatAIClient("http://localhost:11434", "test:model", 2048, _LOG)
        assert client._options["num_ctx"] == 2048


# ── extract_tool_call() think-tag stripping ───────────────────────────────────


class TestExtractToolCall:
    def _client(self) -> AIClient:
        return _make_client("test:model")

    def test_clean_json(self):
        tc = self._client().extract_tool_call(
            '{"tool":"nmap_scan","args":{"target":"10.0.0.1","scan_type":"-sV","ports":"1-1000","additional_args":""}}'
        )
        assert tc is not None
        assert tc["tool"] == "nmap_scan"

    def test_strips_think_tags(self):
        text = (
            "<think>Let me think about this request carefully...</think>"
            '\n{"tool":"nmap_scan","args":{"target":"10.0.0.1","scan_type":"-sV","ports":"80","additional_args":""}}'
        )
        tc = self._client().extract_tool_call(text)
        assert tc is not None
        assert tc["tool"] == "nmap_scan"

    def test_strips_multiline_think_tags(self):
        text = (
            "<think>\n"
            "  I need to produce a tool call here.\n"
            "  The right tool is nmap.\n"
            "</think>\n"
            '{"tool":"gobuster_scan","args":{"url":"http://10.0.0.1","wordlist":"/tmp/w.txt","extensions":""}}'
        )
        tc = self._client().extract_tool_call(text)
        assert tc is not None
        assert tc["tool"] == "gobuster_scan"

    def test_strips_markdown_fence(self):
        text = '```json\n{"tool":"nikto_scan","args":{"target":"10.0.0.1","port":80}}\n```'
        tc = self._client().extract_tool_call(text)
        assert tc is not None
        assert tc["tool"] == "nikto_scan"

    def test_think_tag_then_fence_then_json(self):
        text = (
            "<think>reasoning</think>\n"
            "```json\n"
            '{"tool":"smb_enum","args":{"target":"10.0.0.2"}}\n'
            "```"
        )
        tc = self._client().extract_tool_call(text)
        assert tc is not None
        assert tc["tool"] == "smb_enum"

    def test_prose_with_embedded_json(self):
        text = (
            'Here is my response: {"tool":"whatweb_scan","args":{"url":"http://10.0.0.1"}} '
            "as requested."
        )
        tc = self._client().extract_tool_call(text)
        assert tc is not None
        assert tc["tool"] == "whatweb_scan"

    def test_empty_text_returns_none(self):
        assert self._client().extract_tool_call("") is None

    def test_only_think_tags_returns_none(self):
        assert self._client().extract_tool_call("<think>just thinking</think>") is None

    def test_malformed_json_returns_none(self):
        assert self._client().extract_tool_call('{"tool": "nmap_scan", "args": BROKEN}') is None

    def test_json_without_tool_key_returns_none(self):
        assert self._client().extract_tool_call('{"other": "key"}') is None
