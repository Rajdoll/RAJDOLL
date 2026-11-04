"""OpenAI-compatible chat client with structured output (TRD 5.1, 5.4).

One request per call: `response_format` carries the task's JSON schema (LM Studio enforces it
with a grammar), `<think>` blocks are stripped from the answer, and thinking is switched off with
Qwen's `/no_think` marker unless the settings enable it. The client never goes through the egress
proxy: the LLM is not a target.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

_THINK = re.compile(r"<think>.*?</think>\s*", re.S | re.I)
_ORPHAN_THINK = re.compile(r"</?think>\s*", re.I)
NO_THINK = "/no_think"


class LlmUnavailable(Exception):
    """The server could not be reached (connection refused, DNS, TLS)."""


class LlmTimeout(Exception):
    """The server did not answer within the task's time limit."""


class LlmError(Exception):
    """The server answered with an error or an unusable body."""


@dataclass(frozen=True)
class LlmConfig:
    base_url: str
    model: str
    api_key: str | None = None
    thinking: bool = False


@dataclass(frozen=True)
class Completion:
    text: str
    tokens_in: int | None
    tokens_out: int | None
    duration_ms: int


def strip_thinking(text: str) -> str:
    return _ORPHAN_THINK.sub("", _THINK.sub("", text or "")).strip()


def extract_json(text: str) -> Any:
    """The JSON object in a model's answer (tolerates code fences and text around it)."""
    cleaned = strip_thinking(text)
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned.strip())
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(cleaned[start : end + 1])


class LlmClient:
    def __init__(self, config: LlmConfig, transport: httpx.BaseTransport | None = None) -> None:
        self.config = config
        self.transport = transport

    def _messages(self, messages: list[dict[str, str]]) -> list[dict[str, str]]:
        if self.config.thinking or not messages:
            return messages
        first, *rest = messages
        if first.get("role") == "system":
            return [{**first, "content": f"{first['content']}\n{NO_THINK}"}, *rest]
        return [{"role": "system", "content": NO_THINK}, *messages]

    def complete(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | None,
        name: str,
        max_tokens: int,
        timeout_s: float,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": self._messages(messages),
            "max_tokens": max_tokens,
            "temperature": 0.2,
            "stream": False,
        }
        if schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": name, "strict": False, "schema": schema},
            }
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        started = time.monotonic()
        try:
            with httpx.Client(
                transport=self.transport, timeout=timeout_s, trust_env=False
            ) as client:
                response = client.post(url, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise LlmTimeout(str(exc)) from exc
        except httpx.TransportError as exc:
            raise LlmUnavailable(f"{type(exc).__name__}: {exc}") from exc
        duration_ms = int((time.monotonic() - started) * 1000)
        if response.status_code >= 400:
            raise LlmError(f"HTTP {response.status_code}: {response.text[:300]}")
        try:
            body = response.json()
            text = body["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LlmError(f"jawaban tidak dikenali: {response.text[:300]}") from exc
        usage = body.get("usage") or {}
        return Completion(
            text=text,
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
            duration_ms=duration_ms,
        )

    def ping(self, timeout_s: float = 30) -> Completion:
        """A tiny structured call for the connection test in the settings."""
        schema = {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        }
        messages = [{"role": "user", "content": 'Balas dengan JSON {"ok": true}.'}]
        return self.complete(messages, schema, "ping", max_tokens=20, timeout_s=timeout_s)
