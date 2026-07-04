# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""OpenAI-compatible chat provider.

Covers OpenAI itself plus every backend that speaks the same /chat/completions
wire format: Ollama (/v1), LM Studio, vLLM, AnythingLLM's OpenAI endpoint, and
most local runtimes. Tool-calling is used when the model supports it; the agent
also has a text-based fallback for models that don't.
"""
from __future__ import annotations

import json
from typing import Optional

import httpx

from .base import Completion, LLMProvider, Message, ToolCall


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, model: str, base_url: str, api_key: Optional[str],
                 temperature: float = 0.2, max_tokens: int = 2048,
                 name: str = "openai_compatible", timeout: float = 600.0):
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        # Short connect timeout (fail fast if the server is down) but a long
        # read timeout, since CPU-only local inference can take minutes.
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0)
        )

    def chat(self, messages: list[Message],
             tools: Optional[list[dict]] = None) -> Completion:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload: dict = {
            "model": self.model,
            "messages": [m.to_api() for m in messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            resp = self._client.post(
                f"{self.base_url}/chat/completions",
                headers=headers, json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"LLM request failed ({e.response.status_code}): "
                f"{e.response.text[:500]}"
            ) from e
        except httpx.RequestError as e:
            raise RuntimeError(
                f"Could not reach LLM at {self.base_url}: {e}. "
                "Is the model server running?"
            ) from e

        data = resp.json()
        choice = data["choices"][0]["message"]
        tool_calls: list[ToolCall] = []
        for tc in choice.get("tool_calls") or []:
            fn = tc.get("function", {})
            args = fn.get("arguments") or "{}"
            try:
                parsed = json.loads(args) if isinstance(args, str) else args
            except json.JSONDecodeError:
                parsed = {"_raw": args}
            tool_calls.append(
                ToolCall(id=tc.get("id", ""), name=fn.get("name", ""),
                         arguments=parsed)
            )
        return Completion(content=choice.get("content") or "",
                          tool_calls=tool_calls)
