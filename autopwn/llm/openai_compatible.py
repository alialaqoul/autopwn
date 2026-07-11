# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""OpenAI-compatible chat provider.

Covers OpenAI itself plus every backend that speaks the same /chat/completions
wire format: Ollama (/v1), LM Studio, vLLM, AnythingLLM's OpenAI endpoint, and
most local runtimes. Tool-calling is used when the model supports it; the agent
also has a text-based fallback for models that don't.
"""
from __future__ import annotations

import json
import time
from typing import Optional

import httpx

from . import calllog
from .base import Completion, LLMProvider, Message, ToolCall


class OpenAICompatibleProvider(LLMProvider):
    def __init__(self, model: str, base_url: str, api_key: Optional[str],
                 temperature: float = 0.2, max_tokens: int = 2048,
                 name: str = "openai_compatible", timeout: float = 600.0,
                 embed_model: Optional[str] = None):
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.embed_model = embed_model
        # Short connect timeout (fail fast if the server is down) but a long
        # read timeout, since CPU-only local inference can take minutes.
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0)
        )

    def chat(self, messages: list[Message],
             tools: Optional[list[dict]] = None,
             response_format: Optional[dict] = None) -> Completion:
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
        if response_format:
            # Force valid JSON output (Ollama/OpenAI "JSON mode") so weak models
            # can't emit prose/tutorials instead of an action.
            payload["response_format"] = response_format

        t0 = time.monotonic()
        prompt_chars = sum(len(m.content or "") for m in messages)
        # Full request captured for the Settings log (content capped so the log
        # file can't run away on very long conversations).
        _CAP = 12000
        req_msgs = []
        for m in messages:
            row = {"role": m.role, "content": (m.content or "")[:_CAP]}
            if m.tool_calls:
                row["tool_calls"] = [{"name": tc.name, "arguments": tc.arguments}
                                     for tc in m.tool_calls]
            req_msgs.append(row)

        def _log(ok, **extra):
            calllog.record({"kind": "chat", "model": self.model,
                            "base_url": self.base_url, "ok": ok,
                            "duration_ms": int((time.monotonic() - t0) * 1000),
                            "prompt_chars": prompt_chars,
                            "with_tools": bool(tools),
                            "tool_count": len(tools) if tools else 0,
                            "request": req_msgs, **extra})

        try:
            resp = self._client.post(
                f"{self.base_url}/chat/completions",
                headers=headers, json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            _log(False, error=f"HTTP {e.response.status_code}: {e.response.text[:200]}")
            raise RuntimeError(
                f"LLM request failed ({e.response.status_code}): "
                f"{e.response.text[:500]}"
            ) from e
        except httpx.RequestError as e:
            _log(False, error=f"connection: {e}")
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
        content = choice.get("content") or ""
        _log(True, completion_chars=len(content), tool_calls=len(tool_calls),
             usage=data.get("usage"),
             response={"content": content[:12000],
                       "tool_calls": [{"name": tc.name, "arguments": tc.arguments}
                                      for tc in tool_calls]})
        return Completion(content=content, tool_calls=tool_calls)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Return embedding vectors for texts (OpenAI-compatible /embeddings)."""
        # An empty batch makes some /v1/embeddings servers 400 — nothing to do.
        texts = [t for t in (texts or []) if (t or "").strip()]
        if not texts:
            return []
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = self._client.post(
            f"{self.base_url}/embeddings",
            headers=headers,
            json={"model": self.embed_model or self.model, "input": texts},
        )
        resp.raise_for_status()
        return [d["embedding"] for d in resp.json()["data"]]
