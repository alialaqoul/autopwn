# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Provider-agnostic LLM interface.

Every backend (cloud or local) is normalized to this contract so the agent
never cares which model is behind it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: Optional[str] = None  # set on role=="tool" replies

    def to_api(self) -> dict:
        msg: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name,
                                 "arguments": _json(tc.arguments)},
                }
                for tc in self.tool_calls
            ]
        if self.tool_call_id:
            msg["tool_call_id"] = self.tool_call_id
        return msg


@dataclass
class Completion:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMProvider(Protocol):
    """Contract all providers implement."""

    name: str

    def chat(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
    ) -> Completion:
        ...


def _json(obj: Any) -> str:
    import json
    return json.dumps(obj)
