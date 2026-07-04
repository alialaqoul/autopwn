# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Tool contract.

A Tool exposes a JSON-schema describing its parameters (so the LLM can call it)
and a run() method. Every tool that touches a network target must call
`ctx.authorize(target)` before acting — the base class provides a helper.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..authorization import Scope


@dataclass
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""

    def as_observation(self) -> str:
        """Compact text the LLM reads back as the result of its action."""
        head = f"[{'OK' if self.ok else 'ERROR'}] {self.summary}"
        if self.raw_output:
            clipped = self.raw_output[:4000]
            return f"{head}\n{clipped}"
        return head


@dataclass
class ToolContext:
    scope: "Scope"
    confirm_active_actions: bool = True
    # Set False by the agent when the model is not permitted to run intrusive
    # tools (e.g. exploit modules) without explicit human sign-off.
    allow_active: bool = True


class Tool:
    #: unique tool name exposed to the model
    name: str = "tool"
    #: one-line description shown to the model
    description: str = ""
    #: True if the tool sends traffic that alters remote state / is intrusive
    active: bool = False
    #: category for grouping: recon | web | ad-smb | credentials | exploit
    category: str = "misc"
    #: JSON schema for parameters (OpenAI function-calling format)
    parameters: dict[str, Any] = {"type": "object", "properties": {}}

    def spec(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        raise NotImplementedError

    # helper for subclasses
    @staticmethod
    def _authorize(ctx: ToolContext, target: str) -> None:
        ctx.scope.authorize(target)
