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
    # Safe-by-default gate: when False, tools flagged `intrusive` (exploits,
    # brute-force, relay/coercion, target writes) are BLOCKED before they run —
    # only recon + safe read-only checks proceed. Real entry points set this from
    # Config.allow_intrusive (default False); direct callers default True.
    allow_intrusive: bool = True


class Tool:
    #: unique tool name exposed to the model
    name: str = "tool"
    #: one-line description shown to the model
    description: str = ""
    #: True if the tool sends traffic to the target (recon scans included).
    active: bool = False
    #: True if the tool exploits / brute-forces / relays / coerces / writes to
    #: the target — a stricter subset of `active`. The safe-by-default gate
    #: (ToolContext.allow_intrusive=False) blocks these; recon/enum stays allowed.
    intrusive: bool = False
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

    def _intrusive_block(self, ctx: ToolContext):
        """Safe-by-default gate. Returns a BLOCKED ToolResult if this tool is
        intrusive and the context forbids intrusive actions, else None."""
        if getattr(self, "intrusive", False) and not getattr(ctx, "allow_intrusive", True):
            return ToolResult(ok=False, summary=(
                f"[BLOCKED] '{self.name}' is intrusive and Autopwn is in "
                "non-intrusive mode. Enable intrusive mode (Settings → allow "
                "intrusive, or --intrusive) to run exploits/brute-force/relay."))
        return None
