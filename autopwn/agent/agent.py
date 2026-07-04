# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""The reason/act agent loop.

The agent sends the objective + tool specs to the LLM, executes whatever tool
the model calls, feeds the observation back, and repeats until the model emits
a FINDINGS summary or the step budget is exhausted. Every step is logged.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from ..authorization import Scope, ScopeError
from ..config import Config
from ..llm.base import LLMProvider, Message
from ..tools.base import ToolContext
from ..tools.registry import ToolRegistry
from .prompts import SYSTEM_PROMPT
from .toolparse import parse_tool_calls

# Callback signature for surfacing progress to a UI/CLI.
Reporter = Callable[[str, str], None]  # (event_type, text)


class Agent:
    #: how many consecutive narrate-instead-of-act turns to tolerate
    MAX_STALLS = 3
    #: corrective sent when the model writes prose instead of calling a tool
    NUDGE = (
        "You did NOT call a tool. Do not explain, plan, summarize, or write "
        "code. Respond with EXACTLY ONE tool call as a single JSON object and "
        "nothing else, for example:\n"
        '{"name": "nmap_scan", "parameters": {"target": "TARGET"}}\n'
        "Choose the next concrete action toward the objective and emit only "
        "that JSON now. When you are truly finished, reply with a line starting "
        "'FINDINGS:' instead."
    )

    def __init__(self, config: Config, provider: LLMProvider,
                 registry: ToolRegistry, scope: Scope,
                 reporter: Optional[Reporter] = None):
        self.config = config
        self.provider = provider
        self.registry = registry
        self.scope = scope
        self.report = reporter or (lambda kind, text: None)
        self.transcript: list[dict] = []

    def _confirm_active(self, tool_name: str, args: dict) -> bool:
        """Hook for human-in-the-loop on intrusive tools. Default: allow.

        The CLI overrides this by assigning a real prompt function.
        """
        return True

    confirm_hook: Callable[[str, dict], bool] | None = None

    def run(self, objective: str) -> str:
        ctx = ToolContext(
            scope=self.scope,
            confirm_active_actions=self.config.agent.confirm_active_actions,
        )
        messages: list[Message] = [
            Message(role="system", content=SYSTEM_PROMPT),
            Message(role="user",
                    content=f"Authorized scope: {self.scope.summary()}\n\n"
                            f"Objective: {objective}"),
        ]
        tool_specs = self.registry.specs()

        final = "Agent stopped without producing findings."
        stalls = 0  # consecutive turns where the model narrated instead of acting
        for step in range(1, self.config.agent.max_steps + 1):
            self.report("step", f"— step {step}/{self.config.agent.max_steps}")
            completion = self.provider.chat(messages, tools=tool_specs)

            if completion.content:
                self.report("thought", completion.content)

            structured = bool(completion.tool_calls)
            calls = completion.tool_calls
            # Fallback: some models narrate the call as JSON in the content
            # instead of using the tool_calls field. Recover it from text.
            if not calls:
                calls = parse_tool_calls(completion.content,
                                         {t.name for t in self.registry.all()})

            content = (completion.content or "").strip()
            if not calls:
                # An explicit FINDINGS report is a real finish.
                if content.upper().startswith("FINDINGS:"):
                    final = content
                    self._log("final", {"content": final})
                    break
                # Otherwise the model narrated / wrote a tutorial instead of
                # acting. Do NOT accept prose as the answer — nudge and retry.
                stalls += 1
                if stalls > self.MAX_STALLS:
                    self.report("warn", "Model kept narrating; giving up.")
                    final = content or final
                    self._log("final", {"content": final})
                    break
                self.report("warn", "No tool call — nudging the model to act.")
                self._log("stall", {"content": content[:400]})
                messages.append(Message(role="assistant", content=content))
                messages.append(Message(role="user", content=self.NUDGE))
                continue
            stalls = 0  # a real action resets the stall counter

            # Record the assistant turn. Only attach structured tool_calls when
            # the model actually produced them (so tool-role replies match).
            messages.append(Message(
                role="assistant",
                content=completion.content,
                tool_calls=completion.tool_calls if structured else [],
            ))

            for call in calls:
                observation = self._execute(ctx, call.name, call.arguments)
                if structured:
                    messages.append(Message(role="tool", content=observation,
                                            tool_call_id=call.id))
                else:
                    # No tool protocol in play; feed the result back as user text.
                    messages.append(Message(
                        role="user",
                        content=f"Result of {call.name}:\n{observation}\n\n"
                                "Continue toward the objective, or reply with a "
                                "line starting 'FINDINGS:' if you are done."))

            if completion.content.strip().upper().startswith("FINDINGS:"):
                final = completion.content
                break
        else:
            self.report("warn", "Reached max steps.")

        return final

    def _execute(self, ctx: ToolContext, name: str, args: dict) -> str:
        tool = self.registry.get(name)
        if tool is None:
            msg = f"[ERROR] Unknown tool '{name}'."
            self._log("tool_error", {"name": name, "error": "unknown"})
            return msg

        # Human-in-the-loop gate for intrusive tools.
        if tool.active and ctx.confirm_active_actions and self.confirm_hook:
            if not self.confirm_hook(name, args):
                self._log("tool_skipped", {"name": name, "args": args})
                return f"[SKIPPED] Operator declined to run '{name}'."

        self.report("action", f"{name}({json.dumps(args)})")
        try:
            result = tool.run(ctx, **args)
        except ScopeError as e:
            self._log("scope_denied", {"name": name, "args": args,
                                       "error": str(e)})
            return f"[DENIED] {e}"
        except TypeError as e:
            return f"[ERROR] Bad arguments for '{name}': {e}"
        except Exception as e:  # tool crashed; report, keep the loop alive
            self._log("tool_exception", {"name": name, "error": repr(e)})
            return f"[ERROR] Tool '{name}' failed: {e}"

        self._log("tool_result", {"name": name, "args": args,
                                  "ok": result.ok, "summary": result.summary})
        self.report("observation", result.summary)
        return result.as_observation()

    def _log(self, kind: str, payload: dict) -> None:
        self.transcript.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind, **payload,
        })

    def save_transcript(self, log_dir: str) -> Path:
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = d / f"session-{stamp}.json"
        path.write_text(json.dumps(self.transcript, indent=2), encoding="utf-8")
        return path
