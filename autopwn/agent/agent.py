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
from .prompts import STRUCTURED_SYSTEM, SYSTEM_PROMPT, tool_signatures
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

    def run(self, objective: str, seed_target: Optional[str] = None) -> str:
        ctx = ToolContext(
            scope=self.scope,
            confirm_active_actions=self.config.agent.confirm_active_actions,
        )
        self._structured = self.config.agent.structured
        system = (STRUCTURED_SYSTEM.replace(
            "{tools}", tool_signatures(self.registry.all()))
            if self._structured else SYSTEM_PROMPT)
        messages: list[Message] = [
            Message(role="system", content=system),
            Message(role="user",
                    content=f"Authorized scope: {self.scope.summary()}\n\n"
                            f"Objective: {objective}"),
        ]
        # Priming: give the model real recon data up front so it reacts instead
        # of planning from a blank slate (a big win for small models).
        if self.config.agent.prime_recon and seed_target:
            obs = self._prime(ctx, seed_target)
            if obs:
                messages.append(Message(
                    role="user",
                    content=f"Initial reconnaissance of {seed_target}:\n{obs}\n\n"
                            "Use this real data to choose your next action."))

        # Optional semantic tool retrieval: rank tools per step, pass only top-k.
        top_k = self.config.agent.tool_top_k
        retriever = None
        if top_k and top_k > 0:
            from ..retrieval import ToolRetriever
            retriever = ToolRetriever(self.provider, self.registry.all())

        final = "Agent stopped without producing findings."
        stalls = 0
        for step in range(1, self.config.agent.max_steps + 1):
            self.report("step", f"— step {step}/{self.config.agent.max_steps}")

            # Choose which tools to expose this step.
            if retriever:
                last = messages[-1].content if messages else ""
                active = retriever.top_k(f"{objective}\n{last}"[:1500], top_k)
                if len(active) < len(self.registry.all()):
                    self.report("thought",
                                "tools in play: " + ", ".join(t.name for t in active))
            else:
                active = self.registry.all()
            tool_specs = [t.spec() for t in active]
            if self._structured:
                messages[0] = Message(role="system",
                                      content=STRUCTURED_SYSTEM.replace(
                                          "{tools}", tool_signatures(active)))

            calls, finish_text, raw, native = self._decide(messages, tool_specs)

            if finish_text is not None:
                final = finish_text
                self.report("thought", final)
                self._log("final", {"content": final})
                break

            if not calls:
                stalls += 1
                if stalls > self.MAX_STALLS:
                    self.report("warn", "Model would not act; giving up.")
                    final = raw or final
                    self._log("final", {"content": final})
                    break
                self.report("warn", "No valid action — nudging the model.")
                self._log("stall", {"content": raw[:400]})
                messages.append(Message(role="assistant", content=raw))
                messages.append(Message(role="user", content=self.NUDGE))
                continue
            stalls = 0

            messages.append(Message(role="assistant", content=raw,
                                    tool_calls=calls if native else []))
            for call in calls:
                observation = self._execute(ctx, call.name, call.arguments)
                if native:
                    messages.append(Message(role="tool", content=observation,
                                            tool_call_id=call.id))
                else:
                    messages.append(Message(
                        role="user",
                        content=f"Result of {call.name}:\n{observation}\n\n"
                                "Choose the next action (or finish)."))
        else:
            self.report("warn", "Reached max steps.")
        return final

    def _decide(self, messages, tool_specs):
        """Get the next step. Returns (calls, finish_text, raw, native)."""
        import uuid
        from ..llm.base import ToolCall
        valid = {t.name for t in self.registry.all()}
        if self._structured:
            completion = self.provider.chat(
                messages, response_format={"type": "json_object"})
            raw = (completion.content or "").strip()
            obj = self._first_json(raw)
            if obj is None:
                return [], None, raw, False
            reasoning = obj.get("reasoning")
            if reasoning:
                self.report("thought", str(reasoning))
            action = obj.get("action") or obj.get("tool") or obj.get("name")
            params = obj.get("parameters") or obj.get("arguments") or {}
            if isinstance(action, str) and action.lower() == "finish":
                return [], (obj.get("findings") or raw), raw, False
            if action in valid:
                return ([ToolCall(id=f"s-{uuid.uuid4().hex[:8]}", name=action,
                                  arguments=params if isinstance(params, dict) else {})],
                        None, raw, False)
            return [], None, raw, False
        # Native tool-calling path (capable models).
        completion = self.provider.chat(messages, tools=tool_specs)
        raw = (completion.content or "").strip()
        if raw:
            self.report("thought", raw)
        native = bool(completion.tool_calls)
        calls = completion.tool_calls or parse_tool_calls(raw, valid)
        finish = raw if (not calls and raw.upper().startswith("FINDINGS:")) else None
        return calls, finish, raw, native

    @staticmethod
    def _first_json(text: str):
        from .toolparse import _iter_json_objects
        for obj in _iter_json_objects(text):
            if isinstance(obj, dict):
                return obj
        return None

    def _prime(self, ctx: ToolContext, target: str) -> str:
        """Return an initial recon observation — from the store if we already
        scanned this host, else a quick nmap scan."""
        try:
            from .. import store
            entry = store.all_hosts().get(target)
            if entry and any(p.get("state") == "open"
                             for p in entry.get("ports", {}).values()):
                lines = [f"{p['port']}/{p.get('proto', 'tcp')} "
                         f"{p.get('service', '')}".strip()
                         for p in sorted(entry["ports"].values(),
                                         key=lambda p: p["port"])
                         if p.get("state") == "open"]
                self.report("observation",
                            f"prime: reusing known scan of {target}")
                return "Open ports/services:\n" + "\n".join(lines)
        except Exception:
            pass
        self.report("action", f"priming recon: nmap_scan({target})")
        return self._execute(ctx, "nmap_scan",
                             {"target": target, "profile": "quick"})

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
