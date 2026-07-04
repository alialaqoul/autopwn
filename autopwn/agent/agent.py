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
    #: after this many failed credential guesses on one host, block further ones
    CRED_FAIL_LIMIT = 2
    #: consecutive failed/blocked credential guesses that abort the run
    CRED_SPIN_LIMIT = 3
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
        # Credential-guessing guardrail state (per run). Small local models tend
        # to burn steps trying default passwords one-by-one; we cap that.
        self._auth_fails: dict[str, int] = {}
        self._tried_creds: set[tuple] = set()
        self._cred_spin = 0
        self._abort = False
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

        # Scope tools to those applicable to the target's discovered ports so
        # the agent doesn't run e.g. wpscan/SMB tools on hosts that lack them.
        base_tools = self.registry.all()
        if seed_target and getattr(self.config.agent, "scope_tools", True):
            from ..applicability import tools_applicable_to
            base_tools = tools_applicable_to(seed_target, base_tools)
        # Drop tools that REQUIRE credentials until we actually have some, so the
        # agent doesn't waste steps on kerberoast/secretsdump with no creds.
        from .. import store as _st
        if not (_st.facts().get("username") and _st.facts().get("password")):
            base_tools = [t for t in base_tools if not self._needs_creds(t)]
        self.report("thought", f"applicable tools for {seed_target or 'objective'}: "
                    + ", ".join(t.name for t in base_tools))

        # Optional semantic tool retrieval: rank tools per step, pass only top-k.
        top_k = self.config.agent.tool_top_k
        retriever = None
        if top_k and top_k > 0:
            from ..retrieval import ToolRetriever
            retriever = ToolRetriever(self.provider, base_tools)

        # RAG knowledge base: retrieve pentest methodology to guide decisions.
        kb = None
        if getattr(self.config.agent, "use_kb", True):
            from ..kb import KnowledgeBase
            kb = KnowledgeBase(self.provider)
            if kb.load():
                self.report("thought",
                            f"knowledge base: {len(kb.chunks)} playbook chunks loaded")
            else:
                kb = None

        final = "Agent stopped without producing findings."
        stalls = 0
        for step in range(1, self.config.agent.max_steps + 1):
            self.report("step", f"— step {step}/{self.config.agent.max_steps}")

            last = messages[-1].content if messages else ""
            query = f"{objective}\n{last}"[:1500]

            # Choose which tools to expose this step.
            active = retriever.top_k(query, top_k) if retriever else base_tools
            tool_specs = [t.spec() for t in active]

            # Retrieve methodology guidance for the current situation (RAG).
            kb_text = ""
            if kb:
                guidance = kb.retrieve(query, self.config.agent.kb_top_k)
                if guidance:
                    kb_text = ("\n\nRELEVANT METHODOLOGY (retrieved knowledge — "
                               "follow it):\n" + "\n\n".join(guidance))

            base_sys = (STRUCTURED_SYSTEM.replace("{tools}", tool_signatures(active))
                        if self._structured else SYSTEM_PROMPT)
            messages[0] = Message(role="system", content=base_sys + kb_text)

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
            if self._abort:
                self.report("warn", "Repeated failed logins with no valid "
                            "credentials — stopping the password-guessing loop "
                            "and synthesising findings.")
                break
        else:
            self.report("warn", "Reached max steps.")

        # Synthesise a grounded executive summary if the model didn't produce a
        # real one — this is the AI's interpretation of the collected evidence.
        if getattr(self.config.agent, "synthesize", True):
            if not self._is_real_findings(final):
                self.report("step", "— synthesising findings")
                syn = self._synthesize()
                if syn:
                    final = syn
                    self.report("final", syn)

        # Append the deterministic evidence block so the report is grounded in
        # real scan data regardless of what the model wrote.
        evidence = self._evidence(seed_target)
        if evidence:
            final = f"{final}\n\n{evidence}"
        return final

    @staticmethod
    def _needs_creds(tool) -> bool:
        req = set(tool.parameters.get("required", []))
        return "username" in req and "password" in req

    @staticmethod
    def _is_real_findings(text: str) -> bool:
        t = (text or "").strip()
        if not t or len(t) < 20:
            return False
        if t.startswith("{") and "action" in t[:40]:
            return False
        return not t.startswith("Assessment complete")

    def _synthesize(self) -> str:
        """Ask the model to write an executive summary from the real evidence."""
        try:
            from .. import store
            from ..analysis import assess
        except Exception:
            return ""
        a = assess(store.all_hosts(), store.facts())
        ev = [a["summary"]]
        for h in a["hosts"]:
            ev.append(f"\nHost {h['host']} — role: {h['role']}")
            ev += [f"  - {o}" for o in h["observations"]]
        acts = [e for e in self.transcript if e.get("kind") == "tool_result"]
        if acts:
            ev.append("\nTool results:")
            ev += [f"  - {e.get('name')}: {'OK' if e.get('ok') else 'failed'} — "
                   f"{e.get('summary', '')[:100]}" for e in acts[:25]]
        prompt = [
            Message(role="system", content=(
                "You are a penetration tester writing the executive summary of "
                "an assessment report. Use ONLY the evidence provided below. Be "
                "concrete and concise: state each host's role, the key exposures/"
                "misconfigurations actually observed, and the most likely attack "
                "paths. Do NOT invent CVEs, versions, or findings.")),
            Message(role="user", content="EVIDENCE:\n" + "\n".join(ev) +
                    "\n\nWrite the executive summary (a short paragraph plus a "
                    "short bulleted list of attack paths)."),
        ]
        try:
            c = self.provider.chat(prompt)
            return (c.content or "").strip()
        except Exception:
            return ""

    def _evidence(self, target: Optional[str]) -> str:
        """Build a factual evidence block from the results store."""
        try:
            from .. import store
        except Exception:
            return ""
        lines = ["--- EVIDENCE (from tool output, not the model) ---"]
        facts = store.facts()
        if facts:
            lines.append("Discovered variables: " +
                         ", ".join(f"{k}={v}" for k, v in facts.items()))
        hosts = store.all_hosts()
        targets = [target] if target and target in hosts else list(hosts)
        for h in targets:
            entry = hosts.get(h, {})
            ports = [p for p in entry.get("ports", {}).values()
                     if p.get("state") == "open"]
            if not ports:
                continue
            name = entry.get("hostname", "")
            lines.append(f"{h}{(' (' + name + ')') if name else ''} — open:")
            for p in sorted(ports, key=lambda p: p["port"]):
                svc = p.get("service", "")
                ver = p.get("version", "")
                lines.append(f"  {p['port']}/{p.get('proto','tcp')} {svc}"
                             + (f"  [{ver}]" if ver else ""))
        return "\n".join(lines) if len(lines) > 1 else ""

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
                fin = obj.get("findings") or obj.get("summary")
                return [], (fin or "Assessment complete — see evidence below."), raw, False
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
        """Deterministic baseline: a broad nmap scan of the target, then a
        NetExec SMB check on every discovered SMB host to capture signing /
        null-auth / domain. This guarantees the store holds the facts that
        findings are built from, regardless of what the model chooses to do."""
        from .. import store

        def _is_range(t):
            return "/" in t or "-" in t

        # Scan: reuse a prior scan of a single host, else run the broad default.
        entry = store.all_hosts().get(target)
        if entry and not _is_range(target) and any(
                p.get("state") == "open" for p in entry.get("ports", {}).values()):
            self.report("observation", f"prime: reusing known scan of {target}")
        else:
            self.report("action", f"priming recon: nmap_scan({target})")
            self._execute(ctx, "nmap_scan", {"target": target, "profile": "default"})

        # SMB enrichment: run netexec_smb on each host with 445 open that has no
        # signing fact yet, so signing/null-auth/domain findings are reliable.
        smb_hosts = [h for h, e in store.all_hosts().items()
                     if any(p.get("port") == 445 and p.get("state") == "open"
                            for p in e.get("ports", {}).values())
                     and not e.get("facts", {}).get("smb_signing")]
        if smb_hosts and self.registry.get("netexec_smb"):
            self.report("action", f"priming: netexec_smb on {len(smb_hosts)} "
                        "SMB host(s) to capture signing/null-auth/domain")
            for h in smb_hosts[:32]:
                try:
                    self._execute(ctx, "netexec_smb", {"target": h})
                except Exception:
                    pass

        # Build the observation from whatever is now in the store for the target.
        e2 = store.all_hosts().get(target)
        if e2 and any(p.get("state") == "open" for p in e2.get("ports", {}).values()):
            lines = [(f"{p['port']}/{p.get('proto', 'tcp')} {p.get('service', '')} "
                      f"{p.get('version', '')}").strip()
                     for p in sorted(e2["ports"].values(), key=lambda p: p["port"])
                     if p.get("state") == "open"]
            return "Open ports/services on the target:\n" + "\n".join(lines)
        # For a range, summarise discovered hosts.
        hs = store.host_summary()
        if hs:
            return ("Discovered hosts:\n" + "\n".join(
                f"{h['host']} {h['hostname']}: {', '.join(map(str, h['open_ports'][:12]))}"
                for h in hs[:40]))
        return ""

    def _execute(self, ctx: ToolContext, name: str, args: dict) -> str:
        tool = self.registry.get(name)
        if tool is None:
            msg = f"[ERROR] Unknown tool '{name}'."
            self._log("tool_error", {"name": name, "error": "unknown"})
            return msg

        # Credential-guessing guardrail: an authenticated attempt is any call
        # carrying a non-empty password at a host. Small models spray default
        # passwords one-at-a-time, which is slow (a full LLM round-trip per
        # guess) and pointless. Block repeats and stop after a few failures.
        host = args.get("target") or args.get("host") or ""
        pw, user = args.get("password"), args.get("username", "")
        is_cred = bool(pw) and bool(host)
        if is_cred:
            key = (host, str(user), str(pw))
            if key in self._tried_creds:
                self._cred_spin += 1
                if self._cred_spin >= self.CRED_SPIN_LIMIT:
                    self._abort = True
                return (f"[BLOCKED] {user or '(blank)'}:{pw} was already tried on "
                        f"{host} and failed. Do not repeat or guess credentials.")
            if self._auth_fails.get(host, 0) >= self.CRED_FAIL_LIMIT:
                self._cred_spin += 1
                if self._cred_spin >= self.CRED_SPIN_LIMIT:
                    self._abort = True
                return (f"[BLOCKED] {self._auth_fails[host]} credential guesses "
                        f"already failed on {host}; you have NO valid credentials "
                        f"for it. Stop guessing passwords one-by-one — continue "
                        f"unauthenticated enumeration or move to another host. "
                        f"(Bulk credential testing needs a wordlist spray, not "
                        f"single guesses.)")

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

        # Update the credential guardrail from the result.
        if is_cred:
            self._tried_creds.add(key)
            blob = (result.summary + " " + (result.raw_output or "")).upper()
            raw = result.raw_output or ""
            failed = ("LOGON_FAILURE" in blob or "ACCESS_DENIED" in blob
                      or "ACCOUNT_LOCKED" in blob
                      or ("[-]" in raw and "[+]" not in raw))
            if failed:
                self._auth_fails[host] = self._auth_fails.get(host, 0) + 1
                self._cred_spin += 1
                if self._cred_spin >= self.CRED_SPIN_LIMIT:
                    self._abort = True
            else:
                self._cred_spin = 0  # a valid login breaks the guess loop
        else:
            self._cred_spin = 0  # any non-credential action resets the counter

        self._log("tool_result", {"name": name, "args": args,
                                  "ok": result.ok, "summary": result.summary,
                                  "command": result.data.get("command", ""),
                                  "output": (result.raw_output or "")[:2000]})
        self.report("observation", result.summary)
        # Surface the actual command output (clipped) so `watch` shows results.
        if result.ok and result.raw_output and result.raw_output.strip():
            snippet = "\n".join(result.raw_output.strip().splitlines()[:20])
            self.report("output", snippet)
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
