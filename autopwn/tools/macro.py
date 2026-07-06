# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Framework for native-Python "macro" tools.

A macro tool is a built-in tool (like ``ad_kill_chain``) written in Python: it
orchestrates other tools, parses their output *at the Autopwn level*, and returns
structured results (credentials, users, findings, loot). Two design goals:

  * **Transparency** — every step is logged as it happens; because macro tools run
    inside a job, that log streams straight to the console's live view, so the
    operator sees exactly what is happening.
  * **Integration** — recovered credentials/users are emitted in the same format
    the Findings view and the report already parse, so a macro tool's results
    show up automatically.

To add one: subclass ``MacroTool``, set ``name``/``description``/``parameters``/
``plan``, and implement ``execute(self, R, **kwargs)`` using the helpers
(``self.log``, ``self.sub``, ``self.add_cred``, ``self.add_user``,
``self.add_finding``). Register it in ``registry.default_registry`` next to the
other native tools. See ``SmbLootTool`` below for a worked example.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .base import Tool, ToolContext, ToolResult


@dataclass
class Results:
    """What a macro run discovered — filled in by the tool's execute()."""
    steps: list = field(default_factory=list)      # human-readable step log
    creds: list = field(default_factory=list)      # {username,password,domain,note}
    users: set = field(default_factory=set)
    findings: list = field(default_factory=list)   # {title,severity,cvss,...}
    loot: list = field(default_factory=list)       # {name,detail}
    flags: list = field(default_factory=list)


class MacroTool(Tool):
    """Base class for native multi-step tools. Subclasses implement execute()."""
    category = "macro"
    active = True
    #: ordered, human-readable description of what this macro does — shown in the
    #: Tools "View" so the operator knows exactly what it will do before running.
    plan: list = []
    #: which kwarg holds the host to authorize (None → no host authorization)
    host_param: Optional[str] = "target"

    # ---- subclasses implement this ---------------------------------------
    def execute(self, R: Results, **kwargs: Any) -> None:
        raise NotImplementedError

    # ---- runtime ---------------------------------------------------------
    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        from .registry import default_registry
        self._ctx = ctx
        self._reg = default_registry()
        self._R = R = Results()
        host = kwargs.get(self.host_param) if self.host_param else None
        if host:
            self._authorize(ctx, host)          # raises ScopeError if out of scope
        self.log(f"[*] {self.name} against {host or '(no host)'}")
        try:
            self.execute(R, **kwargs)
        except Exception as e:                  # a macro must never crash the job
            self.log(f"[!] {type(e).__name__}: {e}")
        return self._build(R, host)

    # ---- helpers for subclasses ------------------------------------------
    def log(self, msg: str) -> None:
        """Record a step and stream it to the job log (live in the console)."""
        try:
            print(msg, flush=True)
        except UnicodeEncodeError:              # non-UTF-8 console fallback
            print(msg.encode("ascii", "replace").decode(), flush=True)
        self._R.steps.append(msg)

    def sub(self, tool_name: str, **kwargs: Any) -> str:
        """Run another registered tool and return its raw output text ('' on error)."""
        t = self._reg.get(tool_name)
        if t is None:
            self.log(f"[!] sub-tool '{tool_name}' is unavailable")
            return ""
        try:
            r = t.run(self._ctx, **kwargs)
        except Exception as e:
            self.log(f"[!] {tool_name} error: {e}")
            return ""
        return r.raw_output or r.summary or ""

    def add_cred(self, username: str, password: str, domain: str = "",
                 note: str = "") -> None:
        if not any(c["username"] == username and c["password"] == password
                   for c in self._R.creds):
            self._R.creds.append({"username": username, "password": password,
                                  "domain": domain, "note": note or self.name})
        self._R.users.add(username)
        self.log(f"  │ credential: {username}:{password}"
                 + (f" @ {domain}" if domain else ""))

    def add_user(self, username: str) -> None:
        self._R.users.add(username)

    def add_finding(self, title: str, severity: str, description: str = "",
                    cvss: str = "", **extra: Any) -> None:
        self._R.findings.append({"title": title, "severity": severity,
                                 "cvss": cvss, "description": description, **extra})
        self.log(f"  │ finding [{severity}]: {title}")

    def add_loot(self, name: str, detail: str = "") -> None:
        self._R.loot.append({"name": name, "detail": detail})
        self.log(f"  │ loot: {name}")

    # ---- result assembly -------------------------------------------------
    def _build(self, R: Results, host) -> ToolResult:
        from .. import store
        lines = [f"{self.name} against {host or ''}"]
        lines += [f"  - {s}" for s in R.steps if not s.startswith("  │")]
        if R.users:
            lines.append(f"Users ({len(R.users)}): " + ", ".join(sorted(R.users)))
        for c in R.creds:                       # format the Findings view parses
            store.set_fact("username", c["username"])
            store.set_fact("password", c["password"])
            lines.append(f"Credential: {c['username']}:{c['password']} "
                         f"@ {c['domain'] or 'unknown'}")
        ok = bool(R.creds or R.findings or R.users or R.loot or R.flags)
        summary = (f"{self.name}: {len(R.creds)} cred(s), "
                   f"{len(R.findings)} finding(s), {len(R.users)} user(s)")
        return ToolResult(ok=ok, summary=summary, raw_output="\n".join(lines),
                          data={"creds": R.creds, "users": sorted(R.users),
                                "findings": R.findings, "loot": R.loot,
                                "flags": R.flags, "command": f"{self.name} {host or ''}"})


# ==========================================================================
# Worked example — a small native tool built on the framework.
# ==========================================================================
import re

_DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"}
_SHARE_ROW = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+((?:READ|WRITE)[\w,]*)", re.M)


class SmbLootTool(MacroTool):
    """Enumerate readable SMB shares with a credential and flag the non-default
    ones as looting targets — a small, transparent native tool."""
    name = "smb_loot"
    category = "ad-smb"
    description = ("Authenticate over SMB and list shares, then flag readable "
                   "non-default shares (backup/IT/transfer) that commonly leak "
                   "credentials. Native — parses share output at the Autopwn level.")
    plan = [
        "Authenticate over SMB and enumerate shares (netexec_smb --shares)",
        "Filter to readable, non-default shares",
        "Report each readable non-default share as a finding to loot",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to enumerate."},
            "username": {"type": "string", "description": "Username."},
            "password": {"type": "string", "description": "Password."},
            "domain": {"type": "string", "description": "AD domain (optional)."},
            "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (optional)."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        self.log(f"[run] enumerating SMB shares on {host}")
        out = self.sub("netexec_smb", target=host, username=kw.get("username", ""),
                       password=kw.get("password", ""), domain=kw.get("domain", ""),
                       hash=kw.get("hash", ""), enumerate="shares")
        readable = [(m.group(1), m.group(2)) for m in _SHARE_ROW.finditer(out)
                    if m.group(1).upper() not in _DEFAULT_SHARES]
        for share, perm in readable:
            self.log(f"  │ readable non-default share: {share} ({perm})")
            self.add_loot(f"\\\\{host}\\{share}", f"{perm} — loot for creds/backups")
        if readable:
            names = ", ".join(s for s, _ in readable)
            self.add_finding(
                f"Readable non-default SMB share(s): {names}", "Medium", cvss="5.3",
                description="Non-default SMB shares are readable with this credential "
                            "and may expose credentials, backups, scripts (GPP "
                            "cpassword), or KeePass/config files.")
        else:
            self.log("no readable non-default shares")
