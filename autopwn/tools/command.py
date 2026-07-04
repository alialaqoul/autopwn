# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Declarative wrapper turning an external CLI tool into an agent Tool.

Instead of a hand-written class per tool, each tool is described by a
``CommandSpec``: its binary, a JSON-schema for parameters the model fills in, a
function that turns those parameters into an argv list, and how to find the host
to authorize. ``GenericCommandTool`` runs it safely (argv list, never a shell
string) through the shared runner, enforcing scope first.

Adding a new tool is a few lines in ``catalog.py`` — no new class.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

from .base import Tool, ToolContext, ToolResult
from .runner import ToolNotInstalled, run_command, which

# Builds the argument list (everything after the binary) from the model's args.
ArgBuilder = Callable[[dict], list[str]]
# Extracts the host/IP to authorize from the model's args.
HostResolver = Callable[[dict], Optional[str]]
# Optional text piped to the process's stdin.
StdinBuilder = Callable[[dict], Optional[str]]


def host_from_target(kwargs: dict) -> Optional[str]:
    return kwargs.get("target")


def host_from_url(kwargs: dict) -> Optional[str]:
    url = kwargs.get("url") or kwargs.get("target")
    if not url:
        return None
    try:
        return httpx.URL(url).host
    except Exception:
        return None


def host_from_domain(kwargs: dict) -> Optional[str]:
    """For domain-scoped tools: authorize on the domain (or target)."""
    return kwargs.get("domain") or kwargs.get("target")


@dataclass
class CommandSpec:
    name: str
    description: str
    binary: str
    parameters: dict
    #: Explicit arg builder. Optional — if omitted, argv is built declaratively
    #: from subcommand + positional + flags + fixed (the easy way to add tools).
    build_args: Optional[ArgBuilder] = None
    active: bool = True
    #: grouping category: recon | web | ad-smb | credentials | exploit
    category: str = "misc"
    host_resolver: HostResolver = host_from_target
    #: False for local tools (e.g. searchsploit) that don't touch a target.
    requires_host: bool = True
    timeout: int = 900
    stdin: Optional[StdinBuilder] = None
    aliases: list[str] = field(default_factory=list)
    install_hint: str = ""

    # -- declarative argv construction (used when build_args is None) --------
    #: fixed leading tokens, e.g. ["smb"] for `nxc smb ...`
    subcommand: list[str] = field(default_factory=list)
    #: canonical vars rendered as positional args, in order, e.g. ["target"]
    positional: list[str] = field(default_factory=list)
    #: canonical var -> CLI flag. "{v}" placeholder allowed, else `flag value`.
    #: A value of "" makes it a bare boolean flag (emitted only when truthy).
    flags: dict[str, str] = field(default_factory=dict)
    #: always-on tokens appended at the end, e.g. ["-no-pass", "-request"]
    fixed: list[str] = field(default_factory=list)
    #: regex→variable rules to harvest from this tool's output (facts.HarvestRule)
    harvest: list = field(default_factory=list)

    def render_args(self, kwargs: dict) -> list[str]:
        """Declarative argv builder from subcommand/positional/flags/fixed."""
        argv: list[str] = list(self.subcommand)
        for var in self.positional:
            if kwargs.get(var) not in (None, ""):
                argv.append(str(kwargs[var]))
        for var, flag in self.flags.items():
            val = kwargs.get(var)
            if val in (None, ""):
                continue
            if flag == "":                       # bare boolean flag
                continue
            if "{v}" in flag:                    # templated, e.g. "--{v}"
                argv.append(flag.replace("{v}", str(val)))
            else:                                # "flag value"
                argv.extend([flag, str(val)])
        argv.extend(self.fixed)
        return argv


class GenericCommandTool(Tool):
    def __init__(self, spec: CommandSpec):
        self._spec = spec
        self.name = spec.name
        self.description = spec.description
        self.active = spec.active
        self.category = spec.category
        self.parameters = spec.parameters

    @property
    def binary(self) -> str:
        return self._spec.binary

    def available(self) -> bool:
        return which(self._spec.binary) is not None

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        spec = self._spec

        host = spec.host_resolver(kwargs)
        if spec.requires_host:
            if host:
                self._authorize(ctx, host)  # raises ScopeError if out of scope
            else:
                return ToolResult(
                    ok=False,
                    summary=f"{spec.name}: could not determine a target host to "
                            "authorize from arguments.")

        if which(spec.binary) is None:
            hint = f" {spec.install_hint}" if spec.install_hint else ""
            return ToolResult(ok=False,
                              summary=f"'{spec.binary}' is not installed.{hint}")

        try:
            args = spec.build_args(kwargs) if spec.build_args \
                else spec.render_args(kwargs)
            argv = [spec.binary, *args]
        except (KeyError, TypeError, ValueError) as e:
            return ToolResult(ok=False,
                              summary=f"{spec.name}: bad arguments ({e}).")

        stdin_text = spec.stdin(kwargs) if spec.stdin else None
        try:
            res = run_command(argv, timeout=spec.timeout, input_text=stdin_text)
        except ToolNotInstalled as e:
            return ToolResult(ok=False, summary=str(e))

        ok = res.returncode == 0
        out = res.stdout if res.stdout.strip() else res.stderr
        # Harvest canonical variables (domain, hostname, creds…) from the output
        # using the default rules plus this tool's own harvest rules.
        try:
            from ..facts import record_from_text
            got = record_from_text(out, host=host, extra=spec.harvest)
            if got:
                from ..facts import CANONICAL
                learned = ", ".join(f"{k}={v}" for k, v in got.items()
                                    if k in CANONICAL)
                if learned:
                    self._last_learned = learned  # surfaced by callers if useful
        except Exception:
            pass
        summary = (f"{spec.name} against {host} "
                   f"({'ok' if ok else 'exit ' + str(res.returncode)})")
        return ToolResult(ok=ok, summary=summary,
                          data={"host": host, "command": " ".join(argv),
                                "returncode": res.returncode},
                          raw_output=out)
