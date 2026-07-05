# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""User-defined tools (actions), editable from the web console.

Built-in tools live in `catalog.py` as Python. To let an operator add or tweak
actions without touching code, a custom tool is stored declaratively in
``<log_dir>/tools.json`` and turned into a real ``CommandSpec`` at registry
build time — so a tool created in the UI is immediately usable by the agent,
the `run` command, and any playbook that references it.

A custom tool is intentionally limited to the *declarative* argv model
(binary + subcommand + positional + flags + fixed); that is exactly what makes
"how this action runs" transparent and safe (argv list, never a shell string).
Parameters are derived automatically from the positional/flag variables.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..facts import HarvestRule
from .command import (CommandSpec, host_from_domain, host_from_target,
                      host_from_url)

_PATH = Path("logs") / "tools.json"

_HOST_RESOLVERS = {
    "target": host_from_target,
    "url": host_from_url,
    "domain": host_from_domain,
}


def configure(log_dir) -> None:
    global _PATH
    _PATH = Path(log_dir) / "tools.json"


def load() -> list[dict]:
    """Raw custom-tool dicts as authored in the UI."""
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save(tools: list[dict]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(tools, indent=2), encoding="utf-8")
    tmp.replace(_PATH)


def _derive_params(d: dict) -> dict:
    """Build a JSON-schema for the tool from its positional + flag variables."""
    props: dict = {}
    for var in d.get("positional", []):
        props[var] = {"type": "string", "description": f"{var} (positional)"}
    for var in d.get("flags", {}):
        props.setdefault(var, {"type": "string", "description": var})
    required = [v for v in d.get("positional", []) if v]
    return {"type": "object", "properties": props, "required": required}


def _harvest_rules(d: dict) -> list:
    """Build HarvestRules from a custom tool's declared variable extractions, so
    any variable the tool's output matches is captured into the engagement
    automatically (and then autofilled into later tools)."""
    rules = []
    for h in d.get("harvest", []) or []:
        var, regex = (h.get("var") or "").strip(), h.get("regex") or ""
        if not var or not regex:
            continue
        try:
            re.compile(regex)
        except re.error:
            continue
        rules.append(HarvestRule(var=var, regex=regex,
                                 scope=h.get("scope", "global"),
                                 group=int(h.get("group", 1)),
                                 multi=bool(h.get("multi", False))))
    return rules


def to_spec(d: dict) -> CommandSpec:
    """Turn a stored custom-tool dict into a runnable CommandSpec."""
    host_from = d.get("host_from", "target")
    return CommandSpec(
        name=d["name"],
        description=d.get("description", ""),
        binary=d["binary"],
        parameters=d.get("parameters") or _derive_params(d),
        active=bool(d.get("active", True)),
        category=d.get("category", "custom"),
        host_resolver=_HOST_RESOLVERS.get(host_from, host_from_target),
        requires_host=bool(d.get("requires_host", True)),
        timeout=int(d.get("timeout", 900)),
        install_hint=d.get("install_hint", ""),
        subcommand=list(d.get("subcommand", [])),
        positional=list(d.get("positional", [])),
        flags=dict(d.get("flags", {})),
        fixed=list(d.get("fixed", [])),
        harvest=_harvest_rules(d),
    )


def specs() -> list[CommandSpec]:
    out = []
    for d in load():
        try:
            if d.get("name") and d.get("binary"):
                out.append(to_spec(d))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def command_template(spec: CommandSpec) -> str:
    """A readable one-line preview of the argv a declarative spec builds."""
    parts = [spec.binary, *spec.subcommand]
    for var in spec.positional:
        parts.append(f"<{var}>")
    for var, flag in spec.flags.items():
        if flag == "":
            parts.append(f"[{var}]")
        elif "{v}" in flag:
            parts.append(f"[{flag.replace('{v}', var)}]")
        else:
            parts.append(f"[{flag} <{var}>]")
    parts.extend(spec.fixed)
    return " ".join(parts)
