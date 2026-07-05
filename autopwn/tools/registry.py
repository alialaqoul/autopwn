# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Registry mapping tool names to instances and building LLM tool specs."""
from __future__ import annotations

from dataclasses import replace

from ..config import ToolsConfig
from .ad_chain import AdChainTool
from .base import Tool
from .catalog import CATALOG
from .command import GenericCommandTool
from .http_probe import HttpProbeTool
from .nmap_tool import NmapTool
from .port_scan import PortScanTool
from .runner import which


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def specs(self, include_active: bool = True) -> list[dict]:
        return [t.spec() for t in self._tools.values()
                if include_active or not t.active]

    def names(self) -> list[str]:
        return sorted(self._tools)


def _resolve_binary(spec) -> str | None:
    """Return the first of the spec's binary/aliases that exists on PATH."""
    for candidate in (spec.binary, *spec.aliases):
        if which(candidate) is not None:
            return candidate
    return None


def default_registry(tools_cfg: ToolsConfig | None = None,
                     include_unavailable: bool = False) -> ToolRegistry:
    """Build the registry.

    Native tools are always present. Catalogued external tools are included only
    when their binary is installed (unless include_unavailable=True, used by the
    `tools` CLI command to show the whole catalog).
    """
    cfg = tools_cfg or ToolsConfig()
    reg = ToolRegistry()

    # Always-available native tools.
    reg.register(PortScanTool())
    reg.register(NmapTool(nmap_path=cfg.nmap_path))
    reg.register(HttpProbeTool())
    reg.register(AdChainTool())  # macro-action: full AD kill chain

    # Catalogued external tools.
    for spec in CATALOG:
        found = _resolve_binary(spec)
        if found is None and not include_unavailable:
            continue
        # Bind the actually-present binary name (handles aliases).
        bound = replace(spec, binary=found) if found else spec
        reg.register(GenericCommandTool(bound))

    # User-defined tools (created in the web console, stored in tools.json).
    # Registered last so an operator can extend — or intentionally override — the
    # catalogue. Included only when their binary is installed (like the catalogue).
    from . import custom
    for spec in custom.specs():
        found = _resolve_binary(spec)
        if found is None and not include_unavailable:
            continue
        bound = replace(spec, binary=found) if found else spec
        reg.register(GenericCommandTool(bound))

    return reg
