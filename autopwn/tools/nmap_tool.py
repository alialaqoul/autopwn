# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""nmap wrapper — the primary port/service/OS discovery engine.

Autopwn builds the argument list from validated inputs; the model chooses a
scan *profile* rather than passing raw flags, so it cannot inject arbitrary
arguments.
"""
from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolResult
from .runner import ToolNotInstalled, run_command, which

# Curated profiles. Keeps the model on rails and inputs safe.
PROFILES: dict[str, list[str]] = {
    "quick":       ["-T4", "-F"],                      # fast, top 100 ports
    "default":     ["-T4", "-sV", "--top-ports", "1000"],
    "full_tcp":    ["-T4", "-p-", "-sV"],              # all 65535 TCP ports
    "service_os":  ["-T4", "-sV", "-O", "--top-ports", "1000"],
    "vuln":        ["-T4", "-sV", "--script", "vuln"], # NSE vuln scripts
    "udp_top":     ["-T4", "-sU", "--top-ports", "50"],
}


class NmapTool(Tool):
    category = "recon"
    name = "nmap_scan"
    description = (
        "Run an nmap scan against a target (host, range, or CIDR). Choose a "
        "profile: quick (top-100 fast), default (top-1000 + versions), "
        "full_tcp (all ports), service_os (versions + OS), vuln (NSE vuln "
        "scripts), udp_top. Returns discovered hosts, ports, and services."
    )
    active = True
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Host, IP, range, or CIDR (e.g. 10.0.0.0/24)."},
            "profile": {
                "type": "string",
                "enum": list(PROFILES.keys()),
                "description": "Scan profile. Default 'default'.",
            },
            "ports": {"type": "string",
                      "description": "Optional explicit ports e.g. '22,80,443' "
                                     "or '1-1000'. Overrides profile ports."},
        },
        "required": ["target"],
    }

    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        target = kwargs["target"]
        self._authorize(ctx, target)

        if which(self.nmap_path) is None:
            return ToolResult(
                ok=False,
                summary="nmap is not installed. Use native_port_scan instead, "
                        "or install nmap (https://nmap.org/download).",
            )

        profile = kwargs.get("profile", "default")
        args = PROFILES.get(profile, PROFILES["default"]).copy()
        if ports := kwargs.get("ports"):
            # sanitize: digits, commas, dashes only
            if all(c.isdigit() or c in ",-" for c in ports):
                args = [a for a in args if a not in
                        ("-F", "--top-ports") and not a.isdigit()]
                args += ["-p", ports]

        argv = [self.nmap_path, *args, target]
        try:
            res = run_command(argv, timeout=1800)
        except ToolNotInstalled as e:
            return ToolResult(ok=False, summary=str(e))

        ok = res.returncode == 0
        # Record discovered ports/services into the shared results store so the
        # service matrix and other commands (and background jobs) can see them.
        if ok and res.stdout:
            try:
                from ..parsers import parse_normal, record_to_store
                record_to_store(parse_normal(res.stdout))
                from ..facts import record_from_text
                record_from_text(res.stdout)
            except Exception:
                pass  # recording is best-effort; never fail a scan over it
        summary = (f"nmap {profile} scan of {target} "
                   f"({'complete' if ok else 'exit ' + str(res.returncode)})")
        return ToolResult(
            ok=ok,
            summary=summary,
            data={"target": target, "profile": profile,
                  "command": " ".join(argv)},
            raw_output=res.stdout or res.stderr,
        )
