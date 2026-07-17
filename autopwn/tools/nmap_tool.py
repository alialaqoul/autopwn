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

# Curated port list for the default scan: common services PLUS enterprise/AD
# ports that are NOT all in nmap's top-1000 — Kerberos/LDAP/GC/ADWS/kpasswd,
# WinRM, WSUS (8530/8531), endpoint-mgmt consoles (ePO 8443/8444), databases,
# and web-alt ports. Also the management/monitoring appliances that run an
# estate: Splunk (8089 mgmt, 9997 receiver), SolarWinds SWIS (17777-17791),
# Acronis Cyber Protect (7780/9876/9877). This is what makes enterprise
# services actually discovered.
_DEFAULT_PORTS = (
    "21,22,23,25,53,67,69,80,88,110,111,123,135,137,139,143,161,389,443,445,"
    "464,500,514,515,548,593,623,636,873,993,995,1099,1433,1521,1723,2049,2121,"
    "2181,3128,3268,3269,3306,3389,4444,5000,5040,5060,5432,5555,5601,5900,5985,"
    "5986,6379,6443,7001,7780,8000,8008,8009,8080,8081,8088,8089,8161,8443,8444,"
    "8530,8531,8888,9000,9090,9200,9389,9443,9876,9877,9997,10000,11211,17777,"
    "17778,17790,17791,27017,47001,49152,49664")

PROFILES: dict[str, list[str]] = {
    "quick":       ["-T4", "-F"],                      # fast, top 100 ports
    "default":     ["-T4", "-sV", "-p", _DEFAULT_PORTS],
    "full_tcp":    ["-T4", "-p-", "-sV"],              # all 65535 TCP ports
    "service_os":  ["-T4", "-sV", "-O", "-p", _DEFAULT_PORTS],
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
                # drop any existing port selection (-F / --top-ports N / -p list)
                clean, skip = [], False
                for a in args:
                    if skip:
                        skip = False; continue
                    if a == "-F":
                        continue
                    if a in ("--top-ports", "-p"):
                        skip = True; continue
                    clean.append(a)
                args = clean + ["-p", ports]

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
