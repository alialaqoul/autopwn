# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Map tools to the services they apply to, and expand a tool over the matrix.

Given the discovered service→hosts picture in the results store, this figures
out which hosts a given tool should run against (e.g. an SMB tool → every host
with 445 open) and builds the per-host arguments (a `target` for host-based
tools, or a `http(s)://host:port/` URL for web tools).
"""
from __future__ import annotations

from typing import Optional

from . import store

# For each tool: which ports/service-name fragments make a host "applicable",
# whether it takes a URL (web) instead of a host target, and any URL suffix.
TOOL_SERVICES: dict[str, dict] = {
    # SMB / Windows
    "netexec_smb":      {"ports": [139, 445], "services": ["microsoft-ds", "smb", "netbios"]},
    "netexec_winrm":    {"ports": [5985, 5986], "services": ["wsman", "winrm"]},
    "smbmap":           {"ports": [139, 445], "services": ["microsoft-ds", "smb", "netbios"]},
    "smbclient_shares": {"ports": [139, 445], "services": ["microsoft-ds", "smb", "netbios"]},
    "enum4linux":       {"ports": [139, 445], "services": ["microsoft-ds", "smb", "netbios"]},
    "secretsdump":      {"ports": [139, 445], "services": ["microsoft-ds", "smb"]},
    # LDAP / Directory
    "netexec_ldap":     {"ports": [389, 636, 3268, 3269], "services": ["ldap"]},
    "ldapsearch_anon":  {"ports": [389, 636, 3268, 3269], "services": ["ldap"]},
    # Kerberos / AD auth
    "kerbrute_userenum": {"ports": [88], "services": ["kerberos"]},
    "asrep_roast":       {"ports": [88], "services": ["kerberos"]},
    "kerberoast":        {"ports": [88], "services": ["kerberos"]},
    # DNS
    "dns_recon":        {"ports": [53], "services": ["domain", "dns"]},
    # Web (URL-based)
    "whatweb":  {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8008, 8081], "services": ["http"]},
    "http_probe": {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8008, 8081, 5985], "services": ["http"]},
    "nikto":    {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "nuclei":   {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "gobuster_dir": {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "wpscan":   {"web": True, "ports": [80, 443, 8080, 8443], "services": ["http"]},
    "sqlmap":   {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "ffuf":     {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"],
                 "url_suffix": "FUZZ"},
}


def _scheme(port: int, service: str) -> str:
    s = (service or "").lower()
    if "https" in s or "ssl" in s or port in (443, 8443, 993, 995):
        return "https"
    return "http"


def _matches(meta: dict, port: int, service: str) -> bool:
    if port in meta.get("ports", []):
        return True
    svc = (service or "").lower()
    return any(frag in svc for frag in meta.get("services", []))


def targets_for_tool(tool_name: str) -> list[dict]:
    """Return per-host argument dicts for running *tool_name* over the matrix.

    Each item: {"label": <str for display>, "kwargs": {"target"|"url": ...}}.
    Empty if the tool has no service mapping or nothing applicable was found.
    """
    meta = TOOL_SERVICES.get(tool_name)
    if not meta:
        return []
    web = meta.get("web", False)
    suffix = meta.get("url_suffix", "")
    out: list[dict] = []
    seen_hosts: set[str] = set()
    for host, entry in store.all_hosts().items():
        matched: list[tuple[int, str]] = []
        for p in entry.get("ports", {}).values():
            if p.get("state") != "open":
                continue
            if _matches(meta, p["port"], p.get("service", "")):
                matched.append((p["port"], p.get("service", "")))
        if not matched:
            continue
        if web:
            for port, svc in matched:
                url = f"{_scheme(port, svc)}://{host}:{port}/{suffix}"
                out.append({"label": url, "kwargs": {"url": url}})
        else:
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            out.append({"label": host, "kwargs": {"target": host}})
    return out


def applicable_count(tool_name: str) -> int:
    return len(targets_for_tool(tool_name))


def mapped_tools() -> set[str]:
    return set(TOOL_SERVICES)
