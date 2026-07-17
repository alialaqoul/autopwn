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
    "bloodhound_python": {"ports": [389, 636, 3268], "services": ["ldap"]},
    "certipy_find":      {"ports": [389, 636], "services": ["ldap"]},
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
    # Extended web tools (cheat-sheet additions) — same web surface.
    "httpx":       {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081, 5985], "services": ["http"]},
    "katana":      {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "feroxbuster": {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "arjun":       {"web": True, "ports": [80, 443, 8080, 8443, 8000, 8081], "services": ["http"]},
    "testssl":     {"web": True, "ports": [443, 8443, 993, 995, 465], "services": ["ssl", "https"]},
    "subzy":       {"web": True, "ports": [80, 443, 8080, 8443], "services": ["http"]},
    # Enterprise management / monitoring servers (host-target, not URL).
    "product_recon": {"ports": [443, 8443, 8444, 8081, 8082, 8000, 8089, 9997,
                                8080, 8530, 8531, 9877, 9876, 7780, 17777, 17778,
                                17790, 17791, 1812, 1813],
                      "services": ["http", "splunk", "radius"]},
    "default_creds": {"ports": [443, 8443, 8444, 8081, 8082, 8000, 8089, 9997,
                                8080, 9877, 9876, 7780],
                      "services": ["http", "splunk"]},
    # Network devices & firewalls (host-target).
    "net_device_recon": {"ports": [22, 23, 80, 443, 161, 4786, 8443, 10443, 830, 541],
                         "services": ["ssh", "telnet", "http", "snmp"]},
    "snmp_audit":       {"ports": [161, 22, 23, 443, 4786],
                         "services": ["snmp", "ssh", "telnet"]},
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


# Banners that speak HTTP but are NOT browsable web apps — web content tools
# (wpscan/nikto/ffuf/…) shouldn't be pointed at these.
_NON_WEBAPP = ("httpapi", "winrm", "wsman", "wsdapi", "mcafee", "rpc over http")
# Tools that only make sense against a real web application.
_WEB_CONTENT = {"wpscan", "nikto", "ffuf", "gobuster_dir", "sqlmap",
                "feroxbuster", "arjun", "katana", "subzy"}


def _is_web_app(service: str, version: str) -> bool:
    # Require the service to actually BE http/https (not e.g. ncacn_http = RPC
    # over HTTP), then reject non-browsable banners (WinRM/HTTPAPI/McAfee).
    s = (service or "").lower().replace("ssl/", "").replace("ssl|", "").rstrip("?")
    if not s.startswith("http"):
        return False
    return not any(b in (version or "").lower() for b in _NON_WEBAPP)


def tools_applicable_to(host: str, tools):
    """Filter *tools* to those relevant to a single host's open ports.

    Uses the nmap banner/version, not just the service name: web *content*
    tools apply only to ports that are actual web apps (so wpscan/nikto don't
    fire at a DC's WinRM/HTTPAPI ports). Unmapped tools (recon, OSINT, local
    crackers) are always kept.
    """
    entry = store.all_hosts().get(host, {})
    ports = [p for p in entry.get("ports", {}).values()
             if p.get("state") == "open"]
    if not ports:
        return list(tools)  # nothing discovered yet — don't over-filter
    open_ports = [(p["port"], p.get("service", "")) for p in ports]
    has_web_app = any(_is_web_app(p.get("service", ""), p.get("version", ""))
                      for p in ports)
    out = []
    for t in tools:
        meta = TOOL_SERVICES.get(t.name)
        if meta is None:
            out.append(t)
        elif t.name in _WEB_CONTENT:
            if has_web_app:
                out.append(t)
        elif any(_matches(meta, port, svc) for port, svc in open_ports):
            out.append(t)
    return out


def mapped_tools() -> set[str]:
    return set(TOOL_SERVICES)
