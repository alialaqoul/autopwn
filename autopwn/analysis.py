# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Deterministic security analysis of the results store.

Turns raw open ports/services/banners into a real assessment — each host's
likely role, the notable exposures, and concrete attack paths — using
rule-based logic. This gives the report substance independent of the LLM, so
even a weak local model produces a useful deliverable. The LLM's job is then to
*synthesise* a narrative over this, not to invent it.
"""
from __future__ import annotations

from typing import Any


def _open(entry: dict) -> dict[int, dict]:
    return {p["port"]: p for p in entry.get("ports", {}).values()
            if p.get("state") == "open"}


def _role(ports: set[int], banners: str) -> str:
    b = banners.lower()
    if {88, 389, 445}.issubset(ports) or ({88, 389} <= ports and 3268 in ports):
        return "Active Directory Domain Controller"
    if 445 in ports and ("windows" in b or 3389 in ports or 135 in ports):
        return "Windows host / file server"
    if {80, 443} & ports and "apache" in b:
        return "Apache web server"
    if {80, 443} & ports and ("nginx" in b or "iis" in b):
        return "Web server"
    if {80, 443, 8080, 8443} & ports:
        return "Web server"
    if 22 in ports:
        return "Linux / SSH host"
    if {1433, 3306, 5432, 27017, 6379} & ports:
        return "Database server"
    return "Unknown / generic host"


def assess_host(host: str, entry: dict) -> dict:
    ports = _open(entry)
    pset = set(ports)
    banners = " ".join(f"{p.get('service','')} {p.get('version','')}"
                       for p in ports.values())
    role = _role(pset, banners)
    obs: list[str] = []
    paths: list[str] = []

    is_dc = role == "Active Directory Domain Controller"
    if is_dc:
        obs.append("Active Directory Domain Controller: Kerberos (88), LDAP "
                   "(389/636), Global Catalog (3268/3269), SMB (445), DNS (53).")
        paths += [
            "Enumerate users without creds: kerbrute userenum, then AS-REP "
            "roast accounts lacking pre-auth (asrep_roast) → crack with hashcat.",
            "With any valid credential: Kerberoast service accounts "
            "(kerberoast) → crack; enumerate via LDAP/BloodHound.",
            "Password-spray discovered users; then dump secrets "
            "(secretsdump/DCSync) if a privileged account is obtained.",
        ]
    if 445 in pset:
        obs.append("SMB (445) exposed — check signing, null/guest sessions, and "
                   "share permissions (netexec_smb, smbclient, enum4linux).")
        if entry.get("facts", {}).get("smb_signing") == "False":
            obs.append("SMB signing is NOT required — NTLM/SMB relay attack "
                       "surface: capture auth (Responder) and relay it to this "
                       "host (ntlmrelayx) for code execution or hash dumping.")
            paths.append("Poison name resolution (Responder) to capture NTLM "
                         "auth, then relay it to this host's SMB (signing off) "
                         "with ntlmrelayx → command execution or SAM dump.")
    if 389 in pset or 636 in pset:
        obs.append("LDAP exposed — test anonymous bind and enumerate the "
                   "directory (ldapsearch_anon, netexec_ldap).")
    if 3389 in pset:
        obs.append("RDP (3389) exposed — credential brute-force surface; verify "
                   "NLA and patch level (BlueKeep on legacy).")
    if 5985 in pset or 5986 in pset:
        obs.append("WinRM (5985/5986) exposed — remote command execution with "
                   "valid credentials (netexec_winrm).")
    web = [p for p in pset if p in (80, 443, 8080, 8443, 8000)]
    if web:
        obs.append(f"Web service(s) on {', '.join(map(str, sorted(web)))} — "
                   "fingerprint and test (whatweb, nuclei, nikto, ffuf).")
    if 21 in pset:
        obs.append("FTP (21) — test anonymous login and known CVEs.")
    if 22 in pset:
        obs.append("SSH (22) — enumerate version; brute-force only if in scope.")

    return {"host": host, "hostname": entry.get("hostname", ""),
            "role": role, "observations": obs, "attack_paths": paths,
            "open_count": len(pset)}


def assess(hosts: dict, facts: dict) -> dict:
    """Return {'hosts': [per-host assessment], 'domain': ..., 'creds': ...}."""
    out = {"hosts": [], "domain": facts.get("domain"),
           "creds": None, "summary": ""}
    if facts.get("username") and facts.get("password"):
        out["creds"] = f"{facts['username']}:{facts['password']}"
    roles = []
    for host, entry in sorted(hosts.items()):
        if _open(entry):
            a = assess_host(host, entry)
            out["hosts"].append(a)
            roles.append(a["role"])
    # A one-line factual summary.
    dc = sum(1 for r in roles if "Domain Controller" in r)
    parts = [f"{len(out['hosts'])} live host(s) assessed"]
    if dc:
        parts.append(f"{dc} Active Directory domain controller(s)")
    if out["domain"]:
        parts.append(f"domain {out['domain']}")
    if out["creds"]:
        parts.append("valid credentials captured")
    out["summary"] = "; ".join(parts) + "."
    return out
