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
    if 8530 in pset or 8531 in pset:
        obs.append("WSUS (8530/8531) — update server. If clients use HTTP (8530) "
                   "without SSL enforced, it is a spoofing/lateral-movement "
                   "target (PyWSUS/SharpWSUS with a MITM position).")
        paths.append("If WSUS runs over HTTP and clients aren't forced to SSL: "
                     "MITM update traffic to push a signed binary as SYSTEM.")
    if 8443 in pset or 8444 in pset:
        obs.append("Management console (8443) / agent handler (8444) — likely "
                   "Trellix/McAfee ePO. Test the console for default admin creds; "
                   "ePO admin => code execution across all managed endpoints.")
    if 21 in pset:
        obs.append("FTP (21) — test anonymous login and known CVEs.")
    if 22 in pset:
        obs.append("SSH (22) — enumerate version; brute-force only if in scope.")

    return {"host": host, "hostname": entry.get("hostname", ""),
            "role": role, "observations": obs, "attack_paths": paths,
            "open_count": len(pset)}


def _evidence(transcript, *tool_names):
    """Find the command + output of the first successful matching tool run."""
    for e in transcript or []:
        if e.get("kind") == "tool_result" and e.get("name") in tool_names:
            cmd = e.get("command") or f"{e.get('name')} {e.get('args', {})}"
            out = (e.get("output") or e.get("summary") or "").strip()
            return cmd, out[:1500]
    return "", ""


# Generic finding rules. Each: predicate over a host's open ports + facts =>
# a finding dict. Severity/impact/recommendation are standard and NOT tied to
# any specific environment.
def build_findings(hosts: dict, facts: dict, transcript=None) -> list[dict]:
    findings: list[dict] = []

    def host_facts(entry):
        return entry.get("facts", {})

    # Collect hosts matching each condition.
    def hosts_where(pred):
        out = []
        for h, entry in sorted(hosts.items()):
            ports = {p["port"] for p in entry.get("ports", {}).values()
                     if p.get("state") == "open"}
            if pred(h, entry, ports):
                out.append(h)
        return out

    rules = [
        dict(title="SMB Signing Not Enforced", severity="High", cvss="6.5",
             pred=lambda h, e, p: host_facts(e).get("smb_signing") == "False" and 445 in p,
             desc="One or more hosts do not require SMB signing. Unsigned SMB "
                  "allows an attacker who can capture or coerce NTLM "
                  "authentication to relay it to these hosts.",
             impact="NTLM/SMB relay to the host can yield command execution or a "
                    "credential/SAM dump, enabling lateral movement.",
             rec="Enforce SMB signing (Require) via GPO on all servers and "
                 "workstations; disable NTLM where possible.",
             tools=("netexec_smb",)),
        dict(title="SMB Null / Anonymous Authentication Permitted", severity="Medium",
             cvss="5.3",
             pred=lambda h, e, p: host_facts(e).get("smb_nullauth") == "True" and 445 in p,
             desc="The host accepts an anonymous (null) SMB session.",
             impact="Depending on configuration, anonymous users may enumerate "
                    "shares, users, or policy — useful reconnaissance for an "
                    "unauthenticated attacker.",
             rec="Restrict anonymous access (RestrictNullSessAccess=1, "
                 "RestrictAnonymous=1); review share and RID enumeration exposure.",
             tools=("netexec_smb", "smbclient_shares")),
        dict(title="WSUS Served Over HTTP", severity="High", cvss="8.1",
             pred=lambda h, e, p: 8530 in p,
             desc="A WSUS update service is reachable over cleartext HTTP (8530).",
             impact="If clients are not forced to use WSUS over SSL, an on-path "
                    "attacker can spoof updates and execute code as SYSTEM on "
                    "managed endpoints.",
             rec="Require WSUS over HTTPS (8531) and set the "
                 "'Do not store passwords'/SSL enforcement GPO for clients.",
             tools=("nmap_scan",)),
        dict(title="Administration Console Exposed", severity="Low", cvss="4.0",
             pred=lambda h, e, p: bool({8443, 8444} & p),
             desc="A management console / agent handler (e.g. endpoint-management "
                  "platform) is network-reachable.",
             impact="If protected only by default or weak credentials, console "
                    "access can push tasks/software to every managed endpoint.",
             rec="Restrict the console to management networks, enforce strong "
                 "unique admin credentials and MFA, and patch to current.",
             tools=("nmap_scan",)),
        dict(title="Remote Desktop (RDP) Exposed", severity="Low", cvss="4.0",
             pred=lambda h, e, p: 3389 in p,
             desc="RDP (3389) is reachable on the network.",
             impact="Credential brute-force / password-spray surface; legacy "
                    "hosts may be vulnerable to pre-auth RCE (e.g. BlueKeep).",
             rec="Restrict RDP to jump hosts/VPN, require NLA, enforce account "
                 "lockout, and keep hosts patched.",
             tools=("nmap_scan",)),
        dict(title="Missing HTTP Security Headers", severity="Low", cvss="3.1",
             pred=lambda h, e, p: bool({80, 8080, 8000} & p) and _has_missing_headers(transcript, h),
             desc="Web responses omit recommended security headers "
                  "(e.g. Content-Security-Policy, X-Frame-Options, HSTS).",
             impact="Increases exposure to clickjacking, MIME sniffing, and "
                    "transport downgrade attacks.",
             rec="Add CSP, X-Frame-Options/frame-ancestors, "
                 "X-Content-Type-Options, and Strict-Transport-Security.",
             tools=("http_probe",)),
    ]

    fid = 1
    for r in rules:
        matched = hosts_where(r["pred"])
        if not matched:
            continue
        cmd, out = _evidence(transcript, *r["tools"])
        findings.append({
            "id": f"F-{fid:02d}", "title": r["title"], "severity": r["severity"],
            "cvss": r["cvss"], "hosts": matched, "description": r["desc"],
            "impact": r["impact"], "recommendation": r["rec"],
            "evidence_cmd": cmd, "evidence_out": out,
        })
        fid += 1
    return findings


def _has_missing_headers(transcript, host: str) -> bool:
    for e in transcript or []:
        if e.get("kind") == "tool_result" and e.get("name") == "http_probe":
            if host in str(e.get("args", {})) and "missing security headers" in \
                    (e.get("output", "") + e.get("summary", "")):
                return True
    return False


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
