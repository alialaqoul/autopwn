# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Editable, persisted playbook definitions for the web console.

A playbook is a declarative description of an attack path Autopwn follows — the
AD kill chain in `chains.py`, plus web / relay side-paths. Each has:

  * ``match``  — how it is selected against scan results (ports / fact signals).
  * ``run``    — the macro tool that executes it (e.g. ad_kill_chain), so a
                 playbook can be launched as a job straight from the console.
  * ``steps``  — the ordered actions. Every step is a small data-flow node:
      - ``trigger``  : the condition that fires the step (what must be true).
      - ``tool``     : the action it runs.
      - ``consumes`` : artifacts it needs from earlier steps.
      - ``produces`` : artifacts it hands forward.
      - ``next``     : where control flows on success ("next" / "final" / a step).
      - ``branches`` : conditional re-routes ("if guest disabled → …").

    This makes each step's trigger and what it passes on explicit, which is what
    the console's step builder edits and the reader view visualises.

Defaults live in DEFAULT_PLAYBOOKS. On first use they are written to
``<log_dir>/playbooks.json``; after that the operator edits them through the UI.
`evaluate()` computes — and explains — whether a playbook matches the current
service matrix, so the matching is transparent rather than magic.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path


# Controlled vocabulary the step builder offers (free text is still allowed).
ARTIFACTS = [
    "userlist", "credential", "hash", "ticket", "spn_hash", "asrep_hash",
    "shares", "relay_targets", "machine_account", "admin", "flag",
]
TRIGGERS = [
    "start", "no userlist yet", "have userlist", "have credential",
    "have hash", "have ticket", "delegation found", "signing disabled",
]
SIGNALS = [
    "username", "nthash", "signing_false", "guest", "has_users",
    "kerberoastable", "asreproastable",
]
NEXT_CHOICES = ["next", "final"]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
# Host facts a finding playbook can match on (fact -> what it means).
HOST_FACTS = {
    "smb_signing": "'False' when SMB signing is not enforced",
    "smb_nullauth": "'True' when anonymous SMB is permitted",
    "os": "OS string harvested from the host",
    "pwned": "'Pwn3d!' when an account is admin on the host",
    "kerberoastable": "SPN hashes were obtained",
    "asreproastable": "AS-REP hashes were obtained",
}

SCHEMA = {
    "artifacts": ARTIFACTS,   # what a step can consume / produce
    "triggers": TRIGGERS,     # common step preconditions
    "signals": SIGNALS,       # fact signals usable in match / triggers
    "next": NEXT_CHOICES,
    "severities": SEVERITIES,
    "host_facts": HOST_FACTS,
    "notes": {
        "trigger": "The condition that fires this step.",
        "consumes": "Artifacts this step needs from earlier steps.",
        "produces": "Artifacts this step hands to the next / final step.",
        "next": "'next' = fall through, 'final' = goal, or a step title.",
        "severity": "Set severity+cvss to make this playbook a reportable finding.",
        "host_facts": "Match a host only when these facts equal these values.",
    },
}


def _finding(pb_id, name, severity, cvss, summary, impact, recommendation,
             any_ports=None, host_facts=None, evidence_tools=None,
             detector="", signals=None):
    """A detection/reporting playbook: when it matches the scan it becomes a
    finding in the report carrying this severity, CVSS, impact and recommendation."""
    return {
        "id": pb_id, "name": name, "category": "finding",
        "severity": severity, "cvss": cvss, "summary": summary,
        "impact": impact, "recommendation": recommendation,
        "match": {"any_ports": any_ports or [], "host_facts": host_facts or {},
                  "signals": signals or []},
        "evidence_tools": evidence_tools or [], "detector": detector,
        "run": {"tool": ""}, "steps": [],
    }


def _step(n, title, trigger, tool, consumes, produces, detail, nxt="next",
          branches=None):
    return {"n": n, "title": title, "trigger": trigger, "tool": tool,
            "consumes": consumes, "produces": produces, "detail": detail,
            "next": nxt, "branches": branches or []}


DEFAULT_PLAYBOOKS = [
    {
        "id": "ad-kill-chain",
        "name": "Active Directory — no/low creds → Domain Admin",
        "summary": "Guest/RID → spray → AS-REP → Kerberoast → loot → pass-the-hash. "
                   "Re-routes on what each step actually finds.",
        "match": {"any_ports": [88, 389, 445, 636, 3268], "signals": []},
        "run": {"tool": "ad_kill_chain"},
        "steps": [
            _step(1, "Guest / null session + RID cycle", "start",
                  "netexec_smb / netexec_rid_brute", [], ["userlist"],
                  "netexec_smb -u guest -p '' then RID-brute to walk every domain "
                  "user (SidTypeUser) into a user list.", "next",
                  [{"cond": "guest enabled", "then": "RID-brute the full user list"},
                   {"cond": "guest disabled / RID blocked", "then": "→ step 2 (user enum)"}]),
            _step(2, "User enumeration (hardened DC fallback)", "no userlist yet",
                  "netexec_ldap / kerbrute_userenum", ["credential"], ["userlist"],
                  "Build a user list another way when RID cycling returns nothing.",
                  "next",
                  [{"cond": "have a credential", "then": "authenticated netexec_ldap --users (complete list)"},
                   {"cond": "no credential", "then": "kerbrute_userenum (Kerberos pre-auth, no lockout)"}]),
            _step(3, "AS-REP roast + crack", "have userlist",
                  "asrep_roast + john/hashcat", ["userlist"], ["credential", "asrep_hash"],
                  "Roast accounts without Kerberos pre-auth, crack offline "
                  "(john krb5asrep / hashcat 18200). Foothold that beats guest-disabled DCs.",
                  "next",
                  [{"cond": "hash cracked", "then": "recovered password becomes a real domain credential"}]),
            _step(4, "Password spray (username == password)", "have userlist",
                  "netexec_spray", ["userlist"], ["credential"],
                  "--no-bruteforce in one server-side batch (one attempt per user → "
                  "no lockout). Highest-yield first spray.", "next",
                  [{"cond": "hit", "then": "foothold credential (e.g. hodor:hodor)"}]),
            _step(5, "Kerberoast + crack", "have credential",
                  "kerberoast + hashcat", ["credential"], ["credential", "spn_hash", "ticket"],
                  "GetUserSPNs for SPN accounts; crack offline (hashcat 13100). "
                  "Detects delegation on the SPN account.", "next",
                  [{"cond": "constrained / unconstrained delegation", "then": "S4U2Proxy: get_st -impersonate Administrator"},
                   {"cond": "password cracked", "then": "spray it for reuse across all users"}]),
            _step(6, "Password reuse + loot shares", "have credential",
                  "netexec_spray / smb_get", ["credential"], ["hash", "shares"],
                  "Spray recovered passwords across all users; loot readable "
                  "non-default shares (backups, scripts, GPP, KeePass).", "next",
                  [{"cond": "machine-account / NTLM hashes found", "then": "→ step 7 (pass-the-hash)"}]),
            _step(7, "Pass-the-hash → goal", "have hash",
                  "netexec_smb -H / secretsdump", ["hash"], ["admin", "flag"],
                  "netexec_smb -u acct -H <nt> against the DC; watch for Pwn3d!. "
                  "Then read C$ / flags or secretsdump (DCSync).", "final",
                  [{"cond": "Pwn3d!", "then": "admin on DC → dump NTDS / capture flags"}]),
        ],
    },
    {
        "id": "rbcd",
        "name": "RBCD to Domain Admin (write over a computer)",
        "summary": "Abuse write access to a computer's delegation attribute plus "
                   "MachineAccountQuota to impersonate an admin.",
        "match": {"any_ports": [88, 445], "signals": ["username"]},
        "run": {"tool": ""},
        "steps": [
            _step(1, "Create a machine account", "have credential", "add_computer",
                  ["credential"], ["machine_account"],
                  "Needs MachineAccountQuota>0 (netexec_ldap -M maq). Default ATTACK$ / Attack123!."),
            _step(2, "Write delegation", "have credential", "rbcd",
                  ["credential", "machine_account"], [],
                  "delegate-from your new computer, delegate-to the target computer (e.g. DC01$)."),
            _step(3, "S4U2Proxy ticket", "have credential", "get_st",
                  ["machine_account"], ["ticket"],
                  "get_st -spn cifs/<dc.fqdn> -impersonate Administrator → .ccache."),
            _step(4, "Use the ticket", "have ticket", "secretsdump -k",
                  ["ticket"], ["admin", "flag"],
                  "export KRB5CCNAME=<ccache>; secretsdump -k -no-pass <dc> (DCSync) or read C$.",
                  "final"),
        ],
    },
    {
        "id": "smb-relay",
        "name": "NTLM / SMB relay (member servers)",
        "summary": "Signing-disabled member servers are relay targets: capture NTLM "
                   "auth and relay it for code exec or a SAM/secrets dump.",
        "match": {"any_ports": [445], "signals": ["signing_false"]},
        "run": {"tool": ""},
        "steps": [
            _step(1, "Find relay targets", "start", "netexec_smb --gen-relay-list",
                  [], ["relay_targets"],
                  "Check signing on every host; list signing:False targets."),
            _step(2, "Poison + relay", "signing disabled", "responder / ntlmrelayx",
                  ["relay_targets"], ["hash"],
                  "Responder poisons LLMNR/NBT-NS/mDNS; ntlmrelayx relays to a signing-disabled host."),
            _step(3, "Execute / dump", "have hash", "ntlmrelayx", ["hash"], ["admin"],
                  "Command execution or SAM/secrets dump on the relayed host.", "final"),
        ],
    },
    {
        "id": "web-app",
        "name": "Web application assessment",
        "summary": "Fingerprint, enumerate content, test the common classes; pivot "
                   "any recovered credential back into the network.",
        "match": {"any_ports": [80, 443, 8080, 8443, 8000], "signals": []},
        "run": {"tool": ""},
        "steps": [
            _step(1, "Fingerprint", "start", "http_probe", [], [],
                  "Server, tech stack, titles, redirects, headers."),
            _step(2, "Content discovery", "start", "ffuf / feroxbuster", [], [],
                  "Directory/vhost brute force; find admin panels, APIs, uploads."),
            _step(3, "Vulnerability scan", "start", "nuclei", [], ["credential"],
                  "Test auth, injection, SSRF, deserialization, default creds."),
            _step(4, "Pivot credentials", "have credential", "netexec_spray",
                  ["credential"], ["admin"],
                  "Any recovered credential → spray across the AD estate.", "final"),
        ],
    },

    # ---- finding playbooks (detection + report content) ------------------
    _finding("smb-signing", "SMB Signing Not Enforced", "High", "6.5",
             "One or more hosts do not require SMB signing. Unsigned SMB allows "
             "an attacker who can capture or coerce NTLM authentication to relay "
             "it to these hosts.",
             "NTLM/SMB relay to the host can yield command execution or a "
             "credential/SAM dump, enabling lateral movement.",
             "Enforce SMB signing (Require) via GPO on all servers and "
             "workstations; disable NTLM where possible.",
             any_ports=[445], host_facts={"smb_signing": "False"},
             evidence_tools=["netexec_smb"]),
    _finding("smb-nullauth", "SMB Null / Anonymous Authentication Permitted",
             "Medium", "5.3",
             "The host accepts an anonymous (null) SMB session. The evidence "
             "shows what an unauthenticated attacker can enumerate over that "
             "session (e.g. shares) — confirming real, not just theoretical, exposure.",
             "Anonymous users can enumerate shares, and depending on configuration "
             "also users (RID cycling) and password policy — valuable recon and a "
             "starting point for further access.",
             "Restrict anonymous access (RestrictNullSessAccess=1, "
             "RestrictAnonymous=1); review share and RID enumeration exposure.",
             any_ports=[445], host_facts={"smb_nullauth": "True"},
             evidence_tools=["smbclient_shares", "netexec_smb"]),
    _finding("wsus-http", "WSUS Served Over HTTP", "High", "8.1",
             "A WSUS update service is reachable over cleartext HTTP (8530).",
             "If clients are not forced to use WSUS over SSL, an on-path attacker "
             "can spoof updates and execute code as SYSTEM on managed endpoints.",
             "Require WSUS over HTTPS (8531) and set the 'Do not store passwords'/"
             "SSL enforcement GPO for clients.",
             any_ports=[8530]),
    _finding("admin-console", "Administration Console Exposed", "Low", "4.0",
             "A management console / agent handler (e.g. endpoint-management "
             "platform) is network-reachable.",
             "If protected only by default or weak credentials, console access can "
             "push tasks/software to every managed endpoint.",
             "Restrict the console to management networks, enforce strong unique "
             "admin credentials and MFA, and patch to current.",
             any_ports=[8443, 8444]),
    _finding("rdp-exposed", "Remote Desktop (RDP) Exposed", "Low", "4.0",
             "RDP (3389) is reachable on the network.",
             "Credential brute-force / password-spray surface; legacy hosts may be "
             "vulnerable to pre-auth RCE (e.g. BlueKeep).",
             "Restrict RDP to jump hosts/VPN, require NLA, enforce account lockout, "
             "and keep hosts patched.",
             any_ports=[3389]),
    _finding("http-headers", "Missing HTTP Security Headers", "Low", "3.1",
             "Web responses omit recommended security headers (e.g. "
             "Content-Security-Policy, X-Frame-Options, HSTS).",
             "Increases exposure to clickjacking, MIME sniffing, and transport "
             "downgrade attacks.",
             "Add CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, "
             "and Strict-Transport-Security.",
             any_ports=[80, 8080, 8000], evidence_tools=["http_probe"],
             detector="missing_http_headers"),
]


def _path(log_dir) -> Path:
    return Path(log_dir) / "playbooks.json"


def load(log_dir) -> list:
    """Return the stored playbooks, seeding the defaults on first use."""
    p = _path(log_dir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list) and data:
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    save(log_dir, copy.deepcopy(DEFAULT_PLAYBOOKS))
    return copy.deepcopy(DEFAULT_PLAYBOOKS)


def save(log_dir, playbooks: list) -> None:
    p = _path(log_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(playbooks, indent=2), encoding="utf-8")
    tmp.replace(p)


def reset(log_dir) -> list:
    save(log_dir, copy.deepcopy(DEFAULT_PLAYBOOKS))
    return copy.deepcopy(DEFAULT_PLAYBOOKS)


def _open_ports(services: list) -> dict:
    """port -> [hosts] from the service matrix (each service row has ports+hosts)."""
    ports: dict[int, list] = {}
    for s in services:
        hosts = [h["host"] for h in s.get("hosts", [])]
        for p in s.get("ports", []):
            ports.setdefault(int(p), [])
            for h in hosts:
                if h not in ports[int(p)]:
                    ports[int(p)].append(h)
    return ports


def _host_open_ports(entry: dict) -> set:
    return {p["port"] for p in entry.get("ports", {}).values()
            if p.get("state") == "open"}


def matching_hosts(pb: dict, hosts: dict) -> list:
    """Hosts a playbook applies to: those exposing one of its ports AND whose
    facts equal every required host_fact (that's what makes a finding per-host)."""
    match = pb.get("match", {}) or {}
    any_ports = set(int(p) for p in (match.get("any_ports") or []))
    host_facts = match.get("host_facts") or {}
    out = []
    for h, entry in sorted((hosts or {}).items()):
        ports = _host_open_ports(entry)
        if any_ports and not (any_ports & ports):
            continue
        hf = entry.get("facts", {})
        if any(str(hf.get(k)) != str(v) for k, v in host_facts.items()):
            continue
        out.append(h)
    return out


def evaluate(pb: dict, hosts: dict, services: list, facts: dict) -> dict:
    """Explain whether *pb* matches the current scan results.

    Returns {matched, matched_hosts, reasons:[{rule,matched,hits}]}. A playbook
    matches when a required port is open (and, for finding playbooks, the required
    host facts hold on that host). Signals add context.
    """
    ports = _open_ports(services)
    reasons = []
    match = pb.get("match", {}) or {}
    host_facts = match.get("host_facts") or {}

    any_ports = match.get("any_ports") or []
    port_matched = None
    if any_ports:
        hits = [f"{h}:{p}" for p in any_ports for h in ports.get(int(p), [])]
        port_matched = bool(hits)
        reasons.append({"rule": f"any open port in {any_ports}",
                        "matched": port_matched, "hits": sorted(hits)})

    matched_hosts = matching_hosts(pb, hosts)
    for k, v in host_facts.items():
        hits = [h for h in matched_hosts]
        reasons.append({"rule": f"host fact {k} = {v}",
                        "matched": bool(matched_hosts), "hits": hits})

    for sig in match.get("signals") or []:
        present = bool(facts.get(sig)) or (sig == "username" and (
            facts.get("username") or facts.get("nthash")))
        reasons.append({"rule": f"fact signal '{sig}'",
                        "matched": bool(present),
                        "hits": [f"{sig}={facts.get(sig)}"] if facts.get(sig) else []})

    if host_facts:
        matched = bool(matched_hosts)
    elif port_matched is not None:
        matched = port_matched
    else:
        matched = True
    return {"matched": matched, "matched_hosts": matched_hosts, "reasons": reasons}


def annotate(hosts: dict, services: list, facts: dict, log_dir) -> list:
    out = []
    for pb in load(log_dir):
        out.append({**pb, "evaluation": evaluate(pb, hosts, services, facts)})
    return out
