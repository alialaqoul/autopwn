# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Editable, persisted playbook definitions for the web console.

A playbook is a declarative description of an attack path Autopwn follows — the
AD kill chain in `chains.py`, plus web / relay side-paths. Each has:

  * ``match``  — how it is selected against scan results (ports / fact signals).
  * ``run``    — the macro tool that executes it (e.g. ad_kill_chain), so a
                 playbook can be launched as a job straight from the console.
  * ``steps``  — the ordered actions, each naming the tool it uses and any
                 branches ("if guest disabled → …") so an operator sees exactly
                 how it runs and where it re-routes.

Defaults live in DEFAULT_PLAYBOOKS. On first use they are written to
``<log_dir>/playbooks.json``, after which the operator edits them through the UI
(the file is the single source of truth; ``reset`` restores the defaults).
`evaluate()` computes — and explains — whether a playbook matches the current
service matrix, so the matching is transparent rather than magic.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path


DEFAULT_PLAYBOOKS = [
    {
        "id": "ad-kill-chain",
        "name": "Active Directory — no/low creds → Domain Admin",
        "summary": "Guest/RID → spray → AS-REP → Kerberoast → loot → pass-the-hash. "
                   "Re-routes on what each step actually finds.",
        "match": {"any_ports": [88, 389, 445, 636, 3268], "signals": []},
        "run": {"tool": "ad_kill_chain"},
        "steps": [
            {"n": 1, "title": "Guest / null session + RID cycle", "tool": "netexec_smb / netexec_rid_brute",
             "detail": "netexec_smb -u guest -p '' then RID-brute to walk every "
                       "domain user (SidTypeUser) into a user list.",
             "branches": [
                 {"cond": "guest enabled", "then": "RID-brute the full user list"},
                 {"cond": "guest disabled / RID blocked", "then": "fall through to user-enum (step 2)"}]},
            {"n": 2, "title": "User enumeration (hardened DC fallback)", "tool": "netexec_ldap / kerbrute_userenum",
             "detail": "Build a user list another way when RID cycling returns nothing.",
             "branches": [
                 {"cond": "have a credential", "then": "authenticated netexec_ldap --users (complete list)"},
                 {"cond": "no credential", "then": "kerbrute_userenum (Kerberos pre-auth, no lockout)"}]},
            {"n": 3, "title": "AS-REP roast + crack", "tool": "asrep_roast + john/hashcat",
             "detail": "Roast accounts without Kerberos pre-auth, crack offline "
                       "(john krb5asrep / hashcat 18200). A foothold that beats "
                       "guest-disabled DCs.",
             "branches": [
                 {"cond": "hash cracked", "then": "recovered password becomes a real domain credential"}]},
            {"n": 4, "title": "Password spray (username == password)", "tool": "netexec_spray",
             "detail": "--no-bruteforce in one server-side batch (one attempt per "
                       "user → no lockout). Highest-yield first spray.",
             "branches": [
                 {"cond": "hit", "then": "foothold credential (e.g. hodor:hodor)"}]},
            {"n": 5, "title": "Kerberoast + crack", "tool": "kerberoast + hashcat",
             "detail": "GetUserSPNs for SPN accounts; crack offline (hashcat 13100). "
                       "Detects delegation on the SPN account.",
             "branches": [
                 {"cond": "constrained / unconstrained delegation", "then": "S4U2Proxy: get_st -impersonate Administrator"},
                 {"cond": "password cracked", "then": "spray it for reuse across all users"}]},
            {"n": 6, "title": "Password reuse + loot shares", "tool": "netexec_spray / smb_get",
             "detail": "Spray recovered passwords across all users; loot readable "
                       "non-default shares (backups, scripts, GPP, KeePass).",
             "branches": [
                 {"cond": "machine-account / NTLM hashes found", "then": "carry to pass-the-hash (step 7)"}]},
            {"n": 7, "title": "Pass-the-hash → goal", "tool": "netexec_smb -H / secretsdump",
             "detail": "netexec_smb -u acct -H <nt> against the DC; watch for Pwn3d!. "
                       "Then read C$ / flags or secretsdump (DCSync).",
             "branches": [
                 {"cond": "Pwn3d!", "then": "admin on DC → dump NTDS / capture flags"}]},
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
            {"n": 1, "title": "Create a machine account", "tool": "add_computer",
             "detail": "Needs MachineAccountQuota>0 (netexec_ldap -M maq). Default ATTACK$ / Attack123!.",
             "branches": []},
            {"n": 2, "title": "Write delegation", "tool": "rbcd",
             "detail": "delegate-from your new computer, delegate-to the target computer (e.g. DC01$).",
             "branches": []},
            {"n": 3, "title": "S4U2Proxy ticket", "tool": "get_st",
             "detail": "get_st -spn cifs/<dc.fqdn> -impersonate Administrator → .ccache.",
             "branches": []},
            {"n": 4, "title": "Use the ticket", "tool": "secretsdump -k",
             "detail": "export KRB5CCNAME=<ccache>; secretsdump -k -no-pass <dc> (DCSync) or read C$.",
             "branches": []},
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
            {"n": 1, "title": "Find relay targets", "tool": "netexec_smb --gen-relay-list",
             "detail": "Check signing on every host; list signing:False targets.", "branches": []},
            {"n": 2, "title": "Poison + relay", "tool": "responder / ntlmrelayx",
             "detail": "Responder poisons LLMNR/NBT-NS/mDNS; ntlmrelayx relays to a signing-disabled host.",
             "branches": []},
            {"n": 3, "title": "Execute / dump", "tool": "ntlmrelayx",
             "detail": "Command execution or SAM/secrets dump on the relayed host.", "branches": []},
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
            {"n": 1, "title": "Fingerprint", "tool": "http_probe",
             "detail": "Server, tech stack, titles, redirects, headers.", "branches": []},
            {"n": 2, "title": "Content discovery", "tool": "ffuf / feroxbuster",
             "detail": "Directory/vhost brute force; find admin panels, APIs, uploads.", "branches": []},
            {"n": 3, "title": "Vulnerability scan", "tool": "nuclei",
             "detail": "Test auth, injection, SSRF, deserialization, default creds.", "branches": []},
            {"n": 4, "title": "Pivot credentials", "tool": "netexec_spray",
             "detail": "Any recovered credential → spray across the AD estate.", "branches": []},
        ],
    },
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


def evaluate(pb: dict, hosts: list, services: list, facts: dict) -> dict:
    """Explain whether *pb* matches the current scan results.

    Returns {matched: bool, reasons: [{rule, matched, hits}]}. A playbook matches
    when any required port is open somewhere (or it declares no port rule). Fact
    signals are reported too but do not gate the match — they add context.
    """
    ports = _open_ports(services)
    reasons = []
    match = pb.get("match", {}) or {}

    any_ports = match.get("any_ports") or []
    port_matched = None
    if any_ports:
        hits = []
        for p in any_ports:
            for h in ports.get(int(p), []):
                hits.append(f"{h}:{p}")
        port_matched = bool(hits)
        reasons.append({"rule": f"any open port in {any_ports}",
                        "matched": port_matched, "hits": sorted(hits)})

    for sig in match.get("signals") or []:
        present = bool(facts.get(sig)) or (sig == "username" and (
            facts.get("username") or facts.get("nthash")))
        reasons.append({"rule": f"fact signal '{sig}'",
                        "matched": bool(present),
                        "hits": [f"{sig}={facts.get(sig)}"] if facts.get(sig) else []})

    # matched if there is a port rule and it hit, or no port rule at all
    matched = port_matched if port_matched is not None else True
    return {"matched": matched, "reasons": reasons}


def annotate(hosts: list, services: list, facts: dict, log_dir) -> list:
    out = []
    for pb in load(log_dir):
        out.append({**pb, "evaluation": evaluate(pb, hosts, services, facts)})
    return out
