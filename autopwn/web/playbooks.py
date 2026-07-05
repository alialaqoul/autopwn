# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Playbook definitions for the web console.

A declarative view of the attack paths Autopwn actually follows — primarily the
deterministic AD kill chain in `chains.py`, plus the web and relay side-paths.
Each step can fork into branches ("if guest disabled → …"), which is what the
console renders so an operator can see the different routes and where a run will
re-route based on evidence.

`applies_when` lists port/signal hints so the UI can highlight which playbooks
are relevant to the current engagement (from the discovered service matrix).
"""
from __future__ import annotations


PLAYBOOKS = [
    {
        "id": "ad-kill-chain",
        "name": "Active Directory — no/low creds → Domain Admin",
        "summary": "Guest/RID → spray → AS-REP → Kerberoast → loot → pass-the-hash. "
                   "Re-routes on what each step actually finds.",
        "applies_when": ["port:88", "port:445", "port:389"],
        "tool": "ad_kill_chain",
        "steps": [
            {"n": 1, "title": "Guest / null session + RID cycle",
             "detail": "netexec_smb -u guest -p '' then netexec_rid_brute to walk "
                       "every domain user (SidTypeUser) into a user list.",
             "branches": [
                 {"cond": "guest enabled", "then": "RID-brute the full user list"},
                 {"cond": "guest disabled / RID blocked", "then": "fall through to user-enum (step 2)"}]},
            {"n": 2, "title": "User enumeration (hardened DC fallback)",
             "detail": "Build a user list another way when RID cycling returns nothing.",
             "branches": [
                 {"cond": "have a credential", "then": "authenticated netexec_ldap --users (complete list)"},
                 {"cond": "no credential", "then": "kerbrute_userenum (Kerberos pre-auth, no lockout)"}]},
            {"n": 3, "title": "AS-REP roast + crack",
             "detail": "asrep_roast accounts without Kerberos pre-auth, crack offline "
                       "(john krb5asrep / hashcat 18200). A no/low-cred foothold that "
                       "beats guest-disabled DCs.",
             "branches": [
                 {"cond": "hash cracked", "then": "recovered password becomes a real domain credential"}]},
            {"n": 4, "title": "Password spray (username == password)",
             "detail": "netexec_spray --no-bruteforce in one server-side batch (one "
                       "attempt per user → no lockout). Highest-yield first spray.",
             "branches": [
                 {"cond": "hit", "then": "foothold credential (e.g. hodor:hodor)"}]},
            {"n": 5, "title": "Kerberoast + crack",
             "detail": "kerberoast (GetUserSPNs) for SPN accounts; crack offline "
                       "(hashcat 13100). Detects delegation on the SPN account.",
             "branches": [
                 {"cond": "constrained / unconstrained delegation", "then": "S4U2Proxy: get_st -impersonate Administrator → privileged ticket"},
                 {"cond": "password cracked", "then": "spray it for reuse across all users"}]},
            {"n": 6, "title": "Password reuse + loot shares",
             "detail": "Spray every recovered password across all users; enumerate "
                       "readable non-default shares and smb_get interesting files "
                       "(backups, scripts, GPP, KeePass).",
             "branches": [
                 {"cond": "machine-account / NTLM hashes found", "then": "carry to pass-the-hash (step 7)"}]},
            {"n": 7, "title": "Pass-the-hash → goal",
             "detail": "netexec_smb -u acct -H <nt> against the DC; watch for Pwn3d!. "
                       "Then read C$ / flags or secretsdump (DCSync).",
             "branches": [
                 {"cond": "Pwn3d!", "then": "admin on DC → dump NTDS / capture flags → full compromise"}]},
        ],
    },
    {
        "id": "rbcd",
        "name": "RBCD to Domain Admin (write over a computer)",
        "summary": "Abuse write access to a computer's delegation attribute plus "
                   "MachineAccountQuota to impersonate an admin.",
        "applies_when": ["port:88", "port:445", "signal:username"],
        "tool": "add_computer / rbcd / get_st",
        "steps": [
            {"n": 1, "title": "Create a machine account",
             "detail": "add_computer (needs MachineAccountQuota>0; check with "
                       "netexec_ldap -M maq). Default ATTACK$ / Attack123!."},
            {"n": 2, "title": "Write delegation",
             "detail": "rbcd — as the account with write rights, delegate-from your "
                       "new computer, delegate-to the target computer (e.g. DC01$)."},
            {"n": 3, "title": "S4U2Proxy ticket",
             "detail": "get_st -spn cifs/<dc.fqdn> -impersonate Administrator → .ccache."},
            {"n": 4, "title": "Use the ticket",
             "detail": "export KRB5CCNAME=<ccache>; secretsdump -k -no-pass <dc> (DCSync) "
                       "or read C$ with Kerberos auth."},
        ],
    },
    {
        "id": "smb-relay",
        "name": "NTLM / SMB relay (member servers)",
        "summary": "Signing-disabled member servers are relay targets: capture NTLM "
                   "auth and relay it for code exec or a SAM/secrets dump.",
        "applies_when": ["port:445", "signal:signing_false"],
        "tool": "responder / ntlmrelayx",
        "steps": [
            {"n": 1, "title": "Find relay targets",
             "detail": "Check signing on every host (netexec_smb banner). "
                       "netexec smb <range> --gen-relay-list targets.txt."},
            {"n": 2, "title": "Poison + relay",
             "detail": "Responder poisons LLMNR/NBT-NS/mDNS; ntlmrelayx relays the "
                       "captured auth to a signing-disabled host."},
            {"n": 3, "title": "Execute / dump",
             "detail": "Command execution or SAM/secrets dump on the relayed host."},
        ],
    },
    {
        "id": "web-app",
        "name": "Web application assessment",
        "summary": "Fingerprint, enumerate content, and test the common classes; "
                   "pivot any recovered credential back into the network.",
        "applies_when": ["port:80", "port:443", "port:8080"],
        "tool": "http_probe / nuclei / ffuf",
        "steps": [
            {"n": 1, "title": "Fingerprint",
             "detail": "http_probe: server, tech stack, titles, redirects, headers."},
            {"n": 2, "title": "Content discovery",
             "detail": "Directory/vhost brute force; find admin panels, APIs, uploads."},
            {"n": 3, "title": "Vulnerability scan",
             "detail": "nuclei templates; test auth, injection, SSRF, deserialization, "
                       "default creds."},
            {"n": 4, "title": "Pivot credentials",
             "detail": "Any recovered credential → spray across the AD estate "
                       "(password reuse is the most common bridge)."},
        ],
    },
]


def signals_from_hosts(hosts: list, services: list) -> set:
    """Derive playbook-relevance signals from the discovered service matrix."""
    sig = set()
    for s in services:
        for p in s.get("ports", []):
            sig.add(f"port:{p}")
    return sig


def annotate(hosts: list, services: list, facts: dict) -> list:
    """Return the playbooks tagged with whether they currently apply."""
    sig = signals_from_hosts(hosts, services)
    if facts.get("username") or facts.get("password") or facts.get("nthash"):
        sig.add("signal:username")
    out = []
    for pb in PLAYBOOKS:
        applies = any(w in sig for w in pb["applies_when"] if w.startswith("port:"))
        out.append({**pb, "active": applies})
    return out
