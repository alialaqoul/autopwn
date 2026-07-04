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


# Reusable parameter fragments -------------------------------------------------
_TARGET = {"target": {"type": "string", "description": "Host or IP."}}
_URL = {"url": {"type": "string", "description": "Full URL incl. scheme/port."}}
_AUTH = {
    "username": {"type": "string", "description": "Username (optional)."},
    "password": {"type": "string", "description": "Password (optional)."},
}
_DOMAIN = {"domain": {"type": "string", "description": "Domain, e.g. cyberlab.local or example.com."}}
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
        description="Enumerate SMB on a host with NetExec: OS/domain info, and "
                    "with creds, shares/users/passwordpolicy. protocol fixed to smb.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH,
            "enumerate": {"type": "string", "description": "One of: shares, users, "
                          "groups, pass-pol, loggedon-users, sessions, disks. Optional."}},
            ["target"]),
        subcommand=["smb"],
        positional=["target"],
        flags={"username": "-u", "password": "-p", "enumerate": "--{v}"},
        install_hint="pipx install netexec (provides nxc).",
    ),
    # Added purely declaratively — shows how little a new tool needs.
    CommandSpec(
        name="netexec_winrm",
        description="Check WinRM (5985/5986) access and run whoami with NetExec. "
                    "Great for validating creds give remote-exec.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH}, ["target"]),
        subcommand=["winrm"],
        positional=["target"],
        flags={"username": "-u", "password": "-p"},
        fixed=["-x", "whoami"],
        install_hint="pipx install netexec.",
    ),
    CommandSpec(
        name="netexec_ldap",
        description="Query LDAP/AD via NetExec (with creds): users, groups, and "
                    "Kerberoast/asreproast discovery.",
        binary="nxc",
        parameters=_params({**_TARGET, **_AUTH,
            "action": {"type": "string", "description": "e.g. '--users', "
                       "'--kerberoasting out.txt', '--asreproast out.txt'. Optional."}},
            ["target"]),
        build_args=lambda k: ["ldap", _s(k["target"])] + _creds(k)
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
            "base_dn": {"type": "string", "description": "e.g. DC=cyberlab,DC=local"},
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
    CommandSpec(
        name="certipy_find",
        description="Enumerate Active Directory Certificate Services (AD CS): "
                    "CAs and certificate templates, flagging vulnerable ones "
                    "(ESC1-ESC8). Needs valid domain credentials.",
        binary="certipy-ad", category="ad-smb",
        parameters=_params({**_TARGET, **_DOMAIN, **_AUTH}, ["target", "domain", "username", "password"]),
        build_args=lambda k: ["find", "-u", f"{_s(k['username'])}@{_s(k['domain'])}",
                              "-p", _s(k["password"]), "-dc-ip", _s(k["target"]),
                              "-stdout", "-vulnerable"],
        aliases=["certipy"], timeout=600, install_hint="pipx install certipy-ad.",
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
