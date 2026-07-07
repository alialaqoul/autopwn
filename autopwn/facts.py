# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Canonical variables + output harvesting — the shared 'knowledge' layer.

Autopwn works in terms of *canonical variables* (``username``, ``password``,
``domain``, ``base_dn``, ``dc_ip`` …). Each tool maps these to its own CLI flags
(see ``CommandSpec.flags``), so a value learned once — typed by the operator or
parsed out of another tool's output — automatically flows into every other tool
that uses it.

Two mechanisms:
  * **harvest rules** (regex → variable) run over a tool's output and store what
    they find, globally or per-host.
  * **autofill** supplies stored variables to a tool's parameters by name,
    deriving ``base_dn`` from ``domain`` when needed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import store

# Canonical variables Autopwn understands, with human descriptions. Tools refer
# to these names; the flag map on each tool translates them to CLI switches.
CANONICAL: dict[str, str] = {
    "target":   "Host or IP to act on",
    "url":      "Full URL (scheme://host:port/)",
    "domain":   "AD / DNS domain, e.g. corp.local",
    "base_dn":  "LDAP base DN (auto-derived from domain)",
    "dc_ip":    "Domain controller IP",
    "username": "Username / login",
    "password": "Password",
    "nthash":   "NTLM hash (pass-the-hash)",
    "userlist": "Path to a usernames wordlist",
    "passlist": "Path to a passwords wordlist",
    "wordlist": "Path to a wordlist (fuzzing / cracking)",
    "hashfile": "Path to a file of hashes to crack",
}


@dataclass
class HarvestRule:
    """Extract a canonical variable from tool output via regex.

    With ``multi=True`` every match is captured (findall), not just the first —
    used e.g. to record a list of discovered subdomains as hosts.
    """
    var: str
    regex: str
    scope: str = "global"   # "global" | "host"
    group: int = 1
    flags: int = re.IGNORECASE
    multi: bool = False


# Applied to every tool's output regardless of which tool ran.
DEFAULT_HARVEST: list[HarvestRule] = [
    # Match "(domain:corp.local)", "Found AD domain: corp.local", and
    # "-domain corp.local" style output. Code-artifact captures like
    # "domain=args.domain" (from a tool's Python traceback) are dropped by the
    # reject filter in apply_harvest, so they no longer poison the domain.
    HarvestRule("domain", r"domain[:=]\s*\(?([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})"),
    HarvestRule("hostname", r"\bname:\s*([A-Za-z0-9\-]{1,32})", scope="host"),
    HarvestRule("os", r"(Windows[^()\[\]\n]{0,40})", scope="host"),
    # NetExec SMB banner: "(signing:False)" — signing not required = relay target.
    HarvestRule("smb_signing", r"\(signing:(True|False)\)", scope="host"),
    HarvestRule("smb_nullauth", r"Null Auth:\s*(True|False)", scope="host"),
    # NetExec/CME success line: "[+] corp.local\\admin:Passw0rd (Pwn3d!)"
    # The negative lookahead rejects lines that fell back to Guest ("(Guest)") or
    # carry a disqualifying account status ("STATUS_..."): those are NOT valid
    # credentials, and capturing them poisons the shared username/password.
    HarvestRule("username",
                r"\[\+\](?![^\n]*(?:\(Guest\)|STATUS_))\s*[^\\\s]+\\([^:\s]+):",
                scope="global"),
    HarvestRule("password",
                r"\[\+\](?![^\n]*(?:\(Guest\)|STATUS_))\s*[^\\\s]+\\[^:\s]+:([^\s(]+)",
                scope="global"),
    # ---- structured branch signals (drive adaptive path selection) -------
    # Guest/null session accepted -> RID enumeration is available.
    HarvestRule("smb_guest", r"\[\+\]\s*[^\\\s]+\\(guest):", scope="host", group=1),
    # "(Pwn3d!)" -> the authenticating account is a local admin on this host.
    HarvestRule("pwned", r"(Pwn3d!)", scope="host"),
    # RID-brute yielded users -> we have a real user list.
    HarvestRule("has_users", r"([0-9]+)\s+\(SidTypeUser\)", scope="host"),
    # Kerberoastable SPN present in GetUserSPNs output.
    HarvestRule("kerberoastable", r"(\$krb5tgs\$)", scope="host"),
    # AS-REP roastable account hash present.
    HarvestRule("asreproastable", r"(\$krb5asrep\$)", scope="host"),
]

_BAD_DOMAINS = ("home.arpa", "in-addr.arpa")


def apply_harvest(text: str, rules: list[HarvestRule], host: str | None = None) -> dict:
    """Run harvest *rules* over *text*, store hits, and return what was found."""
    found: dict[str, str] = {}
    if not text:
        return found
    for rule in rules:
        if rule.multi:
            # Record every match. For var=="host", each becomes a store host so
            # discovered subdomains show up alongside scanned ones.
            seen = []
            for m in re.finditer(rule.regex, text, rule.flags):
                val = (m.group(rule.group) or "").strip(".,) ").strip()
                if not val or val in seen:
                    continue
                seen.append(val)
                if rule.var == "host":
                    store.record_ports(val, [])
                else:
                    store.set_fact(rule.var, val)
            if seen:
                found[rule.var] = f"{len(seen)} found"
            continue
        m = re.search(rule.regex, text, rule.flags)
        if not m:
            continue
        val = (m.group(rule.group) or "").strip(".,) ").strip()
        if not val:
            continue
        if rule.var == "domain" and (
                any(val.lower().endswith(b) for b in _BAD_DOMAINS)
                or re.match(r"(?:args|self|kwargs|options|config|params)\.", val, re.I)):
            continue          # skip bogus / code-artifact domains
        if rule.scope == "host" and host:
            store.set_host_fact(host, rule.var, val)
        else:
            store.set_fact(rule.var, val)
        found[rule.var] = val
    return found


def record_from_text(text: str, host: str | None = None,
                     extra: list[HarvestRule] | None = None) -> dict:
    """Harvest using the default rules plus any tool-specific ones."""
    return apply_harvest(text, DEFAULT_HARVEST + (extra or []), host=host)


def base_dn_from_domain(domain: str) -> str:
    """corp.local -> DC=corp,DC=local"""
    return "DC=" + ",DC=".join(p for p in domain.split(".") if p)


def autofill(param_names) -> dict[str, str]:
    """Values we can supply for *param_names* from stored variables."""
    names = set(param_names)
    f = store.facts()
    out: dict[str, str] = {}
    for name in names:
        if name in f and f[name]:
            out[name] = f[name]
    domain = f.get("domain")
    if "base_dn" in names and "base_dn" not in out and domain:
        out["base_dn"] = base_dn_from_domain(domain)
    if "dc_ip" in names and "dc_ip" not in out and f.get("dc_ip"):
        out["dc_ip"] = f["dc_ip"]
    return out
