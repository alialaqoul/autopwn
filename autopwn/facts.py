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
    "domain":   "AD / DNS domain, e.g. cyberlab.local",
    "base_dn":  "LDAP base DN (auto-derived from domain)",
    "dc_ip":    "Domain controller IP",
    "username": "Username / login",
    "password": "Password",
    "nthash":   "NTLM hash (pass-the-hash)",
    "userlist": "Path to a usernames wordlist",
    "passlist": "Path to a passwords wordlist",
}


@dataclass
class HarvestRule:
    """Extract a canonical variable from tool output via regex."""
    var: str
    regex: str
    scope: str = "global"   # "global" | "host"
    group: int = 1
    flags: int = re.IGNORECASE


# Applied to every tool's output regardless of which tool ran.
DEFAULT_HARVEST: list[HarvestRule] = [
    HarvestRule("domain", r"domain[:=]\s*\(?([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})"),
    HarvestRule("hostname", r"\bname:\s*([A-Za-z0-9\-]{1,32})", scope="host"),
    HarvestRule("os", r"(Windows[^()\[\]\n]{0,40})", scope="host"),
    # NetExec/CME success line: "[+] cyberlab.local\\admin:Passw0rd (Pwn3d!)"
    HarvestRule("username", r"\[\+\]\s*[^\\\s]+\\([^:\s]+):", scope="global"),
    HarvestRule("password", r"\[\+\]\s*[^\\\s]+\\[^:\s]+:([^\s(]+)", scope="global"),
]

_BAD_DOMAINS = ("home.arpa", "in-addr.arpa")


def apply_harvest(text: str, rules: list[HarvestRule], host: str | None = None) -> dict:
    """Run harvest *rules* over *text*, store hits, and return what was found."""
    found: dict[str, str] = {}
    if not text:
        return found
    for rule in rules:
        m = re.search(rule.regex, text, rule.flags)
        if not m:
            continue
        val = (m.group(rule.group) or "").strip(".,) ").strip()
        if not val:
            continue
        if rule.var == "domain" and any(val.lower().endswith(b) for b in _BAD_DOMAINS):
            continue
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
    """cyberlab.local -> DC=cyberlab,DC=local"""
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
