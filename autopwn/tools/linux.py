# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Local Linux privilege-escalation enumeration (post-foothold).

The Linux analogue of ``win_privesc``. Given an SSH foothold (a recovered/sprayed
credential or a key), it runs a curated, **read-only** enumeration on the target
over SSH and parses the output into findings — the way you'd read linPEAS, but
structured and ATT&CK-tagged:

  * sudo rights (NOPASSWD / ``(ALL) ALL`` / a GTFOBins-abusable sudo command),
  * SUID/SGID binaries that GTFOBins turns into a root shell or file read,
  * file capabilities (``cap_setuid`` -> root),
  * dangerous group membership (docker / lxd / disk -> root-equivalent),
  * kernel + pkexec + sudo versions vs known local-root CVEs (PwnKit,
    Baron Samedit, DirtyPipe, DirtyCow),
  * a writable ``/etc/passwd`` or ``/etc/shadow``, world-writable cron, readable
    private SSH keys, and writable ``$PATH`` directories.

Posture: **enumerate + safe read-only PoCs** — every check is a read (``sudo -n``
never prompts, ``test -w`` never writes, ``find``/``getcap`` only read). Nothing
is executed to actually escalate. Native — emits findings the report + ATT&CK
view pick up.
"""
from __future__ import annotations

import glob
import os
import re
import sys
from typing import Any, Optional

from .macro import MacroTool, Results


def _import_paramiko():
    """Import paramiko, falling back to a system dist-packages install when the
    venv lacks it (offline boxes where paramiko is present system-wide but the
    venv was created with include-system-site-packages=false)."""
    try:
        import paramiko
        return paramiko
    except ImportError:
        pass
    for pat in ("/usr/lib/python3/dist-packages",
                "/usr/lib/python3/site-packages",
                "/usr/local/lib/python3*/dist-packages",
                "/usr/local/lib/python3*/site-packages"):
        for d in glob.glob(pat):
            if os.path.isdir(os.path.join(d, "paramiko")) and d not in sys.path:
                sys.path.append(d)
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None

# GTFOBins SUID entries that yield a root shell or arbitrary file read when the
# binary is setuid-root. (Not exhaustive, but the ones that actually matter.)
_GTFO_SUID = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox",
    "find", "vim", "vim.basic", "vi", "rvim", "view", "nano", "pico", "ed",
    "nmap", "less", "more", "man", "awk", "gawk", "nawk", "mawk",
    "perl", "python", "python2", "python3", "ruby", "lua", "lua5.1", "node",
    "php", "gdb", "tclsh", "expect", "socat", "env", "cp", "mv", "dd",
    "tar", "bsdtar", "cpio", "zip", "xxd", "openssl", "tee", "sed", "ex",
    "emacs", "git", "make", "ionice", "nice", "stdbuf", "time", "taskset",
    "watch", "xargs", "flock", "start-stop-daemon", "strace", "ltrace",
    "rsync", "scp", "wget", "curl", "base64", "base32", "cat", "head",
    "tail", "cut", "grep", "egrep", "fgrep", "dialog", "whiptail", "jq",
    "sqlite3", "systemctl", "docker", "nohup", "setarch", "unshare",
}
# GTFOBins sudo entries (a subset — binaries that spawn a shell / read files).
_GTFO_SUDO = _GTFO_SUID | {"apt", "apt-get", "dpkg", "pip", "gcc", "ftp", "man",
                            "mount", "service", "crontab", "journalctl", "wall",
                            "mysql", "psql", "vi", "screen", "tmux", "zip"}
# Setuid binaries that are normal on a stock system (don't flag as "unusual").
_BASELINE_SUID = {
    "su", "sudo", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "ssh-keysign", "ntfs-3g", "chrome-sandbox", "dbus-daemon-launch-helper",
    "polkit-agent-helper-1", "snap-confine", "vmware-user-suid-wrapper",
    "at", "sg", "expiry", "unix_chkpwd", "pppd", "Xorg.wrap", "vmware-vmx",
}
_DANGEROUS_GROUPS = {"docker": "T1611", "lxd": "T1611", "lxc": "T1611",
                     "disk": "T1006", "shadow": "T1003.008", "sudo": "",
                     "wheel": "", "adm": ""}

# Read-only enumeration. Every command is a read; no writes, no escalation.
_ENUM = r'''
echo "=CTX="; id; uname -rms; (grep -E '^(NAME|VERSION)=' /etc/os-release 2>/dev/null)
echo "=SUDO="; sudo -n -l 2>/dev/null
echo "=SUID="; find / -perm -4000 -type f 2>/dev/null
echo "=SGID="; find / -perm -2000 -type f 2>/dev/null
echo "=CAPS="; getcap -r / 2>/dev/null
echo "=PKEXEC="; ls -l "$(command -v pkexec 2>/dev/null)" 2>/dev/null
echo "=SUDOVER="; sudo --version 2>/dev/null | head -1
echo "=PASSWD="; ls -l /etc/passwd /etc/shadow 2>/dev/null; ( [ -w /etc/passwd ] && echo PASSWD_WRITABLE ); ( [ -w /etc/shadow ] && echo SHADOW_WRITABLE )
echo "=CRON="; cat /etc/crontab 2>/dev/null | grep -vE '^\s*#'; ls -la /etc/cron.d/ /etc/cron.hourly/ 2>/dev/null
echo "=NFS="; cat /etc/exports 2>/dev/null | grep -vE '^\s*#'
echo "=KEYS="; ls -la ~/.ssh 2>/dev/null; find /home /root -maxdepth 3 \( -name id_rsa -o -name id_ed25519 -o -name id_dsa \) 2>/dev/null
echo "=WPATH="; for d in $(echo "$PATH" | tr ':' ' '); do [ -w "$d" ] && echo "WRITABLE:$d"; done
echo "=DONE="
'''


def _section(out: str, name: str) -> list[str]:
    m = re.search(rf"^=\s*{name}\s*=\s*$(.*?)^=", out, re.M | re.S)
    if not m:
        return []
    return [l.rstrip() for l in m.group(1).splitlines() if l.strip()]


def _ver_tuple(v: str) -> tuple:
    nums = re.findall(r"\d+", v)
    return tuple(int(x) for x in nums[:3]) + (0,) * (3 - len(nums[:3]))


class LinuxPrivescTool(MacroTool):
    name = "linux_privesc"
    category = "credentials"
    host_param = "target"
    description = (
        "Enumerate LOCAL Linux privilege-escalation vectors over an SSH foothold "
        "and report each as a finding: abusable sudo rights, GTFOBins SUID/SGID "
        "binaries, dangerous capabilities, docker/lxd/disk group membership, "
        "kernel/pkexec/sudo versions vs local-root CVEs (PwnKit, Baron Samedit, "
        "DirtyPipe, DirtyCow), writable /etc/passwd, world-writable cron, readable "
        "private keys. The automated linPEAS pass — read-only, parsed into "
        "findings at the Autopwn level.")
    plan = [
        "SSH to the target with the supplied credential/key",
        "Run a read-only privesc enumeration (sudo -l, SUID/SGID, caps, versions)",
        "Parse each abusable vector into a finding with the root path + fix",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to enumerate over SSH."},
            "username": {"type": "string", "description": "SSH username."},
            "password": {"type": "string", "description": "SSH password (or use key)."},
            "key": {"type": "string", "description": "Path to a private key file (optional)."},
            "port": {"type": "string", "description": "SSH port (default 22)."},
        },
        "required": ["target"],
    }

    # ---- SSH exec --------------------------------------------------------
    def _ssh_run(self, host: str, user: str, password: str, key: str,
                 port: int, script: str) -> Optional[str]:
        paramiko = _import_paramiko()
        if paramiko is None:
            self.log("[!] paramiko is not available (not in the venv or system "
                     "dist-packages) — install it to enable SSH enumeration.")
            return None
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(host, port=port, username=user or None,
                        password=password or None,
                        key_filename=key or None,
                        look_for_keys=bool(key), allow_agent=False,
                        timeout=15, banner_timeout=15, auth_timeout=15)
        except Exception as e:                       # auth / network failure
            self.log(f"[!] SSH to {user}@{host}:{port} failed: {type(e).__name__}: {e}")
            return None
        try:
            _in, out, err = cli.exec_command(script, timeout=90)
            return out.read().decode("utf-8", "replace") + \
                err.read().decode("utf-8", "replace")
        except Exception as e:
            self.log(f"[!] SSH exec error: {e}")
            return None
        finally:
            cli.close()

    # ---- run -------------------------------------------------------------
    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        user = kw.get("username", "")
        try:
            port = int(kw.get("port") or 22)
        except ValueError:
            port = 22
        self.log(f"[run] SSH privesc enumeration on {user or '?'}@{host}:{port}")
        out = self._ssh_run(host, user, kw.get("password", ""), kw.get("key", ""),
                            port, _ENUM)
        if not out or "=DONE=" not in out:
            self.log("[!] enumeration did not complete — check the SSH credential/key.")
            return

        ctx = " ".join(_section(out, "CTX"))
        km = re.search(r"\b(\d+\.\d+\.\d+\S*)\b", ctx)
        kernel = km.group(1) if km else ""
        self.log(f"  | context: {ctx[:120]}")
        found = False

        # ---- sudo -------------------------------------------------------
        sudo = "\n".join(_section(out, "SUDO"))
        sl = sudo.lower()
        if re.search(r"\(all\s*:?\s*all\)\s*(nopasswd:\s*)?all", sl) or \
           re.search(r"\(all\)\s*(nopasswd:\s*)?all", sl):
            found = True
            self.add_finding(
                "Sudo Grants Full Root ((ALL) ALL)", "Critical", cvss="8.8",
                description="This account may run any command via sudo ((ALL) ALL / "
                "NOPASSWD: ALL) — an immediate, trivial path to root.",
                recommendation="Restrict sudoers to the minimum specific commands; "
                "avoid (ALL) ALL and NOPASSWD for interactive users.")
        else:
            # specific NOPASSWD commands that map to a GTFOBins sudo escape
            for line in _section(out, "SUDO"):
                m = re.search(r"NOPASSWD:\s*(.+)$", line, re.I)
                cmds = m.group(1) if m else (line if line.strip().startswith("/") else "")
                for path in re.findall(r"/\S+", cmds):
                    b = path.rsplit("/", 1)[-1]
                    if b in _GTFO_SUDO:
                        found = True
                        self.add_finding(
                            f"Sudo GTFOBins Escalation — {b}", "Critical", cvss="8.8",
                            description=f"The account may run '{path}' via sudo "
                            f"(often NOPASSWD). '{b}' has a GTFOBins sudo escape that "
                            "spawns a root shell or reads/writes root-owned files.",
                            recommendation=f"Remove '{b}' from sudoers or wrap it "
                            "without shell/file-access capability.")
                        self.add_loot(f"sudo {path}", f"GTFOBins: {b} -> root")
                        break

        # ---- SUID / SGID ------------------------------------------------
        suids = _section(out, "SUID")
        gtfo_suid = sorted({p.rsplit("/", 1)[-1] for p in suids
                            if p.rsplit("/", 1)[-1] in _GTFO_SUID})
        if gtfo_suid:
            found = True
            self.add_finding(
                f"GTFOBins SUID Binary(ies): {', '.join(gtfo_suid[:8])}",
                "High", cvss="8.4",
                description="Setuid-root binaries with a known GTFOBins escape are "
                "present: " + ", ".join(gtfo_suid) + ". Each spawns a root shell or "
                "reads/writes root-owned files with no password.",
                recommendation="Remove the setuid bit (chmod u-s) from non-essential "
                "binaries; keep only vetted setuid programs.")
            for b in gtfo_suid[:10]:
                self.add_loot(f"SUID {b}", f"GTFOBins SUID -> root ({b})")
        unusual = sorted({p.rsplit("/", 1)[-1] for p in suids
                          if p.rsplit("/", 1)[-1] not in _BASELINE_SUID
                          and p.rsplit("/", 1)[-1] not in _GTFO_SUID})
        if unusual:
            self.add_loot("unusual SUID: " + ", ".join(unusual[:12]),
                          "non-standard setuid binaries — check GTFOBins / custom bins")

        # ---- capabilities ----------------------------------------------
        caps = [c for c in _section(out, "CAPS")
                if re.search(r"cap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace)", c)]
        if caps:
            found = True
            self.add_finding(
                "Dangerous File Capabilities", "High", cvss="8.0",
                description="Binaries carry privesc-grade capabilities:\n"
                + "\n".join(caps[:8]) + "\ncap_setuid -> set uid 0; cap_dac_read_search "
                "-> read any file (SAM/shadow); cap_sys_admin/ptrace -> broad root access.",
                recommendation="Remove capabilities (setcap -r) from binaries that "
                "don't require them.")
            for c in caps[:8]:
                self.add_loot(f"capability: {c}", "privesc-grade file capability")

        # ---- dangerous groups ------------------------------------------
        gm = re.search(r"groups=([^\s]+)", ctx)
        groups = re.findall(r"\(([a-z0-9_]+)\)", gm.group(1)) if gm else []
        hits = [g for g in groups if g in _DANGEROUS_GROUPS
                and _DANGEROUS_GROUPS[g]]   # only the root-equivalent ones
        for g in hits:
            found = True
            self.add_finding(
                f"Root-Equivalent Group Membership — {g}", "Critical", cvss="8.8",
                description=f"The account is in the '{g}' group. "
                + {"docker": "Members of 'docker' can run a container that mounts the "
                             "host filesystem as root — instant root.",
                   "lxd": "Members of 'lxd'/'lxc' can launch a privileged container "
                          "mounting the host root — instant root.",
                   "lxc": "Members of 'lxc'/'lxd' can launch a privileged container "
                          "mounting the host root — instant root.",
                   "disk": "The 'disk' group can read/write raw block devices "
                           "(debugfs /dev/sda) — read /etc/shadow or overwrite files.",
                   "shadow": "The 'shadow' group can read /etc/shadow — offline-crack "
                             "every local password."}.get(g, "Root-equivalent access."),
                recommendation=f"Remove the account from '{g}' unless strictly required.")

        # ---- kernel / pkexec / sudo CVEs -------------------------------
        pkexec = "\n".join(_section(out, "PKEXEC"))
        if re.search(r"rws|/pkexec", pkexec) and "pkexec" in pkexec:
            found = True
            self.add_finding(
                "PwnKit — pkexec Local Root (CVE-2021-4034)", "Critical", cvss="7.8",
                description="A setuid pkexec is present. Unless patched (polkit "
                ">= 0.120-2 / distro fix), CVE-2021-4034 (PwnKit) gives any local "
                "user root with a public, reliable exploit.",
                recommendation="Patch polkit/pkexec; if unused, remove the setuid bit.")
        sudover = " ".join(_section(out, "SUDOVER"))
        sm = re.search(r"(\d+\.\d+\.\d+)(p\d+)?", sudover)
        if sm:
            sv = _ver_tuple(sm.group(1)) + (int(re.sub(r"\D", "", sm.group(2) or "0") or 0),)
            if sv < (1, 9, 5, 2):   # < 1.9.5p2
                found = True
                self.add_finding(
                    f"Sudo Baron Samedit (CVE-2021-3156) — sudo {sm.group(0)}",
                    "Critical", cvss="7.8",
                    description=f"sudo {sm.group(0)} predates 1.9.5p2 and is vulnerable "
                    "to CVE-2021-3156 (Baron Samedit), a heap overflow giving local "
                    "root with a public exploit — no sudo rights required.",
                    recommendation="Update sudo to >= 1.9.5p2.")
        if kernel:
            kv = _ver_tuple(kernel)
            if (5, 8, 0) <= kv <= (5, 16, 11):
                found = True
                self.add_finding(
                    f"DirtyPipe (CVE-2022-0847) — kernel {kernel}", "Critical",
                    cvss="7.8",
                    description=f"Kernel {kernel} is in the DirtyPipe range "
                    "(5.8 – 5.16.11): a public local-root exploit overwrites read-only "
                    "files (e.g. /etc/passwd) to gain root.",
                    recommendation="Patch the kernel (>= 5.16.11 / distro backport).")
            elif kv and kv < (4, 8, 3):
                found = True
                self.add_finding(
                    f"DirtyCow (CVE-2016-5195) — kernel {kernel}", "Critical",
                    cvss="7.8",
                    description=f"Kernel {kernel} predates 4.8.3 and is vulnerable to "
                    "DirtyCow (CVE-2016-5195), a race-condition local-root exploit.",
                    recommendation="Patch/upgrade the kernel.")

        # ---- writable passwd/shadow, cron, keys, PATH ------------------
        pw = "\n".join(_section(out, "PASSWD"))
        if "PASSWD_WRITABLE" in pw or "SHADOW_WRITABLE" in pw:
            found = True
            tgt = "/etc/shadow" if "SHADOW_WRITABLE" in pw else "/etc/passwd"
            self.add_finding(
                f"World/Group-Writable {tgt}", "Critical", cvss="9.1",
                description=f"{tgt} is writable by this account — add a root user "
                "(passwd) or blank the root hash (shadow) to become root immediately.",
                recommendation=f"Restore {tgt} to root:root 0644 (passwd) / 0640 "
                "(shadow).")
        cron = _section(out, "CRON")
        if any(re.search(r"\*\s+.*\s+/\S+\.sh", c) for c in cron):
            self.add_loot("cron jobs (check writable scripts): "
                          + "; ".join(cron[:4]), "T1053.003 — writable cron -> root")
        keys = [k for k in _section(out, "KEYS") if re.search(r"id_(rsa|ed25519|dsa)$", k)]
        if keys:
            self.add_loot("private SSH keys readable: " + "; ".join(keys[:6]),
                          "T1552.004 — reuse for lateral movement")
        wpath = [w.split(":", 1)[1] for w in _section(out, "WPATH") if ":" in w]
        if wpath:
            found = True
            self.add_finding(
                f"Writable $PATH Director(ies): {', '.join(wpath[:5])}", "High",
                cvss="7.8",
                description="A directory on $PATH is writable — plant a binary that "
                "shadows a command run by root/cron/sudo for privilege escalation.",
                recommendation="Remove writable directories from PATH; fix their "
                "permissions.")

        if not found:
            self.log("no local privilege-escalation vectors found in the checked set.")
