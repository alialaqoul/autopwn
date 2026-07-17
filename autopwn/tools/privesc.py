# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Local Windows privilege-escalation enumeration (post-foothold).

Autopwn's AD chain gets you a foothold; this finds the way from that foothold to
SYSTEM on the box. It runs a curated set of local privesc checks *on the target*
(via NetExec command execution) and parses the output into findings — the way
you'd read WinPEAS / PrivescCheck output, but structured and ATT&CK-tagged:

  * abusable token privileges (SeImpersonate / SeAssignPrimaryToken -> Potato ->
    SYSTEM; SeBackup / SeRestore -> read the SAM/SYSTEM hives),
  * AlwaysInstallElevated (any MSI runs as SYSTEM),
  * unquoted service paths (writable-dir hijack),
  * autologon plaintext credentials in the registry,
  * UAC disabled.

Needs a credential that can execute on the host — a local admin (SMB, look for
``Pwn3d!``) or a Remote-Management member (WinRM). Native — parses at the Autopwn
level and emits findings the report + ATT&CK view pick up.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from .macro import MacroTool, Results

# Curated privesc enumeration — kept compact so it fits a base64 `powershell -e`.
_PS = r'''$ErrorActionPreference='SilentlyContinue'
Write-Output "=PRIV="
whoami /priv | Select-String "SeImpersonate|SeAssignPrimaryToken|SeBackup|SeRestore|SeDebug|SeTakeOwnership|SeLoadDriver|SeManageVolume" | %{ ($_ -replace '\s+',' ').Trim() }
Write-Output "=AIE="
Write-Output ("HKLM="+(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated+" HKCU="+(Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer").AlwaysInstallElevated)
Write-Output "=UNQUOTED="
Get-CimInstance win32_service | ?{ $_.PathName -match '^[^"].*\s.*\.exe' -and $_.PathName -notmatch '(?i)C:\\Windows' } | %{ $_.Name+" | "+$_.PathName }
Write-Output "=AUTOLOGON="
$w=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; if($w.DefaultPassword){ Write-Output ("user="+$w.DefaultUserName+" pass="+$w.DefaultPassword) }
Write-Output "=UAC="
Write-Output ("EnableLUA="+(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA)
Write-Output "=DONE="'''


def _section(out: str, name: str) -> list[str]:
    """Lines between the =NAME= marker and the next =...= marker."""
    m = re.search(rf"^=\s*{name}\s*=\s*$(.*?)^=", out, re.M | re.S)
    if not m:
        return []
    return [l.strip() for l in m.group(1).splitlines() if l.strip()]


class WinPrivescTool(MacroTool):
    name = "win_privesc"
    category = "credentials"
    host_param = "target"
    description = (
        "Enumerate LOCAL Windows privilege-escalation vectors on a host you can "
        "execute on (local admin via SMB, or a WinRM member) and report each as a "
        "finding: SeImpersonate/SeAssignPrimaryToken (Potato -> SYSTEM), SeBackup/"
        "SeRestore, AlwaysInstallElevated, unquoted service paths, autologon "
        "credentials, UAC state. The automated WinPEAS/PrivescCheck pass — parsed "
        "into findings at the Autopwn level.")
    plan = [
        "Run a curated privesc enumeration on the target via NetExec (SMB -x / WinRM)",
        "Parse token privileges, AlwaysInstallElevated, unquoted services, autologon, UAC",
        "Report each abusable vector as a finding (with the local-admin/SYSTEM path)",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to enumerate (you must be able to exec on it)."},
            "username": {"type": "string", "description": "Username."},
            "password": {"type": "string", "description": "Password."},
            "domain": {"type": "string", "description": "AD domain (optional; use '.' for a local account)."},
            "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (optional)."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        auth = {"username": kw.get("username", ""), "password": kw.get("password", ""),
                "domain": kw.get("domain", ""), "hash": kw.get("hash", "")}
        b64 = base64.b64encode(_PS.encode("utf-16-le")).decode()
        cmd = f"powershell -e {b64}"

        # Execute on the host: SMB (needs local admin -> Pwn3d!) first, then WinRM.
        self.log(f"[run] local privesc enumeration on {host} (SMB exec)")
        out = self.sub("netexec_smb", target=host, command=cmd, **auth)
        if "=DONE=" not in out:
            self.log(f"[run] SMB exec gave nothing — trying WinRM on {host}")
            out = self.sub("netexec_winrm", target=host, command=cmd, **auth)
        if "=DONE=" not in out:
            self.log("[!] could not execute on the target — need local admin (SMB "
                     "'Pwn3d!') or Remote-Management (WinRM) rights for this account.")
            return

        # NetExec prefixes every line with "PROTO  IP  PORT  HOST  " — strip it so the
        # =SECTION= markers anchor at the start of a line for _section() parsing.
        out = re.sub(r"(?im)^(?:SMB|WINRM|LDAP)\s+\S+\s+\d+\s+\S+\s+", "", out)
        found = False
        # ---- token privileges -------------------------------------------------
        priv = " ".join(_section(out, "PRIV")).lower()
        if "seimpersonate" in priv or "seassignprimarytoken" in priv:
            found = True
            self.add_finding(
                "Abusable Token Privilege — SeImpersonate/SeAssignPrimaryToken (SYSTEM)",
                "High", cvss="7.8",
                description="The account holds SeImpersonate/SeAssignPrimaryToken. A "
                "'Potato' attack (Juicy/Print/RoguePotato, GodPotato) abuses it to "
                "impersonate SYSTEM — full local privilege escalation from a service "
                "or low-privileged shell.",
                recommendation="Avoid granting these privileges to non-service users; "
                "patch, and restrict service accounts.")
        if "sebackup" in priv or "serestore" in priv:
            found = True
            self.add_finding(
                "SeBackup/SeRestore Privilege — SAM/SYSTEM Hive Read", "High", cvss="7.1",
                description="SeBackup/SeRestore lets the account read protected files "
                "including the SAM and SYSTEM registry hives, yielding local account "
                "hashes (and often a path to SYSTEM).",
                recommendation="Remove backup/restore rights from interactive users.")
        other_priv = [p for p in ("SeDebug", "SeTakeOwnership", "SeLoadDriver", "SeManageVolume")
                      if p.lower() in priv]
        if other_priv:
            found = True
            self.add_finding(
                f"Dangerous Token Privilege(s): {', '.join(other_priv)}", "Medium", cvss="6.5",
                description="These privileges can be abused for local privilege "
                "escalation (e.g. SeLoadDriver -> vulnerable driver; SeDebug -> inject "
                "into a SYSTEM process).",
                recommendation="Remove these privileges from non-administrative accounts.")

        # ---- AlwaysInstallElevated -------------------------------------------
        aie = " ".join(_section(out, "AIE"))
        if re.search(r"HKLM=1", aie) and re.search(r"HKCU=1", aie):
            found = True
            self.add_finding(
                "AlwaysInstallElevated — MSI Packages Install as SYSTEM", "High", cvss="7.8",
                description="Both HKLM and HKCU AlwaysInstallElevated are set, so any "
                "user can install a crafted MSI that runs as SYSTEM — trivial local "
                "privilege escalation.",
                recommendation="Disable the AlwaysInstallElevated policy (both hives).")

        # ---- unquoted service paths ------------------------------------------
        unq = _section(out, "UNQUOTED")
        if unq:
            found = True
            names = ", ".join(u.split(" | ")[0] for u in unq[:6])
            self.add_finding(
                f"Unquoted Service Path(s): {names}", "Medium", cvss="6.5",
                description="Service(s) run from an unquoted path containing spaces "
                "outside C:\\Windows. If any parent directory is writable, a planted "
                "binary executes as the service account (often SYSTEM) at start.",
                recommendation="Quote all service ImagePath values; fix directory ACLs.")
            for u in unq[:8]:
                self.add_loot(f"unquoted service: {u}", "check writable parent dirs")

        # ---- autologon credential --------------------------------------------
        al = _section(out, "AUTOLOGON")
        for line in al:
            m = re.search(r"user=(\S*)\s+pass=(.+)$", line)
            if m and m.group(2).strip():
                found = True
                self.add_cred(m.group(1) or "autologon", m.group(2).strip(),
                              kw.get("domain", ""), note="autologon (registry)")
                self.add_finding(
                    "Autologon Plaintext Credential in Registry", "High", cvss="7.5",
                    description="A cleartext autologon password is stored under "
                    "Winlogon (DefaultPassword) — recoverable by any local user.",
                    recommendation="Remove DefaultPassword; use a managed/gMSA logon "
                    "or disable autologon.")

        # ---- UAC --------------------------------------------------------------
        if re.search(r"EnableLUA=0\b", " ".join(_section(out, "UAC"))):
            found = True
            self.add_finding(
                "UAC Disabled (EnableLUA=0)", "Low", cvss="4.0",
                description="User Account Control is disabled, so any admin-group "
                "process runs fully elevated with no consent prompt — easier local "
                "escalation and lateral movement.",
                recommendation="Re-enable UAC (EnableLUA=1) at the highest workable level.")

        if not found:
            self.log("no local privilege-escalation vectors found in the checked set.")
