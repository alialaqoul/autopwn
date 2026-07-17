# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Network-device & firewall tooling (Cluster B) — recognise and safely test the
switches and firewalls that carry an estate: Cisco IOS / ASA-FTD, Extreme EXOS,
Fortinet FortiGate, Juniper JunOS.

Two native tools, both **non-destructive** (SNMP GETs, a banner read, read-only
HTTP GETs and ordinary login attempts — no SNMP SET, no config writes, no
exploitation, no persistence):

  * ``net_device_recon`` — fingerprint a host from its SSH banner, HTTP title and
    SNMP sysDescr, match it against ``signatures`` (kind="netdev"), tag it, raise
    an Exposed-device finding with the product's CVEs + config-loot, run each
    product's **read-only** proof-of-access PoC (FortiOS/ASA path-traversal
    confirmation, Juniper J-Web reachability), and flag an exposed Cisco Smart
    Install service (TCP 4786).
  * ``snmp_audit`` — brute a small list of common SNMP community strings (GET
    only), read sysDescr for each that answers, and report readable communities —
    escalating write-suggesting names (private/manager/…) as likely RW = config
    push.

Device catalogue is data (`signatures.py`).
"""
from __future__ import annotations

import re
import socket
from typing import Any

from .. import signatures
from .macro import MacroTool, Results
from .mgmt import _http, _base, _TITLE   # reuse the safe HTTP helpers

# Community strings worth a non-destructive sweep. Names in _RW_HINT typically
# denote a read-WRITE community (config push) when they answer.
_COMMUNITIES = ["public", "private", "community", "cisco", "manager", "secret",
                "admin", "read", "write", "snmp", "default", "monitor",
                "network", "security", "root"]
_RW_HINT = {"private", "write", "manager", "secret", "admin", "root", "security"}

# onesixtyone hit:  <ip> [<community>] <sysDescr...>
_ONESIXTYONE = re.compile(r"\[([^\]]+)\]\s*(.*)")


def _ssh_banner(host: str, port: int = 22, timeout: int = 5) -> str:
    """Read the SSH identification banner the server sends on connect (passive)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256).decode("latin-1", "replace").strip()
        return data if data.upper().startswith("SSH-") else ""
    except OSError:
        return ""


def _tcp_open(host: str, port: int, timeout: int = 4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# --------------------------------------------------------------------------- #
class NetDeviceReconTool(MacroTool):
    name = "net_device_recon"
    category = "recon"
    description = ("Fingerprint a host as a network device / firewall (Cisco IOS "
                   "& ASA-FTD, Extreme EXOS, FortiGate, Juniper) from its SSH "
                   "banner, HTTP title and SNMP sysDescr, tag it, and raise an "
                   "Exposed-device finding with CVEs + config-loot, a read-only "
                   "proof-of-access PoC, and a Cisco Smart Install (4786) check. "
                   "Non-destructive.")
    plan = [
        "Read the SSH banner + HTTP title (passive/read-only)",
        "Read SNMP sysDescr with common communities (GET only)",
        "Match against signatures (kind=netdev); tag host is_<product>",
        "Run each product's read-only PoC (FortiOS/ASA traversal, J-Web reach)",
        "Flag an exposed Cisco Smart Install service (TCP 4786)",
        "Report each device as a finding with CVEs + config-loot",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to fingerprint."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        from .. import store
        host = kw["target"]
        entry = (store.all_hosts() or {}).get(host, {})
        open_ports = signatures._host_open_ports(entry)

        # 1) evidence: SSH banner + HTTP titles + one quick SNMP sysDescr
        evidence = [_ssh_banner(host)]
        for prod in signatures.by_kind("netdev"):
            if prod.web_port and (open_ports & set(prod.ports)):
                st, hdrs, body = _http("GET", _base(prod, host, prod.url_port) + "/")
                if st:
                    t = _TITLE.search(body)
                    evidence.append((t.group(1).strip() if t else "")
                                    + " " + hdrs.get("Server", ""))
        sysdescr = self._snmp_sysdescr(host, ["public"])
        if sysdescr:
            evidence.append(sysdescr)

        found = signatures.identify(entry, " ".join(e for e in evidence if e),
                                    kind="netdev")
        if not found:
            self.log("no network device / firewall recognised on this host")
            return

        for hit in found:
            prod: signatures.Product = hit["product"]
            self.log(f"[+] {prod.name} on {host} — {hit['reason']}")
            store.set_host_fact(host, f"is_{prod.id}", "true")

            poc_note = self._safe_poc(prod, host)
            smi_note = ""
            if prod.id == "cisco_ios" and (4786 in open_ports or _tcp_open(host, 4786)):
                smi_note = " Cisco Smart Install (TCP 4786) is OPEN — unauthenticated " \
                           "running-config exfiltration / RCE (CVE-2018-0171, SIET)."
                self.add_finding(
                    "Cisco Smart Install exposed (TCP 4786)", "Critical", cvss="9.8",
                    description="Smart Install accepts unauthenticated commands: an "
                                "attacker can pull or overwrite the running-config "
                                "and achieve code execution (CVE-2018-0171). Disable "
                                "with 'no vstack' if Smart Install is not in use.")

            desc = (f"{prod.name} is exposed on port(s) {', '.join(map(str, hit['ports']))} "
                    f"({hit['reason']}). "
                    + (f"Notable CVEs: {'; '.join(prod.cves)}. " if prod.cves else "")
                    + (f"Impact: {prod.loot}" if prod.loot else "")
                    + (f" {poc_note}" if poc_note else "") + smi_note)
            self.add_finding(f"Exposed {prod.name} management interface",
                             prod.severity, description=desc, cvss=prod.cvss)
            if prod.loot:
                self.add_loot(f"{prod.name} @ {host}", prod.loot)

    def _snmp_sysdescr(self, host: str, communities: list) -> str:
        """One onesixtyone sweep for sysDescr (device model) — read-only."""
        for c in communities:
            out = self.sub("onesixtyone", target=host, community=c)
            m = _ONESIXTYONE.search(out or "")
            if m:
                return m.group(2).strip()
        return ""

    def _safe_poc(self, prod: signatures.Product, host: str) -> str:
        poc = prod.safe_poc
        if not poc:
            return ""
        st, _h, body = _http("GET", _base(prod, host, prod.url_port) + poc["path"])
        if st and re.search(poc["ok"], body):
            tag = f" ({poc['cve']})" if poc.get("cve") else ""
            self.log(f"  │ PoC confirmed{tag}: {poc.get('desc', '')}")
            return f"Read-only PoC confirmed{tag}: {poc.get('desc', '')}"
        return ""


# --------------------------------------------------------------------------- #
class SnmpAuditTool(MacroTool):
    name = "snmp_audit"
    category = "recon"
    description = ("Brute a small list of common SNMP community strings (GET "
                   "only) and read sysDescr for each that answers. Reports "
                   "readable communities; write-suggesting names (private / "
                   "manager / …) are flagged as likely read-write = device "
                   "configuration push. Non-destructive (no SNMP SET).")
    plan = [
        "Try common community strings with onesixtyone (single UDP GET each)",
        "For each that answers, capture the device sysDescr",
        "Report readable communities; flag likely-RW ones as Critical",
    ]
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host/IP to audit."},
        },
        "required": ["target"],
    }

    def execute(self, R: Results, **kw: Any) -> None:
        host = kw["target"]
        readable = []
        for c in _COMMUNITIES:
            out = self.sub("onesixtyone", target=host, community=c)
            m = _ONESIXTYONE.search(out or "")
            if not m:
                continue
            community, sysdescr = m.group(1).strip(), m.group(2).strip()
            if community in [r[0] for r in readable]:
                continue
            readable.append((community, sysdescr))
            rw = community.lower() in _RW_HINT
            self.log(f"  │ SNMP community '{community}' READABLE"
                     + (" (likely READ-WRITE)" if rw else "")
                     + (f" — {sysdescr[:80]}" if sysdescr else ""))
            self.add_loot(f"SNMP {community}@{host}",
                          sysdescr or "device readable over SNMP")
        if not readable:
            self.log("no readable SNMP community found")
            return
        rw_comms = [c for c, _ in readable if c.lower() in _RW_HINT]
        names = ", ".join(c for c, _ in readable)
        if rw_comms:
            self.add_finding(
                f"Writable SNMP community on {host}: {', '.join(rw_comms)}",
                "Critical", cvss="9.1",
                description=f"The host answers to SNMP community/-ies '{', '.join(rw_comms)}', "
                            "whose name denotes read-WRITE access. An RW community "
                            "lets an attacker download AND overwrite the device "
                            "configuration (e.g. TFTP the running-config out, or push "
                            "a new one) — full control of the device. Restrict SNMP "
                            "to SNMPv3 with auth+priv and remove default communities.")
        else:
            self.add_finding(
                f"Readable SNMP community on {host}: {names}", "High", cvss="7.5",
                description=f"The host exposes SNMP with community/-ies '{names}'. A "
                            "readable community discloses the interface/route/ARP "
                            "tables and often the device configuration and "
                            "credentials. Move to SNMPv3 (auth+priv) and remove "
                            "default/guessable communities.")
