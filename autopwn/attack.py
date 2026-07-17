# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""MITRE ATT&CK mapping for Autopwn — the interoperability layer.

Every finding Autopwn reports and every tool it runs maps to one or more
ATT&CK technique IDs, kept in ONE place here (rather than sprinkled across the
catalog/playbooks) so the mapping is easy to audit and extend. From that mapping
we can emit a **MITRE ATT&CK Navigator layer** for an assessment — the common
export format consumed by Navigator, VECTR, Caldera and OpenBAS — turning a
Autopwn run into measurable, technique-level coverage a blue team can track.

Fully offline: the technique catalogue below is embedded, so nothing is fetched
at runtime (the appliance has no internet).
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Optional

# --------------------------------------------------------------------------- #
# Technique catalogue: id -> (name, ATT&CK tactic shortname)
# Curated to the subset Autopwn actually exercises.
# --------------------------------------------------------------------------- #
TECHNIQUES: dict[str, tuple[str, str]] = {
    # discovery
    "T1046": ("Network Service Discovery", "discovery"),
    "T1018": ("Remote System Discovery", "discovery"),
    "T1087.002": ("Account Discovery: Domain Account", "discovery"),
    "T1069.002": ("Permission Groups Discovery: Domain Groups", "discovery"),
    "T1135": ("Network Share Discovery", "discovery"),
    "T1201": ("Password Policy Discovery", "discovery"),
    "T1482": ("Domain Trust Discovery", "discovery"),
    # credential access
    "T1110": ("Brute Force", "credential-access"),
    "T1110.001": ("Brute Force: Password Guessing", "credential-access"),
    "T1110.002": ("Brute Force: Password Cracking", "credential-access"),
    "T1110.003": ("Brute Force: Password Spraying", "credential-access"),
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1003.002": ("OS Credential Dumping: Security Account Manager", "credential-access"),
    "T1003.006": ("OS Credential Dumping: DCSync", "credential-access"),
    "T1558": ("Steal or Forge Kerberos Tickets", "credential-access"),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", "credential-access"),
    "T1558.004": ("Steal or Forge Kerberos Tickets: AS-REP Roasting", "credential-access"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "credential-access"),
    "T1187": ("Forced Authentication", "credential-access"),
    "T1649": ("Steal or Forge Authentication Certificates", "credential-access"),
    "T1557.001": ("Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay",
                  "credential-access"),
    "T1556": ("Modify Authentication Process", "credential-access"),
    # lateral movement
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "lateral-movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "lateral-movement"),
    "T1550.002": ("Use Alternate Authentication Material: Pass the Hash", "lateral-movement"),
    # privilege escalation / persistence
    "T1098": ("Account Manipulation", "persistence"),
    "T1078": ("Valid Accounts", "privilege-escalation"),
    # initial access / execution
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1072": ("Software Deployment Tools", "execution"),
    "T1210": ("Exploitation of Remote Services", "lateral-movement"),
    "T1569.002": ("System Services: Service Execution", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    # collection
    "T1039": ("Data from Network Shared Drive", "collection"),
}

# --------------------------------------------------------------------------- #
# Finding -> techniques. Keyed by a keyword matched (case-insensitive) against
# the finding title, so minor title wording changes still map. First list wins
# per keyword; a finding accumulates techniques from every keyword it matches.
# --------------------------------------------------------------------------- #
_FINDING_RULES: list[tuple[str, list[str]]] = [
    ("dcsync", ["T1003.006"]),
    ("ntds", ["T1003.006"]),
    ("esc8", ["T1557.001", "T1649"]),
    ("relay to ad cs", ["T1557.001", "T1649"]),
    ("relay to ldap", ["T1557.001", "T1098"]),
    ("relay to smb", ["T1557.001", "T1003.002"]),
    ("smb signing", ["T1557.001"]),
    ("ad cs", ["T1649"]),
    ("certificate template", ["T1649"]),
    ("shadow credential", ["T1649", "T1098"]),
    ("coercion", ["T1187"]),
    ("printerbug", ["T1187"]),
    ("petitpotam", ["T1187"]),
    ("kerberoast", ["T1558.003"]),
    ("as-rep", ["T1558.004"]),
    ("asrep", ["T1558.004"]),
    ("delegation", ["T1558"]),
    ("dpapi", ["T1555"]),
    ("password store", ["T1555"]),
    ("readable share", ["T1552.001", "T1039"]),
    ("credential reuse", ["T1552.001"]),
    ("wsus", ["T1557.001", "T1072"]),
    ("sccm", ["T1072"]),
    ("mecm", ["T1072"]),
    ("weak", ["T1110.003"]),
    ("guessable", ["T1110.003"]),
    ("spray", ["T1110.003"]),
    ("password policy", ["T1201"]),
    ("pre-created", ["T1078"]),
    ("pre-windows", ["T1078"]),
    ("null", ["T1087.002", "T1135"]),
    ("anonymous", ["T1087.002", "T1135"]),
    ("user enumeration", ["T1087.002"]),
    ("web application", ["T1190"]),
    ("default credential", ["T1078", "T1190"]),
    ("administration console", ["T1133", "T1190"]),
    ("rdp", ["T1021.001"]),
    ("remote desktop", ["T1021.001"]),
    ("winrm", ["T1021.006"]),
    ("pass-the-hash", ["T1550.002"]),
    ("pass the hash", ["T1550.002"]),
    ("rbcd", ["T1098"]),
    # local privilege escalation (win_privesc)
    ("token privilege", ["T1134.001"]),
    ("seimpersonate", ["T1134.001"]),
    ("sebackup", ["T1003.002"]),
    ("alwaysinstallelevated", ["T1548.002"]),
    ("unquoted service", ["T1574.009"]),
    ("autologon", ["T1552.002"]),
    ("uac disabled", ["T1548.002"]),
    # IPv6 DNS takeover (mitm6)
    ("ipv6", ["T1557.001"]),
    ("dns takeover", ["T1557.001"]),
    # live-host credential harvest (win_creds / lsassy)
    ("host credentials recovered", ["T1003.001", "T1003.002", "T1003.004"]),
    ("lsass", ["T1003.001"]),
    ("lsa secret", ["T1003.004"]),
    # domain persistence
    ("golden ticket", ["T1558.001"]),
    ("silver ticket", ["T1558.002"]),
    ("golden certificate", ["T1649"]),
    ("dcshadow", ["T1207"]),
    ("skeleton key", ["T1556.001"]),
    ("adminsdholder", ["T1098"]),
    # enterprise management / monitoring servers (mgmt-server-audit)
    ("management interface", ["T1190", "T1078"]),
    ("solarwinds", ["T1190", "T1552.001"]),
    ("epolicy orchestrator", ["T1190", "T1072"]),
    ("splunk", ["T1190", "T1552.001", "T1072"]),
    ("acronis", ["T1190", "T1078"]),
    ("tripwire", ["T1190", "T1562.001"]),
    ("extremecloud", ["T1190", "T1552.001"]),
    ("netsight", ["T1190", "T1552.001"]),
    ("radius", ["T1557", "T1110.002"]),
    ("nps", ["T1557", "T1110.002"]),
]

# --------------------------------------------------------------------------- #
# Tool (catalog name) -> techniques. Used for "attempted/tested" coverage.
# --------------------------------------------------------------------------- #
TOOL_TECHNIQUES: dict[str, list[str]] = {
    "nmap_scan": ["T1046", "T1018"],
    "netexec_smb": ["T1021.002", "T1087.002", "T1135"],
    "netexec_winrm": ["T1021.006"],
    "netexec_ldap": ["T1087.002", "T1069.002"],
    "netexec_module": ["T1046"],
    "enum4linux": ["T1087.002", "T1135"],
    "lookupsid": ["T1087.002"],
    "rid_brute": ["T1087.002"],
    "asrep_roast": ["T1558.004"],
    "kerberoast": ["T1558.003"],
    "targeted_kerberoast": ["T1558.003"],
    "secretsdump": ["T1003.006", "T1003"],
    "coercer": ["T1187"],
    "ntlm_relay": ["T1557.001"],
    "certipy_find": ["T1649"],
    "certipy_req": ["T1649"],
    "certipy_auth": ["T1649"],
    "certipy_shadow": ["T1649", "T1098"],
    "finddelegation": ["T1558"],
    "bloodhound_python": ["T1087.002", "T1069.002", "T1482"],
    "bloodyad": ["T1098"],
    "dacledit": ["T1098"],
    "hashcat": ["T1110.002"],
    "john": ["T1110.002"],
    "hydra": ["T1110.001"],
    "smbclient": ["T1135", "T1039"],
    "smbmap": ["T1135", "T1039"],
    "evil_winrm": ["T1021.006"],
    "psexec": ["T1569.002", "T1021.002"],
    "wmiexec": ["T1047", "T1021.002"],
    "smbexec": ["T1569.002"],
    "nikto": ["T1190"],
    "sqlmap": ["T1190"],
    "searchsploit": ["T1190"],
    "spray": ["T1110.003"],
    "netexec_spray": ["T1110.003"],
    "mitm6": ["T1557.001", "T1557"],
    "win_privesc": ["T1134.001", "T1548.002", "T1574.009", "T1552.002"],
    "lsassy": ["T1003.001"],
    "win_creds": ["T1003.001", "T1003.002", "T1003.004"],
    "ticketer": ["T1558.001", "T1558.002"],
    "product_recon": ["T1046", "T1595.002", "T1590.002", "T1190"],
    "default_creds": ["T1078", "T1110.001"],
}


# --------------------------------------------------------------------------- #
# Offline-first technique catalogue with an optional online/offline refresh.
#
# TECHNIQUES above is the built-in, zero-config baseline — it needs no internet.
# If a refreshed catalogue file is present it is merged on top, so technique
# names/tactics can be updated to the latest MITRE ATT&CK release either ONLINE
# (fetch the STIX bundle) or OFFLINE (drop the downloaded enterprise-attack.json
# on the box and update from that path). Only the distilled id->name/tactic map
# is stored (~100 KB), never the ~35 MB STIX bundle.
# --------------------------------------------------------------------------- #
_DATA_DIR = Path(__file__).resolve().parent / "data"
_CATALOG_FILE = _DATA_DIR / "attack_catalog.json"
# Canonical machine-readable ATT&CK (MITRE-maintained), enterprise domain.
MITRE_STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/"
                  "attack-stix-data/master/enterprise-attack/enterprise-attack.json")

_catalog_cache: Optional[dict] = None
_catalog_meta: dict = {}


def _load_catalog() -> dict:
    """Effective technique catalogue: built-in baseline merged with a refreshed
    file (if any). Cached; _invalidate_catalog() drops the cache after an update."""
    global _catalog_cache, _catalog_meta
    if _catalog_cache is not None:
        return _catalog_cache
    cat = {k: (v[0], v[1]) for k, v in TECHNIQUES.items()}
    _catalog_meta = {"source": "built-in", "attack_version": "", "updated": None,
                     "builtin": len(TECHNIQUES)}
    try:
        payload = json.loads(_CATALOG_FILE.read_text(encoding="utf-8"))
        for tid, nt in (payload.get("techniques") or {}).items():
            if isinstance(nt, (list, tuple)) and nt:
                cat[tid] = (nt[0], nt[1] if len(nt) > 1 else "")
        _catalog_meta = {"source": "file", "attack_version": payload.get("attack_version", ""),
                         "updated": payload.get("updated"), "builtin": len(TECHNIQUES),
                         "file_source": payload.get("source", "")}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    _catalog_cache = cat
    return cat


def _invalidate_catalog() -> None:
    global _catalog_cache
    _catalog_cache = None


def name_of(tech: str) -> tuple[str, str]:
    """(name, tactic) for a technique id, from the effective catalogue."""
    return _load_catalog().get(tech, (tech, ""))


def catalog_status() -> dict:
    """What technique catalogue is active — for the Settings 'ATT&CK data' panel."""
    total = len(_load_catalog())
    return {"techniques": total, **_catalog_meta}


def _parse_stix(bundle: dict) -> tuple[dict, str]:
    """Distil an ATT&CK STIX bundle to {technique_id: [name, tactic]} + version."""
    out: dict = {}
    version = ""
    for obj in bundle.get("objects", []):
        t = obj.get("type")
        if t == "x-mitre-collection":
            version = obj.get("x_mitre_version", "") or version
            continue
        if t != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = ref["external_id"]
                break
        if not tid:
            continue
        tactic = ""
        for ph in obj.get("kill_chain_phases", []):
            if ph.get("kill_chain_name") == "mitre-attack":
                tactic = ph.get("phase_name", "")
                break
        out[tid] = [obj.get("name", tid), tactic]
    return out, version


def update(url: Optional[str] = None, from_path: Optional[str] = None) -> dict:
    """Refresh the technique catalogue to the latest MITRE ATT&CK.

    Online:  fetch the STIX bundle from ``url`` (default MITRE) — needs internet.
    Offline: pass ``from_path`` to a downloaded ``enterprise-attack.json``.
    Writes the distilled catalogue next to the module; returns a status dict.
    Raises on failure (e.g. no internet) so the caller can report it.
    """
    if from_path:
        raw = Path(from_path).read_bytes()
        source = str(from_path)
    else:
        u = url or MITRE_STIX_URL
        with urllib.request.urlopen(u, timeout=45) as r:   # raises when offline
            raw = r.read()
        source = u
    techniques, version = _parse_stix(json.loads(raw))
    if not techniques:
        raise ValueError("no ATT&CK techniques parsed from the bundle")
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _CATALOG_FILE.write_text(json.dumps(
        {"attack_version": version, "updated": time.time(), "source": source,
         "techniques": techniques}), encoding="utf-8")
    _invalidate_catalog()
    return {"ok": True, "techniques": len(techniques), "attack_version": version,
            "source": source}


def for_finding(title: str) -> list[str]:
    """ATT&CK technique IDs for a finding title (deduped, order-stable)."""
    t = (title or "").lower()
    out: list[str] = []
    for kw, techs in _FINDING_RULES:
        if kw in t:
            for tech in techs:
                if tech not in out:
                    out.append(tech)
    return out


def for_tool(name: str) -> list[str]:
    """ATT&CK technique IDs for a tool/transcript entry name."""
    n = (name or "").strip()
    if n.startswith("playbook:"):
        return []
    return TOOL_TECHNIQUES.get(n, [])


def tools_from_transcript(transcript) -> list[str]:
    """Distinct tool names executed in a run (from tool_result entries)."""
    seen: list[str] = []
    for e in transcript or []:
        if e.get("kind") == "tool_result":
            n = e.get("name") or ""
            if n and n not in seen:
                seen.append(n)
    return seen


# --------------------------------------------------------------------------- #
# Detection expectations: for each technique, what a defender should have seen.
# Turns a red-team run into a blue-team checklist (data sources + guidance).
# --------------------------------------------------------------------------- #
DETECTION: dict[str, tuple[str, str]] = {
    "T1003.006": ("Security 4662 (DS-Replication-Get-Changes GUID 1131f6aa-…/1131f6ad-…), "
                  "Directory Service Access",
                  "Alert on replication (DCSync) requested by any principal that is NOT a domain "
                  "controller or expected sync account."),
    "T1003.002": ("Security 4624/4672, registry SAM access",
                  "Alert on SAM/LSA secrets access and remote registry reads of the SAM hive."),
    "T1003": ("Security 4688, LSASS handle access (Sysmon 10), 4624",
              "Alert on LSASS access from non-security tooling and remote SAM/NTDS reads."),
    "T1187": ("RPC MS-RPRN/MS-EFSRPC/MS-DFSNM calls, unexpected DC→host authentication",
              "Alert on a DC authenticating outbound to a non-DC host; deploy auth canaries; "
              "patch PetitPotam/PrinterBug and restrict the Print Spooler."),
    "T1557.001": ("SMB signing state, NTLM auth relayed, 4624 type-3 from one source to many hosts",
                  "Enforce SMB signing + EPA; alert on the same credential authenticating to many "
                  "hosts from one source in a short window."),
    "T1649": ("AD CS 4886/4887 (cert requested/issued), 4768 with a certificate",
              "Enable CA request auditing; alert on certificates issued for anomalous templates or "
              "with a SAN that mismatches the requester (ESC1/ESC8)."),
    "T1558.003": ("Security 4769 (TGS request), RC4 (0x17) encryption type",
                  "Alert on many 4769 TGS requests for SPN accounts using RC4 from a single user."),
    "T1558.004": ("Security 4768 (AS-REQ) without pre-authentication",
                  "Alert on AS-REQ for accounts with DONT_REQUIRE_PREAUTH; audit that flag."),
    "T1558": ("Security 4768/4769, anomalous ticket requests",
              "Monitor ticket requests for delegation abuse and unusual encryption types."),
    "T1110.003": ("Security 4625/4771 across many accounts, 4740 lockouts",
                  "Alert on failed logons spread across many accounts from one source (spraying); "
                  "enable smart lockout."),
    "T1110": ("Security 4625, 4740",
              "Alert on high failed-logon volume per source/account; lockout thresholds."),
    "T1110.002": ("Offline — no host telemetry",
                  "Not host-detectable (offline cracking); prevent by strong password policy and "
                  "protecting hash material."),
    "T1555": ("File access to DPAPI masterkeys/Credential store, 4663",
              "Alert on access to DPAPI masterkeys and browser/credential stores by non-owner tools."),
    "T1552.001": ("File reads on shares (5145), sensitive-file access",
                  "Alert on mass reads of shares and access to files containing credentials; DLP."),
    "T1046": ("Netflow / IDS port-scan signatures",
              "Alert on horizontal/vertical port scans from a single host."),
    "T1018": ("Security 4624/4648, LDAP/SMB enumeration",
              "Alert on broad host enumeration from a single non-admin account."),
    "T1087.002": ("Security 4661/4662, LDAP query volume",
                  "Alert on bulk LDAP directory enumeration (users/groups) from one account."),
    "T1069.002": ("LDAP group queries, 4661",
                  "Alert on bulk group-membership enumeration."),
    "T1135": ("Security 5140/5145 (share access)",
              "Alert on enumeration of many shares from one source."),
    "T1201": ("LDAP reads of domain password policy",
              "Low-signal; monitor for policy reads combined with subsequent spraying."),
    "T1482": ("LDAP trust queries",
              "Monitor for domain/forest trust enumeration."),
    "T1021.001": ("Security 4624 type-10, 1149 (RDP)",
                  "Alert on RDP logons from unusual sources; restrict RDP exposure + NLA."),
    "T1021.002": ("Security 4624 type-3, 5140, service creation 7045",
                  "Alert on admin-share writes and remote service creation (psexec-style)."),
    "T1021.006": ("WinRM 4624, WSMan operational log",
                  "Alert on WinRM sessions from unexpected sources."),
    "T1550.002": ("Security 4624 with NTLM, no interactive logon",
                  "Alert on NTLM auth without a preceding interactive logon (pass-the-hash)."),
    "T1098": ("Security 4738/5136 (object/attribute modification)",
              "Alert on writes to sensitive attributes (msDS-KeyCredentialLink, RBCD, group members)."),
    "T1078": ("Security 4624/4625, impossible-travel / anomalous logon",
              "Baseline account behaviour; alert on valid-account use from anomalous context."),
    "T1190": ("Web/WAF logs, 4xx/5xx spikes, app error logs",
              "Alert on exploitation patterns and default-credential logins to web apps."),
    "T1133": ("VPN/gateway logs, 4624 from external",
              "Restrict and monitor external remote services; MFA."),
    "T1072": ("WSUS/SCCM logs, package deployment events",
              "Enforce HTTPS + signing for WSUS/SCCM; alert on rogue deployments."),
    "T1569.002": ("Security 7045 (service install), 4697",
                  "Alert on remote service creation for execution (psexec/smbexec)."),
    "T1047": ("Sysmon 1/WmiPrvSE, 4688",
              "Alert on remote WMI process creation."),
    "T1039": ("Security 5145 (share read)",
              "Alert on bulk reads of network shares."),
}
_GENERIC_DETECTION = ("Endpoint/AD authentication + process telemetry",
                      "Correlate host + directory logs for this technique; map to your SIEM use cases.")


def detection_for(tech: str) -> dict:
    """Detection expectation for a technique: {data_sources, guidance}."""
    ds, g = DETECTION.get(tech, _GENERIC_DETECTION)
    return {"data_sources": ds, "guidance": g}


# --------------------------------------------------------------------------- #
# Coverage gaps: techniques that are APPLICABLE to the discovered environment
# (a relevant service/condition is present) but were never CONFIRMED — i.e. the
# untested attack surface, so the operator/agent knows what to try next.
# --------------------------------------------------------------------------- #
EXPECTED_BY_SIGNAL: dict[str, list[str]] = {
    "smb":       ["T1021.002", "T1135", "T1557.001", "T1187", "T1003.002"],
    "ldap":      ["T1087.002", "T1069.002", "T1482", "T1201", "T1558.003", "T1558.004"],
    "kerberos":  ["T1558.003", "T1558.004", "T1558"],
    "adcs":      ["T1649"],
    "domain":    ["T1003.006", "T1187", "T1110.003"],
    "http":      ["T1190"],
    "ssl/http":  ["T1190"],
    "winrm":     ["T1021.006"],
    "ms-wbt-server": ["T1021.001"],
    "mssql":     ["T1190", "T1078"],
    "wsus":      ["T1072"],
    "mgmt":      ["T1190", "T1078", "T1552.001"],   # management/monitoring consoles
}


def _signals(services) -> set:
    """Environment signals present, from the discovered service names/ports."""
    sig = set()
    for s in services or []:
        name = (s.get("service") or "").lower()
        for key in EXPECTED_BY_SIGNAL:
            if key in name:
                sig.add(key)
        for p in s.get("ports", []):
            if p in (88,):
                sig.add("kerberos")
            if p in (389, 636, 3268, 3269):
                sig.add("ldap")
            if p in (445, 139):
                sig.add("smb")
            if p in (8530, 8531):
                sig.add("wsus")
            if p in (8443, 8444, 8081, 8082, 8089, 9997, 9877, 9876, 7780,
                     17778, 17790, 17791):
                sig.add("mgmt")   # enterprise management-server ports
    return sig


def gaps(coverage_rows: Iterable[dict], services) -> list[dict]:
    """Techniques applicable to this environment but not confirmed by a finding."""
    confirmed = {r["technique"] for r in coverage_rows if r["confirmed"]}
    attempted = {r["technique"] for r in coverage_rows if not r["confirmed"]}
    expected: set = set()
    for sig in _signals(services):
        expected.update(EXPECTED_BY_SIGNAL.get(sig, []))
    out = []
    # "Untested" means genuinely untried: a technique a mapped tool actually
    # exercised WAS tested — it simply wasn't confirmed vulnerable (e.g.
    # Kerberoasting returned "no SPN accounts") — so it belongs in the coverage
    # matrix as "attempted", not in the untested-gaps list. Exclude attempted.
    for tech in sorted(expected - confirmed - attempted):
        name, tactic = name_of(tech)
        out.append({"technique": tech, "name": name, "tactic": tactic,
                    "attempted": False})
    out.sort(key=lambda r: (r["tactic"], r["technique"]))
    return out


def coverage(findings: Iterable[dict], transcript=None) -> list[dict]:
    """Per-technique coverage for an assessment: which techniques were merely
    *attempted* (a tool ran) vs. *confirmed* (a finding proves it), and by what.
    """
    tools = tools_from_transcript(transcript)
    cov: dict[str, dict] = {}

    def _touch(tech: str) -> dict:
        name, tactic = name_of(tech)
        return cov.setdefault(tech, {"technique": tech, "name": name, "tactic": tactic,
                                     "confirmed": False, "findings": [], "tools": [],
                                     "detection": detection_for(tech)})

    for tool in tools:
        for tech in for_tool(tool):
            _touch(tech)["tools"].append(tool)
    for f in findings or []:
        for tech in (f.get("attack") or for_finding(f.get("title", ""))):
            row = _touch(tech)
            row["confirmed"] = True
            title = f.get("title", "")
            if title and title not in row["findings"]:
                row["findings"].append(title)

    return sorted(cov.values(),
                  key=lambda r: (not r["confirmed"], r["tactic"], r["technique"]))


def vectr_csv(coverage_rows, engagement: str = "") -> str:
    """A VECTR-importable purple-team test-case CSV: one row per exercised
    technique with tactic, MITRE id, red-team outcome, and the expected detection.
    Import into a VECTR assessment and map the columns in its CSV import wizard."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Campaign", "Test Case", "Phase (Tactic)", "MITRE ID", "Technique",
                "Red Team Outcome", "Expected Detection", "Data Sources", "Evidence"])
    camp = engagement or "Autopwn assessment"
    for r in coverage_rows:
        det = r.get("detection") or {}
        ev = "; ".join((r.get("findings") or [])
                       + (["tools: " + ", ".join(r["tools"])] if r.get("tools") else []))
        w.writerow([camp, f"{r['technique']} — {r['name']}",
                    (r.get("tactic") or "").replace("-", " ").title(),
                    r["technique"], r["name"],
                    "Executed / Successful" if r.get("confirmed") else "Attempted",
                    det.get("guidance", ""), det.get("data_sources", ""), ev])
    return buf.getvalue()


def navigator_layer(engagement: str, findings: Iterable[dict],
                    transcript=None, description: str = "") -> dict:
    """Build a MITRE ATT&CK Navigator layer (v4.5) from an assessment.

    Confirmed techniques (proven by a finding) score 2 (brand green); techniques
    only attempted by a tool score 1 (light green). Load the file in the ATT&CK
    Navigator, VECTR, or any layer-aware platform.
    """
    rows = coverage(findings, transcript)
    techniques = []
    for r in rows:
        confirmed = r["confirmed"]
        src = (["Confirmed by: " + "; ".join(r["findings"])] if r["findings"] else [])
        src += (["Tools: " + ", ".join(r["tools"])] if r["tools"] else [])
        techniques.append({
            "techniqueID": r["technique"],
            "score": 2 if confirmed else 1,
            "color": "#00B140" if confirmed else "#A7E3C1",
            "comment": " | ".join(src),
            "enabled": True,
            "metadata": [],
            "showSubtechniques": True,
        })
    return {
        "name": f"Autopwn — {engagement}" if engagement else "Autopwn assessment",
        "versions": {"attack": "15", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description or ("Techniques exercised by a Autopwn "
                                       "assessment. Score 2 = confirmed by a finding, "
                                       "1 = attempted/tested by a tool."),
        "techniques": techniques,
        "gradient": {"colors": ["#A7E3C1", "#00B140"], "minValue": 1, "maxValue": 2},
        "legendItems": [
            {"label": "Confirmed (finding)", "color": "#00B140"},
            {"label": "Attempted (tool ran)", "color": "#A7E3C1"},
        ],
        "sorting": 0,
        "hideDisabled": False,
        "techniques_count": len(techniques),
    }
