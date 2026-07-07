# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Deterministic security analysis of the results store.

Turns raw open ports/services/banners into a real assessment — each host's
likely role, the notable exposures, and concrete attack paths — using
rule-based logic. This gives the report substance independent of the LLM, so
even a weak local model produces a useful deliverable. The LLM's job is then to
*synthesise* a narrative over this, not to invent it.
"""
from __future__ import annotations

import re
from typing import Any

# ---- result extraction from a run transcript (shared by report + web) ------
_CRED_RE = re.compile(r"\[\+\]\s*([^\\\s]+)\\([^:\s]+):([^\s(]+)")
# ad_kill_chain emits "Credential: user:pass @ domain" (domain per credential).
_CHAIN_CRED_RE = re.compile(r"^Credential:\s*([^\s:]+):(\S+?)\s*@\s*(\S+)\s*$", re.M)
# Backward-compat: older chain output — an authoritative summary line
# ("Credentials: a:b, c:d") and, failing that, per-step logs.
_OLD_CHAIN_SUMMARY_RE = re.compile(r"^Credentials:\s*(.+)$", re.M)
_OLD_CHAIN_CRED_RE = re.compile(r"valid credential:\s*([^\s:]+):(\S+?)(?:\s|\(|$)", re.I)
_KERBRUTE_RE = re.compile(r"VALID USERNAME:\s+([^@\s]+)@")
_LDAP_USER_RE = re.compile(r"LDAP\s+\S+\s+\d+\s+\S+\s+(\S+)\s+\d{4}-\d{2}-\d{2}")
_RID_USER_RE = re.compile(r"\\([^\\\s]+)\s+\(SidTypeUser\)", re.I)
_CHAIN_USERS_RE = re.compile(r"^Users \(\d+\):\s*(.+)$", re.M)


def extract_results(transcript, domain: str = "") -> dict:
    """Credentials and usernames a run discovered, from its tool output.

    Aggregated by (username, domain): the same account found by several tools is
    ONE row whose ``sources`` list every tool that found it. A domain-bearing hit
    is preferred over a domainless one, and a real secret over a weak
    username==password spray hit.
    """
    creds: dict = {}   # (user.lower(), domain.lower()) -> record
    users: set = set()

    # Built-in disabled accounts NetExec may report a "[+]" for — never real creds,
    # neither as a username nor (paired with a real user) as a password.
    _NEVER = {"guest", "defaultaccount", "wdagutilityaccount", "krbtgt"}

    def _find(u_l):
        """An existing record for this user in any domain (to merge/upgrade)."""
        for (uu, dd), r in creds.items():
            if uu == u_l:
                return (uu, dd), r
        return None, None

    def add_cred(u, pw, dom, source):
        pw = pw or ""
        if u.lower() in _NEVER or u.endswith("$"):
            return
        if pw.lower() in _NEVER:            # a built-in account name is never a password
            return
        users.add(u)
        u_l, dom_l = u.lower(), (dom or "").lower()
        key = (u_l, dom_l)
        rec = creds.get(key)
        if rec is None:
            # Merge with the same user under a different/blank domain rather than
            # creating a second row: prefer a real domain, keep one identity.
            k2, r2 = _find(u_l)
            if r2 is not None and (not r2["domain"] or not dom_l):
                if dom_l and not r2["domain"]:      # upgrade the domainless record
                    del creds[k2]
                    r2["domain"] = dom
                    creds[key] = r2
                rec = r2
        if rec is None:
            rec = {"username": u, "password": pw, "domain": dom, "sources": []}
            creds[key] = rec
        # Secret: fill if empty, and upgrade a weak user==pass hit to a real secret.
        if pw:
            if not rec["password"]:
                rec["password"] = pw
            elif rec["password"].lower() == u_l and pw.lower() != u_l:
                rec["password"] = pw
        if source and source not in rec["sources"]:
            rec["sources"].append(source)

    for e in transcript or []:
        out = e.get("output") or e.get("raw_output") or e.get("summary") or ""
        if not out:
            continue
        # Source = the tool that produced this output, so a cred found by several
        # tools lists each of them. The consolidated playbook entry is labelled
        # "kill-chain" rather than "playbook:<id>".
        src = e.get("name") or "tool"
        if src.startswith("playbook:"):
            src = "kill-chain"
        for line in out.splitlines():
            # Skip NetExec Guest-fallback ("(Guest)") and disqualified-status lines:
            # the password is not valid for that user (it mapped to Guest).
            if "(Guest)" in line or "STATUS_" in line:
                continue
            m = _CRED_RE.search(line)
            if m:
                add_cred(m.group(2), m.group(3), m.group(1), src)
        chain_hits = list(_CHAIN_CRED_RE.finditer(out))
        for m in chain_hits:       # authoritative "Credential: user:pass @ domain"
            dom = "" if m.group(3) == "unknown" else m.group(3)
            add_cred(m.group(1), m.group(2), dom, src)
        if not chain_hits:         # older transcripts: prefer the summary line
            summ = _OLD_CHAIN_SUMMARY_RE.search(out)
            if summ:
                for pair in summ.group(1).split(","):
                    u, _, pw = pair.strip().partition(":")
                    if u and pw:
                        add_cred(u, pw, "", src)
            else:                  # last resort: per-step logs (noisier)
                for m in _OLD_CHAIN_CRED_RE.finditer(out):
                    add_cred(m.group(1), m.group(2), "", src)
        for m in _KERBRUTE_RE.finditer(out):
            users.add(m.group(1))
        for m in _LDAP_USER_RE.finditer(out):
            u = m.group(1)
            if u.lower() not in ("username", "guest", "krbtgt") and not u.endswith("$"):
                users.add(u)
        for m in _RID_USER_RE.finditer(out):
            if not m.group(1).endswith("$"):
                users.add(m.group(1))
        for m in _CHAIN_USERS_RE.finditer(out):   # ad_kill_chain "Users (N): ..."
            for u in m.group(1).split(","):
                u = u.strip()
                if u and not u.endswith("$"):
                    users.add(u)
    # Present a joined "note" (the tools that found each cred) for back-compat, plus
    # the structured "sources" list.
    out_creds = []
    for r in creds.values():
        r["note"] = ", ".join(r.get("sources", []))
        out_creds.append(r)
    return {"credentials": out_creds, "users": sorted(users)}


def _open(entry: dict) -> dict[int, dict]:
    return {p["port"]: p for p in entry.get("ports", {}).values()
            if p.get("state") == "open"}


def _role(ports: set[int], banners: str) -> str:
    b = banners.lower()
    if {88, 389, 445}.issubset(ports) or ({88, 389} <= ports and 3268 in ports):
        return "Active Directory Domain Controller"
    if 445 in ports and ("windows" in b or 3389 in ports or 135 in ports):
        return "Windows host / file server"
    if {80, 443} & ports and "apache" in b:
        return "Apache web server"
    if {80, 443} & ports and ("nginx" in b or "iis" in b):
        return "Web server"
    if {80, 443, 8080, 8443} & ports:
        return "Web server"
    if 22 in ports:
        return "Linux / SSH host"
    if {1433, 3306, 5432, 27017, 6379} & ports:
        return "Database server"
    return "Unknown / generic host"


def assess_host(host: str, entry: dict) -> dict:
    ports = _open(entry)
    pset = set(ports)
    banners = " ".join(f"{p.get('service','')} {p.get('version','')}"
                       for p in ports.values())
    role = _role(pset, banners)
    obs: list[str] = []
    paths: list[str] = []

    is_dc = role == "Active Directory Domain Controller"
    if is_dc:
        obs.append("Active Directory Domain Controller: Kerberos (88), LDAP "
                   "(389/636), Global Catalog (3268/3269), SMB (445), DNS (53).")
        paths += [
            "Enumerate users without creds: kerbrute userenum, then AS-REP "
            "roast accounts lacking pre-auth (asrep_roast) → crack with hashcat.",
            "With any valid credential: Kerberoast service accounts "
            "(kerberoast) → crack; enumerate via LDAP/BloodHound.",
            "Password-spray discovered users; then dump secrets "
            "(secretsdump/DCSync) if a privileged account is obtained.",
        ]
    if 445 in pset:
        obs.append("SMB (445) exposed — check signing, null/guest sessions, and "
                   "share permissions (netexec_smb, smbclient, enum4linux).")
        if entry.get("facts", {}).get("smb_signing") == "False":
            obs.append("SMB signing is NOT required — NTLM/SMB relay attack "
                       "surface: capture auth (Responder) and relay it to this "
                       "host (ntlmrelayx) for code execution or hash dumping.")
            paths.append("Poison name resolution (Responder) to capture NTLM "
                         "auth, then relay it to this host's SMB (signing off) "
                         "with ntlmrelayx → command execution or SAM dump.")
    if 389 in pset or 636 in pset:
        obs.append("LDAP exposed — test anonymous bind and enumerate the "
                   "directory (ldapsearch_anon, netexec_ldap).")
    if 3389 in pset:
        obs.append("RDP (3389) exposed — credential brute-force surface; verify "
                   "NLA and patch level (BlueKeep on legacy).")
    if 5985 in pset or 5986 in pset:
        obs.append("WinRM (5985/5986) exposed — remote command execution with "
                   "valid credentials (netexec_winrm).")
    web = [p for p in pset if p in (80, 443, 8080, 8443, 8000)]
    if web:
        obs.append(f"Web service(s) on {', '.join(map(str, sorted(web)))} — "
                   "fingerprint and test (whatweb, nuclei, nikto, ffuf).")
    if 8530 in pset or 8531 in pset:
        obs.append("WSUS (8530/8531) — update server. If clients use HTTP (8530) "
                   "without SSL enforced, it is a spoofing/lateral-movement "
                   "target (PyWSUS/SharpWSUS with a MITM position).")
        paths.append("If WSUS runs over HTTP and clients aren't forced to SSL: "
                     "MITM update traffic to push a signed binary as SYSTEM.")
    if 8443 in pset or 8444 in pset:
        obs.append("Management console (8443) / agent handler (8444) — likely "
                   "Trellix/McAfee ePO. Test the console for default admin creds; "
                   "ePO admin => code execution across all managed endpoints.")
    if 21 in pset:
        obs.append("FTP (21) — test anonymous login and known CVEs.")
    if 22 in pset:
        obs.append("SSH (22) — enumerate version; brute-force only if in scope.")

    return {"host": host, "hostname": entry.get("hostname", ""),
            "role": role, "observations": obs, "attack_paths": paths,
            "open_count": len(pset)}


def _evidence(transcript, tool_names, hosts=None):
    """Command + output of a matching tool run.

    `tool_names` is a PREFERENCE order — earlier tools win (e.g. prefer an
    anonymous share listing over a plain banner). Within a tool, prefer a run
    that actually targeted one of the finding's hosts (so the evidence isn't,
    say, a loopback probe). Falls back to the first match overall.
    """
    hosts = hosts or []
    overall = None
    for tool in tool_names:
        any_match = None
        for e in transcript or []:
            if e.get("kind") != "tool_result" or e.get("name") != tool:
                continue
            cmd = e.get("command") or f"{e.get('name')} {e.get('args', {})}"
            out = (e.get("output") or e.get("summary") or "").strip()
            blob = f"{cmd} {e.get('args', {})} {out}"
            pick = (cmd, out[:1500])
            if hosts and any(h in blob for h in hosts):
                return pick                # best: this tool, on a finding host
            if any_match is None:
                any_match = pick
        if any_match:
            return any_match               # this preferred tool, any host
        if overall is None:
            overall = None
    return overall or ("", "")


# Generic finding rules. Each: predicate over a host's open ports + facts =>
# a finding dict. Severity/impact/recommendation are standard and NOT tied to
# any specific environment.
def build_findings(hosts: dict, facts: dict, transcript=None,
                   log_dir=None) -> list[dict]:
    """Generate report findings from the finding playbooks (those with a
    severity). Editing a playbook's severity/CVSS/impact/recommendation — or its
    match — changes the report. Falls back to the built-in default playbooks when
    no per-engagement playbooks file is given.
    """
    from . import playbooks as pb_mod

    books = pb_mod.load(log_dir) if log_dir else pb_mod.DEFAULT_PLAYBOOKS
    findings: list[dict] = []
    fid = 1
    for pb in books:
        if not pb.get("severity"):
            continue  # attack-path playbook, not a reportable finding
        matched = pb_mod.matching_hosts(pb, hosts)
        detector = pb.get("detector")
        if detector == "missing_http_headers":
            matched = [h for h in matched if _has_missing_headers(transcript, h)]
        if not matched:
            continue
        ports = pb.get("match", {}).get("any_ports") or []
        ev_tools = pb.get("evidence_tools") or []
        if ev_tools:
            cmd, out = _evidence(transcript, tuple(ev_tools), matched)
        elif ports:
            cmd = _scan_cmd(transcript, tuple(ports), matched)
            out = _port_evidence(hosts, matched, set(ports))
        else:
            cmd, out = "", ""
        findings.append({
            "id": f"F-{fid:02d}", "title": pb.get("name", pb.get("id", "")),
            "severity": pb["severity"], "cvss": pb.get("cvss", ""),
            "hosts": matched, "description": pb.get("summary", ""),
            "impact": pb.get("impact", ""),
            "recommendation": pb.get("recommendation", ""),
            "evidence_cmd": cmd, "evidence_out": out,
        })
        fid += 1

    # --- step-level findings ------------------------------------------------
    # Any playbook STEP that has a severity becomes a reportable finding *when it
    # actually fired* — i.e. the artifact it produces is evidenced in the run (a
    # cracked hash, a Pwn3d! admin, recovered creds, …). This turns the attack
    # path itself (Kerberoast, AS-REP, spray, pass-the-hash) into findings, not
    # just the standalone detection playbooks.
    results = extract_results(transcript or [])
    seen = {f["title"] for f in findings}
    for pb in books:
        if pb.get("severity"):
            continue                     # already handled above
        if not _playbook_ran(pb, transcript):
            continue                     # don't attribute evidence to a playbook that
                                         # never executed (e.g. RBCD firing on the AD
                                         # chain's Pwn3d!)
        matched = pb_mod.matching_hosts(pb, hosts)
        ports = pb.get("match", {}).get("any_ports") or []
        if ports and not matched:
            continue                     # this playbook's services aren't present
        for st in pb.get("steps", []):
            sev = st.get("severity")
            if not sev:
                continue
            ev = _step_evidence(st, transcript, results, matched)
            if ev is None:
                continue                 # step didn't fire — nothing to report
            # Prefer the dedicated report title (a proper vulnerability name) over
            # the terse action/step name.
            title = (st.get("finding_title") or st.get("title")
                     or f"{pb.get('id','')} step {st.get('n','')}")
            if title in seen:
                continue
            seen.add(title)
            findings.append({
                "id": f"F-{fid:02d}", "title": title, "severity": sev,
                "cvss": st.get("cvss", ""), "hosts": ev[2] or matched,
                "description": st.get("detail", ""),
                "impact": st.get("impact", ""),
                "recommendation": st.get("recommendation", ""),
                "evidence_cmd": ev[0], "evidence_out": ev[1],
            })
            fid += 1

    findings.sort(key=lambda f: SEV_ORDER.get(f.get("severity"), 9))
    return findings


# Signals that a step's produced artifact was actually obtained, so the step
# becomes a real finding only when it fired. Ordered most-distinctive first so a
# Kerberoast step reports Kerberoast evidence, not generic "a credential exists".
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_STEP_SIGNALS = {
    "admin": [r"\(Pwn3d!\)"],
    "flag": [r"(?:THM|HTB|flag|FLAG)\{[^}]{2,80}\}"],
    "spn_hash": [r"\$krb5tgs\$"],
    "ticket": [r"\$krb5tgs\$"],
    "asrep_hash": [r"\$krb5asrep\$"],
    "hash": [r"[a-f0-9]{32}:[a-f0-9]{32}:::"],
    "machine_account": [r"[Ss]uccessfully added (?:machine )?account", r"Adding computer"],
    "relay_targets": [r"\(signing:False\)"],
    "shares": [r"Readable non-default SMB share", r"Loot: \\\\", r"readable non-default share"],
    "userlist": [r"\(SidTypeUser\)", r"VALID USERNAME:"],
    # new artifacts (ADCS / MSSQL / coercion / ACL / delegation / trust / creds-in-AD)
    "adcs_vuln": [r"ESC\d+", r"\[!\].*[Vv]ulnerable"],
    "certificate": [r"Saved certificate and private key", r"Got hash for '"],
    "mssql_exec": [r"MSSQL[^\n]*\(Pwn3d!\)", r"nt service\\mssqlserver",
                   r"Executed command via", r"xp_cmdshell"],
    "coerced": [r"\[\+\][^\n]*SMB\s+Auth", r"named pipe[^\n]*efsrpc[^\n]*accessible"],
    "delegation": [r"[Uu]nconstrained", r"Constrained w/", r"Resource-Based",
                   r"Protocol Transition", r"AllowedToDelegate"],
    "trust": [r"[Tt]rusted-?Domain", r"trustAttributes", r"trustPartner",
              r"trustDirection", r"flatName\s"],
    "acl_write": [r"\$krb5tgs\$",
                  r"permission:\s*(?:WRITE|FULL_CONTROL|GENERIC_ALL|WRITE_DACL|WRITE_OWNER|ALLOWED_TO_ACT)",
                  r"GenericAll|WriteDacl|WriteOwner|GenericWrite|ForceChangePassword"],
    # a credential recovered from AD storage (GPP cpassword, description, LAPS)
    "gpp": [r"cpassword", r"Found credentials in", r"description:[^\n]*[Pp]ass",
            r"Computer:[^\n]*Password:", r"[Gg]ot LAPS[^\n]*[Pp]assword"],
}
_ARTIFACT_ORDER = ["admin", "flag", "certificate", "adcs_vuln", "spn_hash", "ticket",
                   "asrep_hash", "mssql_exec", "coerced", "delegation", "trust",
                   "gpp", "acl_write", "hash", "machine_account",
                   "shares", "relay_targets", "userlist", "credential"]


def _playbook_ran(pb, transcript):
    """True if this playbook actually executed in the run — so its step findings
    are attributed to it, not to unrelated evidence another playbook produced.

    Executed = one of its built-in sequence tools ran, its single run tool ran, or
    a consolidated ``playbook:<id>`` entry exists. Documentation playbooks with no
    executor (RBCD, relay, web-app) therefore report nothing unless actually run."""
    names = {e.get("name") for e in transcript or []
             if e.get("kind") == "tool_result"}
    if not names:
        return False
    from . import playbooks as pb_mod
    seq_tools = {s.get("tool") for s in pb_mod.runnable_sequence(pb)}
    if seq_tools & names:
        return True
    if (pb.get("run") or {}).get("tool") in names and pb["run"]["tool"]:
        return True
    return f"playbook:{pb.get('id')}" in names


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _scan_transcript(transcript, patterns, hosts):
    """(command, matching-lines excerpt) of the first tool output matching any
    pattern; prefer a run that targeted one of the finding's hosts."""
    rx = re.compile("|".join(patterns))
    best = None
    for e in transcript or []:
        if e.get("kind") != "tool_result":
            continue
        out = _ANSI.sub("", e.get("output") or e.get("summary") or "")
        if not out or not rx.search(out):
            continue
        cmd = e.get("command") or e.get("name") or ""
        lines = [ln for ln in out.splitlines() if rx.search(ln)][:12]
        excerpt = "\n".join(lines)[:1500] or out[:800]
        if hosts and any(h in (cmd + " " + out) for h in hosts):
            return (cmd, excerpt)
        best = best or (cmd, excerpt)
    return best


def _step_evidence(step, transcript, results, matched):
    """Return (cmd, evidence, hosts) if the step fired, else None."""
    produces = step.get("produces") or []
    creds = results.get("credentials", [])
    for art in _ARTIFACT_ORDER:
        if art not in produces:
            continue
        if art == "credential":
            if creds:
                out = "\n".join(
                    f"{c['username']}:{c.get('password') or '(hash)'}"
                    f" @ {c.get('domain') or '?'}" for c in creds[:12])
                return ("credential recovery (spray / crack / reuse)", out, matched)
            continue
        pats = _STEP_SIGNALS.get(art)
        if not pats:
            continue
        hit = _scan_transcript(transcript, pats, matched)
        if hit:
            return (hit[0], hit[1], matched)
    return None


def _port_evidence(hosts: dict, matched: list, ports: set) -> str:
    """Per-host open-port evidence straight from the results store — shows each
    finding host with the relevant open port(s) and service/version."""
    lines = []
    for h in matched:
        entry = hosts.get(h, {})
        for p in sorted(entry.get("ports", {}).values(),
                        key=lambda x: x.get("port", 0)):
            if p.get("state") == "open" and (not ports or p.get("port") in ports):
                svc = (str(p.get("service", "")) + " "
                       + str(p.get("version", ""))).strip()
                lines.append(f"{h:<16} {p['port']}/tcp open  {svc}".rstrip())
    return "\n".join(lines)


def _scan_cmd(transcript, ports, matched) -> str:
    """The nmap command that discovered these ports, if in the transcript;
    otherwise a representative command scoped to the finding's hosts/ports."""
    for e in transcript or []:
        if e.get("kind") == "tool_result" and e.get("name") == "nmap_scan":
            cmd = e.get("command")
            if cmd:
                return cmd
    plist = ",".join(str(p) for p in sorted(ports))
    return f"nmap -Pn -p {plist} " + " ".join(matched)


def _has_missing_headers(transcript, host: str) -> bool:
    for e in transcript or []:
        if e.get("kind") == "tool_result" and e.get("name") == "http_probe":
            if host in str(e.get("args", {})) and "missing security headers" in \
                    (e.get("output", "") + e.get("summary", "")):
                return True
    return False


def assess(hosts: dict, facts: dict) -> dict:
    """Return {'hosts': [per-host assessment], 'domain': ..., 'creds': ...}."""
    out = {"hosts": [], "domain": facts.get("domain"),
           "creds": None, "summary": ""}
    if facts.get("username") and facts.get("password"):
        out["creds"] = f"{facts['username']}:{facts['password']}"
    roles = []
    for host, entry in sorted(hosts.items()):
        if _open(entry):
            a = assess_host(host, entry)
            out["hosts"].append(a)
            roles.append(a["role"])
    # A one-line factual summary.
    dc = sum(1 for r in roles if "Domain Controller" in r)
    parts = [f"{len(out['hosts'])} live host(s) assessed"]
    if dc:
        parts.append(f"{dc} Active Directory domain controller(s)")
    if out["domain"]:
        parts.append(f"domain {out['domain']}")
    if out["creds"]:
        parts.append("valid credentials captured")
    out["summary"] = "; ".join(parts) + "."
    return out
