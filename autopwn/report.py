# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Assessment report generation — export an AI job as Markdown / HTML / DOCX.

Builds a professional penetration-test report (executive summary, finding
summary, scope, testing process, per-finding detail with evidence, prioritised
recommendations, and a command-log appendix) entirely from the session
transcript, the results store, and the deterministic analysis — nothing is
hardcoded to any environment. DOCX uses python-docx when installed;
Markdown/HTML always work with no dependencies.
"""
from __future__ import annotations

import html as _html
import re as _re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _routable_hosts(hosts: dict) -> dict:
    """Drop loopback / localhost entries — never real assessment targets."""
    out = {}
    for h, entry in (hosts or {}).items():
        hl = str(h).strip().lower()
        if hl.startswith("127.") or hl in ("::1", "localhost", "0.0.0.0"):
            continue
        out[h] = entry
    return out


def _clean_summary(text: str) -> str:
    """Turn the model's final message into clean prose for the exec summary.

    Strips the machine-readable EVIDENCE block the agent appends to its
    narrative, drops a repeated 'Executive Summary' label, and normalises
    markdown emphasis / bullet glyphs so they don't render literally.
    """
    t = (text or "").strip()
    if not t:
        return ""
    for marker in ("--- EVIDENCE", "EVIDENCE (from tool", "--- Discovered",
                   "Discovered variables:"):
        i = t.find(marker)
        if i != -1:
            t = t[:i].strip()
    t = _re.sub(r"^\**\s*executive summary\s*\**[:\-]?\s*", "", t, flags=_re.I)
    t = t.replace("**", "").replace("__", "")
    # Models often write bullets inline ("include: * a * b" / "paths: • x • y").
    # Break those onto their own lines so they render as a real list.
    t = _re.sub(r"\s*[•‣▪]\s+", "\n- ", t)                 # glyph bullets
    t = _re.sub(r"(?<=[\w\).:,])\s+\*\s+", "\n- ", t)       # ' * ' between words
    t = _re.sub(r"^\s*[•‣▪·*]\s+", "- ", t, flags=_re.M)    # line-start bullet
    t = _re.sub(r"[•‣▪·]", "-", t)                          # any stray glyph
    t = _re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


@dataclass
class Engagement:
    engagement: str = "Security assessment"
    client: str = ""
    assessor: str = ""
    authorized_by: str = ""
    date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    target: str = ""
    objective: str = ""

    def rows(self):
        return [("Engagement", self.engagement), ("Client", self.client),
                ("Assessor", self.assessor), ("Authorized by", self.authorized_by),
                ("Date", self.date), ("Target", self.target),
                ("Objective", self.objective)]


_METHODOLOGY = (
    "Testing followed a standard methodology: reconnaissance and service "
    "discovery, targeted enumeration of each exposed service, analysis of the "
    "results, and identification of realistic attack paths. All actions were run "
    "against the authorized in-scope targets and are recorded in the command-log "
    "appendix. Testing was non-destructive; where a technique was validated it "
    "was taken only to a proof-of-concept."
)


def _tool_purposes():
    try:
        from .tools.registry import default_registry
        return {t.name: (t.description or "").split(".")[0]
                for t in default_registry(include_unavailable=True).all()}
    except Exception:
        return {}


def build_model(meta: Engagement, transcript: list, hosts: dict,
                facts: dict, final: str) -> dict:
    from .analysis import assess, build_findings

    hosts = _routable_hosts(hosts)
    analysis = assess(hosts, facts or {})
    findings = build_findings(hosts, facts or {}, transcript)

    # Severity counts.
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Scope: one row per live host with role and OS.
    role_by_host = {h["host"]: h["role"] for h in analysis["hosts"]}
    scope = []
    for host, entry in sorted(hosts.items()):
        open_ports = [p for p in entry.get("ports", {}).values()
                      if p.get("state") == "open"]
        if not open_ports:
            continue
        os_ = entry.get("facts", {}).get("os") or ""
        scope.append({"ip": host, "hostname": entry.get("hostname") or "",
                      "role": role_by_host.get(host, "Host") or "", "os": os_})

    # Tools used (unique, in first-use order) with a one-line purpose.
    purposes = _tool_purposes()
    seen, tools_used = set(), []
    actions = [e for e in transcript if e.get("kind") == "tool_result"]
    for e in actions:
        n = e.get("name")
        if n and n not in seen:
            seen.add(n)
            tools_used.append({"tool": n, "purpose": purposes.get(n, "")})

    # Prioritised recommendations grouped by severity.
    sev_priority = {"Critical": "High", "High": "High", "Medium": "Medium",
                    "Low": "Low", "Info": "Low"}
    recs = []
    for f in findings:
        recs.append({"priority": sev_priority.get(f["severity"], "Low"),
                     "action": f["recommendation"], "finding": f["id"]})
    recs.sort(key=lambda r: {"High": 0, "Medium": 1, "Low": 2}[r["priority"]])

    # Executive summary: prefer the model's real narrative (cleaned of the
    # machine evidence block and markdown noise), else a factual auto-summary.
    cleaned = _clean_summary(final)
    exec_summary = cleaned if _real(cleaned) else _auto_summary(analysis, counts)

    return {
        "meta": meta, "exec_summary": exec_summary, "analysis": analysis,
        "findings": findings, "counts": counts, "scope": scope,
        "tools_used": tools_used, "methodology": _METHODOLOGY,
        "recommendations": recs,
        "command_log": [{"tool": e.get("name", ""),
                         "command": e.get("command", "") or f"{e.get('name')} {e.get('args', {})}",
                         "ok": e.get("ok", False),
                         "output": (e.get("output") or e.get("summary") or "")}
                        for e in actions
                        if "127.0.0.1" not in (e.get("command", "") + str(e.get("args", "")))],
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _auto_summary(analysis: dict, counts: dict) -> str:
    parts = [analysis.get("summary", "").strip()]
    tot = sum(counts.values())
    if tot:
        by = ", ".join(f"{counts[s]} {s.lower()}" for s in _SEV_ORDER if counts[s])
        parts.append(f"{tot} finding(s) were identified ({by}).")
    for h in analysis.get("hosts", []):
        if h.get("attack_paths"):
            parts.append("The most likely path to compromise starts from "
                         f"{h['host']} ({h['role']}).")
            break
    return " ".join(p for p in parts if p)


def _real(text: str) -> bool:
    t = (text or "").strip()
    if not t or len(t) < 20:
        return False
    if t.startswith("{") and "action" in t[:40]:
        return False
    return not t.startswith("Assessment complete")


# ---- Markdown ---------------------------------------------------------------

def to_markdown(m: dict) -> str:
    meta: Engagement = m["meta"]
    o = ["# Penetration Test Report", "", f"## {meta.engagement}", ""]
    for k, v in meta.rows():
        if v and k != "Engagement":
            o.append(f"- **{k}:** {v}")

    o += ["", "## 1. Executive Summary", "", m["exec_summary"] or "_None._", ""]

    o += ["## 2. Finding Summary", "", "| Severity | Count |", "|---|---|"]
    for s in _SEV_ORDER:
        o.append(f"| {s} | {m['counts'][s]} |")
    o += ["", "| ID | Title | Severity | Host(s) |", "|---|---|---|---|"]
    for f in m["findings"]:
        o.append(f"| {f['id']} | {f['title']} | {f['severity']} | "
                 f"{', '.join(f['hosts'])} |")
    if not m["findings"]:
        o.append("| — | No findings identified | — | — |")

    o += ["", "## 3. Scope Overview", "",
          "| IP Address | Hostname | Role | OS |", "|---|---|---|---|"]
    for s in m["scope"]:
        o.append(f"| {s['ip']} | {s['hostname']} | {s['role']} | {s['os']} |")

    o += ["", "## 4. Testing Process", "", "### 4.1 Methodology", "",
          m["methodology"], "", "### 4.2 Tools Used", "",
          "| Tool | Purpose |", "|---|---|"]
    for t in m["tools_used"]:
        o.append(f"| {t['tool']} | {t['purpose']} |")

    o += ["", "## 5. Findings", ""]
    for f in m["findings"]:
        o += [f"### {f['id']} — {f['title']} ({f['severity']})", "",
              "**Description**", "", f["description"], ""]
        if f["evidence_cmd"]:
            o += ["**Evidence — Command**", "", "```", f["evidence_cmd"], "```", ""]
        if f["evidence_out"]:
            o += ["**Evidence — Output**", "", "```", f["evidence_out"][:1200], "```", ""]
        o += ["**Impact**", "", f["impact"], "", "**Recommendation**", "",
              f["recommendation"], ""]
    if not m["findings"]:
        o += ["_No findings were identified in this assessment._", ""]

    o += ["## 6. Recommendations (Prioritised)", "",
          "| Priority | Action | Finding |", "|---|---|---|"]
    for r in m["recommendations"]:
        o.append(f"| {r['priority']} | {r['action']} | {r['finding']} |")

    o += ["", "## Appendix A — Command Log", ""]
    for c in m["command_log"]:
        o += [f"**{c['tool']}** — `{c['command']}`", "", "```",
              c["output"][:1000].strip(), "```", ""]
    o += [f"_Generated by Autopwn on {m['generated']} — authorized testing only._"]
    return "\n".join(o)


# ---- HTML -------------------------------------------------------------------

_CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;color:#1a1a1a;margin:40px;line-height:1.5}
h1{color:#0b5394;border-bottom:3px solid #0b5394;padding-bottom:6px}
h2{color:#0b5394;margin-top:26px;border-bottom:1px solid #ccc;padding-bottom:3px}
h3{color:#222;margin-top:18px}h4{color:#444;margin:10px 0 2px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:12px;table-layout:fixed}
th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top;word-wrap:break-word}
th{background:#0b5394;color:#fff}tbody tr:nth-child(even){background:#f4f7fb}
tr{page-break-inside:avoid}thead{display:table-header-group}
.sev-Critical{color:#fff;background:#7b0000;padding:1px 5px;white-space:nowrap}.sev-High{color:#fff;background:#c00;padding:1px 5px;white-space:nowrap}
.sev-Medium{color:#000;background:#f4b400;padding:1px 5px;white-space:nowrap}.sev-Low{color:#fff;background:#3c78d8;padding:1px 5px;white-space:nowrap}
.sev-Info{color:#fff;background:#888;padding:1px 5px;white-space:nowrap}
pre{background:#f5f5f5;border:1px solid #ddd;padding:8px;font-size:11px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word}
.meta td{border:none;padding:2px 8px}.foot{color:#888;font-size:11px;margin-top:30px;border-top:1px solid #ddd;padding-top:8px}
"""


def _e(s):
    return _html.escape(str(s or ""))


def _pre(text: str, width: int = 88) -> str:
    """Escape text for a <pre> block and hard-wrap over-long lines.

    Long unbreakable tokens (e.g. a comma-separated port list) can overflow the
    page when the HTML is printed. We insert real breaks at a separator near the
    width — preserving all existing whitespace (nmap output columns) rather than
    collapsing it the way textwrap would.
    """
    out = []
    for line in str(text or "").split("\n"):
        while len(line) > width:
            seg = line[:width]
            cut = max(seg.rfind(","), seg.rfind(" "), seg.rfind("/"),
                      seg.rfind(";"), seg.rfind("|"))
            if cut < width - 24:      # no good separator near the edge → hard cut
                cut = width - 1
            out.append(line[:cut + 1])
            line = line[cut + 1:]
        out.append(line)
    return _e("\n".join(out))


def _summary_html(text: str) -> str:
    """Render cleaned summary text as HTML paragraphs and bullet lists."""
    para: list[str] = []
    bullets: list[str] = []
    out: list[str] = []

    def flush_para():
        if para:
            out.append(f"<p>{_e(' '.join(para))}</p>")
            para.clear()

    def flush_bullets():
        if bullets:
            out.append("<ul>" + "".join(f"<li>{_e(b)}</li>" for b in bullets) + "</ul>")
            bullets.clear()

    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            flush_para(); flush_bullets(); continue
        if s.startswith("- "):
            flush_para(); bullets.append(s[2:].strip())
        else:
            flush_bullets(); para.append(s)
    flush_para(); flush_bullets()
    return "".join(out) or f"<p>{_e(text)}</p>"


def to_html(m: dict) -> str:
    meta: Engagement = m["meta"]
    p = [f"<html><head><meta charset='utf-8'><style>{_CSS}</style></head><body>"]
    p.append(f"<h1>Penetration Test Report</h1><h2 style='border:none'>{_e(meta.engagement)}</h2>")
    p.append("<table class='meta'>")
    for k, v in meta.rows():
        if v and k != "Engagement":
            p.append(f"<tr><td><b>{_e(k)}</b></td><td>{_e(v)}</td></tr>")
    p.append("</table>")

    p.append("<h2>1. Executive Summary</h2>")
    p.append(_summary_html(m['exec_summary']))

    p.append("<h2>2. Finding Summary</h2>")
    p.append("<table><thead><tr><th width='60%'>Severity</th><th width='40%'>Count</th></tr></thead><tbody>")
    for s in _SEV_ORDER:
        p.append(f"<tr><td width='60%'><span class='sev-{s}'>{s}</span></td>"
                 f"<td width='40%'>{m['counts'][s]}</td></tr>")
    p.append("</tbody></table>")
    p.append("<table><thead><tr><th width='8%'>ID</th><th width='40%'>Title</th>"
             "<th width='16%'>Severity</th><th width='36%'>Host(s)</th></tr></thead><tbody>")
    for f in m["findings"]:
        p.append(f"<tr><td width='8%'>{f['id']}</td><td width='40%'>{_e(f['title'])}</td>"
                 f"<td width='16%'><span class='sev-{f['severity']}'>{f['severity']}</span></td>"
                 f"<td width='36%'>{_e(', '.join(f['hosts']))}</td></tr>")
    if not m["findings"]:
        p.append("<tr><td>—</td><td>No findings identified</td><td>—</td><td>—</td></tr>")
    p.append("</tbody></table>")

    p.append("<h2>3. Scope Overview</h2>")
    p.append("<table><thead><tr><th width='20%'>IP Address</th><th width='22%'>Hostname</th>"
             "<th width='28%'>Role</th><th width='30%'>OS</th></tr></thead><tbody>")
    for s in m["scope"]:
        p.append(f"<tr><td width='20%'>{_e(s['ip'])}</td><td width='22%'>{_e(s['hostname'])}</td>"
                 f"<td width='28%'>{_e(s['role'])}</td><td width='30%'>{_e(s['os'])}</td></tr>")
    p.append("</tbody></table>")

    p.append("<h2>4. Testing Process</h2><h3>4.1 Methodology</h3>")
    p.append(f"<p>{_e(m['methodology'])}</p><h3>4.2 Tools Used</h3>")
    p.append("<table><thead><tr><th width='25%'>Tool</th><th width='75%'>Purpose</th></tr></thead><tbody>")
    for t in m["tools_used"]:
        p.append(f"<tr><td width='25%'>{_e(t['tool'])}</td><td width='75%'>{_e(t['purpose'])}</td></tr>")
    p.append("</tbody></table>")

    p.append("<h2>5. Findings</h2>")
    for f in m["findings"]:
        p.append(f"<h3>{f['id']} — {_e(f['title'])} "
                 f"<span class='sev-{f['severity']}'>{f['severity']}</span></h3>")
        p.append(f"<h4>Description</h4><p>{_e(f['description'])}</p>")
        if f["evidence_cmd"]:
            p.append(f"<h4>Evidence — Command</h4><pre>{_pre(f['evidence_cmd'])}</pre>")
        if f["evidence_out"]:
            p.append(f"<h4>Evidence — Output</h4><pre>{_pre(f['evidence_out'][:1200])}</pre>")
        p.append(f"<h4>Impact</h4><p>{_e(f['impact'])}</p>")
        p.append(f"<h4>Recommendation</h4><p>{_e(f['recommendation'])}</p>")
    if not m["findings"]:
        p.append("<p><i>No findings were identified in this assessment.</i></p>")

    p.append("<h2>6. Recommendations (Prioritised)</h2>")
    p.append("<table><thead><tr><th width='14%'>Priority</th><th width='72%'>Action</th>"
             "<th width='14%'>Finding</th></tr></thead><tbody>")
    for r in m["recommendations"]:
        p.append(f"<tr><td width='14%'>{r['priority']}</td><td width='72%'>{_e(r['action'])}</td>"
                 f"<td width='14%'>{r['finding']}</td></tr>")
    p.append("</tbody></table>")

    p.append("<h2>Appendix A — Command Log</h2>")
    for c in m["command_log"]:
        p.append(f"<h4>{_e(c['tool'])} — <code>{_pre(c['command'])}</code></h4>"
                 f"<pre>{_pre(c['output'][:1000].strip())}</pre>")
    p.append(f"<div class='foot'>Generated by Autopwn on {m['generated']} — "
             "for authorized security testing only.</div></body></html>")
    return "\n".join(p)


# ---- DOCX -------------------------------------------------------------------

def to_docx(m: dict, path: Path) -> bool:
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
    except Exception:
        return False
    try:
        meta: Engagement = m["meta"]
        doc = Document()
        doc.add_heading("Penetration Test Report", level=0)
        doc.add_heading(meta.engagement, level=1)
        t = doc.add_table(rows=0, cols=2); t.style = "Light List Accent 1"
        for k, v in meta.rows():
            if v and k != "Engagement":
                r = t.add_row().cells; r[0].text = k; r[1].text = str(v)

        doc.add_heading("1. Executive Summary", level=1)
        for ln in (m["exec_summary"] or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            if s.startswith("- "):
                doc.add_paragraph(s[2:].strip(), style="List Bullet")
            else:
                doc.add_paragraph(s)

        doc.add_heading("2. Finding Summary", level=1)
        st = doc.add_table(rows=1, cols=2); st.style = "Light Grid Accent 1"
        st.rows[0].cells[0].text = "Severity"; st.rows[0].cells[1].text = "Count"
        for s in _SEV_ORDER:
            c = st.add_row().cells; c[0].text = s; c[1].text = str(m["counts"][s])
        ft = doc.add_table(rows=1, cols=4); ft.style = "Light Grid Accent 1"
        for i, h in enumerate(["ID", "Title", "Severity", "Host(s)"]):
            ft.rows[0].cells[i].text = h
        for f in m["findings"]:
            c = ft.add_row().cells
            c[0].text = f["id"]; c[1].text = f["title"]
            c[2].text = f["severity"]; c[3].text = ", ".join(f["hosts"])

        doc.add_heading("3. Scope Overview", level=1)
        sc = doc.add_table(rows=1, cols=4); sc.style = "Light Grid Accent 1"
        for i, h in enumerate(["IP Address", "Hostname", "Role", "OS"]):
            sc.rows[0].cells[i].text = h
        for s in m["scope"]:
            c = sc.add_row().cells
            c[0].text = s["ip"]; c[1].text = s["hostname"]
            c[2].text = s["role"]; c[3].text = s["os"]

        doc.add_heading("4. Testing Process", level=1)
        doc.add_heading("4.1 Methodology", level=2)
        doc.add_paragraph(m["methodology"])
        doc.add_heading("4.2 Tools Used", level=2)
        tt = doc.add_table(rows=1, cols=2); tt.style = "Light Grid Accent 1"
        tt.rows[0].cells[0].text = "Tool"; tt.rows[0].cells[1].text = "Purpose"
        for t2 in m["tools_used"]:
            c = tt.add_row().cells; c[0].text = t2["tool"]; c[1].text = t2["purpose"]

        doc.add_heading("5. Findings", level=1)
        for f in m["findings"]:
            doc.add_heading(f"{f['id']} — {f['title']} ({f['severity']})", level=2)
            doc.add_heading("Description", level=3)
            doc.add_paragraph(f["description"])
            if f["evidence_cmd"]:
                doc.add_heading("Evidence — Command", level=3)
                _mono(doc, f["evidence_cmd"])
            if f["evidence_out"]:
                doc.add_heading("Evidence — Output", level=3)
                _mono(doc, f["evidence_out"][:1200])
            doc.add_heading("Impact", level=3)
            doc.add_paragraph(f["impact"])
            doc.add_heading("Recommendation", level=3)
            doc.add_paragraph(f["recommendation"])
        if not m["findings"]:
            doc.add_paragraph("No findings were identified in this assessment.")

        doc.add_heading("6. Recommendations (Prioritised)", level=1)
        rt = doc.add_table(rows=1, cols=3); rt.style = "Light Grid Accent 1"
        for i, h in enumerate(["Priority", "Action", "Finding"]):
            rt.rows[0].cells[i].text = h
        for r in m["recommendations"]:
            c = rt.add_row().cells
            c[0].text = r["priority"]; c[1].text = r["action"]; c[2].text = r["finding"]

        doc.add_heading("Appendix A — Command Log", level=1)
        for c in m["command_log"]:
            doc.add_heading(f"{c['tool']}", level=3)
            _mono(doc, c["command"])
            if c["output"].strip():
                _mono(doc, c["output"][:1000].strip())

        doc.add_paragraph()
        foot = doc.add_paragraph(
            f"Generated by Autopwn on {m['generated']} — for authorized "
            "security testing only.")
        foot.runs[0].font.size = Pt(8)
        foot.runs[0].font.color.rgb = RGBColor(0x88, 0x88, 0x88)
        doc.save(str(path))
        return True
    except Exception:
        import os as _os
        if _os.environ.get("AUTOPWN_DEBUG"):
            import traceback
            traceback.print_exc()
        return False


# Strip ANSI escapes and control characters that are invalid in XML/DOCX.
_ANSI = _re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CTRL = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _xml_safe(text: str) -> str:
    return _CTRL.sub("", _ANSI.sub("", str(text or "")))


def _mono(doc, text: str):
    from docx.shared import Pt
    p = doc.add_paragraph()
    run = p.add_run(_xml_safe(text))
    run.font.name = "Consolas"; run.font.size = Pt(8)


# ---- export -----------------------------------------------------------------

def export(m: dict, base: Path, formats: list[str]) -> list[Path]:
    written: list[Path] = []
    if "md" in formats:
        p = base.with_suffix(".md"); p.write_text(to_markdown(m), encoding="utf-8")
        written.append(p)
    if "html" in formats:
        p = base.with_suffix(".html"); p.write_text(to_html(m), encoding="utf-8")
        written.append(p)
    if "docx" in formats:
        p = base.with_suffix(".docx")
        if to_docx(m, p):
            written.append(p)
    return written
