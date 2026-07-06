/* Autopwn web console — vanilla JS over the JSON API. Author: Ali Alaqoul */
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch { }
    throw new Error(msg);
  }
  return r.headers.get("content-type")?.includes("json") ? r.json() : r.text();
}

/* ---- view switching --------------------------------------------------- */
const TITLES = { dashboard: "Dashboard", launch: "Launch Assessment",
  findings: "Findings", console: "Console", playbooks: "Playbooks", tools: "Tools",
  jobs: "Jobs", reports: "Reports", scope: "Scope & Vars", settings: "Settings" };

function show(view) {
  if (!TITLES[view]) view = "dashboard";
  $$("#mainNav .ap-nav-link").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $$("section[data-panel]").forEach(s => (s.hidden = s.dataset.panel !== view));
  $("#viewTitle").textContent = TITLES[view] || view;
  // remember the view in the URL so a refresh stays put (no history spam)
  try { history.replaceState(null, "", "#" + view); } catch { }
  const loaders = { dashboard: loadDashboard, findings: loadFindings,
    console: loadConsole, playbooks: loadPlaybooks, tools: loadTools, jobs: loadJobs,
    reports: loadReports, scope: loadScope, settings: loadSettings };
  loaders[view]?.();
}
$$("#mainNav .ap-nav-link").forEach(b => b.addEventListener("click", () => show(b.dataset.view)));

/* ---- dashboard -------------------------------------------------------- */
async function loadDashboard() {
  let d;
  try { d = await api("/api/summary"); } catch (e) { return; }
  if (typeof d.ai_enabled === "boolean") { _aiEnabled = d.ai_enabled; reflectAi(); }
  const rb = $("#runningBadge"), n = d.counts.running_jobs;
  rb.textContent = `${n} running`;
  rb.classList.toggle("d-none", n === 0);

  const cards = [
    ["Hosts", d.counts.hosts], ["Open ports", d.counts.open_ports],
    ["Services", d.counts.services], ["Running jobs", d.counts.running_jobs],
  ];
  $("#statCards").innerHTML = cards.map(([label, val]) => `
    <div class="col-6 col-xl-3"><div class="card stat-card text-center py-3">
      <div class="display-6">${val}</div><div class="stat-label">${label}</div>
    </div></div>`).join("");

  $("#hostsTable tbody").innerHTML = d.hosts.length ? d.hosts.map(h => `
    <tr><td class="small text-secondary">${esc(h.host)}</td><td class="small text-secondary">${esc(h.hostname)}</td>
    <td>${h.open_ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${esc(h.services.join(", "))}</td></tr>`).join("")
    : `<tr><td colspan="4" class="text-center text-secondary py-3">No hosts yet — launch an assessment.</td></tr>`;

  $("#servicesTable tbody").innerHTML = d.services.length ? d.services.map(s => {
    const uniqHosts = [...new Set(s.hosts.map(h => h.host))];
    return `<tr><td class="small text-secondary">${esc(s.service)}</td>
    <td>${s.ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${uniqHosts.map(esc).join(", ")}</td></tr>`;
  }).join("")
    : `<tr><td colspan="3" class="text-center text-secondary py-3">No services discovered.</td></tr>`;
}

/* ---- playbooks -------------------------------------------------------- */
let _pbEditorId = null;   // id being edited; null = create-new
let _pbModal = null;

function pbMatchPanel(ev) {
  if (!ev || !ev.reasons || !ev.reasons.length)
    return `<div class="pb-match"><span class="text-secondary small">No match rules — always applicable.</span></div>`;
  const rows = ev.reasons.map(r => {
    const icon = r.matched ? `<span class="text-success">✓</span>` : `<span class="text-secondary">✗</span>`;
    const hits = (r.hits && r.hits.length)
      ? `<span class="text-secondary small ms-1">→ ${r.hits.map(esc).join(", ")}</span>` : "";
    return `<div>${icon} <code class="small">${esc(r.rule)}</code>${hits}</div>`;
  }).join("");
  return `<div class="pb-match">${rows}</div>`;
}

async function loadPlaybooks() {
  let pbs;
  try { pbs = await api("/api/playbooks"); } catch { return; }
  $("#playbooksList").innerHTML = pbs.map(pb => {
    const ev = pb.evaluation || {};
    const steps = pb.steps.map(st => {
      const branches = (st.branches || []).map(b =>
        `<div class="pb-branch"><span class="cond">${esc(b.cond)}</span>
         <span class="mx-1 text-secondary">→</span><span class="then">${esc(b.then)}</span></div>`).join("");
      const tool = st.tool ? `<span class="badge text-bg-light text-secondary border ms-2">${esc(st.tool)}</span>` : "";
      const flow = [];
      if (st.trigger) flow.push(`<span class="pb-flow-tag trig" title="trigger">⚡ ${esc(st.trigger)}</span>`);
      (st.consumes || []).forEach(c => flow.push(`<span class="pb-flow-tag cons" title="consumes">↤ ${esc(c)}</span>`));
      (st.produces || []).forEach(p => flow.push(`<span class="pb-flow-tag prod" title="produces">↦ ${esc(p)}</span>`));
      if (st.next) flow.push(`<span class="pb-flow-tag nxt" title="next">▸ ${esc(st.next)}</span>`);
      const flowRow = flow.length ? `<div class="pb-flow-row">${flow.join("")}</div>` : "";
      return `<div class="pb-step">
        <div class="pb-step-num">${esc(st.n)}</div>
        <div class="pb-step-body">
          <div class="pb-step-title">${esc(st.title)}${tool}</div>
          ${flowRow}
          <div class="pb-step-detail">${esc(st.detail || "")}</div>
          ${branches}
        </div></div>`;
    }).join("");
    const badge = ev.matched
      ? `<span class="badge text-bg-success">matches scan</span>`
      : `<span class="badge text-bg-light text-secondary border">no match yet</span>`;
    const sev = pb.severity
      ? `<span class="badge ${SEV_CLASS[pb.severity] || "text-bg-secondary"}">${esc(pb.severity)}</span>${pb.cvss ? ` <span class="badge text-bg-light text-secondary border">CVSS ${esc(pb.cvss)}</span>` : ""}` : "";
    const report = pb.severity ? `
        <div class="pb-section-label mt-3">Report content (finding)</div>
        <div class="pb-match">
          ${pb.impact ? `<div class="small"><b>Impact:</b> ${esc(pb.impact)}</div>` : ""}
          ${pb.recommendation ? `<div class="small mt-1"><b>Recommendation:</b> ${esc(pb.recommendation)}</div>` : ""}
          ${(ev.matched_hosts || []).length ? `<div class="small mt-1"><b>Affected hosts:</b> ${ev.matched_hosts.map(h => `<code>${esc(h)}</code>`).join(" ")}</div>` : ""}
        </div>` : "";
    const runTool = (pb.run || {}).tool;
    const runBtn = runTool
      ? `<button class="btn btn-sm btn-outline-danger py-0" data-pb-run="${esc(pb.id)}" title="Run ${esc(runTool)}">▶ Run</button>` : "";
    const hasSteps = (pb.steps || []).length;
    return `<div class="card pb-card">
      <div class="card-body">
        <div class="pb-head mb-2">
          <div>
            <div class="h6 mb-1">${esc(pb.name)} <span class="text-secondary small">(${esc(pb.id)})</span> ${sev}</div>
            <div class="text-secondary small">${esc(pb.summary || "")}</div>
          </div>
          <div class="text-end text-nowrap">
            ${badge}
            <div class="btn-group btn-group-sm mt-2">
              ${runBtn}
              <button class="btn btn-outline-secondary py-0" data-pb-edit="${esc(pb.id)}">Edit</button>
              <button class="btn btn-outline-secondary py-0" data-pb-del="${esc(pb.id)}">Delete</button>
            </div>
          </div>
        </div>
        <div class="pb-section-label">Matching against scan results</div>
        ${pbMatchPanel(ev)}
        ${report}
        ${hasSteps ? `<div class="pb-section-label mt-3">Execution</div>
        ${runTool ? `<div class="small mb-1"><span class="text-secondary">launches:</span> <code>${esc(runTool)}</code></div>` : ""}
        <div class="pb-flow">${steps}</div>` : ""}
      </div></div>`;
  }).join("");

  $$("#playbooksList [data-pb-edit]").forEach(b => b.onclick = () => pbEdit(b.dataset.pbEdit));
  $$("#playbooksList [data-pb-del]").forEach(b => b.onclick = () => pbDelete(b.dataset.pbDel));
  $$("#playbooksList [data-pb-run]").forEach(b => b.onclick = () => pbRun(b.dataset.pbRun));
}

/* ---- structured playbook builder ------------------------------------- */
let _pbDraft = null;
let _pbSchema = { artifacts: [], triggers: [], signals: [], next: ["next", "final"] };
let _pbToolNames = [];

async function ensureSchema() {
  if (!_pbSchema.artifacts.length) {
    try { _pbSchema = await api("/api/playbook-schema"); } catch { }
  }
  try { _pbToolNames = (await api("/api/tools")).map(t => t.name); } catch { }
}

function blankStep(n) {
  return { n, title: "", trigger: "start", tool: "", consumes: [], produces: [],
    detail: "", next: "next", branches: [] };
}
function blankPlaybook() {
  return { id: "my-playbook", name: "New playbook", summary: "",
    match: { any_ports: [445], signals: [] }, run: { tool: "" },
    steps: [blankStep(1)] };
}

function chipRow(group, selected, stepIdx, options) {
  return options.map(a => {
    const on = (selected || []).includes(a);
    const step = stepIdx !== undefined ? `data-step="${stepIdx}"` : "";
    return `<button type="button" class="pb-chip ${on ? "on" : ""}" data-act="chip"
      data-group="${group}" data-val="${esc(a)}" ${step}>${esc(a)}</button>`;
  }).join("");
}

// A <select> whose options come from a fixed list; keeps the current value even
// if it isn't in the list (shown as an extra "custom" option) so nothing is lost.
function pbSelect(list, val, attrs) {
  const opts = list.slice();
  if (val && !opts.includes(val)) opts.push(val);
  const body = opts.map(o =>
    `<option ${o === val ? "selected" : ""}>${esc(o)}</option>`).join("");
  return `<select class="form-select form-select-sm" ${attrs}>${body}</select>`;
}

function renderBuilder() {
  const d = _pbDraft;
  const toolOpts = _pbToolNames.map(t => `<option value="${esc(t)}">`).join("");
  const nextChoices = _pbSchema.next.concat(d.steps.map(s => s.title).filter(Boolean));

  const steps = d.steps.map((st, i) => {
    const branches = (st.branches || []).map((b, j) => `
      <div class="input-group input-group-sm mb-1">
        <span class="input-group-text">if</span>
        <input class="form-control" placeholder="condition" value="${esc(b.cond)}" data-step="${i}" data-branch="${j}" data-field="cond">
        <span class="input-group-text">→</span>
        <input class="form-control" placeholder="route / result" value="${esc(b.then)}" data-step="${i}" data-branch="${j}" data-field="then">
        <button class="btn btn-outline-danger" type="button" data-act="delBranch" data-step="${i}" data-branch="${j}">✕</button>
      </div>`).join("");
    return `<div class="pb-build-step">
      <div class="pb-step-head d-flex justify-content-between align-items-center mb-2">
        <span class="pb-step-badge">Step ${st.n}</span>
        <div class="btn-group btn-group-sm">
          <button class="btn btn-outline-secondary py-0" type="button" data-act="upStep" data-step="${i}" ${i === 0 ? "disabled" : ""}>↑</button>
          <button class="btn btn-outline-secondary py-0" type="button" data-act="downStep" data-step="${i}" ${i === d.steps.length - 1 ? "disabled" : ""}>↓</button>
          <button class="btn btn-outline-danger py-0" type="button" data-act="delStep" data-step="${i}">Remove</button>
        </div>
      </div>
      <div class="row g-2 mb-2">
        <div class="col-md-7"><label class="pb-lbl">Title</label>
          <input class="form-control form-control-sm" value="${esc(st.title)}" data-step="${i}" data-field="title"></div>
        <div class="col-md-5"><label class="pb-lbl">Action / tool</label>
          <input class="form-control form-control-sm" list="dlTools" value="${esc(st.tool)}" data-step="${i}" data-field="tool" placeholder="e.g. netexec_spray"></div>
      </div>
      <div class="row g-2 mb-2">
        <div class="col-md-7"><label class="pb-lbl">Trigger <span class="text-secondary">(when this step fires)</span></label>
          ${pbSelect(_pbSchema.triggers, st.trigger || "start", `data-step="${i}" data-field="trigger"`)}</div>
        <div class="col-md-5"><label class="pb-lbl">Next on success</label>
          ${pbSelect(nextChoices, st.next || "next", `data-step="${i}" data-field="next"`)}</div>
      </div>
      <div class="mb-2"><label class="pb-lbl">Consumes <span class="text-secondary">(needs from earlier steps)</span></label>
        <div class="pb-chips">${chipRow("consumes", st.consumes, i, _pbSchema.artifacts)}</div></div>
      <div class="mb-2"><label class="pb-lbl">Produces <span class="text-secondary">(passes to next / final)</span></label>
        <div class="pb-chips">${chipRow("produces", st.produces, i, _pbSchema.artifacts)}</div></div>
      <div class="mb-2"><label class="pb-lbl">Detail</label>
        <textarea class="form-control form-control-sm" rows="2" data-step="${i}" data-field="detail">${esc(st.detail || "")}</textarea></div>
      <div class="mb-2"><label class="pb-lbl">Branches <span class="text-secondary">(conditional re-routes)</span></label>
        ${branches}
        <button class="btn btn-sm btn-outline-secondary py-0" type="button" data-act="addBranch" data-step="${i}">+ branch</button></div>
      <div class="pb-finding-box border rounded p-2 mt-2">
        <div class="row g-2 align-items-end">
          <div class="col-md-5"><label class="pb-lbl">Report as finding <span class="text-secondary">(severity)</span></label>
            <select class="form-select form-select-sm" data-step="${i}" data-field="severity">
              <option value="">— off (don't report) —</option>
              ${(_pbSchema.severities || []).map(s => `<option ${st.severity === s ? "selected" : ""}>${s}</option>`).join("")}
            </select></div>
          <div class="col-md-3"><label class="pb-lbl">CVSS</label>
            <input class="form-control form-control-sm" value="${esc(st.cvss || "")}" data-step="${i}" data-field="cvss" placeholder="8.1"></div>
        </div>
        <div class="form-text mb-1">Set a severity to include this step in the report — it appears when the step actually fires (its produced artifact is evidenced in the run).</div>
        <div class="mb-1"><label class="pb-lbl">Finding title <span class="text-secondary">(shown in the report — a proper vulnerability name, not the action name)</span></label>
          <input class="form-control form-control-sm" value="${esc(st.finding_title || "")}" data-step="${i}" data-field="finding_title" placeholder="e.g. Kerberoastable Service Accounts"></div>
        <div class="mb-1"><label class="pb-lbl">Impact</label>
          <textarea class="form-control form-control-sm" rows="2" data-step="${i}" data-field="impact" placeholder="What an attacker gains when this step succeeds.">${esc(st.impact || "")}</textarea></div>
        <div><label class="pb-lbl">Recommendation</label>
          <textarea class="form-control form-control-sm" rows="2" data-step="${i}" data-field="recommendation" placeholder="How to remediate.">${esc(st.recommendation || "")}</textarea></div>
      </div>
    </div>`;
  }).join("");

  const hasSequence = ((d.run || {}).sequence || []).length;
  $("#pbBuilder").innerHTML = `
    <datalist id="dlTools">${toolOpts}</datalist>
    <div class="row g-2 mb-1">
      <div class="col-md-4"><label class="pb-lbl">ID</label>
        <input class="form-control form-control-sm" value="${esc(d.id)}" data-field="id"></div>
      <div class="col-md-8"><label class="pb-lbl">Name</label>
        <input class="form-control form-control-sm" value="${esc(d.name)}" data-field="name"></div>
    </div>
    <div class="form-text mb-2"><code>ID</code> is the stable slug used in URLs/commands (no spaces). <code>Name</code> is the human title shown in the list.</div>
    <div class="mb-2"><label class="pb-lbl">Summary</label>
      <textarea class="form-control form-control-sm" rows="2" data-field="summary">${esc(d.summary || "")}</textarea></div>
    <div class="row g-2 mb-1">
      <div class="col-md-7"><label class="pb-lbl">Match — any of these open ports</label>
        <input class="form-control form-control-sm" value="${(d.match.any_ports || []).join(", ")}" data-field="ports" placeholder="88, 445, 389"></div>
      <div class="col-md-5"><label class="pb-lbl">Run — single tool <span class="text-secondary">(optional)</span></label>
        ${pbSelect([""].concat(_pbToolNames), (d.run || {}).tool || "", `data-field="tool" ${hasSequence ? "disabled" : ""}`)}</div>
    </div>
    <div class="form-text mb-2">
      Ports: comma-separated, e.g. <code>88, 445, 389</code> — the playbook matches a host with any of them open.
      ${hasSequence
        ? `Run: this playbook executes a <strong>built-in sequence</strong> of ${hasSequence} tools (edit it in the JSON tab); the single-tool field is disabled.`
        : `Run: pick one built-in/catalog tool to launch, or leave blank for a detection-only finding.`}
    </div>
    <div class="mb-3"><label class="pb-lbl">Match — fact signals <span class="text-secondary">(extra conditions; click to toggle)</span></label>
      <div class="pb-chips">${chipRow("signals", d.match.signals, undefined, _pbSchema.signals)}</div></div>
    <hr>
    <div class="pb-section-label mb-1">Report — set a severity to make this a finding</div>
    <div class="row g-2 mb-2">
      <div class="col-md-4"><label class="pb-lbl">Severity</label>
        <select class="form-select form-select-sm" data-field="severity">
          <option value="">— none (attack path) —</option>
          ${(_pbSchema.severities || []).map(s => `<option ${d.severity === s ? "selected" : ""}>${s}</option>`).join("")}
        </select></div>
      <div class="col-md-3"><label class="pb-lbl">CVSS</label>
        <input class="form-control form-control-sm" value="${esc(d.cvss || "")}" data-field="cvss" placeholder="6.5"></div>
      <div class="col-md-5"><label class="pb-lbl">Match — host facts <span class="text-secondary">(key = value per line)</span></label>
        <textarea class="form-control form-control-sm font-monospace" rows="2" data-field="host_facts" placeholder="smb_signing = False">${esc(Object.entries((d.match || {}).host_facts || {}).map(([k, v]) => `${k} = ${v}`).join("\n"))}</textarea></div>
    </div>
    <div class="mb-2"><label class="pb-lbl">Impact</label>
      <textarea class="form-control form-control-sm" rows="2" data-field="impact">${esc(d.impact || "")}</textarea></div>
    <div class="mb-2"><label class="pb-lbl">Recommendation</label>
      <textarea class="form-control form-control-sm" rows="2" data-field="recommendation">${esc(d.recommendation || "")}</textarea></div>
    <hr>
    <div class="d-flex justify-content-between align-items-center mb-1">
      <span class="pb-section-label mb-0">Steps</span>
      <button class="btn btn-sm btn-outline-primary py-0" type="button" data-act="addStep">+ Add step</button>
    </div>
    <div class="form-text mb-2">Steps document the attack path (shown in the reader view). Each has a
      <strong>Trigger</strong> (when it fires), an <strong>Action</strong>, what it <strong>Consumes</strong>/<strong>Produces</strong>,
      and where it goes <strong>Next</strong>. <code>Trigger</code> and <code>Next</code> are fixed choices; <code>Consumes</code>/<code>Produces</code> toggle from the artifact list.</div>
    <div class="d-flex flex-column gap-2">${steps}</div>`;
  syncJsonFromDraft();
}

function syncJsonFromDraft() {
  const t = $("#pbEditorText");
  if (t) t.value = JSON.stringify(_pbDraft, null, 2);
}

function parsePorts(s) {
  return String(s).split(",").map(x => parseInt(x.trim(), 10)).filter(n => !isNaN(n));
}

async function pbEdit(id) {
  await ensureSchema();
  _pbEditorId = id;
  try { _pbDraft = await api(`/api/playbooks/${encodeURIComponent(id)}`); } catch (e) { return alert(e.message); }
  _pbDraft.match = _pbDraft.match || { any_ports: [], signals: [] };
  _pbDraft.run = _pbDraft.run || { tool: "" };
  _pbDraft.steps = _pbDraft.steps || [];
  $("#pbEditorTitle").textContent = "Edit playbook — " + id;
  $("#pbEditorError").textContent = "";
  renderBuilder();
  _pbModal.show();
}

async function pbNew() {
  await ensureSchema();
  _pbEditorId = null;
  _pbDraft = blankPlaybook();
  $("#pbEditorTitle").textContent = "New playbook";
  $("#pbEditorError").textContent = "";
  renderBuilder();
  _pbModal.show();
}

async function pbSave() {
  _pbDraft.steps.forEach((s, i) => (s.n = i + 1));   // renumber
  const body = _pbDraft;
  try {
    if (_pbEditorId === null) {
      await api("/api/playbooks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } else {
      await api(`/api/playbooks/${encodeURIComponent(_pbEditorId)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    }
  } catch (e) { $("#pbEditorError").textContent = e.message; return; }
  _pbModal.hide();
  loadPlaybooks();
}

/* builder event delegation (bound once at boot) */
function bindBuilder() {
  const root = $("#pbBuilder");
  const onEdit = (e) => {
    const t = e.target, f = t.dataset.field;
    if (!f || !_pbDraft) return;
    if (t.dataset.branch !== undefined) {
      _pbDraft.steps[+t.dataset.step].branches[+t.dataset.branch][f] = t.value;
    } else if (t.dataset.step !== undefined) {
      _pbDraft.steps[+t.dataset.step][f] = t.value;
    } else if (f === "ports") {
      _pbDraft.match.any_ports = parsePorts(t.value);
    } else if (f === "host_facts") {
      const hf = {};
      t.value.split("\n").forEach(line => {
        const i = line.indexOf("=");
        if (i < 1) return;
        const k = line.slice(0, i).trim(), v = line.slice(i + 1).trim();
        if (k) hf[k] = v;
      });
      _pbDraft.match.host_facts = hf;
    } else if (f === "tool") {
      _pbDraft.run.tool = t.value;
    } else {
      _pbDraft[f] = t.value;
    }
    syncJsonFromDraft();
  };
  root.addEventListener("input", onEdit);
  root.addEventListener("change", onEdit);   // <select> dropdowns
  root.addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (!b || !_pbDraft) return;
    const act = b.dataset.act, si = +b.dataset.step;
    if (act === "addStep") _pbDraft.steps.push(blankStep(_pbDraft.steps.length + 1));
    else if (act === "delStep") _pbDraft.steps.splice(si, 1);
    else if (act === "upStep" && si > 0) [_pbDraft.steps[si - 1], _pbDraft.steps[si]] = [_pbDraft.steps[si], _pbDraft.steps[si - 1]];
    else if (act === "downStep" && si < _pbDraft.steps.length - 1) [_pbDraft.steps[si + 1], _pbDraft.steps[si]] = [_pbDraft.steps[si], _pbDraft.steps[si + 1]];
    else if (act === "addBranch") _pbDraft.steps[si].branches.push({ cond: "", then: "" });
    else if (act === "delBranch") _pbDraft.steps[si].branches.splice(+b.dataset.branch, 1);
    else if (act === "chip") {
      const g = b.dataset.group, v = b.dataset.val;
      const arr = g === "signals" ? _pbDraft.match.signals : _pbDraft.steps[si][g];
      const at = arr.indexOf(v);
      at === -1 ? arr.push(v) : arr.splice(at, 1);
    } else return;
    _pbDraft.steps.forEach((s, i) => (s.n = i + 1));
    renderBuilder();
  });
}

function applyJsonToDraft() {
  try { _pbDraft = JSON.parse($("#pbEditorText").value); }
  catch (e) { $("#pbEditorError").textContent = "Invalid JSON: " + e.message; return; }
  $("#pbEditorError").textContent = "";
  renderBuilder();
}

async function pbDelete(id) {
  if (!confirm(`Delete playbook "${id}"?`)) return;
  try { await api(`/api/playbooks/${encodeURIComponent(id)}`, { method: "DELETE" }); } catch (e) { return alert(e.message); }
  loadPlaybooks();
}

async function pbRun(id) {
  const target = prompt(`Run playbook "${id}" against which target?`);
  if (!target) return;
  try {
    const res = await api(`/api/playbooks/${encodeURIComponent(id)}/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target.trim() }),
    });
    show("jobs");
    setTimeout(() => watch(res.id), 300);
  } catch (e) { alert(e.message); }
}

async function pbReset() {
  if (!confirm("Restore the default playbooks? Your edits will be replaced.")) return;
  try { await api("/api/playbooks/reset", { method: "POST" }); } catch (e) { return alert(e.message); }
  loadPlaybooks();
}

/* ---- console (C2: credentialed exec + reverse-shell listeners) -------- */
async function loadConsole() {
  try {
    const hosts = await api("/api/hosts");
    const sel = $("#ex_host"), keep = sel.value;
    sel.innerHTML = `<option value="">— select a discovered host —</option>` +
      hosts.map(h => `<option value="${esc(h.host)}">${esc(h.host)}${h.hostname ? " (" + esc(h.hostname) + ")" : ""}</option>`).join("");
    if (keep) sel.value = keep;
  } catch { }
  loadListeners();
}

function openSessionFrom(cred) {   // called from Findings "Open session"
  show("console");
  if (_execConnected) execDisconnect();
  $("#ex_user").value = cred.username || "";
  $("#ex_secret").value = cred.password || "";
  $("#ex_domain").value = cred.domain || "";
  $("#ex_auth").value = "password";
  updateSecretLabel();
  setTimeout(() => $("#ex_host").focus(), 100);   // pick the target host next
}

function updateSecretLabel() {
  const hash = $("#ex_auth").value === "hash";
  $("#ex_secret_lbl").textContent = hash ? "NT hash" : "Password";
  $("#ex_secret").placeholder = hash ? "aad3b435...:<nthash> or <nthash>" : "password";
}

let _execConnected = false;
function execSetStatus(text, cls) {
  const b = $("#ex_status"); b.textContent = text; b.className = "badge " + cls;
}
function execFields() {
  return ["ex_host", "ex_proto", "ex_auth", "ex_user", "ex_secret", "ex_domain"];
}
let _shellId = null, _shellES = null;
// strip terminal control/colour codes and evil-winrm noise; collapse repeated prompts
function cleanShell(line) {
  let s = line
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")   // OSC
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "")               // CSI (colours, cursor)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "");        // stray control chars
  // keep only the last of several repeated "*Evil-WinRM* PS …>" prompts on a line
  s = s.replace(/(?:\*Evil-WinRM\*\s+PS\s+[^>\n]*>\s*)+(?=\*Evil-WinRM\*\s+PS)/g, "");
  return s.replace(/\s+$/, "");
}

async function execConnect() {
  const host = $("#ex_host").value.trim();
  if (!host) { alert("Select a target host first."); return; }
  const btn = $("#ex_connect"), out = $("#ex_out"), term = $("#exTerm");
  btn.disabled = true; execSetStatus("connecting…", "text-bg-secondary");
  out.insertAdjacentHTML("beforeend", `<span class="l-run">[*] opening ${$("#ex_proto").value.toUpperCase()} session to ${esc(host)} as ${esc($("#ex_user").value || "?")}…</span>\n`);
  try {
    const r = await api("/api/shells", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, protocol: $("#ex_proto").value, auth: $("#ex_auth").value,
        username: $("#ex_user").value.trim(), secret: $("#ex_secret").value,
        domain: $("#ex_domain").value.trim() }),
    });
    _shellId = r.id; _execConnected = true;
    execSetStatus("connected", "text-bg-success");
    execFields().forEach(id => $("#" + id).disabled = true);
    $("#ex_disconnect").disabled = false;
    const cmd = $("#ex_cmd"); cmd.disabled = false; cmd.placeholder = "type into the session (Enter)"; cmd.focus();
    if (_shellES) _shellES.close();
    const es = new EventSource(`/api/shells/${_shellId}/stream`); _shellES = es;
    es.onmessage = (ev) => { out.insertAdjacentHTML("beforeend", esc(cleanShell(ev.data)) + "\n"); term.scrollTop = term.scrollHeight; };
    es.onerror = () => { if (_execConnected) execSetStatus("stream lost", "text-bg-warning"); };
  } catch (e) {
    out.insertAdjacentHTML("beforeend", `<span class="l-warn">[!] ${esc(e.message)}</span>\n`);
    execSetStatus("error", "text-bg-danger"); btn.disabled = false;
  } finally {
    term.scrollTop = term.scrollHeight;
  }
}

async function execDisconnect() {
  if (_shellES) { _shellES.close(); _shellES = null; }
  if (_shellId) { try { await api(`/api/shells/${_shellId}/stop`, { method: "POST" }); } catch { } }
  _shellId = null; _execConnected = false;
  execSetStatus("disconnected", "text-bg-secondary");
  $("#ex_connect").disabled = false; $("#ex_disconnect").disabled = true;
  execFields().forEach(id => $("#" + id).disabled = false);
  const c = $("#ex_cmd"); c.disabled = true; c.value = ""; c.placeholder = "Connect to start a session…";
  $("#ex_out").insertAdjacentHTML("beforeend", `<span class="text-secondary">[*] session closed</span>\n`);
}

async function execRun() {   // send a command into the persistent session
  const input = $("#ex_cmd"), cmd = input.value;
  if (!_execConnected || !_shellId || !cmd) return;
  input.value = "";
  $("#ex_out").insertAdjacentHTML("beforeend", `<span class="l-run">&gt; ${esc(cmd)}</span>\n`);
  $("#exTerm").scrollTop = $("#exTerm").scrollHeight;
  try { await api(`/api/shells/${_shellId}/send`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: cmd }) }); }
  catch (e) { alert(e.message); }
  input.focus();
}

function execClear() { $("#ex_out").innerHTML = ""; }

let _lstES = null, _lstActive = null;
async function loadListeners() {
  let ls;
  try { ls = await api("/api/listeners"); } catch { return; }
  const cls = { listening: "text-bg-secondary", connected: "text-bg-success",
    closed: "text-bg-light", stopped: "text-bg-warning" };
  $("#listenersList").innerHTML = ls.length ? ls.map(l => `
    <div class="d-flex align-items-center justify-content-between border rounded px-2 py-1 mb-1">
      <span class="small">:${l.port} <span class="badge ${cls[l.status] || "text-bg-secondary"}">${esc(l.status)}</span></span>
      <span class="text-nowrap">
        <button class="btn btn-sm btn-outline-secondary py-0 me-1" data-watch-lst="${esc(l.id)}">watch</button>
        <button class="btn btn-sm btn-outline-danger py-0" data-stop-lst="${esc(l.id)}">stop</button>
      </span></div>`).join("") : `<div class="text-secondary small">No listeners.</div>`;
  $$("#listenersList [data-watch-lst]").forEach(b => b.onclick = () => watchListener(b.dataset.watchLst));
  $$("#listenersList [data-stop-lst]").forEach(b => b.onclick = async () => {
    try { await api(`/api/listeners/${b.dataset.stopLst}/stop`, { method: "POST" }); } catch (e) { alert(e.message); }
    loadListeners();
  });
}

function watchListener(id) {
  if (_lstES) { _lstES.close(); _lstES = null; }
  _lstActive = id;
  $("#lstActive").textContent = "#" + id;
  const out = $("#lst_out"), term = $("#lstTerm"), input = $("#lst_cmd");
  out.innerHTML = "";
  $("#lstStatus").textContent = "streaming"; $("#lstStatus").className = "badge text-bg-success";
  input.disabled = false; input.placeholder = "type into the shell (Enter to send)"; input.focus();
  const es = new EventSource(`/api/listeners/${id}/stream`);
  _lstES = es;
  es.onmessage = (ev) => { out.insertAdjacentHTML("beforeend", esc(ev.data) + "\n"); term.scrollTop = term.scrollHeight; };
  es.onerror = () => { $("#lstStatus").textContent = "disconnected"; $("#lstStatus").className = "badge text-bg-warning"; };
}

async function sendListenerCmd() {
  const input = $("#lst_cmd"), cmd = input.value;
  if (!_lstActive || !cmd) return;
  input.value = "";
  try { await api(`/api/listeners/${_lstActive}/send`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ command: cmd }) }); }
  catch (e) { alert(e.message); }
  input.focus();
}

/* ---- findings / results ----------------------------------------------- */
const SEV_CLASS = { Critical: "text-bg-dark", High: "text-bg-danger",
  Medium: "text-bg-warning", Low: "text-bg-secondary", Info: "text-bg-light" };
const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

async function loadFindings() {
  let d;
  try { d = await api("/api/findings"); } catch { return; }

  // credentials
  $("#credCount").textContent = d.credentials.length;
  window._creds = d.credentials;
  $("#credsTable tbody").innerHTML = d.credentials.length ? d.credentials.map((c, i) => {
    const secret = c.password ? esc(c.password) : "(hash)";
    const srcs = (c.sources && c.sources.length) ? c.sources : (c.note ? [c.note] : []);
    const srcBadges = srcs.map(s =>
      `<span class="badge text-bg-light text-secondary border me-1">${esc(s)}</span>`).join("") || "—";
    return `<tr><td class="font-monospace">${esc(c.username)}</td>
      <td class="font-monospace">${secret}</td><td class="small">${esc(c.domain || "")}</td>
      <td>${srcBadges}</td>
      <td class="text-end align-middle"><button class="btn btn-sm btn-outline-danger py-0 text-nowrap" data-open-session="${i}">Open session</button></td></tr>`;
  }).join("") : `<tr><td colspan="5" class="text-center text-secondary py-3">No credentials recovered yet.</td></tr>`;
  $$("#credsTable [data-open-session]").forEach(b => b.onclick = () => openSessionFrom(window._creds[+b.dataset.openSession]));

  // users
  $("#userCount").textContent = d.users.length;
  $("#usersBox").innerHTML = d.users.length
    ? d.users.map(u => `<span class="chip font-monospace">${esc(u)}</span>`).join("")
    : `<div class="text-secondary small">No usernames enumerated yet.</div>`;

  // findings
  const fs = [...d.findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  $("#findingCount").textContent = fs.length;
  $("#findingsList").innerHTML = fs.length ? fs.map(f => {
    const sev = `<span class="badge ${SEV_CLASS[f.severity] || "text-bg-secondary"}">${esc(f.severity)}</span>`;
    const hosts = (f.hosts || []).map(h => `<span class="badge text-bg-light text-secondary border font-monospace">${esc(h)}</span>`).join(" ");
    const ev = f.evidence_out ? `<div class="pb-section-label mt-2">Evidence${f.evidence_cmd ? " — <code>" + esc(f.evidence_cmd) + "</code>" : ""}</div>
      <pre class="finding-ev">${esc(f.evidence_out)}</pre>` : "";
    return `<div class="finding-item">
      <div class="d-flex justify-content-between align-items-start gap-2">
        <div class="fw-semibold">${esc(f.title)}</div>
        <div class="text-nowrap">${sev}${f.cvss ? ` <span class="badge text-bg-light text-secondary border">CVSS ${esc(f.cvss)}</span>` : ""}</div>
      </div>
      ${hosts ? `<div class="mt-1">${hosts}</div>` : ""}
      <div class="text-secondary small mt-1">${esc(f.description || "")}</div>
      ${f.impact ? `<div class="small mt-1"><b>Impact:</b> ${esc(f.impact)}</div>` : ""}
      ${f.recommendation ? `<div class="small mt-1"><b>Recommendation:</b> ${esc(f.recommendation)}</div>` : ""}
      ${ev}
    </div>`;
  }).join("") : `<div class="text-secondary py-3 text-center">No findings yet — run an assessment.</div>`;

  $("#findingsSource").textContent = d.transcript
    ? `Derived from the latest run (${d.transcript}) and the results store.`
    : "Derived from the results store (no run transcript in this session yet).";
}

/* ---- tools (actions) -------------------------------------------------- */
let _toolModal = null;
let _toolViewModal = null;
let _toolEditName = null;   // null = create
let _allTools = [];

const CAT_CLASS = { recon: "text-bg-info", web: "text-bg-primary",
  "ad-smb": "text-bg-danger", credentials: "text-bg-warning",
  exploit: "text-bg-dark", custom: "text-bg-success" };

async function loadTools() {
  try { _allTools = await api("/api/tools"); } catch { return; }
  renderTools();
}

function renderTools() {
  const q = ($("#toolSearch").value || "").toLowerCase();
  const tools = _allTools.filter(t =>
    !q || t.name.toLowerCase().includes(q) || (t.description || "").toLowerCase().includes(q) ||
    (t.category || "").toLowerCase().includes(q));

  const rows = tools.map(t => {
    const cat = `<span class="badge ${CAT_CLASS[t.category] || "text-bg-secondary"}">${esc(t.category)}</span>`;
    const custom = t.custom ? `<span class="badge text-bg-success">custom</span>`
      : `<span class="badge text-bg-light text-secondary border">built-in</span>`;
    const cmd = t.programmatic
      ? `<span class="text-secondary fst-italic">${t.kind === "builtin" ? "built-in module" : "programmatic argument builder"}</span>`
      : `<code>${esc(t.template || "")}</code>`;
    const params = Object.keys((t.parameters || {}).properties || {});
    const paramBadges = params.map(p => `<span class="badge text-bg-light text-secondary border">${esc(p)}</span>`).join(" ");
    const actions = t.custom
      ? `<button class="btn btn-sm btn-outline-secondary py-0 me-1" data-tool-view="${esc(t.name)}">View</button>
         <button class="btn btn-sm btn-outline-secondary py-0 me-1" data-tool-edit="${esc(t.name)}">Edit</button>
         <button class="btn btn-sm btn-outline-danger py-0" data-tool-del="${esc(t.name)}">Delete</button>`
      : `<button class="btn btn-sm btn-outline-secondary py-0" data-tool-view="${esc(t.name)}">View</button>`;
    return `<div class="card mb-2"><div class="card-body py-2">
      <div class="d-flex justify-content-between align-items-start gap-2">
        <div class="flex-grow-1">
          <div class="d-flex align-items-center gap-2 flex-wrap">
            <span class="fw-semibold font-monospace">${esc(t.name)}</span> ${cat} ${custom}
            ${t.binary && t.kind !== "builtin" ? `<span class="text-secondary small">binary: <code>${esc(t.binary)}</code></span>` : ""}
          </div>
          <div class="text-secondary small mt-1">${esc(t.description || "")}</div>
          <div class="mt-1 small">${cmd}</div>
          ${params.length ? `<div class="mt-1 small"><span class="text-secondary">params:</span> ${paramBadges}</div>` : ""}
        </div>
        <div class="text-nowrap">${actions}</div>
      </div></div></div>`;
  }).join("");
  $("#toolsList").innerHTML = rows || `<div class="text-secondary py-3">No tools match.</div>`;

  $$("#toolsList [data-tool-view]").forEach(b => b.onclick = () => toolView(b.dataset.toolView));
  $$("#toolsList [data-tool-edit]").forEach(b => b.onclick = () => toolEdit(b.dataset.toolEdit));
  $$("#toolsList [data-tool-del]").forEach(b => b.onclick = () => toolDelete(b.dataset.toolDel));
}

function toolView(name) {
  const t = _allTools.find(x => x.name === name);
  if (!t) return;
  const builtin = t.kind === "builtin";

  // Read-only mirrors of the "New tool" form controls, so the View window is the
  // same window as Add tool — a live reference for building a new tool.
  const roInput = (label, val, help = "", col = "") =>
    `<div class="${col || "mb-2"}"><label class="pb-lbl">${label}${help ? ` <span class="text-secondary">${help}</span>` : ""}</label>
       <input class="form-control form-control-sm" value="${esc(val || "")}" disabled></div>`;
  const roArea = (label, val, rows, help = "", mono = true) =>
    `<div class="mb-2"><label class="pb-lbl">${label}${help ? ` <span class="text-secondary">${help}</span>` : ""}</label>
       <textarea class="form-control form-control-sm${mono ? " font-monospace" : ""}" rows="${rows}" disabled>${esc(val || "")}</textarea></div>`;

  const flagsText = Object.entries(t.flags || {}).map(([v, f]) => `${v} = ${f}`).join("\n");
  const harvestText = (t.harvest || []).map(h =>
    `${h.var}${h.multi ? "*" : ""}${h.scope === "host" ? "@host" : ""} = ${h.regex}`
    + (h.source === "tool" ? "   # tool-specific" : "")).join("\n");
  // Command preview built exactly like the editor's live preview.
  const parts = [builtin ? "(built-in module)" : (t.binary || "binary"), ...(t.subcommand || [])];
  (t.positional || []).forEach(v => parts.push(`<${v}>`));
  for (const [v, f] of Object.entries(t.flags || {}))
    parts.push(f === "" ? `[${v}]` : f.includes("{v}") ? `[${f.replace("{v}", v)}]` : `[${f} <${v}>]`);
  parts.push(...(t.fixed || []));
  const preview = parts.join(" ");

  const params = (t.parameters || {}).properties || {};
  const req = (t.parameters || {}).required || [];
  const paramRows = Object.entries(params).map(([p, s]) =>
    `<div><code>${esc(p)}</code> <span class="text-secondary small">${esc(s.description || s.type || "")}</span>${req.includes(p) ? ` <span class="badge text-bg-light text-secondary border">required</span>` : ""}</div>`).join("") || `<span class="text-secondary">none</span>`;
  const plan = (t.plan && t.plan.length)
    ? `<ol class="mb-0 ps-3">${t.plan.map(s => `<li>${esc(s)}</li>`).join("")}</ol>` : "";

  $("#toolViewTitle").textContent = t.name;
  $("#toolViewBody").innerHTML = `
    <p class="small text-secondary">${builtin
      ? `A <strong>built-in</strong> tool: a Python module that runs its own logic and parses output into variables at the Autopwn level. The fields below mirror the <em>Add tool</em> form so you can see how an action is described.`
      : `A tool runs an installed command line, built as an argv list (never a shell string): <code>binary → subcommand → &lt;positional&gt; → [flags] → fixed</code>. Same fields as the <em>Add tool</em> form — this one is read-only.`}</p>
    <div class="row g-2 mb-2">
      ${roInput("Name", t.name, "", "col-md-5")}
      ${roInput(builtin ? "Binary" : "Binary (on PATH)", builtin ? "(built-in module)" : t.binary, "", "col-md-4")}
      ${roInput("Category", t.category, "", "col-md-3")}
    </div>
    ${roArea("Description", t.description, 2, "", false)}
    <div class="row g-2">
      ${roInput("Subcommand", (t.subcommand || []).join(" "), "(space or comma separated)", "col-md-6 mb-2")}
      ${roInput("Positional variables", (t.positional || []).join(", "), "(comma)", "col-md-6 mb-2")}
    </div>
    ${roArea("Flags", flagsText, 4, "(one per line: <code>variable = -flag</code>; empty = bare boolean; <code>--{v}</code> templates the value)")}
    <div class="row g-2">
      ${roInput("Fixed trailing tokens", (t.fixed || []).join(", "), "(comma)", "col-md-6 mb-2")}
      ${roInput("Authorize on", t.authorize_on || t.host_from || (t.requires_host === false ? "—" : "target"), "", "col-md-3 mb-2")}
      ${roInput("Install hint", t.install_hint, "", "col-md-3 mb-2")}
    </div>
    ${roArea("Harvested variables", harvestText, 3,
      "(auto-captured from output; one per line: <code>variable = regex</code>. <code>var*</code> = every match, <code>var@host</code> = attach to host. First capture group is the value.)")}
    ${plan ? `<div class="mb-2"><label class="pb-lbl">What it does</label>${plan}</div>` : ""}
    <div class="mb-1"><label class="pb-lbl">Parameters ${builtin ? "" : "<span class='text-secondary'>(derived from positional + flag variables)</span>"}</label>${paramRows}</div>
    <div class="pb-lbl">Preview</div>
    <div class="pb-match font-monospace">${esc(preview)}</div>
    <div class="d-flex gap-3 mt-2 small text-secondary">
      <span>Kind: <strong>${builtin ? "built-in" : "catalog"}</strong>${t.custom ? " (editable)" : ""}</span>
      <span>Installed: <strong>${t.installed ? "yes" : "no"}</strong></span>
      ${!builtin ? `<span>Intrusive: <strong>${t.intrusive ? "yes" : "no"}</strong></span>` : ""}
      ${t.timeout ? `<span>Timeout: <strong>${esc(t.timeout)}s</strong></span>` : ""}
    </div>`;
  _toolViewModal.show();
}

function _toolFieldGet() {
  const flags = {};
  ($("#t_flags").value || "").split("\n").forEach(line => {
    if (!line.trim()) return;
    const i = line.indexOf("=");
    const k = (i === -1 ? line : line.slice(0, i)).trim();
    const v = (i === -1 ? "" : line.slice(i + 1)).trim();
    if (k) flags[k] = v;
  });
  const csv = (id) => ($(id).value || "").split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
  const harvest = [];
  ($("#t_harvest").value || "").split("\n").forEach(line => {
    const i = line.indexOf("=");
    if (i < 1) return;
    let name = line.slice(0, i).trim();
    const regex = line.slice(i + 1).trim();
    if (!name || !regex) return;
    let scope = "global", multi = false;
    if (name.includes("@host")) { scope = "host"; name = name.replace("@host", "").trim(); }
    if (name.endsWith("*")) { multi = true; name = name.slice(0, -1).trim(); }
    if (name) harvest.push({ var: name, regex, scope, multi, group: 1 });
  });
  return {
    name: $("#t_name").value.trim(), binary: $("#t_binary").value.trim(),
    category: $("#t_category").value.trim() || "custom",
    description: $("#t_description").value.trim(),
    subcommand: csv("#t_subcommand"), positional: csv("#t_positional"),
    flags, fixed: csv("#t_fixed"), harvest,
    host_from: $("#t_host_from").value, install_hint: $("#t_install_hint").value.trim(),
  };
}

function _toolPreview() {
  const d = _toolFieldGet();
  const parts = [d.binary || "binary", ...d.subcommand];
  d.positional.forEach(v => parts.push(`<${v}>`));
  for (const [v, f] of Object.entries(d.flags))
    parts.push(f === "" ? `[${v}]` : f.includes("{v}") ? `[${f.replace("{v}", v)}]` : `[${f} <${v}>]`);
  parts.push(...d.fixed);
  $("#t_preview").textContent = parts.join(" ");
}

function _toolFieldSet(d) {
  $("#t_name").value = d.name || "";
  $("#t_binary").value = d.binary || "";
  $("#t_category").value = d.category || "custom";
  $("#t_description").value = d.description || "";
  $("#t_subcommand").value = (d.subcommand || []).join(" ");
  $("#t_positional").value = (d.positional || []).join(", ");
  $("#t_flags").value = Object.entries(d.flags || {}).map(([k, v]) => `${k} = ${v}`).join("\n");
  $("#t_fixed").value = (d.fixed || []).join(", ");
  $("#t_harvest").value = (d.harvest || []).map(h => {
    const name = h.var + (h.multi ? "*" : "") + (h.scope === "host" ? "@host" : "");
    return `${name} = ${h.regex}`;
  }).join("\n");
  $("#t_host_from").value = d.host_from || "target";
  $("#t_install_hint").value = d.install_hint || "";
  _toolPreview();
}

function toolNew() {
  _toolEditName = null;
  $("#toolEditorTitle").textContent = "New tool";
  $("#toolEditorError").textContent = "";
  _toolFieldSet({ category: "custom", positional: ["target"], host_from: "target" });
  _toolModal.show();
}

async function toolEdit(name) {
  _toolEditName = name;
  let d;
  try { d = await api(`/api/tools/custom/${encodeURIComponent(name)}`); } catch (e) { return alert(e.message); }
  $("#toolEditorTitle").textContent = "Edit tool — " + name;
  $("#toolEditorError").textContent = "";
  _toolFieldSet(d);
  _toolModal.show();
}

async function toolSave() {
  const body = _toolFieldGet();
  if (!body.name || !body.binary) { $("#toolEditorError").textContent = "Name and binary are required."; return; }
  try {
    if (_toolEditName === null)
      await api("/api/tools/custom", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    else
      await api(`/api/tools/custom/${encodeURIComponent(_toolEditName)}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } catch (e) { $("#toolEditorError").textContent = e.message; return; }
  _toolModal.hide();
  loadTools();
}

async function toolDelete(name) {
  if (!confirm(`Delete custom tool "${name}"?`)) return;
  try { await api(`/api/tools/custom/${encodeURIComponent(name)}`, { method: "DELETE" }); } catch (e) { return alert(e.message); }
  loadTools();
}

/* ---- launch ----------------------------------------------------------- */
$("#launchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.target).entries());
  const btn = $("#launchBtn");
  btn.disabled = true; btn.textContent = "Launching…";
  try {
    const res = await api("/api/jobs/agent", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    e.target.reset();
    show("jobs");
    setTimeout(() => watch(res.id), 300);
  } catch (err) {
    alert("Launch failed: " + err.message);
  } finally {
    btn.disabled = false; btn.textContent = "▶ Launch";
  }
});

/* ---- jobs ------------------------------------------------------------- */
const STATUS_CLASS = { running: "text-bg-success", finished: "text-bg-primary",
  stopped: "text-bg-warning" };

async function loadJobs() {
  let jobs;
  try { jobs = await api("/api/jobs"); } catch { return; }
  $("#jobsTable tbody").innerHTML = jobs.length ? jobs.map(j => {
    const t = new Date(j.started * 1000).toLocaleString();
    const cls = STATUS_CLASS[j.status] || "text-bg-secondary";
    const stop = j.status === "running"
      ? `<button class="btn btn-sm btn-outline-danger py-0" data-stop="${j.id}">stop</button>` : "";
    return `<tr><td class="small">${esc(t)}</td><td class="small">${esc(j.label)}</td>
      <td><span class="badge ${cls}">${esc(j.status)}</span></td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-secondary py-0 me-1" data-watch="${j.id}">watch</button>${stop}</td></tr>`;
  }).join("") : `<tr><td colspan="4" class="text-center text-secondary py-3">No jobs yet.</td></tr>`;

  $$("#jobsTable [data-watch]").forEach(b => b.onclick = () => watch(b.dataset.watch));
  $$("#jobsTable [data-stop]").forEach(b => b.onclick = async () => {
    try { await api(`/api/jobs/${b.dataset.stop}/stop`, { method: "POST" }); } catch (e) { alert(e.message); }
    loadJobs();
  });
}

let _es = null;
function colorize(line) {
  let cls = "";
  if (/^\s*\[think\]/.test(line)) cls = "l-think";
  else if (/^\s*\[run\]/.test(line)) cls = "l-run";
  else if (/^\s*\[result\]|^\s*│/.test(line)) cls = "l-result";
  else if (/\[warn\]|error|failed/i.test(line)) cls = "l-warn";
  else if (/complete|═══/.test(line)) cls = "l-final";
  return `<span class="${cls}">${esc(line)}</span>`;
}

function watch(jobId) {
  show("jobs");
  if (_es) { _es.close(); _es = null; }
  const view = $("#logView");
  view.innerHTML = "";
  $("#logJobId").textContent = "#" + jobId;
  const status = $("#logStatus");
  status.textContent = "streaming"; status.className = "badge text-bg-success";

  const es = new EventSource(`/api/jobs/${jobId}/stream`);
  _es = es;
  es.onmessage = (ev) => {
    view.insertAdjacentHTML("beforeend", colorize(ev.data) + "\n");
    view.scrollTop = view.scrollHeight;
  };
  es.addEventListener("end", (ev) => {
    status.textContent = ev.data; status.className = "badge text-bg-primary";
    es.close(); _es = null;
    loadJobs(); loadReports();
  });
  es.onerror = () => {
    status.textContent = "disconnected"; status.className = "badge text-bg-warning";
    es.close(); _es = null;
  };
}

/* ---- reports ---------------------------------------------------------- */
async function loadReports() {
  let reports;
  try { reports = await api("/api/reports"); } catch { return; }
  const kb = (n) => n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB";
  $("#reportsTable tbody").innerHTML = reports.length ? reports.map(r => {
    const t = new Date(r.modified * 1000).toLocaleString();
    const view = r.format === "docx"
      ? `<a class="btn btn-sm btn-outline-secondary py-0" href="/reports/${encodeURIComponent(r.name)}?download=true">download</a>`
      : `<a class="btn btn-sm btn-outline-secondary py-0 me-1" href="/reports/${encodeURIComponent(r.name)}" target="_blank">view</a>
         <a class="btn btn-sm btn-outline-secondary py-0" href="/reports/${encodeURIComponent(r.name)}?download=true">download</a>`;
    return `<tr><td class="small font-monospace">${esc(r.name)}</td>
      <td><span class="badge text-bg-secondary text-uppercase">${esc(r.format)}</span></td>
      <td class="small">${kb(r.size)}</td><td class="small">${esc(t)}</td><td class="text-nowrap">${view}</td></tr>`;
  }).join("") : `<tr><td colspan="5" class="text-center text-secondary py-3">No reports yet.</td></tr>`;
}

/* ---- scope & vars ----------------------------------------------------- */
async function loadScope() {
  let sc, vars;
  try { [sc, vars] = await Promise.all([api("/api/scope"), api("/api/vars")]); } catch { return; }

  $("#scopeList").innerHTML =
    (sc.allow.length ? sc.allow.map(a => `<span class="chip">${esc(a)}
      <button data-allow="${esc(a)}" title="remove">✕</button></span>`).join("")
      : `<div class="text-secondary small">No allow entries.</div>`) +
    (sc.deny.length ? `<div class="mt-2 small text-secondary">Deny: ${sc.deny.map(esc).join(", ")}</div>` : "");
  $$("#scopeList [data-allow]").forEach(b => b.onclick = async () => {
    try { await api(`/api/scope/allow/${encodeURIComponent(b.dataset.allow)}`, { method: "DELETE" }); } catch (e) { alert(e.message); }
    loadScope();
  });

  const rows = vars.canonical.map(v => {
    let val = "—", cls = "text-secondary";
    if (v.value) {
      val = v.secret ? "•".repeat(Math.min(10, String(v.value).length)) : esc(v.value);
      cls = "font-monospace";
      if (v.derived) val += ` <span class="badge text-bg-light text-secondary border">derived</span>`;
    }
    const del = v.set ? `<button class="btn btn-sm btn-outline-danger py-0" data-fact="${esc(v.name)}">✕</button>` : "";
    return `<tr><td class="fw-semibold">${esc(v.name)}</td><td class="${cls}">${val}</td>
      <td class="small text-secondary">${esc(v.description)}</td><td class="text-end">${del}</td></tr>`;
  });
  const extraRows = vars.extra.map(v =>
    `<tr><td class="fw-semibold">${esc(v.name)} <span class="badge text-bg-light text-secondary border">extra</span></td>
     <td class="font-monospace">${esc(v.value)}</td><td class="small text-secondary">harvested</td>
     <td class="text-end"><button class="btn btn-sm btn-outline-danger py-0" data-fact="${esc(v.name)}">✕</button></td></tr>`);
  $("#varsTable tbody").innerHTML = rows.concat(extraRows).join("");
  const setCount = vars.canonical.filter(v => v.set).length + vars.extra.length;
  $("#varsSetCount").textContent = `${setCount} set`;
  $$("#varsTable [data-fact]").forEach(b => b.onclick = async () => {
    try { await api(`/api/facts/${encodeURIComponent(b.dataset.fact)}`, { method: "DELETE" }); } catch (e) { alert(e.message); }
    loadScope();
  });
}

$("#scopeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const entry = new FormData(e.target).get("entry").trim();
  if (!entry) return;
  try { await api("/api/scope/allow", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ entry }) }); }
  catch (err) { alert(err.message); }
  e.target.reset(); loadScope();
});

$("#factForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target).entries());
  if (!f.key) return;
  try { await api("/api/facts", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(f) }); }
  catch (err) { alert(err.message); }
  e.target.reset(); loadScope();
});

/* ---- settings (AI / model) -------------------------------------------- */
async function loadSettings() {
  let s;
  try { s = await api("/api/settings"); } catch { return; }
  $("#s_ai_enabled").checked = !!s.ai_enabled;
  const L = s.llm || {};
  $("#s_provider").value = L.provider || "";
  $("#s_model").value = L.model || "";
  $("#s_embed_model").value = L.embed_model || "";
  $("#s_base_url").value = L.base_url || "";
  $("#s_api_key").value = "";
  $("#s_key_state").textContent = L.has_api_key ? "(set — blank keeps it)" : "(none)";
  $("#s_temperature").value = L.temperature ?? "";
  $("#s_max_tokens").value = L.max_tokens ?? "";
  $("#s_request_timeout").value = L.request_timeout ?? "";
  const A = s.agent || {};
  $("#s_max_steps").value = A.max_steps ?? "";
  $("#s_prime_recon").checked = !!A.prime_recon;
  $("#s_use_kb").checked = !!A.use_kb;
  $("#s_confirm_active_actions").checked = !!A.confirm_active_actions;
  _aiEnabled = !!s.ai_enabled;
  reflectAi();
  loadAiLog();
  loadSessionsAdmin();
}

async function loadSessionsAdmin() {
  let data;
  try { data = await api("/api/sessions"); } catch { return; }
  $("#sessionsTable tbody").innerHTML = data.sessions.map(s => {
    const badges = (s.current ? ` <span class="badge text-bg-success">current</span>` : "")
      + (s.name === "default" ? ` <span class="badge text-bg-light text-secondary border">default</span>` : "");
    const clear = `<button class="btn btn-sm btn-outline-secondary py-0 me-1" data-clear-session="${esc(s.name)}">Clear data</button>`;
    const del = s.name === "default"
      ? `<span class="text-secondary small">protected</span>`
      : `<button class="btn btn-sm btn-outline-danger py-0" data-del-session="${esc(s.name)}">Delete</button>`;
    return `<tr><td class="fw-semibold">${esc(s.name)}${badges}</td>
      <td class="small">${s.hosts} host${s.hosts === 1 ? "" : "s"}</td>
      <td class="text-end text-nowrap">${clear}${del}</td></tr>`;
  }).join("");
  $$("#sessionsTable [data-clear-session]").forEach(b => b.onclick = () => clearSession(b.dataset.clearSession));
  $$("#sessionsTable [data-del-session]").forEach(b => b.onclick = () => deleteSession(b.dataset.delSession));
}

async function clearSession(name) {
  if (!confirm(`Clear ALL assessment data in session "${name}" (results, findings, jobs, reports)? Scope, playbooks and custom tools are kept.`)) return;
  try { await api(`/api/sessions/${encodeURIComponent(name)}/clear`, { method: "POST" }); }
  catch (e) { return alert(e.message); }
  await loadSessions();
  loadSettings();
  loadDashboard();
}

async function deleteSession(name) {
  if (!confirm(`Delete session "${name}" and permanently remove ALL its data?`)) return;
  try { await api(`/api/sessions/${encodeURIComponent(name)}`, { method: "DELETE" }); }
  catch (e) { return alert(e.message); }
  _allTools = []; _pbToolNames = [];
  await loadSessions();
  loadSettings();
}

function fmtMsgs(msgs) {
  return (msgs || []).map(m => {
    let s = `[${(m.role || "").toUpperCase()}]\n${m.content || ""}`;
    (m.tool_calls || []).forEach(tc =>
      s += `\n  → tool_call ${tc.name}(${JSON.stringify(tc.arguments)})`);
    return s;
  }).join("\n\n");
}

async function loadAiLog() {
  let rows;
  try { rows = await api("/api/ai-log"); } catch { return; }
  $("#aiLogTable tbody").innerHTML = rows.length ? rows.map((r, i) => {
    const t = new Date((r.ts || 0) * 1000).toLocaleTimeString();
    const ok = r.ok ? `<span class="badge text-bg-success">ok</span>`
      : `<span class="badge text-bg-danger">error</span>`;
    const lat = r.duration_ms != null ? `${(r.duration_ms / 1000).toFixed(1)}s` : "";
    let summary = "";
    if (r.ok) {
      const bits = [];
      if (r.completion_chars != null) bits.push(`${r.completion_chars} chars`);
      if (r.tool_calls) bits.push(`${r.tool_calls} tool-calls`);
      if (r.usage && r.usage.total_tokens) bits.push(`${r.usage.total_tokens} tok`);
      summary = `<span class="text-secondary small">${esc(bits.join(" · "))}</span>`;
    } else {
      summary = `<span class="text-danger small">${esc((r.error || "").slice(0, 80))}</span>`;
    }
    const req = r.request ? fmtMsgs(r.request) : "(not recorded)";
    const resp = r.ok ? fmtMsgs([{ role: "assistant", content: (r.response || {}).content, tool_calls: (r.response || {}).tool_calls }])
      : (r.error || "");
    const detail = `<tr class="ai-detail d-none" data-detail="${i}"><td colspan="6">
        <div class="ai-io"><div class="pb-section-label">Sent to AI${r.tool_count ? ` · ${r.tool_count} tools` : ""}</div>
          <pre class="ai-body">${esc(req)}</pre>
          <div class="pb-section-label mt-2">Received</div>
          <pre class="ai-body">${esc(resp)}</pre></div></td></tr>`;
    return `<tr class="ai-row" data-row="${i}" style="cursor:pointer">
        <td class="small">${esc(t)}</td><td class="small">${esc(r.kind || "")}</td>
        <td class="small font-monospace">${esc(r.model || "")}</td><td>${ok}</td>
        <td class="small">${esc(lat)}</td><td>${summary} <span class="text-secondary">▾</span></td></tr>${detail}`;
  }).join("") : `<tr><td colspan="6" class="text-center text-secondary py-3">No AI calls yet in this session.</td></tr>`;

  $$("#aiLogTable .ai-row").forEach(row => row.onclick = () => {
    const d = $(`#aiLogTable [data-detail="${row.dataset.row}"]`);
    if (d) d.classList.toggle("d-none");
  });
}

async function testAi() {
  const btn = $("#testAiBtn"), status = $("#testAiStatus");
  const label = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>Testing…`;
  status.className = "small text-secondary";
  status.textContent = "Pinging the model — local models can take 10–30s…";
  try {
    const r = await api("/api/settings/test-ai", { method: "POST" });
    if (r.ok) {
      status.className = "small text-success";
      status.textContent = `✓ Connected to ${r.model} in ${(r.latency_ms / 1000).toFixed(1)}s — reply: “${r.reply || ""}”`;
    } else {
      status.className = "small text-danger";
      status.textContent = `✗ ${r.error || "failed"} (${(r.latency_ms / 1000).toFixed(1)}s)`;
    }
  } catch (e) {
    status.className = "small text-danger"; status.textContent = "✗ " + e.message;
  } finally {
    btn.disabled = false; btn.textContent = label;
    loadAiLog();
  }
}

$("#settingsForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    ai_enabled: $("#s_ai_enabled").checked,
    llm: {
      provider: $("#s_provider").value.trim(), model: $("#s_model").value.trim(),
      embed_model: $("#s_embed_model").value.trim(), base_url: $("#s_base_url").value.trim(),
      api_key: $("#s_api_key").value, temperature: $("#s_temperature").value,
      max_tokens: $("#s_max_tokens").value, request_timeout: $("#s_request_timeout").value,
    },
    agent: {
      max_steps: $("#s_max_steps").value,
      prime_recon: $("#s_prime_recon").checked, use_kb: $("#s_use_kb").checked,
      confirm_active_actions: $("#s_confirm_active_actions").checked,
    },
  };
  try { await api("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch (err) { return alert("Save failed: " + err.message); }
  const ok = $("#settingsSaved"); ok.classList.remove("d-none");
  setTimeout(() => ok.classList.add("d-none"), 2000);
  loadSettings();
});

/* AI enabled state reflected on the Launch page */
let _aiEnabled = true;
function reflectAi() {
  const aiRadio = $("#mode_ai");
  if (!aiRadio) return;
  aiRadio.disabled = !_aiEnabled;
  const lbl = document.querySelector('label[for="mode_ai"]');
  if (lbl) lbl.classList.toggle("disabled", !_aiEnabled);
  if (!_aiEnabled && aiRadio.checked) { $("#mode_playbook").checked = true; }
  updateMode();
}
function updateMode() {
  const ai = $("#mode_ai") && $("#mode_ai").checked;
  const objRow = $("#objectiveRow");
  if (objRow) objRow.classList.toggle("d-none", !ai);
  const hint = $("#modeHint");
  if (hint) hint.textContent = ai
    ? "The LLM agent reasons step-by-step and can improvise on unfamiliar targets."
    : "Recons the target and runs every matching playbook automatically.";
}

/* ---- sessions --------------------------------------------------------- */
async function loadSessions() {
  let data;
  try { data = await api("/api/sessions"); } catch { return; }
  $("#sessionSelect").innerHTML = data.sessions.map(s =>
    `<option value="${esc(s.name)}" ${s.current ? "selected" : ""}>${esc(s.name)} · ${s.hosts} host${s.hosts === 1 ? "" : "s"}</option>`).join("");
}

async function selectSession(name) {
  try { await api("/api/sessions/select", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) }); }
  catch (e) { return alert(e.message); }
  _allTools = []; _pbToolNames = [];   // caches are per-session
  refreshCurrentView();
}

async function newSession() {
  const name = prompt("New session name (letters, digits, _ . -):");
  if (!name) return;
  try { await api("/api/sessions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: name.trim() }) }); }
  catch (e) { return alert(e.message); }
  await loadSessions();
  _allTools = []; _pbToolNames = [];
  refreshCurrentView();
}

function refreshCurrentView() {
  loadDashboard();
  show($("#mainNav .ap-nav-link.active").dataset.view);
}

/* ---- boot ------------------------------------------------------------- */
_pbModal = new bootstrap.Modal($("#pbEditor"));
bindBuilder();
$("#pbNewBtn").addEventListener("click", pbNew);
$("#pbResetBtn").addEventListener("click", pbReset);
$("#pbEditorSave").addEventListener("click", pbSave);
$("#pbApplyJson").addEventListener("click", applyJsonToDraft);

_toolModal = new bootstrap.Modal($("#toolEditor"));
_toolViewModal = new bootstrap.Modal($("#toolViewer"));
$("#toolNewBtn").addEventListener("click", toolNew);
$("#toolEditorSave").addEventListener("click", toolSave);
$("#toolSearch").addEventListener("input", renderTools);
["t_binary", "t_subcommand", "t_positional", "t_flags", "t_fixed"].forEach(id =>
  $("#" + id).addEventListener("input", _toolPreview));

$("#sessionSelect").addEventListener("change", (e) => selectSession(e.target.value));
$("#sessionNewBtn").addEventListener("click", newSession);
$("#testAiBtn").addEventListener("click", testAi);
$("#aiLogRefresh").addEventListener("click", loadAiLog);

// interactive terminals: click anywhere focuses the inline input; Enter runs
$("#ex_cmd").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); execRun(); } });
$("#exTerm").addEventListener("mouseup", () => { if (!getSelection().toString() && !$("#ex_cmd").disabled) $("#ex_cmd").focus(); });
$("#ex_auth").addEventListener("change", updateSecretLabel);
$("#ex_connect").addEventListener("click", execConnect);
$("#ex_disconnect").addEventListener("click", execDisconnect);
$("#ex_clear").addEventListener("click", execClear);
$("#listenerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const port = new FormData(e.target).get("port");
  try { await api("/api/listeners", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ port: Number(port) }) }); }
  catch (err) { return alert(err.message); }
  e.target.reset(); loadListeners();
});
$("#lst_cmd").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); sendListenerCmd(); } });
$("#lstTerm").addEventListener("mouseup", () => { if (!getSelection().toString() && !$("#lst_cmd").disabled) $("#lst_cmd").focus(); });
$$('#launchForm input[name="mode"]').forEach(r => r.addEventListener("change", updateMode));
updateMode();

$("#refreshBtn").addEventListener("click", () => {
  loadSessions();
  show($("#mainNav .ap-nav-link.active").dataset.view);
});

// restore the view from the URL hash (survives a browser refresh); react to back/forward
window.addEventListener("hashchange", () => show((location.hash || "").slice(1)));
loadSessions();
show((location.hash || "").slice(1) || "dashboard");

/* Seamless auto-refresh: silently reload the active view's data in place. Skips
   form-heavy views (Launch/Settings) and pauses while a modal is open, so it
   never clobbers what the operator is typing. */
const _AUTO = { dashboard: loadDashboard, findings: loadFindings,
  playbooks: loadPlaybooks, tools: loadTools, jobs: loadJobs,
  reports: loadReports, scope: loadScope };
setInterval(() => {
  if (document.hidden || document.querySelector(".modal.show")) return;
  const v = $("#mainNav .ap-nav-link.active")?.dataset.view;
  if (v && _AUTO[v]) _AUTO[v]();
}, 6000);
setInterval(loadSessions, 15000);   // keep session host-counts fresh
