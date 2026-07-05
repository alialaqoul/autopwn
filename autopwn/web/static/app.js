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
  playbooks: "Playbooks", tools: "Tools", jobs: "Jobs", reports: "Reports",
  scope: "Scope & Vars" };

function show(view) {
  $$("#mainNav .ap-nav-link").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $$("section[data-panel]").forEach(s => (s.hidden = s.dataset.panel !== view));
  $("#viewTitle").textContent = TITLES[view] || view;
  const loaders = { dashboard: loadDashboard, playbooks: loadPlaybooks,
    tools: loadTools, jobs: loadJobs, reports: loadReports, scope: loadScope };
  loaders[view]?.();
}
$$("#mainNav .ap-nav-link").forEach(b => b.addEventListener("click", () => show(b.dataset.view)));

/* ---- dashboard -------------------------------------------------------- */
async function loadDashboard() {
  let d;
  try { d = await api("/api/summary"); } catch (e) { return; }
  $("#engagementLabel").textContent = d.engagement || "no engagement";
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
    <tr><td class="font-monospace">${esc(h.host)}</td><td>${esc(h.hostname)}</td>
    <td>${h.open_ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${esc(h.services.join(", "))}</td></tr>`).join("")
    : `<tr><td colspan="4" class="text-center text-secondary py-3">No hosts yet — launch an assessment.</td></tr>`;

  $("#servicesTable tbody").innerHTML = d.services.length ? d.services.map(s => {
    const uniqHosts = [...new Set(s.hosts.map(h => h.host))];
    return `<tr><td>${esc(s.service)}</td>
    <td>${s.ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${uniqHosts.map(esc).join(", ")} <span class="text-secondary">(${uniqHosts.length})</span></td></tr>`;
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
    const runTool = (pb.run || {}).tool;
    const runBtn = runTool
      ? `<button class="btn btn-sm btn-outline-danger py-0" data-pb-run="${esc(pb.id)}" title="Run ${esc(runTool)}">▶ Run</button>` : "";
    return `<div class="card pb-card">
      <div class="card-body">
        <div class="pb-head mb-2">
          <div>
            <div class="h6 mb-1">${esc(pb.name)} <span class="text-secondary small">(${esc(pb.id)})</span></div>
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
        <div class="pb-section-label mt-3">Execution</div>
        ${runTool ? `<div class="small mb-1"><span class="text-secondary">launches:</span> <code>${esc(runTool)}</code></div>` : ""}
        <div class="pb-flow">${steps}</div>
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

function renderBuilder() {
  const d = _pbDraft;
  const triggerOpts = _pbSchema.triggers.map(t => `<option value="${esc(t)}">`).join("");
  const nextOpts = _pbSchema.next.concat(d.steps.map(s => s.title).filter(Boolean))
    .map(t => `<option value="${esc(t)}">`).join("");
  const toolOpts = _pbToolNames.map(t => `<option value="${esc(t)}">`).join("");

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
      <div class="d-flex justify-content-between align-items-center mb-2">
        <span class="fw-semibold">Step ${st.n}</span>
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
          <input class="form-control form-control-sm" list="dlTriggers" value="${esc(st.trigger || "")}" data-step="${i}" data-field="trigger"></div>
        <div class="col-md-5"><label class="pb-lbl">Next on success</label>
          <input class="form-control form-control-sm" list="dlNext" value="${esc(st.next || "next")}" data-step="${i}" data-field="next"></div>
      </div>
      <div class="mb-2"><label class="pb-lbl">Consumes <span class="text-secondary">(needs from earlier steps)</span></label>
        <div class="pb-chips">${chipRow("consumes", st.consumes, i, _pbSchema.artifacts)}</div></div>
      <div class="mb-2"><label class="pb-lbl">Produces <span class="text-secondary">(passes to next / final)</span></label>
        <div class="pb-chips">${chipRow("produces", st.produces, i, _pbSchema.artifacts)}</div></div>
      <div class="mb-2"><label class="pb-lbl">Detail</label>
        <textarea class="form-control form-control-sm" rows="2" data-step="${i}" data-field="detail">${esc(st.detail || "")}</textarea></div>
      <div><label class="pb-lbl">Branches <span class="text-secondary">(conditional re-routes)</span></label>
        ${branches}
        <button class="btn btn-sm btn-outline-secondary py-0" type="button" data-act="addBranch" data-step="${i}">+ branch</button></div>
    </div>`;
  }).join("");

  $("#pbBuilder").innerHTML = `
    <datalist id="dlTriggers">${triggerOpts}</datalist>
    <datalist id="dlNext">${nextOpts}</datalist>
    <datalist id="dlTools">${toolOpts}</datalist>
    <div class="row g-2 mb-2">
      <div class="col-md-4"><label class="pb-lbl">ID</label>
        <input class="form-control form-control-sm" value="${esc(d.id)}" data-field="id"></div>
      <div class="col-md-8"><label class="pb-lbl">Name</label>
        <input class="form-control form-control-sm" value="${esc(d.name)}" data-field="name"></div>
    </div>
    <div class="mb-2"><label class="pb-lbl">Summary</label>
      <textarea class="form-control form-control-sm" rows="2" data-field="summary">${esc(d.summary || "")}</textarea></div>
    <div class="row g-2 mb-2">
      <div class="col-md-7"><label class="pb-lbl">Match — any of these open ports</label>
        <input class="form-control form-control-sm" value="${(d.match.any_ports || []).join(", ")}" data-field="ports" placeholder="88, 445, 389"></div>
      <div class="col-md-5"><label class="pb-lbl">Run — macro tool <span class="text-secondary">(optional)</span></label>
        <input class="form-control form-control-sm" list="dlTools" value="${esc((d.run || {}).tool || "")}" data-field="tool" placeholder="ad_kill_chain"></div>
    </div>
    <div class="mb-3"><label class="pb-lbl">Match — fact signals</label>
      <div class="pb-chips">${chipRow("signals", d.match.signals, undefined, _pbSchema.signals)}</div></div>
    <hr>
    <div class="d-flex justify-content-between align-items-center mb-2">
      <span class="pb-section-label mb-0">Steps</span>
      <button class="btn btn-sm btn-outline-primary py-0" type="button" data-act="addStep">+ Add step</button>
    </div>
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
  root.addEventListener("input", (e) => {
    const t = e.target, f = t.dataset.field;
    if (!f || !_pbDraft) return;
    if (t.dataset.branch !== undefined) {
      _pbDraft.steps[+t.dataset.step].branches[+t.dataset.branch][f] = t.value;
    } else if (t.dataset.step !== undefined) {
      _pbDraft.steps[+t.dataset.step][f] = t.value;
    } else if (f === "ports") {
      _pbDraft.match.any_ports = parsePorts(t.value);
    } else if (f === "tool") {
      _pbDraft.run.tool = t.value;
    } else {
      _pbDraft[f] = t.value;
    }
    syncJsonFromDraft();
  });
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
      : (t.kind === "native" ? `<span class="badge text-bg-light text-secondary border">native</span>`
        : `<span class="badge text-bg-light text-secondary border">built-in</span>`);
    const cmd = t.programmatic
      ? `<span class="text-secondary fst-italic">${t.kind === "native" ? "native module" : "programmatic argument builder"}</span>`
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
            ${t.binary && t.kind !== "native" ? `<span class="text-secondary small">binary: <code>${esc(t.binary)}</code></span>` : ""}
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
  const kv = (k, v) => v ? `<div class="row g-0 mb-1"><div class="col-4 text-secondary small">${esc(k)}</div><div class="col-8">${v}</div></div>` : "";
  const params = (t.parameters || {}).properties || {};
  const req = (t.parameters || {}).required || [];
  const paramRows = Object.entries(params).map(([p, s]) =>
    `<div><code>${esc(p)}</code> <span class="text-secondary small">${esc(s.description || s.type || "")}</span>${req.includes(p) ? ` <span class="badge text-bg-light text-secondary border">required</span>` : ""}</div>`).join("") || `<span class="text-secondary">none</span>`;
  const flags = t.flags && Object.keys(t.flags).length
    ? Object.entries(t.flags).map(([v, f]) => `<code>${esc(v)}</code> → <code>${esc(f || "(bare)")}</code>`).join("<br>") : "";
  const cmd = t.programmatic
    ? `<span class="fst-italic text-secondary">${t.kind === "native" ? "native Python module" : "programmatic argument builder (built-in)"}</span>`
    : `<code>${esc(t.template || "")}</code>`;
  $("#toolViewTitle").textContent = t.name;
  $("#toolViewBody").innerHTML =
    kv("Category", `<span class="badge ${CAT_CLASS[t.category] || "text-bg-secondary"}">${esc(t.category)}</span>`) +
    kv("Kind", esc(t.kind) + (t.custom ? " (editable)" : " (read-only)")) +
    kv("Binary", t.kind === "native" ? "<span class='text-secondary'>native module</span>" : `<code>${esc(t.binary)}</code>`) +
    kv("Installed", t.installed ? "yes" : "no") +
    kv("Description", esc(t.description || "")) +
    kv("Command", cmd) +
    (t.subcommand && t.subcommand.length ? kv("Subcommand", `<code>${t.subcommand.map(esc).join(" ")}</code>`) : "") +
    (t.positional && t.positional.length ? kv("Positional", t.positional.map(x => `<code>${esc(x)}</code>`).join(" ")) : "") +
    (flags ? kv("Flags", flags) : "") +
    (t.fixed && t.fixed.length ? kv("Fixed", `<code>${t.fixed.map(esc).join(" ")}</code>`) : "") +
    (t.install_hint ? kv("Install", esc(t.install_hint)) : "") +
    kv("Parameters", paramRows);
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
  return {
    name: $("#t_name").value.trim(), binary: $("#t_binary").value.trim(),
    category: $("#t_category").value.trim() || "custom",
    description: $("#t_description").value.trim(),
    subcommand: csv("#t_subcommand"), positional: csv("#t_positional"),
    flags, fixed: csv("#t_fixed"),
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

$("#refreshBtn").addEventListener("click", () => {
  loadSessions();
  show($("#mainNav .ap-nav-link.active").dataset.view);
});
loadSessions();
loadDashboard();
setInterval(() => { if (!$('section[data-panel="dashboard"]').hidden) loadDashboard(); }, 8000);
setInterval(() => { if (!$('section[data-panel="jobs"]').hidden) loadJobs(); }, 5000);
