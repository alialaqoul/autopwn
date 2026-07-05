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
function show(view) {
  $$("#mainTabs .nav-link").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $$("section[data-panel]").forEach(s => (s.hidden = s.dataset.panel !== view));
  const loaders = { dashboard: loadDashboard, jobs: loadJobs, reports: loadReports, scope: loadScope };
  loaders[view]?.();
}
$$("#mainTabs .nav-link").forEach(b => b.addEventListener("click", () => show(b.dataset.view)));

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
    <div class="col-6 col-lg-3"><div class="card stat-card text-center py-3">
      <div class="display-6">${val}</div><div class="stat-label">${label}</div>
    </div></div>`).join("");

  $("#hostsTable tbody").innerHTML = d.hosts.length ? d.hosts.map(h => `
    <tr><td class="font-monospace">${esc(h.host)}</td><td>${esc(h.hostname)}</td>
    <td>${h.open_ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${esc(h.services.join(", "))}</td></tr>`).join("")
    : `<tr><td colspan="4" class="text-center text-secondary py-3">No hosts yet — launch an assessment.</td></tr>`;

  $("#servicesTable tbody").innerHTML = d.services.length ? d.services.map(s => `
    <tr><td>${esc(s.service)}</td>
    <td>${s.ports.map(p => `<span class="badge text-bg-secondary badge-port">${p}</span>`).join(" ")}</td>
    <td class="small text-secondary">${s.hosts.map(h => esc(h.host)).join(", ")}</td></tr>`).join("")
    : `<tr><td colspan="3" class="text-center text-secondary py-3">No services discovered.</td></tr>`;
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
  let sc, facts;
  try { [sc, facts] = await Promise.all([api("/api/scope"), api("/api/facts")]); } catch { return; }
  $("#scopeList").innerHTML =
    (sc.allow.length ? sc.allow.map(a => `<span class="chip">${esc(a)}
      <button data-allow="${esc(a)}" title="remove">✕</button></span>`).join("")
      : `<div class="text-secondary small">No allow entries.</div>`) +
    (sc.deny.length ? `<div class="mt-2 small text-secondary">Deny: ${sc.deny.map(esc).join(", ")}</div>` : "");
  $$("#scopeList [data-allow]").forEach(b => b.onclick = async () => {
    try { await api(`/api/scope/allow/${encodeURIComponent(b.dataset.allow)}`, { method: "DELETE" }); } catch (e) { alert(e.message); }
    loadScope();
  });

  const keys = Object.keys(facts);
  $("#factsList").innerHTML = keys.length ? keys.map(k => `<span class="chip">
    <b>${esc(k)}</b>=${esc(facts[k])} <button data-fact="${esc(k)}" title="remove">✕</button></span>`).join("")
    : `<div class="text-secondary small">No variables set.</div>`;
  $$("#factsList [data-fact]").forEach(b => b.onclick = async () => {
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

/* ---- boot ------------------------------------------------------------- */
$("#refreshBtn").addEventListener("click", () => {
  const active = $("#mainTabs .nav-link.active").dataset.view;
  show(active);
});
loadDashboard();
setInterval(() => { if (!$('section[data-panel="dashboard"]').hidden) loadDashboard(); }, 8000);
setInterval(() => { if (!$('section[data-panel="jobs"]').hidden) loadJobs(); }, 5000);
