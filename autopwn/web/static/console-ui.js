/* Presentation and navigation for the offline operations console. */
"use strict";

window.AutopwnUI = (() => {
  const el = id => document.getElementById(id);
  const escape = value => String(value ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const views = {
    dashboard: ["Command center", "OPERATIONS / OVERVIEW", "Your attack surface. One operational picture."],
    launch: ["Launch assessment", "OPERATIONS / DEPLOY", "Define your target. Configure your approach. Begin your assessment."],
    findings: ["Security findings", "OPERATIONS / INTELLIGENCE", "Evidence, exposure, and recovered assets from your engagement."],
    attack: ["MITRE ATT&CK", "OPERATIONS / COVERAGE", "Trace confirmed techniques and identify gaps in your assessment."],
    paths: ["Attack paths", "OPERATIONS / RELATIONSHIPS", "Follow identity relationships from foothold to domain control."],
    console: ["Interactive console", "OPERATIONS / TERMINAL", "A direct line to your authorized systems and active sessions."],
    playbooks: ["Playbook library", "ARSENAL / METHODOLOGY", "Inspect, adapt, and execute repeatable assessment workflows."],
    tools: ["Tool arsenal", "ARSENAL / CAPABILITIES", "Your security toolkit. Every action, input, and execution detail."],
    jobs: ["Job operations", "ARSENAL / EXECUTION", "Monitor running assessments and follow their output in real time."],
    reports: ["Engagement reports", "ARSENAL / DELIVERABLES", "Review and export the evidence behind your security assessment."],
    scope: ["Scope & variables", "CONFIGURATION / AUTHORIZATION", "Define the boundaries and shared context of your engagement."],
    settings: ["System settings", "CONFIGURATION / SYSTEM", "Configure your AI backend, scanning behavior, and workspace."],
  };
  const icons = [
    '<rect x="3" y="3" width="18" height="7" rx="1"/><rect x="3" y="14" width="18" height="7" rx="1"/><path d="M6 6h2M6 17h2M16 6h2M16 17h2"/>',
    '<path d="M8 3v5M16 3v5M6 8h12v3a6 6 0 0 1-12 0ZM12 17v4"/>',
    '<path d="m12 2 9 5-9 5-9-5ZM3 12l9 5 9-5M3 17l9 5 9-5"/>',
    '<path d="m8 5 11 7-11 7Z"/>',
  ];
  let topologyKey = "";

  function setView(view) {
    const [title, eyebrow, description] = views[view];
    el("pageHeading").innerHTML = `${escape(title)}<span class="heading-period">.</span>`;
    el("viewTitle").textContent = title;
    el("pageEyebrow").textContent = eyebrow;
    el("pageDescription").textContent = description;
    document.title = `${title} · Autopwn`;
    document.querySelector(".heading-action").hidden = view === "launch";
    document.querySelectorAll("#mainNav [data-view]").forEach(button => {
      if (button.dataset.view === view) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    closeSidebar(false);
  }

  function setConnection(connected) {
    el("connectionState").classList.toggle("offline", !connected);
    el("connectionLabel").textContent = connected ? "Console online" : "Reconnecting";
    el("connectionAlert").hidden = connected;
    if (connected) el("lastSync").textContent = `SYNC ${new Date().toISOString().slice(11, 19)} UTC`;
  }

  function renderSummary(data) {
    const count = data.counts;
    const stats = [
      ["Discovered hosts", count.hosts, "cyan", "Assets in this session"],
      ["Open ports", count.open_ports, "amber", "Observed entry points"],
      ["Services", count.services, "violet", "Identified service types"],
      ["Active jobs", count.running_jobs, "green", count.running_jobs ? "Execution in progress" : "Standing by for launch"],
    ];
    el("statCards").innerHTML = stats.map(([label, value, tone, caption], i) => `
      <div class="col-6 col-xl-3"><div class="card stat-card" style="--stat-tone:var(--ap-${tone === "cyan" ? "accent" : tone})">
        <div class="stat-top"><span class="stat-label">${label}</span><span class="stat-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${icons[i]}</svg></span></div>
        <div class="display-6">${Number(value).toLocaleString()}</div><div class="stat-foot"><span aria-hidden="true">${i === 3 && value ? "◉" : "↗"}</span>${caption}</div>
      </div></div>`).join("");
    el("engagementName").textContent = data.engagement || "Untitled engagement";
    el("missionMode").textContent = data.ai_enabled ? "AI + playbooks" : "Playbooks only";
    const allowed = data.scope?.allow?.length || 0;
    el("missionScope").textContent = `${allowed} allowed / ${data.scope?.deny?.length || 0} denied`;
    el("missionJobs").textContent = count.running_jobs ? `${count.running_jobs} running` : "Standing by";
    el("missionExpiry").textContent = data.expires || "Not set";
    el("hostInventoryCount").textContent = `${count.hosts} ASSET${count.hosts === 1 ? "" : "S"}`;
    el("topologyStatus").textContent = count.hosts ? `${count.hosts} HOST${count.hosts === 1 ? "" : "S"} DISCOVERED` : "AWAITING DISCOVERY";
    document.querySelector(".topology-card").classList.toggle("is-running", count.running_jobs > 0);
    renderTopology(data.hosts);
  }

  function renderTopology(hosts) {
    // Orbit positions are a logical inventory layout, not inferred network links.
    const key = JSON.stringify(hosts.map(h => [h.host, h.hostname, h.open_ports]));
    if (key === topologyKey) return;
    topologyKey = key;
    const visible = hosts.slice(0, 8);
    const nodes = visible.map((host, i) => {
      const angle = (i / Math.max(visible.length, 1)) * Math.PI * 2 - Math.PI / 2 + .3;
      const x = 310 + Math.cos(angle) * 211;
      const y = 146 + Math.sin(angle) * 100;
      return `<g><title>${escape(host.host)}${host.hostname ? " / " + escape(host.hostname) : ""} / ${host.open_ports.length} open ports</title>
        <path class="topology-link" d="M310 146 L${x} ${y}"/>
        <circle class="topology-node-halo" cx="${x}" cy="${y}" r="15"/>
        <rect class="topology-node" x="${x - 5}" y="${y - 5}" width="10" height="10" rx="2"/>
        <text class="topology-label" x="${x}" y="${y + 28}" text-anchor="middle">${escape(host.host)}</text>
        <text class="topology-node-caption" x="${x}" y="${y + 41}" text-anchor="middle">${host.open_ports.length} OPEN PORTS</text></g>`;
    }).join("");
    el("topologyMap").innerHTML = `<svg class="topology-svg" viewBox="0 0 620 320" role="img" aria-labelledby="topologyTitle topologyDesc">
      <title id="topologyTitle">Session host inventory</title><desc id="topologyDesc">${hosts.length ? `${hosts.length} discovered hosts. Lines connect hosts to this session, not to each other. Full inventory is in the table below.` : "No hosts discovered. Launch an assessment to populate the inventory."}</desc>
      <path class="crosshair" d="M310 22v248M55 146h510M30 32h16M38 24v16M574 278h16M582 270v16"/>
      <ellipse class="orbit" cx="310" cy="146" rx="252" ry="115"/><ellipse class="orbit" cx="310" cy="146" rx="170" ry="83"/>
      <circle class="orbit orbit-dash" cx="310" cy="146" r="67"/><circle class="orbit" cx="310" cy="146" r="51"/>
      ${nodes}<path class="topology-core" d="m310 114 28 16v32l-28 16-28-16v-32Z"/>
      <path d="m297 155 13-23 13 23M303 147h14" fill="none" stroke="#58dfed" stroke-width="2"/>
      <text class="topology-center-label" x="310" y="196" text-anchor="middle">${hosts.length ? "SESSION" : "STANDBY"}</text>
      <text class="topology-corner" x="20" y="20">AUTOPWN / ASSET TELEMETRY</text><text class="topology-corner" x="600" y="303" text-anchor="end">LOGICAL VIEW</text>
      </svg>${hosts.length ? (hosts.length > visible.length ? `<span class="topology-more">+${hosts.length - visible.length} more in inventory</span>` : "") : '<div class="topology-empty"><strong>Awaiting first contact</strong><span>Discovered hosts will appear here.</span></div>'}`;
  }

  function renderActivity(jobs) {
    if (!jobs) {
      el("recentActivity").innerHTML = '<div class="empty-state">Activity unavailable. The next refresh will retry.</div>';
      return;
    }
    const recent = [...jobs].sort((a, b) => b.started - a.started).slice(0, 4);
    const statusClass = { running: "success", finished: "primary", stopped: "warning" };
    el("recentActivity").innerHTML = recent.length ? recent.map(job => `
      <div class="activity-row"><span class="activity-icon" aria-hidden="true">&gt;_</span>
        <button class="activity-label" data-activity-job="${escape(job.id)}" title="Watch ${escape(job.label)}">${escape(job.label)}</button>
        <time class="activity-time" datetime="${new Date(job.started * 1000).toISOString()}">${new Date(job.started * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</time>
        <span class="badge text-bg-${statusClass[job.status] || "secondary"}">${escape(job.status)}</span></div>`).join("") :
      '<div class="empty-state"><strong>Your next operation starts here.</strong>Launch an assessment to begin collecting evidence.<br><button class="panel-link" data-go="launch">Configure assessment ↗</button></div>';
  }

  // Mobile navigation is a focus-contained drawer. Desktop navigation stays a landmark.
  const sidebar = el("sidebar");
  function closeSidebar(restoreFocus = true) {
    const wasOpen = sidebar.classList.contains("is-open");
    sidebar.classList.remove("is-open");
    sidebar.removeAttribute("role");
    sidebar.removeAttribute("aria-modal");
    el("sidebarBackdrop").hidden = true;
    el("menuBtn").setAttribute("aria-expanded", "false");
    document.querySelector(".ap-main").inert = false;
    document.body.style.overflow = "";
    if (wasOpen && restoreFocus) el("menuBtn").focus();
  }
  el("menuBtn").addEventListener("click", () => {
    sidebar.classList.add("is-open");
    sidebar.setAttribute("role", "dialog");
    sidebar.setAttribute("aria-modal", "true");
    el("sidebarBackdrop").hidden = false;
    el("menuBtn").setAttribute("aria-expanded", "true");
    document.querySelector(".ap-main").inert = true;
    document.body.style.overflow = "hidden";
    el("sidebarClose").focus();
  });
  el("sidebarClose").addEventListener("click", () => closeSidebar());
  el("sidebarBackdrop").addEventListener("click", () => closeSidebar());
  matchMedia("(min-width: 768px)").addEventListener("change", e => { if (e.matches) closeSidebar(false); });
  sidebar.addEventListener("keydown", event => {
    if (!sidebar.classList.contains("is-open")) return;
    if (event.key === "Escape") { event.preventDefault(); closeSidebar(); }
    if (event.key !== "Tab") return;
    const focusable = [...sidebar.querySelectorAll('button, select, a[href]')].filter(node => !node.disabled && node.getClientRects().length);
    const first = focusable[0], last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });

  // Native dialog supplies focus trapping and Escape-to-close behavior.
  const palette = el("commandPalette");
  let selection = 0;
  function renderCommands() {
    const query = el("commandSearch").value.trim().toLowerCase();
    const matches = Object.entries(views).filter(([view, meta]) => [view, ...meta].join(" ").toLowerCase().includes(query));
    selection = 0;
    el("commandResults").innerHTML = matches.length ? matches.map(([view, [title, category]], i) =>
      `<button class="command-result${i === 0 ? " selected" : ""}" data-command="${view}"><span>${escape(title)}</span><small>${escape(category)}</small></button>`).join("") : '<div class="empty-state">No matching views. Try “tools” or “settings”.</div>';
  }
  function openPalette() {
    if (document.querySelector(".modal.show")) return;
    closeSidebar(false);
    el("commandSearch").value = "";
    renderCommands();
    if (!palette.open) palette.showModal();
    el("commandSearch").focus();
  }
  function navigate(view) { show(view); el("pageHeading").focus({ preventScroll: true }); window.scrollTo(0, 0); }
  el("commandBtn").setAttribute("aria-label", "Quick navigation (Ctrl or Command K)");
  el("commandBtn").addEventListener("click", openPalette);
  el("commandClose").addEventListener("click", () => palette.close());
  el("commandSearch").addEventListener("input", renderCommands);
  palette.addEventListener("click", event => {
    const command = event.target.closest("[data-command]");
    if (command) { palette.close(); navigate(command.dataset.command); }
    if (event.target === palette) {
      const rect = palette.getBoundingClientRect();
      if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) palette.close();
    }
  });
  palette.addEventListener("keydown", event => {
    const commands = [...el("commandResults").querySelectorAll("button")];
    if (!commands.length) return;
    if (["ArrowDown", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      const focused = commands.indexOf(document.activeElement);
      if (focused !== -1) selection = focused;
      selection = (selection + (event.key === "ArrowDown" ? 1 : -1) + commands.length) % commands.length;
      commands.forEach((button, i) => button.classList.toggle("selected", i === selection));
      commands[selection].focus();
      commands[selection].scrollIntoView({ block: "nearest" });
    } else if (event.key === "Enter" && event.target === el("commandSearch")) {
      event.preventDefault(); commands[selection].click();
    }
  });
  document.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      // Keep terminal keyboard shortcuts available while an operator is typing.
      if (event.target.closest(".xterm")) return;
      event.preventDefault();
      if (palette.open) palette.close(); else openPalette();
    }
  });
  document.addEventListener("click", event => {
    const link = event.target.closest("[data-go]");
    if (link) navigate(link.dataset.go);
    const activity = event.target.closest("[data-activity-job]");
    if (activity) watch(activity.dataset.activityJob);
  });
  const tick = () => { const now = new Date(); el("consoleClock").textContent = `${now.toISOString().slice(11, 19)} UTC`; el("consoleClock").dateTime = now.toISOString(); };
  el("statCards").innerHTML = ["Discovered hosts", "Open ports", "Services", "Active jobs"].map(label =>
    `<div class="col-6 col-xl-3"><div class="card stat-card"><span class="stat-label">${label}</span><div class="display-6">—</div><div class="stat-foot">Awaiting telemetry</div></div></div>`).join("");
  renderTopology([]);
  tick();
  setInterval(tick, 1000);
  return { setView, setConnection, renderSummary, renderActivity };
})();
