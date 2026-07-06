# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Autopwn command-line interface."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel

# Windows legacy consoles default to cp1252 and choke on tool output containing
# non-Latin-1 bytes. Force UTF-8 so nothing crashes on an encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass

from . import jobs, store
from .agent.agent import Agent
from .agent.prompts import autopilot_objective
from .authorization import Scope, ScopeError
from .config import Config
from .llm.factory import build_provider
from .parsers import parse_grepable, record_to_store
from .tools.base import ToolContext
from .tools.registry import default_registry

console = Console()


def _load(args) -> tuple[Config, Scope]:
    cfg = Config.load(args.config)
    # Session overrides win over the config file (set by the web console).
    if getattr(args, "log_dir_override", None):
        cfg.log_dir = args.log_dir_override
    if getattr(args, "scope_file_override", None):
        cfg.scope_file = args.scope_file_override
    scope = Scope.load(cfg.scope_file)
    # Point the shared store and job manager at this engagement's log dir.
    store.configure(f"{cfg.log_dir}/results.json")
    jobs.configure(cfg.log_dir)
    from .tools import custom as _custom
    _custom.configure(cfg.log_dir)
    from .llm import calllog as _calllog
    _calllog.configure(f"{cfg.log_dir}/ai_calls.jsonl")
    return cfg, scope


def _reporter(kind: str, text: str) -> None:
    styles = {
        "step": "dim", "thought": "cyan", "action": "yellow",
        "observation": "green", "warn": "bold red", "final": "bold white",
        "output": "dim",
    }
    if kind == "output":
        # Indent the actual command output so it reads as a result block.
        for line in text.splitlines():
            console.print(f"    │ {line}", style="dim")
        return
    prefix = {
        "step": "", "thought": "[think] ", "action": "[run] ",
        "observation": "[result] ", "warn": "[warn] ", "final": "",
    }.get(kind, "")
    console.print(f"{prefix}{text}", style=styles.get(kind, ""))


def _confirm(name: str, args: dict) -> bool:
    console.print(f"[yellow]Active tool requested:[/] {name} {args}")
    try:
        ans = console.input(r"Run it? \[y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False  # no terminal to answer — skip rather than crash
    return ans in ("y", "yes")


def _ensure_in_scope(scope: Scope, target: str) -> bool:
    """Authorize a target, auto-adding it to the allow list if needed.

    Returns True if the target may be scanned. A target that is explicitly
    denied is never auto-added. This is what makes the menu/scan flows "just
    work" while still recording (in scope.yaml) exactly what was authorized.
    """
    if not target:
        console.print("[red]No target given.[/]")
        return False
    if scope.is_denied(target):
        console.print(f"[red]'{target}' is on the deny list — not scanning.[/]")
        return False
    if scope.is_allowed(target):
        return True
    scope.add_allow(target)
    console.print(f"[green][scope][/] added '{target}' to the allow list "
                  f"({scope._path}).")
    return True


def cmd_scope(args) -> int:
    cfg = Config.load(args.config)
    try:
        scope = Scope.load(cfg.scope_file)
    except ScopeError as e:
        console.print(f"[red]{e}[/]")
        return 1
    console.print(Panel(scope.summary(), title="Authorized scope"))
    console.print("Allow:", scope.allow)
    console.print("Deny: ", scope.deny)
    if args.target:
        try:
            scope.authorize(args.target)
            console.print(f"[green][+] {args.target} is IN scope.[/]")
        except ScopeError as e:
            console.print(f"[red][-] {e}[/]")
            return 2
    return 0


def cmd_tools(args) -> int:
    from rich.table import Table
    from .tools.catalog import CATEGORY_ORDER
    from .tools.command import GenericCommandTool
    cfg = Config.load(args.config)
    reg = default_registry(cfg.tools, include_unavailable=True)
    table = Table(title="Autopwn tool catalog (by category)")
    table.add_column("category", style="magenta"); table.add_column("tool", style="cyan")
    table.add_column("installed"); table.add_column("intrusive")
    table.add_column("description", max_width=50)
    installed = missing = 0
    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    tools = sorted(reg.all(),
                   key=lambda t: (order.get(getattr(t, "category", "misc"), 99),
                                  t.name))
    last_cat = None
    for t in tools:
        cat = getattr(t, "category", "misc")
        ok = (not isinstance(t, GenericCommandTool)) or t.available()
        installed += ok; missing += (not ok)
        table.add_row(cat if cat != last_cat else "", t.name,
                      "[green]yes[/]" if ok else "[red]no[/]",
                      "yes" if t.active else "no",
                      (t.description or "")[:50])
        last_cat = cat
    console.print(table)
    console.print(f"[green]{installed} installed[/] / [red]{missing} missing[/]. "
                  "Missing tools are hidden from the agent until installed.")
    return 0


def cmd_recon(args) -> int:
    cfg, scope = _load(args)
    if not _ensure_in_scope(scope, args.target):
        return 2
    registry = default_registry(cfg.tools)
    ctx = ToolContext(scope=scope, confirm_active_actions=False)

    tool_name = "nmap_scan"
    from .tools.runner import which
    if which(cfg.tools.nmap_path) is None:
        console.print("[yellow]nmap not found — using native TCP scanner.[/]")
        tool_name = "native_port_scan"

    tool = registry.get(tool_name)
    console.print(f"[cyan]Running {tool_name} against {args.target}...[/]")
    kwargs = {"target": args.target}
    if tool_name == "nmap_scan":
        kwargs["profile"] = args.profile
    result = tool.run(ctx, **kwargs)
    console.print(Panel(result.raw_output or result.summary,
                        title=result.summary,
                        border_style="green" if result.ok else "red"))
    return 0 if result.ok else 1


def _parse_sets(sets) -> dict:
    kwargs: dict = {}
    for pair in sets or []:
        if "=" not in pair:
            console.print(f"[red]Bad --set '{pair}', expected key=value.[/]")
            continue
        k, _, v = pair.partition("=")
        kwargs[k.strip()] = v
    return kwargs


def _run_tool_all(cfg, scope, tool, base_kwargs: dict) -> int:
    """Run *tool* against every host that exposes its applicable service."""
    from rich.table import Table
    from .applicability import targets_for_tool
    from .tools.command import host_from_url
    targets = targets_for_tool(tool.name)
    if not targets:
        console.print(f"[yellow]No applicable hosts for '{tool.name}' in stored "
                      "results. Run a 'sweep' first, or this tool isn't service-"
                      "mapped.[/]")
        return 1
    # Auto-authorize the discovered hosts we're about to target (skip denied).
    added = 0
    for t in targets:
        host = t["kwargs"].get("target") or host_from_url(t["kwargs"])
        if host and not scope.is_denied(host) and not scope.is_allowed(host):
            scope.add_allow(host); added += 1
    if added:
        console.print(f"[dim][scope] auto-added {added} target(s) to allow list.[/]")

    console.print(f"[cyan]{tool.name} → {len(targets)} applicable target(s):[/] "
                  + ", ".join(t["label"] for t in targets[:8])
                  + (" ..." if len(targets) > 8 else ""))
    ctx = ToolContext(scope=scope, confirm_active_actions=False)
    results = Table(title=f"{tool.name} — results")
    results.add_column("target"); results.add_column("ok"); results.add_column("summary")
    for t in targets:
        kw = {**base_kwargs, **t["kwargs"]}
        try:
            r = tool.run(ctx, **kw)
            results.add_row(t["label"], "[green]yes[/]" if r.ok else "[red]no[/]",
                            r.summary[:70])
        except ScopeError as e:
            results.add_row(t["label"], "[red]denied[/]", str(e)[:70])
        except Exception as e:  # keep going across hosts
            results.add_row(t["label"], "[red]err[/]", str(e)[:70])
    console.print(results)
    console.print("[dim]Tip: re-run a single target for full per-host output.[/]")
    return 0


def cmd_run(args) -> int:
    cfg, scope = _load(args)
    reg = default_registry(cfg.tools)
    tool = reg.get(args.tool)
    if tool is None:
        console.print(f"[red]Unknown or unavailable tool '{args.tool}'.[/] "
                      "Run 'tools' to list available tools.")
        return 1
    kwargs = _parse_sets(args.set)

    # Auto-fill known parameters (domain, base_dn, creds) from discovered facts,
    # without overriding anything the operator supplied explicitly.
    from .facts import autofill
    auto = autofill(set(tool.parameters.get("properties", {})))
    applied = []
    for k, v in auto.items():
        if k not in kwargs:
            kwargs[k] = v; applied.append(f"{k}={v}")
    if applied:
        console.print(f"[dim][auto-filled from discovery] {', '.join(applied)}[/]")

    # --all: fan the tool out over every applicable host from the matrix.
    if getattr(args, "all", False):
        return _run_tool_all(cfg, scope, tool, kwargs)

    ctx = ToolContext(scope=scope, confirm_active_actions=False)
    console.print(f"[cyan]Running {args.tool} {kwargs}...[/]")
    try:
        result = tool.run(ctx, **kwargs)
    except ScopeError as e:
        console.print(f"[red]{e}[/]"); return 2
    console.print(Panel(result.raw_output or result.summary, title=result.summary,
                        border_style="green" if result.ok else "red"))
    return 0 if result.ok else 1


def _render_matrix() -> None:
    from rich.table import Table
    rows = store.service_matrix()
    if not rows:
        console.print("[yellow]No results yet. Run a scan first "
                      "(sweep/recon/agent).[/]")
        return
    table = Table(title="Service → Hosts matrix")
    table.add_column("Service", style="cyan")
    table.add_column("Port(s)")
    table.add_column("#", justify="right")
    table.add_column("Hosts")
    for r in rows:
        ports = ",".join(str(p) for p in r["ports"])
        seen: list[str] = []
        for h in r["hosts"]:  # keep IP-sorted order, drop duplicates
            if h["host"] not in seen:
                seen.append(h["host"])
        table.add_row(r["service"], ports, str(r["count"]), ", ".join(seen))
    console.print(table)


def _render_hosts() -> None:
    from rich.table import Table
    summary = store.host_summary()
    if not summary:
        return
    table = Table(title="Hosts")
    table.add_column("Host", style="green"); table.add_column("Name")
    table.add_column("Open ports"); table.add_column("Services")
    for h in summary:
        table.add_row(h["host"], h["hostname"],
                      ", ".join(str(p) for p in h["open_ports"]),
                      ", ".join(h["services"]))
    console.print(table)


def cmd_sweep(args) -> int:
    """Scan a host/range with nmap greppable output and build the matrix."""
    cfg, scope = _load(args)
    from .tools.runner import which, run_command
    if which(cfg.tools.nmap_path) is None:
        console.print("[red]nmap is required for sweep.[/]")
        return 1
    if not _ensure_in_scope(scope, args.target):
        return 2
    from .tools.nmap_tool import _DEFAULT_PORTS
    ports = ["-p", args.ports or _DEFAULT_PORTS]
    excludes = scope.excludes_within(args.target)
    exclude_args = ["--exclude", ",".join(excludes)] if excludes else []
    if excludes:
        console.print(f"[dim]Excluding denied hosts: {', '.join(excludes)}[/]")
    argv = [cfg.tools.nmap_path, "-T4", "--open", "-sV", *ports, *exclude_args,
            "-oG", "-", args.target]
    console.print(f"[cyan]Sweeping {args.target}...[/] (this can take a while)")
    res = run_command(argv, timeout=3600)
    n = record_to_store(parse_grepable(res.stdout))
    from .facts import record_from_text
    record_from_text(res.stdout)
    console.print(f"[green]Recorded {n} host(s).[/]")
    if dom := store.get_fact("domain"):
        console.print(f"[cyan]Discovered domain:[/] {dom}")
    _render_hosts()
    _render_matrix()
    return 0


def cmd_services(args) -> int:
    _load(args)
    if args.clear:
        store.clear(); console.print("[yellow]Results cleared.[/]"); return 0
    if args.hosts:
        _render_hosts()
    _render_matrix()
    return 0


def _variable_flag_map() -> dict[str, list[str]]:
    """For each canonical variable, which tools use it and via which flag."""
    from .tools.catalog import CATALOG
    out: dict[str, list[str]] = {}
    for spec in CATALOG:
        used: dict[str, str] = {}
        for var, flag in (spec.flags or {}).items():
            used[var] = flag or "(bool)"
        for var in (spec.positional or []):
            used.setdefault(var, "(positional)")
        for var in spec.parameters.get("properties", {}):
            used.setdefault(var, "(arg)")
        for var, how in used.items():
            out.setdefault(var, []).append(f"{spec.name}:{how}")
    return out


def cmd_vars(args) -> int:
    from rich.table import Table
    from .facts import CANONICAL, base_dn_from_domain
    _load(args)  # configures the store
    for pair in getattr(args, "set", None) or []:
        k, _, v = pair.partition("=")
        store.set_fact(k.strip(), v.strip())
        console.print(f"[green]set[/] {k.strip()} = {v.strip()}")
    if getattr(args, "clear", None):
        store.clear_facts(); console.print("[yellow]variables cleared.[/]")

    f = store.facts()
    fmap = _variable_flag_map()
    table = Table(title="Autopwn variables")
    table.add_column("variable", style="cyan"); table.add_column("value")
    table.add_column("used by (tool:flag)", max_width=54)
    for name, desc in CANONICAL.items():
        val = f.get(name, "")
        if not val and name == "base_dn" and f.get("domain"):
            val = base_dn_from_domain(f["domain"]) + " (derived)"
        users = ", ".join(fmap.get(name, [])[:5])
        table.add_row(name, f"[green]{val}[/]" if val else "[dim]—[/]", users)
    console.print(table)
    # Any harvested variables outside the canonical set.
    extra = {k: v for k, v in f.items() if k not in CANONICAL}
    if extra:
        console.print("[dim]other stored: " +
                      ", ".join(f"{k}={v}" for k, v in extra.items()) + "[/]")
    return 0


def _render_jobs(js: list) -> None:
    """Print the jobs as a numbered table."""
    from rich.table import Table
    table = Table(title="Background jobs")
    table.add_column("#", justify="right")
    for c in ("id", "label", "pid", "status"):
        table.add_column(c)
    for i, j in enumerate(js, 1):
        status = j.get("status", "?")
        color = {"running": "green", "finished": "dim",
                 "stopped": "red"}.get(status, "")
        table.add_row(str(i), j["id"], j.get("label", ""), str(j.get("pid", "")),
                      f"[{color}]{status}[/]" if color else status)
    console.print(table)


def cmd_jobs(args) -> int:
    cfg, _ = _load(args)
    js = jobs.list_jobs(cfg.log_dir)
    if not js:
        console.print("[yellow]No jobs.[/]"); return 0
    _render_jobs(js)
    console.print("[dim]In the menu, pick a job by its number. From the CLI: "
                  "autopwn watch <id> / autopwn stop <id>.[/]")
    return 0


def cmd_watch(args) -> int:
    cfg, _ = _load(args)
    lp = jobs.log_path(args.job_id)
    if not lp.exists():
        console.print(f"[red]No log for job '{args.job_id}'. See 'autopwn jobs'.[/]")
        return 1
    console.print(f"[cyan]Following job {args.job_id} — Ctrl-C to stop watching "
                  "(the job keeps running).[/]\n")
    try:
        with open(lp, "r", encoding="utf-8", errors="replace") as f:
            while True:
                line = f.readline()
                if line:
                    console.out(line.rstrip("\n"))
                    continue
                if not jobs.is_running(args.job_id, cfg.log_dir):
                    # drain any final bytes then exit
                    rest = f.read()
                    if rest:
                        console.out(rest)
                    console.print(f"\n[bold green]══ job {args.job_id} finished ══[/]")
                    return 0
                time.sleep(0.4)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching (job still running).[/]")
        return 0


def cmd_stop(args) -> int:
    cfg, _ = _load(args)
    ok = jobs.stop(args.job_id, cfg.log_dir)
    console.print(f"[{'green' if ok else 'red'}]"
                  f"{'Stopped' if ok else 'Could not stop (not running?)'} "
                  f"{args.job_id}.[/]")
    return 0 if ok else 1


# Grouped for display. Keys stay stable (muscle memory + dispatch unchanged);
# the grouping is purely presentational. Each group: (title, icon, [(key, label)]).
_MENU_GROUPS = [
    ("Manual", "🛠", [
        ("1", "Scan (sweep host/range) → service matrix"),
        ("2", "Results (service matrix / hosts / clear)"),
        ("3", "Run a single tool"),
        ("4", "List tools (by category)"),
    ]),
    ("AI-Assisted", "🤖", [
        ("5", "AI agent (autopilot / custom objective)"),
        ("6", "Jobs (list / watch / stop)"),
    ]),
    ("Configuration", "⚙", [
        ("7", "Scope (view / add / remove allow & deny)"),
        ("8", "Variables (discovered domain / creds / …)"),
    ]),
    ("Maintenance", "🧹", [
        ("9", "Clear ALL (results, variables, saved reports & finished jobs)"),
        ("q", "Quit"),
    ]),
]


def _clear_all(ns) -> None:
    """Full fresh slate: wipe the results store (hosts/ports/services) and all
    discovered variables, and delete session transcripts/reports and finished
    job files from the logs folder. Any *running* job is left untouched."""
    from . import store, jobs as _jobs
    from pathlib import Path as _Path
    cfg = Config.load(getattr(ns(), "config", "config.yaml"))
    log_dir = _Path(cfg.log_dir)

    sessions = list(log_dir.glob("session-*"))
    running = {j["id"] for j in _jobs.list_jobs(log_dir) if j.get("status") == "running"}
    jobs_dir = log_dir / "jobs"
    job_files = [f for f in jobs_dir.glob("*")
                 if f.is_file() and not any(rid in f.name for rid in running)]

    console.print(f"[yellow]This will clear all hosts/variables and delete "
                  f"{len(sessions)} session/report file(s) and {len(job_files)} "
                  f"job file(s).[/]")
    if running:
        console.print(f"[dim]({len(running)} running job(s) will be kept.)[/]")
    if not _yn("Proceed with full reset?"):
        console.print("[dim]cancelled.[/]"); _pause(); return

    store.clear()
    store.clear_facts()
    removed = 0
    for f in sessions + job_files:
        try:
            f.unlink(); removed += 1
        except OSError:
            pass
    console.print(f"[yellow]Fresh slate:[/] results and variables reset; "
                  f"{removed} file(s) deleted from {log_dir}.")
    if running:
        console.print(f"[dim]{len(running)} running job(s) left intact.[/]")
    _pause()


def _vars_menu(ns, cfg_path) -> None:
    while True:
        c = _submenu("Variables", [
            ("1", "View variables + which tools use them"),
            ("2", "Set a variable manually"),
            ("3", "Clear all variables"),
            ("b", "Back")])
        if c == "1":
            cmd_vars(ns(set=None, clear=False)); _pause()
        elif c == "2":
            name = _ask("variable name (e.g. username): ")
            val = _ask("value: ")
            if name and val:
                cmd_vars(ns(set=[f"{name}={val}"], clear=False)); _pause()
        elif c == "3":
            if _yn("Clear all variables?"):
                cmd_vars(ns(set=None, clear=True)); _pause()
        elif c == "b":
            return


def _ask(prompt: str) -> str:
    return console.input(prompt).strip()


def _yn(question: str, default: bool = False) -> bool:
    """Yes/no prompt with a consistent, always-visible hint.

    The brackets are escaped so Rich renders them literally (it would otherwise
    treat "[y/N]" as markup and drop it). Pressing Enter accepts the default.
    """
    hint = r"\[Y/n]" if default else r"\[y/N]"
    ans = _ask(f"{question} {hint} ").lower()
    if not ans:
        return default
    return ans in ("y", "yes")


def _pause() -> None:
    """Let the user read output before the screen is cleared for the menu."""
    _ask("\n[dim]press Enter to continue…[/]")


def _submenu(title: str, items: list[tuple[str, str]], render=None) -> str:
    """Clear the screen, optionally render context, show the submenu, return key."""
    console.clear()  # keep the submenu anchored at the top
    if render:
        render()
    console.print(f"[bold]{title}[/]")
    for key, label in items:
        console.print(f"  [bold cyan]{key}[/]  {label}")
    return _ask("\n[bold]› [/]").lower()


def _scan_menu(ns, cfg_path) -> None:
    while True:
        c = _submenu("Scan", [
            ("1", "Sweep a host/range/CIDR (auto-adds to scope)"),
            ("2", "Show current service matrix"),
            ("b", "Back")])
        if c == "1":
            target = _ask("target host/range/CIDR: ")
            ports = _ask("ports (blank = top 1000): ")
            cmd_sweep(ns(target=target, ports=ports or None)); _pause()
        elif c == "2":
            cmd_services(ns(hosts=False, clear=False)); _pause()
        elif c == "b":
            return


def _show_host_detail(host: str) -> None:
    from rich.table import Table
    entry = store.all_hosts().get(host, {})
    ports = sorted(entry.get("ports", {}).values(), key=lambda p: p["port"])
    t = Table(title=f"{host}  {entry.get('hostname', '') or ''}")
    t.add_column("Port", justify="right"); t.add_column("Proto")
    t.add_column("State"); t.add_column("Service", style="cyan")
    t.add_column("Version / banner", style="dim", max_width=48)
    for p in ports:
        t.add_row(str(p["port"]), p.get("proto", ""), p.get("state", ""),
                  p.get("service") or "", p.get("version") or "")
    console.print(t)


def _hosts_menu(ns, cfg_path) -> None:
    from rich.table import Table
    cfg = Config.load(cfg_path)
    store.configure(f"{cfg.log_dir}/results.json")
    while True:
        summary = store.host_summary()
        console.clear()
        if not summary:
            console.print("[yellow]No hosts discovered yet. Run a sweep first.[/]")
            _pause(); return
        table = Table(title="Discovered hosts — pick a number for detail")
        table.add_column("#", justify="right"); table.add_column("Host", style="green")
        table.add_column("Name"); table.add_column("# open", justify="right")
        table.add_column("Services")
        for i, h in enumerate(summary, 1):
            table.add_row(str(i), h["host"], h["hostname"],
                          str(len(h["open_ports"])),
                          ", ".join(h["services"][:6])
                          + (" …" if len(h["services"]) > 6 else ""))
        console.print(table)
        sel = _ask("\nhost number (b = back): ").lower()
        if sel in ("b", ""):
            return
        if not sel.isdigit() or not (1 <= int(sel) <= len(summary)):
            continue
        console.clear()
        _show_host_detail(summary[int(sel) - 1]["host"])
        _pause()


def _results_menu(ns, cfg_path) -> None:
    while True:
        c = _submenu("Results", [
            ("1", "Service → hosts matrix"),
            ("2", "Hosts — pick one for its port/service detail"),
            ("3", "Export report of the last AI job (HTML/DOCX/MD)"),
            ("4", "Clear stored results"),
            ("b", "Back")])
        if c == "1":
            cmd_services(ns(hosts=False, clear=False)); _pause()
        elif c == "2":
            _hosts_menu(ns, cfg_path)
        elif c == "3":
            fmt = _ask("formats [html,docx,md]: ") or "html,docx,md"
            cmd_report(ns(transcript=None, format=fmt)); _pause()
        elif c == "4":
            if _yn("Really clear all results?"):
                cmd_services(ns(hosts=False, clear=True)); _pause()
        elif c == "b":
            return


def _agent_menu(ns, cfg_path) -> None:
    c = _submenu("AI agent", [
        ("1", "Autopilot against a target (background)"),
        ("2", "Custom objective (background)"),
        ("b", "Back")])
    if c == "b":
        return
    target = objective = None
    if c == "1":
        console.print(
            "\n[bold]Enter a target.[/] Accepted forms:\n"
            "  • single IP        e.g. [cyan]10.0.0.10[/]\n"
            "  • hostname         e.g. [cyan]dc01.corp.local[/]\n"
            "  • CIDR range       e.g. [cyan]10.0.0.0/24[/] (assesses each live host)\n"
            "[dim]If it isn't in scope yet, it is added to the allow list "
            "automatically.[/]")
        target = _ask("target: ")
        if not target:
            return
    elif c == "2":
        console.print("\n[dim]Optional target, then describe the goal in plain "
                      "English,\ne.g. 'enumerate SMB shares and find AS-REP "
                      "roastable users'.[/]")
        target = _ask("target (optional): ") or None
        objective = _ask("objective: ")
        if not objective:
            return
    else:
        return

    # Engagement details — printed in the panel and the exported report.
    cfg = Config.load(cfg_path)
    try:
        default_eng = Scope.load(cfg.scope_file).engagement
    except Exception:
        default_eng = "Security assessment"
    # Assumed-breach / authenticated engagement: optional starting credentials.
    console.print("\n[bold]Starting credentials[/] "
                  "[dim](assumed-breach; press Enter to skip for unauthenticated)[/]")
    username = _ask("username (optional): ") or None
    password = _ask("password (optional): ") or None if username else None
    nt_hash = (_ask("NTLM hash (optional, for pass-the-hash): ") or None) if username and not password else None
    ad_domain = _ask("domain (optional, e.g. corp.local): ") or None if username else None

    console.print("\n[bold]Engagement details[/] "
                  "[dim](press Enter to skip / accept default)[/]")
    engagement = _ask(f"engagement name [{default_eng}]: ") or default_eng
    client = _ask("client / organization: ")
    assessor = _ask("assessor (your name): ")
    authorized_by = _ask("authorized by: ")

    rc = cmd_agent(ns(target=target, objective=objective, background=True,
                      engagement=engagement, client=client, assessor=assessor,
                      authorized_by=authorized_by, report_format="html,docx,md",
                      username=username, password=password, domain=ad_domain,
                      nt_hash=nt_hash))
    if rc == 0 and _yn("Watch it now?", default=True):
        js = jobs.list_jobs(cfg.log_dir)
        if js:
            cmd_watch(ns(job_id=js[0]["id"]))
    _pause()


def _jobs_menu(ns, cfg_path) -> None:
    cfg = Config.load(cfg_path)
    while True:
        js = jobs.list_jobs(cfg.log_dir)

        def render():
            if js:
                _render_jobs(js)
            else:
                console.print("[yellow]No background jobs yet.[/]")

        c = _submenu("Jobs", [
            ("w", "Watch a job (by number)"), ("s", "Stop a job (by number)"),
            ("r", "Refresh"), ("b", "Back")], render=render)
        if c in ("w", "s"):
            if not js:
                continue
            sel = _ask("job number: ")
            if not sel.isdigit() or not (1 <= int(sel) <= len(js)):
                continue
            jid = js[int(sel) - 1]["id"]
            (cmd_watch if c == "w" else cmd_stop)(ns(job_id=jid)); _pause()
        elif c == "b":
            return


def _prompt_required(tool, include_primary: bool) -> list[str] | None:
    """Prompt only for the tool's required fields (creds, base_dn, wordlists…).

    Fields we can auto-fill from discovered facts (domain, base_dn, creds) are
    filled silently and shown, not asked. Skips target/url unless
    include_primary. Returns the key=value list, or None if a mandatory target
    was left blank.
    """
    from .facts import autofill
    props = tool.parameters.get("properties", {})
    required = list(tool.parameters.get("required", []))
    auto = autofill(set(required))
    sets: list[str] = []
    for name in required:
        if name in ("target", "url") and not include_primary:
            continue
        if name in auto:  # known from discovery — don't ask
            console.print(f"  [green]{name}[/] = {auto[name]} [dim](auto from discovery)[/]")
            sets.append(f"{name}={auto[name]}")
            continue
        desc = props.get(name, {}).get("description", "")
        val = _ask(f"  {name}" + (f" [dim]({desc})[/]" if desc else "") + ": ")
        if not val and name in ("target", "url"):
            return None  # can't run without a target
        if val:
            sets.append(f"{name}={val}")
    return sets


def _run_menu(ns, cfg_path) -> None:
    from rich.table import Table
    from .applicability import applicable_count
    from .tools.catalog import CATEGORY_ORDER
    from .tools.command import GenericCommandTool
    cfg = Config.load(cfg_path)
    reg = default_registry(cfg.tools)
    # Only installed tools, grouped by category, then by applicable-host count.
    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    tools = [t for t in reg.all()
             if not isinstance(t, GenericCommandTool) or t.available()]
    tools.sort(key=lambda t: (order.get(getattr(t, "category", "misc"), 99),
                              -applicable_count(t.name), t.name))

    console.clear()
    table = Table(title="Run a tool — pick a number")
    table.add_column("category", style="magenta")
    table.add_column("#", justify="right"); table.add_column("tool", style="cyan")
    table.add_column("applies to"); table.add_column("intrusive")
    last_cat = None
    for i, t in enumerate(tools, 1):
        cat = getattr(t, "category", "misc")
        n = applicable_count(t.name)
        table.add_row(cat if cat != last_cat else "", str(i), t.name,
                      f"[green]{n} host(s)[/]" if n else "[dim]—[/]",
                      "yes" if t.active else "no")
        last_cat = cat
    console.print(table)

    sel = _ask("\ntool number (blank to cancel): ")
    if not sel.isdigit() or not (1 <= int(sel) <= len(tools)):
        if sel:
            console.print("[yellow]Invalid number.[/]"); _pause()
        return
    tool = tools[int(sel) - 1]

    console.print(f"\n[bold]Run {tool.name}[/]")
    console.print("  [bold cyan]1[/]  Against ALL applicable hosts (from matrix)")
    console.print("  [bold cyan]2[/]  Against a single target/url")
    console.print("  [bold cyan]b[/]  Back")
    mode = _ask("\n[bold]› [/]").lower()
    if mode not in ("1", "2"):
        return

    # Ask only for the fields this tool actually needs.
    needs = [p for p in tool.parameters.get("required", [])
             if p not in ("target", "url")]
    if needs or mode == "2":
        console.print("[dim]This tool needs the following:[/]")
    sets = _prompt_required(tool, include_primary=(mode == "2"))
    if sets is None:
        console.print("[yellow]Cancelled (no target given).[/]"); _pause(); return

    cmd_run(ns(tool=tool.name, set=sets, all=(mode == "1"))); _pause()


def _scope_menu(ns, cfg_path) -> None:
    from rich.table import Table
    cfg = Config.load(cfg_path)

    def _render_scope(scope):
        table = Table(title=f"Scope — {scope.engagement or 'unnamed'}")
        table.add_column("#", justify="right"); table.add_column("allow", style="green")
        table.add_column("#", justify="right"); table.add_column("deny", style="red")
        for i in range(max(len(scope.allow), len(scope.deny))):
            a = scope.allow[i] if i < len(scope.allow) else ""
            d = scope.deny[i] if i < len(scope.deny) else ""
            table.add_row(str(i + 1) if a else "", a,
                          str(i + 1) if d else "", d)
        console.print(table)

    while True:
        scope = Scope.load(cfg.scope_file)
        c = _submenu("Scope actions", [
            ("a", "Add to allow"), ("d", "Add to deny"),
            ("r", "Remove from allow"), ("x", "Remove from deny"),
            ("c", "Check a target"), ("b", "Back")],
            render=lambda: _render_scope(scope))
        if c == "a":
            e = _ask("allow entry (IP/CIDR/host): ")
            console.print("[green]added[/]" if scope.add_allow(e) else "[yellow]already present / empty[/]"); _pause()
        elif c == "d":
            e = _ask("deny entry (IP/CIDR/host): ")
            console.print("[green]added[/]" if scope.add_deny(e) else "[yellow]already present / empty[/]"); _pause()
        elif c == "r":
            e = _ask("allow entry to remove (exact text): ")
            console.print("[green]removed[/]" if scope.remove_allow(e) else "[yellow]not found[/]"); _pause()
        elif c == "x":
            e = _ask("deny entry to remove (exact text): ")
            console.print("[green]removed[/]" if scope.remove_deny(e) else "[yellow]not found[/]"); _pause()
        elif c == "c":
            t = _ask("target to check: ")
            if t:
                console.print("[green]IN scope[/]" if scope.is_allowed(t)
                              else "[red]NOT in scope[/]")
            _pause()
        elif c == "b":
            return


def cmd_menu(args) -> int:
    from rich.panel import Panel
    cfg_path = getattr(args, "config", "config.yaml")
    ns = lambda **kw: SimpleNamespace(config=cfg_path, **kw)
    dispatch = {
        "1": lambda: _scan_menu(ns, cfg_path),
        "2": lambda: _results_menu(ns, cfg_path),
        "3": lambda: _run_menu(ns, cfg_path),
        "4": lambda: (cmd_tools(ns()), _pause()),  # direct action → self-pause
        "5": lambda: _agent_menu(ns, cfg_path),
        "6": lambda: _jobs_menu(ns, cfg_path),
        "7": lambda: _scope_menu(ns, cfg_path),
        "8": lambda: _vars_menu(ns, cfg_path),
        "9": lambda: _clear_all(ns),
    }
    # Distinct accent per category so the two workflows read at a glance.
    group_style = {"Manual": "bright_green", "AI-Assisted": "bright_magenta",
                   "Configuration": "bright_blue", "Maintenance": "yellow"}
    while True:
        console.clear()  # keep the menu anchored at the top of the terminal
        console.print(Panel(
            "[bold bright_cyan]Autopwn[/]  [dim]— AI-orchestrated authorized "
            "security testing[/]\n"
            "[dim]Ali Alaqoul · alialaqoul@gmail.com · "
            "linkedin.com/in/alialaqoul[/]",
            border_style="bright_cyan", padding=(0, 1)))
        for title, icon, items in _MENU_GROUPS:
            accent = group_style.get(title, "cyan")
            console.print(f"\n [bold {accent}]{icon}  {title.upper()}[/]")
            for key, label in items:
                main, _, hint = label.partition(" (")
                hint = f" [dim]({hint}[/]" if hint else ""
                console.print(f"    [bold {accent}]{key}[/]  {main}{hint}")
        choice = _ask("\n [bold]select ›[/] ").lower()
        if choice == "q":
            console.clear()
            return 0
        handler = dispatch.get(choice)
        if not handler:
            continue
        try:
            handler()  # each handler manages its own clear + read-pause
        except ScopeError as e:
            console.print(f"[red]{e}[/]"); _pause()
        except KeyboardInterrupt:
            console.print("\n[dim](back to main menu)[/]")


def _seed_creds(args) -> None:
    """Seed starting credentials into the results store for an authenticated /
    assumed-breach engagement, so every credentialed tool and the agent use them
    from the first step (they flow via the normal fact autofill)."""
    from . import store
    seeded = []
    for attr, key in (("username", "username"), ("password", "password"),
                      ("domain", "domain"), ("nt_hash", "hash")):
        val = getattr(args, attr, None)
        if val:
            store.set_fact(key, val); seeded.append(key)
    if seeded:
        console.print("[green]Authenticated engagement:[/] seeded "
                      + ", ".join(seeded) + " — credentialed tools enabled.")


def cmd_autorun(args) -> int:
    """Deterministic 'Playbook Autopilot' — no AI. Recon a target/range, then run
    every playbook whose match conditions fire, and report."""
    import json as _json
    from . import playbooks as pb_mod, report, store as _store
    from .facts import autofill
    cfg, scope = _load(args)
    _seed_creds(args)
    # Accept single IP, comma/space-separated IPs, ranges (a-b) and CIDR.
    targets = [t.strip() for t in args.target.replace(",", " ").split() if t.strip()]
    if not targets:
        console.print("[red]No target given.[/]")
        return 2
    for t in targets:
        if not _ensure_in_scope(scope, t):
            return 2

    registry = default_registry(cfg.tools)
    ctx = ToolContext(scope=scope, confirm_active_actions=False)
    transcript: list = []
    ts = time.strftime("%Y%m%d-%H%M%S")
    tpath = Path(cfg.log_dir) / f"session-{ts}.json"
    tpath.parent.mkdir(parents=True, exist_ok=True)

    def _save():
        tpath.write_text(_json.dumps(transcript, indent=2), encoding="utf-8")

    def _run(tool_name, **kw):
        tool = registry.get(tool_name)
        if tool is None:
            return None
        try:
            r = tool.run(ctx, **kw)
        except Exception as e:
            console.print(f"[red]{tool_name} error: {e}[/]")
            return None
        transcript.append({"kind": "tool_result", "name": tool_name,
                           "command": (r.data or {}).get("command", tool_name),
                           "ok": r.ok, "output": r.raw_output or r.summary})
        _save()   # persist incrementally so the Findings view reflects progress
        return r

    from .report import Engagement
    meta = Engagement(
        engagement=getattr(args, "engagement", None) or scope.engagement or "Security assessment",
        client=getattr(args, "client", None) or "", assessor=getattr(args, "assessor", None) or "",
        authorized_by=getattr(args, "authorized_by", None) or scope.authorized_by or "",
        target=args.target, objective=f"Deterministic playbook assessment of {args.target}")
    console.print(Panel(f"[bold]Playbook Autopilot (no AI)[/]\n{args.target}",
                        title="Autopwn", border_style="cyan"))

    # 1) Recon: discover hosts/ports/services (each target: IP / range / CIDR).
    from .tools.runner import which
    scan = "nmap_scan" if which(cfg.tools.nmap_path) else "native_port_scan"
    for t in targets:
        console.print(f"[cyan]═ Recon ═[/] {scan} {t}")
        _run(scan, target=t)

    # 2) Enrich per host so finding conditions (SMB signing/null-auth) + web
    #    header findings have their evidence.
    for host, entry in list(_store.all_hosts().items()):
        ports = {p["port"] for p in entry.get("ports", {}).values()
                 if p.get("state") == "open"}
        if 445 in ports:
            _run("netexec_smb", target=host)
        if {80, 8080, 8000} & ports:
            _run("http_probe", url=f"http://{host}")

    # 3) Run every playbook whose match fires — either a built-in tool SEQUENCE
    #    (the AD kill chain and friends) or a single macro tool.
    from .sequence import run_sequence

    def _record_seq(name, r):
        transcript.append({"kind": "tool_result", "name": name,
                           "command": (getattr(r, "data", None) or {}).get("command", name),
                           "ok": getattr(r, "ok", False),
                           "output": getattr(r, "raw_output", "") or getattr(r, "summary", "")})
        _save()

    hosts = _store.all_hosts()
    ran = 0
    for pb in pb_mod.load(cfg.log_dir):
        run = pb.get("run") or {}
        sequence = run.get("sequence") or []
        tool_name = (run.get("tool") or "").strip()
        matched = pb_mod.matching_hosts(pb, hosts)
        for host in matched:
            if sequence:
                console.print(f"[cyan]▶ {pb.get('id')} (built-in sequence)[/] on {host}")
                run_sequence(pb, host, ctx, registry,
                             lambda k, m: console.print(f"[dim]{m}[/]"),
                             cfg.log_dir, record=_record_seq)
                ran += 1
                continue
            tool = registry.get(tool_name) if tool_name else None
            if tool is None:
                continue
            console.print(f"[cyan]▶ {pb.get('id')} → {tool_name}[/] on {host}")
            kw = autofill(set(tool.parameters.get("properties", {})))
            kw["target"] = host
            r = _run(tool_name, **kw)
            ran += 1
            if r:
                console.print(f"    [dim]{r.summary}[/]")

    # 4) Report (the transcript was saved incrementally during the run).
    _save()
    final = f"Deterministic assessment ran {ran} playbook action(s) across {args.target}."
    model = report.build_model(meta, transcript, _store.all_hosts(),
                               _store.facts(), final, log_dir=cfg.log_dir)
    formats = [f.strip() for f in (getattr(args, "report_format", None) or "html,docx,md").split(",")]
    written = report.export(model, tpath.with_suffix(""), formats)
    creds = model.get("credentials", [])
    console.print(f"[green]Findings:[/] {len(model['findings'])} | "
                  f"[green]Credentials:[/] {len(creds)} | "
                  f"[green]Users:[/] {len(model.get('users', []))}")
    if written:
        console.print("[green]Report:[/] " + ", ".join(str(w) for w in written))
    console.print("[bold green]══ playbook autopilot complete ══[/]")
    return 0


def cmd_playbook(args) -> int:
    """Run one playbook's built-in tool sequence against a target, streaming
    each step and saving a transcript so the Findings view picks up the results."""
    import json as _json
    from . import playbooks as pb_mod, report, store as _store
    from .sequence import run_sequence
    cfg, scope = _load(args)
    _seed_creds(args)
    kwargs = _parse_sets(args.set)
    target = (args.target or kwargs.get("target") or "").strip()
    if not target:
        console.print("[red]A target is required (--target or --set target=…).[/]")
        return 2
    if not _ensure_in_scope(scope, target):
        return 2

    book = next((p for p in pb_mod.load(cfg.log_dir) if p.get("id") == args.id), None)
    if not book:
        console.print(f"[red]No playbook with id '{args.id}'.[/]")
        return 1
    seq = ((book.get("run") or {}).get("sequence")) or []
    if not seq:
        console.print(f"[red]Playbook '{args.id}' has no built-in sequence.[/]")
        return 1

    # Seed any operator-supplied variables (domain, creds) before the run.
    for k, v in kwargs.items():
        if k != "target" and v:
            _store.set_fact(k, v)

    registry = default_registry(cfg.tools)
    ctx = ToolContext(scope=scope, confirm_active_actions=False)
    transcript: list = []
    ts = time.strftime("%Y%m%d-%H%M%S")
    tpath = Path(cfg.log_dir) / f"session-{ts}.json"
    tpath.parent.mkdir(parents=True, exist_ok=True)

    def _record(tool_name, r):
        transcript.append({"kind": "tool_result", "name": tool_name,
                           "command": (getattr(r, "data", None) or {}).get("command", tool_name),
                           "ok": getattr(r, "ok", False),
                           "output": getattr(r, "raw_output", "") or getattr(r, "summary", "")})
        tpath.write_text(_json.dumps(transcript, indent=2), encoding="utf-8")

    # Stream each step to stdout (the job log the console watches live).
    def _report(kind, msg):
        try:
            console.print(msg if kind in ("head", "done") else f"[dim]{msg}[/]")
        except Exception:
            print(msg, flush=True)

    console.print(Panel(f"[bold]Built-in sequence[/] — {book.get('name')}\n{target}",
                        title="Autopwn", border_style="cyan"))
    summary = run_sequence(book, target, ctx, registry, _report, cfg.log_dir, record=_record)

    # A consolidated credential/users entry (authoritative "Credential: u:p @ dom"
    # + "Users (N): …" lines) so extract_results labels creds with the real domain.
    f = _store.facts()
    lines = [f"Playbook {args.id} against {target}"]
    users = []
    ulist = f.get("userlist")
    if ulist and Path(ulist).exists():
        users = [u.strip() for u in Path(ulist).read_text(encoding="utf-8",
                 errors="ignore").splitlines() if u.strip()]
    if users:
        lines.append(f"Users ({len(users)}): " + ", ".join(users))
    if f.get("username") and f.get("password"):
        lines.append(f"Credential: {f['username']}:{f['password']} "
                     f"@ {f.get('domain') or 'unknown'}")
    transcript.append({"kind": "tool_result", "name": f"playbook:{args.id}",
                       "command": f"playbook {args.id} {target}", "ok": True,
                       "output": "\n".join(lines)})
    tpath.write_text(_json.dumps(transcript, indent=2), encoding="utf-8")

    # Export a report alongside the transcript, like autorun does.
    from .report import Engagement
    meta = Engagement(engagement=scope.engagement or "Security assessment",
                      client="", assessor="", authorized_by=scope.authorized_by or "",
                      target=target, objective=f"Built-in playbook '{args.id}' vs {target}")
    model = report.build_model(meta, transcript, _store.all_hosts(), _store.facts(),
                               f"Built-in sequence '{args.id}' complete.", log_dir=cfg.log_dir)
    report.export(model, tpath.with_suffix(""), ["html", "md"])
    console.print(f"[green]Done.[/] {summary.get('ran', 0)} step(s) | "
                  f"credentials: {len(model.get('credentials', []))} | "
                  f"users: {len(model.get('users', []))}")
    return 0


def cmd_agent(args) -> int:
    cfg, scope = _load(args)
    if not cfg.ai_enabled:
        console.print("[yellow]AI is disabled (ai_enabled: false). Enable it in "
                      "config.yaml or the web Settings, or run a playbook/tool.[/]")
        return 1
    _seed_creds(args)

    # Autopilot: with only --target and no --objective, generate a full
    # adaptive-assessment objective that fingerprints first, then branches.
    objective = args.objective
    if not objective:
        if not args.target:
            console.print("[red]Provide --objective, or --target for "
                          "autopilot (e.g. agent --target 10.0.0.10).[/]")
            return 1
        objective = autopilot_objective(args.target)
        console.print("[cyan]Autopilot:[/] no objective given — running a full "
                      f"adaptive assessment of {args.target}.")

    # Ensure the target is authorized (auto-add) before spinning up the model.
    if args.target:
        if not _ensure_in_scope(scope, args.target):
            return 2

    # Engagement metadata (for the panel + exported report). Fall back to scope.
    from .report import Engagement
    meta = Engagement(
        engagement=getattr(args, "engagement", None) or scope.engagement or "Security assessment",
        client=getattr(args, "client", None) or "",
        assessor=getattr(args, "assessor", None) or "",
        authorized_by=getattr(args, "authorized_by", None) or scope.authorized_by or "",
        target=args.target or "", objective=objective)

    # Background: relaunch this same run detached so the terminal stays free.
    if getattr(args, "background", False):
        relaunch = ["agent"]
        if args.target:
            relaunch += ["--target", args.target]
        if args.objective:
            relaunch += ["--objective", args.objective]
        # Carry starting credentials so a detached authenticated / assumed-breach
        # run seeds them from step one (otherwise the background job loses them).
        for flag, val in (("--username", getattr(args, "username", None)),
                          ("--password", getattr(args, "password", None)),
                          ("--domain", getattr(args, "domain", None)),
                          ("--hash", getattr(args, "nt_hash", None))):
            if val:
                relaunch += [flag, val]
        for flag, val in (("--engagement", meta.engagement), ("--client", meta.client),
                          ("--assessor", meta.assessor),
                          ("--authorized-by", meta.authorized_by)):
            if val:
                relaunch += [flag, val]
        job_id = jobs.start(relaunch, label=f"agent {args.target or 'custom'}",
                            log_dir=cfg.log_dir)
        console.print(f"[green]Started background agent job {job_id}.[/]\n"
                      f"  Watch it:  [bold]autopwn watch {job_id}[/]\n"
                      f"  List jobs: [bold]autopwn jobs[/]\n"
                      "Meanwhile you can run other autopwn commands normally.")
        return 0

    try:
        provider = build_provider(cfg.llm)
    except Exception as e:
        console.print(f"[red]LLM setup failed: {e}[/]")
        return 1
    registry = default_registry(cfg.tools)
    agent = Agent(cfg, provider, registry, scope, reporter=_reporter)
    # Only prompt for intrusive tools when attached to a real terminal. A
    # detached/background run has no stdin, so prompting would crash on EOF —
    # there the operator already authorized the target by launching it.
    if cfg.agent.confirm_active_actions and sys.stdin.isatty():
        agent.confirm_hook = _confirm

    meta_line = " | ".join(f"{k}: {v}" for k, v in meta.rows() if v and k not in
                           ("Objective", "Target"))
    console.print(Panel(f"[bold]{objective}[/]\n\n{meta_line}",
                        title="Autopwn agent", border_style="cyan"))
    try:
        final = agent.run(objective, seed_target=args.target)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        final = "(interrupted)"
    path = agent.save_transcript(cfg.log_dir)
    console.print(Panel(final, title="Result", border_style="white"))
    console.print(f"[dim]Transcript: {path}[/]")

    # Auto-export the report alongside the transcript.
    from . import report, store as _store
    _store.configure(f"{cfg.log_dir}/results.json")
    model = report.build_model(meta, agent.transcript, _store.all_hosts(),
                               _store.facts(), final, log_dir=cfg.log_dir)
    formats = [f.strip() for f in (args.report_format or "html,docx,md").split(",")]
    written = report.export(model, path.with_suffix(""), formats)
    if written:
        console.print("[green]Report:[/] " + ", ".join(str(w) for w in written))
    console.print("[bold green]══ agent run complete ══[/]")
    return 0


def cmd_report(args) -> int:
    import json as _json
    from . import report, store as _store
    cfg = Config.load(args.config)
    _store.configure(f"{cfg.log_dir}/results.json")
    # Pick the transcript (given or latest session-*.json).
    if args.transcript:
        tpath = Path(args.transcript)
    else:
        sessions = sorted(Path(cfg.log_dir).glob("session-*.json"))
        if not sessions:
            console.print("[red]No session transcript found. Run an agent first.[/]")
            return 1
        tpath = sessions[-1]
    try:
        transcript = _json.loads(tpath.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Could not read {tpath}: {e}[/]"); return 1
    final = next((e.get("content", "") for e in reversed(transcript)
                  if e.get("kind") == "final"), "")
    meta = report.Engagement(engagement="Security assessment")
    model = report.build_model(meta, transcript, _store.all_hosts(),
                               _store.facts(), final, log_dir=cfg.log_dir)
    formats = [f.strip() for f in args.format.split(",")]
    written = report.export(model, tpath.with_suffix(""), formats)
    if written:
        console.print("[green]Exported:[/] " + ", ".join(str(w) for w in written))
    else:
        console.print("[yellow]Nothing written (for DOCX: pip install python-docx).[/]")
    return 0


def cmd_web(args) -> int:
    """Launch the web console (Bootstrap SPA served by uvicorn)."""
    try:
        from .web import run as run_web
    except ImportError as e:
        console.print(f"[red]Web console needs FastAPI + uvicorn:[/] {e}\n"
                      "  pip install 'autopwn[web]'   (or: pip install fastapi uvicorn)")
        return 1
    url = f"http://{args.host}:{args.port}"
    console.print(Panel(f"Autopwn web console\n[bold]{url}[/]\n\n"
                        "Authorized security testing only.",
                        title="autopwn web", border_style="cyan"))
    try:
        run_web(host=args.host, port=args.port, config_path=args.config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Web console stopped.[/]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autopwn",
        description="Autopwn — AI-orchestrated authorized security testing.")
    p.add_argument("--config", default="config.yaml",
                   help="Path to config file (default config.yaml).")
    # Session overrides (used by the web console to scope a run to a session).
    p.add_argument("--log-dir", dest="log_dir_override",
                   help="Override the results/jobs/reports directory.")
    p.add_argument("--scope-file", dest="scope_file_override",
                   help="Override the scope file.")
    # Not required: no subcommand launches the interactive menu.
    sub = p.add_subparsers(dest="command")

    m = sub.add_parser("menu", help="Interactive menu (default if no command).")
    m.set_defaults(func=cmd_menu)

    s = sub.add_parser("scope", help="Show scope / check a target.")
    s.add_argument("--target", help="Check whether this target is in scope.")
    s.set_defaults(func=cmd_scope)

    t = sub.add_parser("tools", help="List the tool catalog and availability.")
    t.set_defaults(func=cmd_tools)

    r = sub.add_parser("recon", help="Run a one-shot port/service scan.")
    r.add_argument("--target", required=True)
    r.add_argument("--profile", default="default")
    r.set_defaults(func=cmd_recon)

    rn = sub.add_parser("run", help="Run a single tool directly.")
    rn.add_argument("--tool", required=True, help="Tool name (see 'tools').")
    rn.add_argument("--set", action="append", metavar="key=value",
                    help="Tool argument, repeatable. e.g. --set target=10.0.0.1")
    rn.add_argument("--all", action="store_true",
                    help="Run against every host exposing this tool's service "
                         "(from the results matrix). --set adds shared args (e.g. creds).")
    rn.set_defaults(func=cmd_run)

    sw = sub.add_parser("sweep", help="Scan a host/range and build the service matrix.")
    sw.add_argument("--target", required=True, help="Host, IP, range, or CIDR.")
    sw.add_argument("--ports", help="e.g. '22,80,443' or '1-1000'. Default top 1000.")
    sw.set_defaults(func=cmd_sweep)

    sv = sub.add_parser("services", help="Show the service→hosts matrix from stored results.")
    sv.add_argument("--hosts", action="store_true", help="Also show per-host table.")
    sv.add_argument("--clear", action="store_true", help="Clear stored results.")
    sv.set_defaults(func=cmd_services)

    vp = sub.add_parser("vars", help="Show/set discovered variables (domain, creds…).")
    vp.add_argument("--set", action="append", metavar="name=value",
                    help="Set a variable, repeatable. e.g. --set username=admin")
    vp.add_argument("--clear", action="store_true", help="Clear all variables.")
    vp.set_defaults(func=cmd_vars)

    ar = sub.add_parser("autorun", help="Deterministic playbook autopilot (no AI).")
    ar.add_argument("--target", required=True, help="Host/IP/range to assess.")
    ar.add_argument("--username", help="Starting username (assumed-breach).")
    ar.add_argument("--password", help="Starting password.")
    ar.add_argument("--domain", help="AD domain.")
    ar.add_argument("--hash", dest="nt_hash", help="Starting NTLM hash.")
    ar.add_argument("--engagement", help="Engagement name.")
    ar.add_argument("--client", help="Client / organization.")
    ar.add_argument("--assessor", help="Who is running the assessment.")
    ar.add_argument("--authorized-by", dest="authorized_by", help="Who authorized it.")
    ar.add_argument("--report-format", default="html,docx,md", help="html,docx,md")
    ar.set_defaults(func=cmd_autorun)

    pbc = sub.add_parser("playbook", help="Run one playbook's built-in tool sequence.")
    pbc.add_argument("--id", required=True, help="Playbook id (e.g. ad-kill-chain).")
    pbc.add_argument("--target", help="Target host/IP (or use --set target=…).")
    pbc.add_argument("--set", action="append", metavar="key=value",
                     help="Seed a variable, repeatable. e.g. --set domain=corp.local")
    pbc.add_argument("--username", help="Starting username (assumed-breach).")
    pbc.add_argument("--password", help="Starting password.")
    pbc.add_argument("--domain", help="AD domain.")
    pbc.add_argument("--hash", dest="nt_hash", help="Starting NTLM hash.")
    pbc.set_defaults(func=cmd_playbook)

    a = sub.add_parser("agent", help="Run the AI agent (autopilot with --target).")
    a.add_argument("--target", help="Target host/IP. With no --objective, runs "
                   "a full adaptive assessment (autopilot).")
    a.add_argument("--objective", help="Custom goal. Optional if --target given.")
    a.add_argument("--background", action="store_true",
                   help="Run detached; watch with 'autopwn watch <id>'.")
    # Authenticated / assumed-breach engagement: seed starting credentials so
    # every credentialed tool and the agent use them from step one.
    a.add_argument("--username", help="Starting username (assumed-breach creds).")
    a.add_argument("--password", help="Starting password.")
    a.add_argument("--domain", help="AD domain (e.g. corp.local).")
    a.add_argument("--hash", dest="nt_hash", help="Starting NTLM hash (pass-the-hash).")
    # Engagement metadata — printed and included in the exported report.
    a.add_argument("--engagement", help="Engagement / assessment name.")
    a.add_argument("--client", help="Client / organization.")
    a.add_argument("--assessor", help="Who is running the assessment.")
    a.add_argument("--authorized-by", dest="authorized_by",
                   help="Who authorized the test.")
    a.add_argument("--report-format", default="html,docx,md",
                   help="Auto-export formats on completion (html,docx,md).")
    a.set_defaults(func=cmd_agent)

    rp = sub.add_parser("report", help="Export a saved session transcript as a report.")
    rp.add_argument("--transcript", help="Path to logs/session-*.json (default: latest).")
    rp.add_argument("--format", default="html,docx,md", help="html,docx,md")
    rp.set_defaults(func=cmd_report)

    j = sub.add_parser("jobs", help="List background agent jobs.")
    j.set_defaults(func=cmd_jobs)

    w = sub.add_parser("watch", help="Follow a background job's live output.")
    w.add_argument("job_id")
    w.set_defaults(func=cmd_watch)

    st = sub.add_parser("stop", help="Stop a running background job.")
    st.add_argument("job_id")
    st.set_defaults(func=cmd_stop)

    wb = sub.add_parser("web", help="Launch the web console (uvicorn + Bootstrap).")
    wb.add_argument("--host", default="127.0.0.1",
                    help="Bind address (default 127.0.0.1; use 0.0.0.0 to expose).")
    wb.add_argument("--port", type=int, default=8000, help="Port (default 8000).")
    wb.set_defaults(func=cmd_web)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    if not getattr(args, "command", None):
        return cmd_menu(args)  # no subcommand -> interactive menu
    try:
        return args.func(args)
    except ScopeError as e:
        console.print(f"[red]{e}[/]")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
