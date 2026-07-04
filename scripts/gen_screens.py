# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Generate terminal 'screenshots' (SVG) of Autopwn's UI using its own Rich
rendering against the real results store. Run on the Kali box in the venv.
"""
from __future__ import annotations

import pathlib
from types import SimpleNamespace

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import autopwn.cli as cli
from autopwn import store
from autopwn.applicability import applicable_count
from autopwn.config import Config
from autopwn.tools.catalog import CATEGORY_ORDER
from autopwn.tools.command import GenericCommandTool
from autopwn.tools.registry import default_registry

OUT = pathlib.Path("assets")
OUT.mkdir(exist_ok=True)
CFG = Config.load("config.yaml")
store.configure(f"{CFG.log_dir}/results.json")
WIDTH = 104


def shot(name: str, title: str, render) -> None:
    c = Console(record=True, width=WIDTH)
    cli.console = c            # redirect the app's module-level console
    render(c)
    c.save_svg(str(OUT / f"{name}.svg"), title=title)
    print("wrote", name)


def main_menu(c):
    c.print(Panel("[bold]Autopwn[/] — interactive menu\n[dim]by Ali Alaqoul[/]",
                  border_style="cyan"))
    for k, l in cli._MENU:
        c.print(f"  [bold cyan]{k}[/]  {l}")
    c.print("\n[bold]select>[/] ")


def tools(c):
    cli.cmd_tools(SimpleNamespace(config="config.yaml"))


def matrix(c):
    cli._render_matrix()


def hosts(c):
    summary = store.host_summary()
    t = Table(title="Discovered hosts — pick a number for detail")
    t.add_column("#", justify="right"); t.add_column("Host", style="green")
    t.add_column("Name"); t.add_column("# open", justify="right"); t.add_column("Services")
    for i, h in enumerate(summary, 1):
        t.add_row(str(i), h["host"], h["hostname"], str(len(h["open_ports"])),
                  ", ".join(h["services"][:5]) + (" …" if len(h["services"]) > 5 else ""))
    c.print(t)


def host_detail(c):
    cli._show_host_detail("192.168.130.10")


def run_tool(c):
    reg = default_registry(CFG.tools)
    order = {cat: i for i, cat in enumerate(CATEGORY_ORDER)}
    tl = [t for t in reg.all() if not isinstance(t, GenericCommandTool) or t.available()]
    tl.sort(key=lambda t: (order.get(getattr(t, "category", "misc"), 99),
                           -applicable_count(t.name), t.name))
    t = Table(title="Run a tool — pick a number")
    t.add_column("category", style="magenta"); t.add_column("#", justify="right")
    t.add_column("tool", style="cyan"); t.add_column("applies to"); t.add_column("intrusive")
    last = None
    for i, tool in enumerate(tl, 1):
        cat = getattr(tool, "category", "misc"); n = applicable_count(tool.name)
        t.add_row(cat if cat != last else "", str(i), tool.name,
                  f"[green]{n} host(s)[/]" if n else "[dim]—[/]",
                  "yes" if tool.active else "no")
        last = cat
    c.print(t)


def variables(c):
    cli.cmd_vars(SimpleNamespace(config="config.yaml", set=None, clear=False))


shot("menu", "autopwn — interactive menu", main_menu)
shot("tools", "autopwn tools", tools)
shot("matrix", "autopwn — service matrix", matrix)
shot("hosts", "autopwn — host drill-down", hosts)
shot("host_detail", "autopwn — host detail", host_detail)
shot("run_tool", "autopwn — run a tool", run_tool)
shot("variables", "autopwn vars", variables)
print("done")
