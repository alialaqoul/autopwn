"""Browser regression checks for the offline console, using isolated fixture data.

Requires the project's web dependencies plus Playwright:
    python -m pip install playwright
    python -m playwright install chromium
    python scripts/check_web_ui.py

Optional: --screenshots <directory> saves review images. No security tools run;
the browser checks navigation, rendering, filters, and editor interactions only.
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def serve_fixture(config_path: str, port: int) -> None:
  import uvicorn
  from autopwn import playbooks, store
  from autopwn.web import sessions
  from autopwn.web.server import create_app

  app = create_app(config_path)
  for suffix, name, ports in [
    (10, "DC-01", [(53, "dns"), (88, "kerberos"), (389, "ldap"), (445, "smb")]),
    (20, "WEB-01", [(22, "ssh"), (80, "http"), (443, "https")]),
    (30, "FILE-01", [(135, "rpc"), (445, "smb")]),
    (40, "DB-01", [(22, "ssh"), (1433, "mssql")]),
    (50, "GATEWAY", [(443, "https"), (161, "snmp")]),
    (60, "APP-01", [(80, "http"), (8080, "http")]),
  ]:
    store.record_ports(f"192.0.2.{suffix}", [
      {"port": number, "service": service} for number, service in ports
    ], hostname=name)
  # Finish first-use data migrations before browser requests arrive concurrently.
  for _ in range(3):
    playbooks.load(sessions.current()["dir"])
  sessions.create("empty-ui-fixture")
  uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def check_browser(url: str, screenshots: Path | None) -> None:
  from playwright.sync_api import expect, sync_playwright

  ready = {
    "dashboard": ("#hostInventoryCount", "6 ASSETS"),
    "launch": ("#connectionLabel", "Console online"),
    "findings": ("#findingsSource", "Derived"),
    "attack": ("#attackStats", "Techniques"),
    "paths": ("#pathsControl", "No BloodHound collection"),
    "console": ("#exTerm .xterm", None),
    "playbooks": ("#pbResultCount", "PLAYBOOKS"),
    "tools": ("#toolResultCount", "TOOLS"),
    "jobs": ("#jobsTable tbody", "No jobs"),
    "reports": ("#reportsTable tbody", "No reports"),
    "scope": ("#scopeList", "192.0.2.0/24"),
    "settings": ("#attackDataStatus", "techniques"),
  }
  with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", color_scheme="dark")
    errors, failed_requests, external_requests = [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on("response", lambda r: failed_requests.append(f"{r.status}: {r.url}") if r.status >= 400 else None)
    page.on("request", lambda r: external_requests.append(r.url) if not r.url.startswith(url) else None)

    for width in [1440, 390]:
      page.set_viewport_size({"width": width, "height": 1000 if width > 500 else 844})
      for view, (selector, text) in ready.items():
        page.goto(f"{url}/#{view}")
        if text:
          expect(page.locator(selector)).to_contain_text(text, timeout=30000)
        else:
          expect(page.locator(selector)).to_be_visible()
        expect(page.locator(f'section[data-panel="{view}"]')).to_be_visible()
        assert page.locator("section[data-panel]:visible").count() == 1
        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"Overflow: {view} at {width}px"
        if screenshots and view in {"dashboard", "launch", "tools"}:
          page.evaluate("document.documentElement.setAttribute('data-bs-theme','dark')")
          page.screenshot(path=str(screenshots / f"redesign-{view}-{width}.png"), animations="disabled")
          page.evaluate("document.documentElement.setAttribute('data-bs-theme','light')")
          page.screenshot(path=str(screenshots / f"redesign-{view}-light-{width}.png"), animations="disabled")
          page.evaluate("document.documentElement.setAttribute('data-bs-theme','dark')")
        # Other views the README embeds by plain name, captured once at desktop width.
        if screenshots and width == 1440 and view in {"findings", "console", "playbooks", "attack", "paths", "settings"}:
          page.evaluate("document.documentElement.setAttribute('data-bs-theme','dark')")
          page.screenshot(path=str(screenshots / f"{view}.png"), animations="disabled")
      print(f"PASS: all 12 populated/empty views at {width}px", flush=True)

    # Drawer focus containment, dismissal, and navigation.
    page.locator("#menuBtn").click()
    expect(page.locator("#sidebar")).to_have_class(re.compile("is-open"))
    assert page.locator(".ap-main").evaluate("e => e.inert")
    page.locator("#sidebarClose").focus()
    page.keyboard.press("Shift+Tab")
    assert page.evaluate("document.activeElement.closest('#sidebar') !== null")
    page.keyboard.press("Escape")
    expect(page.locator("#menuBtn")).to_be_focused()
    assert not page.locator(".ap-main").evaluate("e => e.inert")
    page.locator("#menuBtn").click()
    page.locator('[data-view="tools"]').click()
    expect(page.locator("#sidebar")).not_to_have_class(re.compile("is-open"))
    expect(page.locator("#pageHeading")).to_contain_text("Tool arsenal")

    # Palette search, keyboard routing, empty results, and dialog dismissal.
    page.keyboard.press("Control+k")
    expect(page.locator("#commandPalette")).to_be_visible()
    page.locator("#commandSearch").fill("no-such-view-123")
    expect(page.locator("#commandResults")).to_contain_text("No matching views")
    page.locator("#commandSearch").fill("launch")
    page.keyboard.press("Enter")
    expect(page.locator("#pageHeading")).to_contain_text("Launch assessment")
    expect(page.locator("#commandPalette")).not_to_be_visible()
    page.locator("#launchTarget").fill("192.0.2.20")
    page.locator('[data-bs-target="#credsBox"]').click()
    expect(page.locator('#launchForm input[name="password"]')).to_be_visible()
    assert page.locator('#launchForm input[name="password"]').get_attribute("type") == "password"
    await_summary = "async () => { await loadDashboard(); }"
    page.evaluate(await_summary)
    expect(page.locator("#launchTarget")).to_have_value("192.0.2.20")

    page.set_viewport_size({"width": 1440, "height": 1000})
    page.locator('[data-view="tools"]').click()
    expect(page.locator("#toolResultCount")).to_contain_text("TOOLS")
    page.locator("#toolSearch").fill("nmap")
    expect(page.locator("#toolsList")).to_contain_text("nmap")
    page.locator("#toolSearch").fill("no-such-tool-123")
    expect(page.locator("#toolsList")).to_contain_text("No tools match")
    page.locator("#toolSearch").fill("")
    page.locator("#toolCategory").select_option("recon")
    assert page.locator("#toolsList .card").count() > 0
    page.locator("[data-tool-view]").first.click()
    expect(page.locator("#toolViewer")).to_be_visible()
    page.locator('#toolViewer .modal-footer button').click()
    page.locator("#toolNewBtn").click()
    expect(page.locator("#toolEditor")).to_be_visible()
    page.locator("#t_binary").fill("fixture-tool")
    expect(page.locator("#t_preview")).to_contain_text("fixture-tool")
    page.locator('#toolEditor .modal-footer [data-bs-dismiss]').click()

    page.locator('[data-view="playbooks"]').click()
    expect(page.locator("#pbResultCount")).to_contain_text("PLAYBOOKS")
    if screenshots:
      # README's management-audit illustration: the mgmt-server-audit playbook detail.
      page.locator('[data-pb-edit="mgmt-server-audit"]').click()
      expect(page.locator("#pbEditor")).to_be_visible()
      expect(page.locator("#pbBuilder")).not_to_be_empty()
      page.evaluate("document.documentElement.setAttribute('data-bs-theme','dark')")
      page.screenshot(path=str(screenshots / "mgmt-audit.png"), animations="disabled")
      page.locator('#pbEditor .modal-footer [data-bs-dismiss]').click()
      expect(page.locator("#pbEditor")).not_to_be_visible()
    total = page.locator(".pb-card").count()
    page.locator("#pbSearch").fill("no-such-playbook-123")
    expect(page.locator("#playbooksList")).to_contain_text("No playbooks match")
    page.locator("#pbSearch").fill("")
    page.locator("#pbMatchOnly").check()
    assert 0 < page.locator(".pb-card").count() <= total
    page.locator("#pbNewBtn").click()
    expect(page.locator("#pbEditor")).to_be_visible()
    expect(page.locator("#pbBuilder")).not_to_be_empty()
    page.locator('#pbEditor .modal-footer [data-bs-dismiss]').click()

    # Switching a real isolated session must clear the graph and metrics.
    page.locator('[data-view="dashboard"]').click()
    page.locator("#sessionSelect").select_option("empty-ui-fixture")
    expect(page.locator("#hostInventoryCount")).to_have_text("0 ASSETS")
    expect(page.locator("#topologyMap")).to_contain_text("Awaiting first contact")
    assert page.locator(".topology-node").count() == 0
    page.locator("#sessionSelect").select_option("default")
    expect(page.locator("#hostInventoryCount")).to_have_text("6 ASSETS")
    assert page.locator(".topology-node").count() == 6

    # Transient disconnection should retain the last snapshot and recover.
    page.route("**/api/summary", lambda route: route.abort())
    page.evaluate(await_summary)
    expect(page.locator("#connectionAlert")).to_be_visible()
    expect(page.locator("#hostInventoryCount")).to_have_text("6 ASSETS")
    page.unroute("**/api/summary")
    page.evaluate(await_summary)
    expect(page.locator("#connectionAlert")).not_to_be_visible()

    # Server-supplied strings in the new visualization stay text, never HTML.
    data = page.request.get(f"{url}/api/summary").json()
    data["hosts"][0]["host"] = '<img src=x onerror="window.uiInjected=true">'
    data["engagement"] = '<svg onload="window.uiInjected=true">'
    page.evaluate("data => AutopwnUI.renderSummary(data)", data)
    assert page.locator("#topologyMap img").count() == 0
    assert not page.evaluate("Boolean(window.uiInjected)")
    expect(page.locator("#engagementName")).to_have_text(data["engagement"])
    assert not errors, errors
    assert not failed_requests, failed_requests
    assert not external_requests, external_requests
    print("PASS: drawer, command palette, filters, editors, session switch, recovery, escaping, and offline assets", flush=True)
    browser.close()


def main() -> None:
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--screenshots", type=Path)
  parser.add_argument("--serve-fixture", nargs=2, metavar=("CONFIG", "PORT"), help=argparse.SUPPRESS)
  args = parser.parse_args()
  if args.serve_fixture:
    serve_fixture(args.serve_fixture[0], int(args.serve_fixture[1]))
    return
  if args.screenshots:
    args.screenshots.mkdir(parents=True, exist_ok=True)
  with tempfile.TemporaryDirectory(prefix="autopwn-ui-check-") as temporary:
    fixture = Path(temporary)
    scope = fixture / "scope.yaml"
    scope.write_text("engagement: Orbital Lab Assessment\nauthorized_by: UI fixture\nallow: [192.0.2.0/24]\ndeny: []\n", encoding="utf-8")
    config = fixture / "config.yaml"
    config.write_text(json.dumps({"log_dir": str(fixture / "logs"), "scope_file": str(scope), "ai_enabled": False}), encoding="utf-8")
    with socket.socket() as sock:
      sock.bind(("127.0.0.1", 0))
      port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    with (fixture / "server.log").open("w", encoding="utf-8") as log:
      server = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve-fixture", str(config), str(port)], cwd=ROOT, stdout=log, stderr=log)
      try:
        deadline = time.monotonic() + 30
        while True:
          try:
            with urllib.request.urlopen(url, timeout=1) as response:
              assert response.status == 200
            break
          except OSError:
            if server.poll() is not None or time.monotonic() > deadline:
              raise RuntimeError("UI fixture failed to start; check web dependencies.")
            time.sleep(.1)
        check_browser(url, args.screenshots)
      finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
  main()
