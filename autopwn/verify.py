# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Playbook verification harness — prove accuracy against a real lab.

A playbook is only trustworthy if, run against a target that actually exercises
it, the finding it claims *fires*. This harness runs a playbook's built-in tool
sequence against a lab target, builds the findings from that fresh transcript,
and asserts each expected finding appears. On success it writes a dated
``verified`` stamp (target + findings) to ``<log_dir>/verification.json`` so the
operator can see when each playbook was last proven and against what.

Run one:   autopwn verify --id kerberoast-da --target 192.168.140.11 \
             --domain north.sevenkingdoms.local --username hodor --password hodor \
             --expect "Kerberoastable Service Accounts"
Run a suite:  autopwn verify --suite examples/goad-verify.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import playbooks as pb_mod, store
from .analysis import build_findings

# facts that must not leak between playbooks in a suite run
_TRANSIENT = ("username", "password", "domain", "userlist", "hashfile",
              "nthash", "smb_guest", "userpass")


def _reset(seed: dict) -> None:
    """Clear transient engagement facts, then seed the assumed-breach inputs."""
    for k in _TRANSIENT:
        store.set_fact(k, "")
    for k, v in (seed or {}).items():
        if v:
            store.set_fact(k, str(v))


def run_one(entry: dict, cfg, scope, report=lambda *a: None) -> dict:
    """Run one playbook and check its expected findings fired.

    entry: {id, target, domain?, username?, password?, hash?, expect:[titles]}
    Returns {id, target, status, fired:[titles], missing:[expected], error?}.
    """
    from .tools.registry import default_registry
    from .tools.base import ToolContext
    from .sequence import run_sequence

    pid = entry["id"]
    target = entry["target"]
    expect = entry.get("expect", []) or []
    book = next((p for p in pb_mod.load(cfg.log_dir) if p.get("id") == pid), None)
    if not book:
        return {"id": pid, "target": target, "status": "ERROR",
                "error": f"no playbook '{pid}'", "fired": [], "missing": expect}

    # authorize the target (verification is operator-driven)
    if scope.is_denied(target):
        return {"id": pid, "target": target, "status": "SKIP",
                "error": "target on deny list", "fired": [], "missing": expect}
    if not scope.is_allowed(target):
        scope.add_allow(target)

    _reset({"domain": entry.get("domain"), "username": entry.get("username"),
            "password": entry.get("password"), "nthash": entry.get("hash")})

    reg = default_registry(cfg.tools)
    ctx = ToolContext(scope=scope, confirm_active_actions=False)
    transcript: list = []

    def _record(name, r):
        transcript.append({"kind": "tool_result", "name": name,
                           "command": (getattr(r, "data", None) or {}).get("command", name),
                           "ok": getattr(r, "ok", False),
                           "output": getattr(r, "raw_output", "") or getattr(r, "summary", "")})

    try:
        run_sequence(book, target, ctx, reg, report, cfg.log_dir, record=_record)
    except Exception as e:                       # a verify run must never crash the suite
        return {"id": pid, "target": target, "status": "ERROR",
                "error": f"{type(e).__name__}: {e}", "fired": [], "missing": expect}

    findings = build_findings(store.all_hosts(), store.facts(), transcript, cfg.log_dir)
    titles = [f["title"] for f in findings]
    missing = [e for e in expect
               if not any(e.lower() in t.lower() for t in titles)]
    status = "PASS" if not missing else ("FAIL" if expect else "RAN")
    return {"id": pid, "target": target, "status": status,
            "fired": titles, "missing": missing, "expect": expect}


def run_suite(suite: list, cfg, scope, report=lambda *a: None) -> list:
    return [run_one(e, cfg, scope, report) for e in suite]


def load_suite(path: str) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("suite", [])
    if not isinstance(data, list):
        raise ValueError("suite file must be a JSON list of {id,target,expect,…}")
    return data


def stamp(results: list, log_dir) -> Path:
    """Persist per-playbook verification stamps (dated) to verification.json."""
    p = Path(log_dir) / "verification.json"
    try:
        record = json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        record = {}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    for r in results:
        record[r["id"]] = {
            "verified_on": now, "target": r["target"], "status": r["status"],
            "fired": r.get("fired", []), "missing": r.get("missing", []),
            "error": r.get("error", ""),
        }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return p
