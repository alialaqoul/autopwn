# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Engagement sessions for the web console.

A *session* is a self-contained data directory: its own results store, scope,
playbooks, custom tools, jobs, and exported reports. The console tracks one
"current" session and presents only that session's data across every view;
switching sessions re-points the shared store/jobs/tools modules at the selected
directory. Launched jobs are told (via --log-dir / --scope-file) to write into
the selected session so background runs stay inside it.

The default session maps to the engagement's original log_dir (so existing data
is preserved as "default"); new sessions live under ``<root>/sessions/<name>``.
State is a small index file at ``<root>/autopwn-sessions.json``.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional

_ROOT = Path(".")
_INDEX = Path("autopwn-sessions.json")
_DEFAULT = {"name": "default", "dir": "logs", "scope": "scope.yaml"}


def configure(default_log_dir: str, default_scope_file: str) -> None:
    """Point the manager at this engagement and make sure an index exists."""
    global _ROOT, _INDEX, _DEFAULT
    root = Path(default_log_dir).resolve().parent
    _ROOT = root
    _INDEX = root / "autopwn-sessions.json"
    _DEFAULT = {"name": "default", "dir": str(Path(default_log_dir)),
                "scope": str(Path(default_scope_file))}
    data = _read()
    if not any(s["name"] == "default" for s in data["sessions"]):
        data["sessions"].insert(0, {**_DEFAULT, "created": time.time()})
        _write(data)


def _read() -> dict:
    try:
        data = json.loads(_INDEX.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "sessions" in data:
            data.setdefault("current", "default")
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return {"current": "default",
            "sessions": [{**_DEFAULT, "created": time.time()}]}


def _write(data: dict) -> None:
    _INDEX.parent.mkdir(parents=True, exist_ok=True)
    tmp = _INDEX.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(_INDEX)


def _hosts_count(session_dir: str) -> int:
    try:
        d = json.loads((Path(session_dir) / "results.json").read_text(encoding="utf-8"))
        return len(d.get("hosts", {}))
    except (FileNotFoundError, json.JSONDecodeError):
        return 0


def _find(data: dict, name: str) -> Optional[dict]:
    return next((s for s in data["sessions"] if s["name"] == name), None)


def current() -> dict:
    data = _read()
    s = _find(data, data["current"]) or _find(data, "default") or data["sessions"][0]
    return s


def list_sessions() -> list:
    data = _read()
    cur = data["current"]
    out = []
    for s in data["sessions"]:
        out.append({"name": s["name"], "dir": s["dir"], "scope": s["scope"],
                    "current": s["name"] == cur, "created": s.get("created"),
                    "hosts": _hosts_count(s["dir"])})
    return out


def set_current(name: str) -> dict:
    data = _read()
    if not _find(data, name):
        raise KeyError(name)
    data["current"] = name
    _write(data)
    return current()


def create(name: str) -> dict:
    name = (name or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
        raise ValueError("Session name must be 1-40 chars: letters, digits, _ . -")
    data = _read()
    if _find(data, name):
        raise FileExistsError(name)
    sdir = _ROOT / "sessions" / name
    sdir.mkdir(parents=True, exist_ok=True)
    scope = sdir / "scope.yaml"
    if not scope.exists():
        scope.write_text(f"engagement: {name}\nallow: []\ndeny: []\n", encoding="utf-8")
    results = sdir / "results.json"
    if not results.exists():
        results.write_text('{"hosts": {}, "facts": {}}', encoding="utf-8")
    entry = {"name": name, "dir": str(sdir), "scope": str(scope),
             "created": time.time()}
    data["sessions"].append(entry)
    _write(data)
    return entry


def delete(name: str) -> None:
    if name == "default":
        raise ValueError("The default session cannot be deleted.")
    data = _read()
    if not _find(data, name):
        raise KeyError(name)
    data["sessions"] = [s for s in data["sessions"] if s["name"] != name]
    if data["current"] == name:
        data["current"] = "default"
    _write(data)
