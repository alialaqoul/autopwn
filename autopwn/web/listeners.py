# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Reverse-shell listener manager (authorized testing only).

Runs one detached handler process per listener (see _listener_proc.py), tracks
it in a small JSON sidecar, tails its captured output, and forwards commands the
operator types by appending them to the listener's .cmd file.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

_DIR = Path("logs") / "listeners"


def configure(log_dir) -> None:
    global _DIR
    _DIR = Path(log_dir) / "listeners"


def _ensure() -> None:
    _DIR.mkdir(parents=True, exist_ok=True)


def _meta(lid: str) -> Path:
    return _DIR / f"{lid}.json"


def log_path(lid: str) -> Path:
    return _DIR / f"{lid}.log"


def _cmd_path(lid: str) -> Path:
    return _DIR / f"{lid}.cmd"


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                             capture_output=True, text=True)
        return str(pid) in out.stdout
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, OSError):
        pass
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def start(port: int) -> dict:
    _ensure()
    lid = time.strftime("%Y%m%d-%H%M%S")
    logf, cmdf = log_path(lid), _cmd_path(lid)
    logf.write_text("", encoding="utf-8")
    cmdf.write_text("", encoding="utf-8")
    script = Path(__file__).parent / "_listener_proc.py"
    argv = [sys.executable, str(script), str(int(port)), str(logf), str(cmdf)]
    kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(argv, **kwargs)
    meta = {"id": lid, "port": int(port), "pid": proc.pid,
            "started": time.time(), "status": "listening"}
    _meta(lid).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _load(lid: str) -> Optional[dict]:
    try:
        return json.loads(_meta(lid).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def list_listeners() -> list:
    _ensure()
    out = []
    for m in sorted(_DIR.glob("*.json")):
        try:
            d = json.loads(m.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if d.get("status") != "stopped" and not _alive(d.get("pid", -1)):
            d["status"] = "closed"
            m.write_text(json.dumps(d, indent=2), encoding="utf-8")
        # reflect whether a shell has connected yet
        try:
            if "[+] connection from" in log_path(d["id"]).read_text(errors="replace"):
                if d.get("status") == "listening":
                    d["status"] = "connected"
        except OSError:
            pass
        out.append(d)
    out.sort(key=lambda d: d.get("started", 0), reverse=True)
    return out


def send(lid: str, command: str) -> bool:
    if _load(lid) is None:
        return False
    with open(_cmd_path(lid), "a", encoding="utf-8") as f:
        f.write(command.rstrip("\n") + "\n")
    return True


def stop(lid: str) -> bool:
    d = _load(lid)
    if not d:
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(d["pid"])], capture_output=True)
        else:
            os.killpg(os.getpgid(d["pid"]), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    d["status"] = "stopped"
    _meta(lid).write_text(json.dumps(d, indent=2), encoding="utf-8")
    return True


def is_running(lid: str) -> bool:
    d = _load(lid)
    return bool(d and _alive(d.get("pid", -1)))
