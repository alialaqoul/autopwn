# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Background job manager.

Lets a long-running agent (or sweep) run detached while the operator keeps using
Autopwn in the same or another terminal. A job is just a detached child process
running the normal `autopwn` CLI, with its stdout/stderr streamed to a log file
and a small JSON sidecar tracking status. Because everything shares the on-disk
results store, manual commands and the background agent build one picture.
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

_JOBS_DIR = Path("logs") / "jobs"


def configure(log_dir: str | Path) -> None:
    global _JOBS_DIR
    _JOBS_DIR = Path(log_dir) / "jobs"


def _ensure() -> None:
    _JOBS_DIR.mkdir(parents=True, exist_ok=True)


def _meta_path(job_id: str) -> Path:
    return _JOBS_DIR / f"{job_id}.json"


def log_path(job_id: str) -> Path:
    return _JOBS_DIR / f"{job_id}.log"


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                 capture_output=True, text=True)
            return str(pid) in out.stdout
        except OSError:
            return False
    # POSIX. A detached job is a direct child of the process that launched it;
    # when it exits it becomes a zombie (<defunct>) until reaped. os.kill(pid, 0)
    # succeeds on a zombie, so we must detect and discount that state, otherwise
    # finished jobs show as "running" forever.
    try:  # if it's our child and already exited, reap it — then it's gone.
        reaped, _ = os.waitpid(pid, os.WNOHANG)
        if reaped == pid:
            return False
    except (ChildProcessError, OSError):
        pass  # not our child (different process is asking), or already reaped
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    try:  # exists — but a zombie counts as finished, not running.
        with open(f"/proc/{pid}/stat", "r") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
        if state == "Z":
            return False
    except (OSError, IndexError):
        pass
    return True


def start(cli_args: list[str], label: str, log_dir: str | Path) -> str:
    """Launch `autopwn <cli_args>` detached. Returns the job id."""
    configure(log_dir)
    _ensure()
    job_id = time.strftime("%Y%m%d-%H%M%S")
    lp = log_path(job_id)
    argv = [sys.executable, "-m", "autopwn", *cli_args]

    logf = open(lp, "w", encoding="utf-8")
    kwargs: dict = {"stdout": logf, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED | NEW_GROUP
    else:
        kwargs["start_new_session"] = True  # detach from our session
    proc = subprocess.Popen(argv, **kwargs)

    _meta_path(job_id).write_text(json.dumps({
        "id": job_id, "label": label, "pid": proc.pid,
        "args": cli_args, "started": time.time(), "status": "running",
    }, indent=2), encoding="utf-8")
    return job_id


def _load(job_id: str) -> Optional[dict]:
    try:
        return json.loads(_meta_path(job_id).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def list_jobs(log_dir: str | Path) -> list[dict]:
    configure(log_dir)
    _ensure()
    jobs = []
    for meta in sorted(_JOBS_DIR.glob("*.json")):
        try:
            m = json.loads(meta.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if m.get("status") == "running" and not _alive(m.get("pid", -1)):
            m["status"] = "finished"
            meta.write_text(json.dumps(m, indent=2), encoding="utf-8")
        jobs.append(m)
    jobs.sort(key=lambda j: j.get("started", 0), reverse=True)
    return jobs


def stop(job_id: str, log_dir: str | Path) -> bool:
    configure(log_dir)
    m = _load(job_id)
    if not m or not _alive(m.get("pid", -1)):
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(m["pid"])],
                           capture_output=True)
        else:
            os.killpg(os.getpgid(m["pid"]), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return False
    m["status"] = "stopped"
    _meta_path(job_id).write_text(json.dumps(m, indent=2), encoding="utf-8")
    return True


def is_running(job_id: str, log_dir: str | Path) -> bool:
    configure(log_dir)
    m = _load(job_id)
    return bool(m and _alive(m.get("pid", -1)))
