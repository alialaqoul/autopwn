# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Persistent interactive credentialed sessions (authorized testing only).

Holds one interactive client per session (evil-winrm for WinRM, impacket-wmiexec
for SMB), so the console shell is stateful (cd/env persist). Mirrors the listener
manager: a detached handler process (see _shell_proc.py), a JSON sidecar, a log
to tail, and a .cmd file to forward commands.
"""
from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

_DIR = Path("logs") / "shells"


def configure(log_dir) -> None:
    global _DIR
    _DIR = Path(log_dir) / "shells"


def _ensure() -> None:
    _DIR.mkdir(parents=True, exist_ok=True)


def _meta(sid: str) -> Path:
    return _DIR / f"{sid}.json"


def log_path(sid: str) -> Path:
    return _DIR / f"{sid}.log"


def _cmd_path(sid: str) -> Path:
    return _DIR / f"{sid}.cmd"


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


def _nt_hash(secret: str) -> str:
    """Normalize a pasted NT hash for pass-the-hash. A copy-paste usually carries
    a trailing space (→ evil-winrm 'Invalid hash format' and impacket 'expected
    bytes… got str'), and users often paste the full 'LMHASH:NTHASH' pair — so
    drop all whitespace and keep just the 32-hex NT half."""
    s = "".join((secret or "").split())     # remove any surrounding/inner whitespace
    if ":" in s:
        s = s.rsplit(":", 1)[-1]             # LMHASH:NTHASH -> NTHASH
    return s


def _client_argv(host, protocol, username, secret, auth, domain) -> list:
    """Build the interactive client command for the chosen protocol/auth."""
    if protocol == "winrm":
        argv = ["evil-winrm", "-i", host, "-u", username]
        argv += (["-H", _nt_hash(secret)] if auth == "hash" else ["-p", secret])
        return argv
    # SMB → impacket-psexec (a real interactive cmd.exe; wmiexec's semi-interactive
    # shell doesn't return output when driven programmatically).
    dom = f"{domain}/" if domain else ""
    if auth == "hash":
        return ["impacket-psexec", "-hashes", f":{_nt_hash(secret)}", f"{dom}{username}@{host}"]
    return ["impacket-psexec", f"{dom}{username}:{secret}@{host}"]


def start(host, protocol, username, secret, auth="password", domain="",
          cols=120, rows=34) -> dict:
    _ensure()
    sid = time.strftime("%Y%m%d-%H%M%S")
    logf, cmdf = log_path(sid), _cmd_path(sid)
    logf.write_text("", encoding="utf-8")
    cmdf.write_text("", encoding="utf-8")
    client = _client_argv(host, protocol, username, secret, auth, domain)
    wrapper = Path(__file__).parent / "_shell_proc.py"
    argv = [sys.executable, str(wrapper), json.dumps(client), str(logf), str(cmdf),
            str(int(cols) or 120), str(int(rows) or 34)]
    kwargs: dict = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                    "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(argv, **kwargs)
    meta = {"id": sid, "host": host, "protocol": protocol, "username": username,
            "pid": proc.pid, "started": time.time(), "status": "open"}
    _meta(sid).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def _load(sid: str) -> Optional[dict]:
    try:
        return json.loads(_meta(sid).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def send(sid: str, data: str) -> bool:
    """Forward raw keystrokes to the session's PTY. `data` is written verbatim
    (base64-framed one-per-line) so control chars — Enter, Ctrl+C, arrows, Tab —
    reach the remote unchanged."""
    if _load(sid) is None:
        return False
    b64 = base64.b64encode((data or "").encode("utf-8", "surrogatepass")).decode("ascii")
    with open(_cmd_path(sid), "a", encoding="utf-8") as f:
        f.write(b64 + "\n")
    return True


def stop(sid: str) -> bool:
    d = _load(sid)
    if not d:
        return False
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(d["pid"])], capture_output=True)
        else:
            os.killpg(os.getpgid(d["pid"]), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    d["status"] = "closed"
    _meta(sid).write_text(json.dumps(d, indent=2), encoding="utf-8")
    return True


def is_running(sid: str) -> bool:
    d = _load(sid)
    return bool(d and _alive(d.get("pid", -1)))
