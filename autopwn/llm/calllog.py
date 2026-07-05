# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Append-only log of LLM API calls (one JSON object per line).

The provider records every chat/embed call — model, endpoint, latency, ok/error,
and token usage when the server reports it — into ``<log_dir>/ai_calls.jsonl``.
Both the agent subprocess and the web console point this at the active session
so the operator can audit exactly what the AI did and when.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_PATH: Path | None = None
_LOCK = threading.Lock()


def configure(path) -> None:
    global _PATH
    _PATH = Path(path)


def record(entry: dict) -> None:
    if _PATH is None:
        return
    entry = {"ts": time.time(), **entry}
    try:
        with _LOCK:
            _PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def tail(path, n: int = 100) -> list:
    """Return the last *n* records from a given ai_calls.jsonl (newest first)."""
    p = Path(path)
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except (FileNotFoundError, OSError):
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out
