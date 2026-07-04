# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Dependency-free TCP connect scanner.

A fallback so Autopwn can do basic port discovery on any machine with a Python
interpreter, even where nmap is not installed. For real engagements prefer the
nmap tool — this is intentionally simple.
"""
from __future__ import annotations

import concurrent.futures
import socket
from typing import Any

from .base import Tool, ToolContext, ToolResult

# Common ports probed when the model doesn't specify.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 27017,
]


def _coerce_ports(value: Any) -> list[int]:
    """Accept a list, a JSON-ish string like '[80,443]', or '80,443'/'1-100'.

    Small models frequently pass ports as a string; normalize to ints.
    """
    if value is None:
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, str):
        s = value.strip().strip("[]").strip()
        if not s:
            return []
        out: list[int] = []
        for part in s.split(","):
            part = part.strip()
            if "-" in part:  # a range like 1-100
                lo, _, hi = part.partition("-")
                try:
                    out.extend(range(int(lo), int(hi) + 1))
                except ValueError:
                    continue
            elif part.isdigit():
                out.append(int(part))
        return out
    if isinstance(value, (list, tuple)):
        result: list[int] = []
        for p in value:
            try:
                result.append(int(p))
            except (TypeError, ValueError):
                continue
        return result
    return []


def _coerce_timeout(value: Any, default: float = 0.5) -> float:
    try:
        t = float(value)
    except (TypeError, ValueError):
        return default
    # Guard against a model passing 0 (which would make every probe fail).
    return t if t >= 0.05 else default


def _probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class PortScanTool(Tool):
    category = "recon"
    name = "native_port_scan"
    description = (
        "Fast TCP connect scan of a single host using no external tools. "
        "Returns the list of open ports. Use when nmap is unavailable or for a "
        "quick liveness/port check."
    )
    active = True  # sends connection attempts to the target
    parameters = {
        "type": "object",
        "properties": {
            "target": {"type": "string",
                       "description": "Hostname or IP of a single host."},
            "ports": {
                "type": "array",
                "items": {"type": "integer"},
                "description": "Ports to scan. Omit for a common-ports sweep.",
            },
            "timeout": {"type": "number",
                        "description": "Per-port timeout seconds (default 0.5)."},
        },
        "required": ["target"],
    }

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        target = kwargs["target"]
        self._authorize(ctx, target)
        ports = _coerce_ports(kwargs.get("ports")) or COMMON_PORTS
        timeout = _coerce_timeout(kwargs.get("timeout"))

        open_ports: list[int] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
            futures = {pool.submit(_probe, target, p, timeout): p
                       for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                if fut.result():
                    open_ports.append(futures[fut])
        open_ports.sort()

        # Feed the shared results store (best-effort).
        if open_ports:
            try:
                from .. import store
                store.record_ports(target, [{"port": p, "proto": "tcp",
                                             "state": "open", "service": ""}
                                            for p in open_ports])
            except Exception:
                pass

        if open_ports:
            summary = (f"{target}: {len(open_ports)} open port(s): "
                       f"{', '.join(map(str, open_ports))}")
        else:
            summary = f"{target}: no open ports found in scanned set."
        return ToolResult(ok=True, summary=summary,
                          data={"target": target, "open_ports": open_ports})
