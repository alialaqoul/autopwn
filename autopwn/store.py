# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Shared results store for discovered hosts, ports, and services.

A single JSON file records everything Autopwn learns about an engagement, so
that separate processes — a background agent run and manual commands in another
terminal — all contribute to and read from the same picture. Writes are
serialized with a cross-platform lock and done read-merge-write, so concurrent
scans don't clobber each other.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

# Module-level path so tools can record without threading config everywhere.
_STORE_PATH = Path("logs") / "results.json"


def configure(path: str | Path) -> None:
    global _STORE_PATH
    _STORE_PATH = Path(path)


def _lock_dir() -> Path:
    return _STORE_PATH.with_suffix(".lock")


class _Lock:
    """Simple cross-platform lock using atomic mkdir; retries then breaks stale."""

    def __init__(self, timeout: float = 10.0):
        self.dir = _lock_dir()
        self.timeout = timeout

    def __enter__(self):
        start = time.time()
        while True:
            try:
                self.dir.mkdir(parents=True, exist_ok=False)
                return self
            except FileExistsError:
                # Break a stale lock (>30s old) left by a crashed process.
                try:
                    if time.time() - self.dir.stat().st_mtime > 30:
                        self.dir.rmdir()
                        continue
                except OSError:
                    pass
                if time.time() - start > self.timeout:
                    return self  # give up waiting; proceed best-effort
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            self.dir.rmdir()
        except OSError:
            pass


def _read() -> dict:
    try:
        return json.loads(_STORE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"hosts": {}}


def _write(data: dict) -> None:
    _STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, _STORE_PATH)  # atomic


def record_ports(host: str, ports: list[dict],
                 hostname: Optional[str] = None) -> None:
    """Merge a set of discovered ports for *host* into the store.

    Each port dict: {"port": int, "proto": str, "state": str, "service": str}.
    """
    if not ports:
        # still record the host as seen
        ports = []
    with _Lock():
        data = _read()
        hosts = data.setdefault("hosts", {})
        entry = hosts.setdefault(host, {"ports": {}, "hostname": hostname})
        if hostname:
            entry["hostname"] = hostname
        for p in ports:
            key = f"{p['port']}/{p.get('proto', 'tcp')}"
            entry["ports"][key] = {
                "port": int(p["port"]),
                "proto": p.get("proto", "tcp"),
                "state": p.get("state", "open"),
                "service": (p.get("service") or "").strip(),
            }
        entry["last_seen"] = time.time()
        _write(data)


def all_hosts() -> dict[str, Any]:
    return _read().get("hosts", {})


# -- facts (environment knowledge base) ------------------------------------

def set_fact(key: str, value: str) -> None:
    """Record a global engagement fact (e.g. the AD domain)."""
    if not value:
        return
    with _Lock():
        data = _read()
        data.setdefault("facts", {})[key] = value
        _write(data)


def get_fact(key: str) -> Optional[str]:
    return _read().get("facts", {}).get(key)


def facts() -> dict[str, str]:
    return dict(_read().get("facts", {}))


def del_fact(key: str) -> None:
    with _Lock():
        data = _read()
        data.get("facts", {}).pop(key, None)
        _write(data)


def clear_facts() -> None:
    with _Lock():
        data = _read()
        data["facts"] = {}
        _write(data)


def set_host_fact(host: str, key: str, value: str) -> None:
    if not value:
        return
    with _Lock():
        data = _read()
        h = data.setdefault("hosts", {}).setdefault(host, {"ports": {}})
        h.setdefault("facts", {})[key] = value
        _write(data)


def service_matrix(open_only: bool = True) -> list[dict]:
    """Group discoveries by service → the hosts exposing it.

    Returns rows: {"service", "ports": sorted[int], "hosts": [ {host, port} ],
    "count"}, sorted by descending host count then service name.
    """
    groups: dict[str, dict] = {}
    for host, entry in all_hosts().items():
        for pk, p in entry.get("ports", {}).items():
            if open_only and p.get("state") != "open":
                continue
            svc = p.get("service") or f"port-{p['port']}"
            g = groups.setdefault(svc, {"service": svc, "hosts": [],
                                        "ports": set()})
            g["hosts"].append({"host": host, "port": p["port"]})
            g["ports"].add(p["port"])
    rows = []
    for g in groups.values():
        rows.append({
            "service": g["service"],
            "ports": sorted(g["ports"]),
            "hosts": sorted(g["hosts"], key=lambda h: _ipkey(h["host"])),
            "count": len({h["host"] for h in g["hosts"]}),
        })
    rows.sort(key=lambda r: (-r["count"], r["service"]))
    return rows


def host_summary() -> list[dict]:
    """One row per host: {host, hostname, open_ports:[int], services:[str]}."""
    out = []
    for host, entry in all_hosts().items():
        ports = [p for p in entry.get("ports", {}).values()
                 if p.get("state") == "open"]
        out.append({
            "host": host,
            "hostname": entry.get("hostname") or "",
            "open_ports": sorted(p["port"] for p in ports),
            "services": sorted({p["service"] for p in ports if p["service"]}),
        })
    out.sort(key=lambda r: _ipkey(r["host"]))
    return out


def clear() -> None:
    with _Lock():
        _write({"hosts": {}})


def _ipkey(host: str):
    """Sort IPs numerically; fall back to string for hostnames."""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts))
    return (1, host)
