# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Parsers that turn nmap output into structured host/port records.

Two formats are supported:
  * greppable (`nmap -oG`) — one line per host, best for range sweeps.
  * normal (default `nmap` stdout) — the "PORT STATE SERVICE" table, so results
    from ordinary scans (including those the agent runs) can be recorded too.

Both return: list of (host, hostname, [ {port, proto, state, service} ]).
"""
from __future__ import annotations

import re

Record = tuple[str, str, list[dict]]

# greppable: "Host: 10.0.0.1 (name)\tPorts: 22/open/tcp//ssh///, 389/open/tcp//ldap///"
_G_HOST = re.compile(r"Host:\s+(\S+)\s+\(([^)]*)\)")
_N_HOSTLINE = re.compile(r"Nmap scan report for\s+(.+)")
_N_PORTLINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$")


def parse_grepable(text: str) -> list[Record]:
    out: list[Record] = []
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        m = _G_HOST.search(line)
        if not m:
            continue
        host, hostname = m.group(1), m.group(2)
        ports_part = line.split("Ports:", 1)[1]
        ports: list[dict] = []
        for spec in ports_part.split(","):
            f = spec.strip().split("/")
            # port/state/proto/owner/service/rpc/version
            if len(f) < 5:
                continue
            try:
                port = int(f[0])
            except ValueError:
                continue
            ports.append({"port": port, "state": f[1], "proto": f[2],
                          "service": f[4]})
        out.append((host, hostname, ports))
    return out


def parse_normal(text: str) -> list[Record]:
    out: list[Record] = []
    host: str | None = None
    hostname = ""
    ports: list[dict] = []

    def flush():
        if host is not None:
            out.append((host, hostname, ports))

    for line in text.splitlines():
        hm = _N_HOSTLINE.match(line.strip())
        if hm:
            flush()
            target = hm.group(1).strip()
            # "hostname (1.2.3.4)" or just "1.2.3.4"
            paren = re.search(r"\(([\d.]+)\)", target)
            if paren:
                host = paren.group(1)
                hostname = target.split("(")[0].strip()
            else:
                host = target
                hostname = ""
            ports = []
            continue
        pm = _N_PORTLINE.match(line.strip())
        if pm and host is not None:
            ports.append({"port": int(pm.group(1)), "proto": pm.group(2),
                          "state": pm.group(3),
                          "service": pm.group(4).strip().split()[0]
                          if pm.group(4).strip() else ""})
    flush()
    return out


def record_to_store(records: list[Record]) -> int:
    """Persist parsed records into the shared store. Returns host count."""
    from . import store
    n = 0
    for host, hostname, ports in records:
        store.record_ports(host, ports, hostname=hostname or None)
        n += 1
    return n
