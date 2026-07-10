#!/usr/bin/env python3
# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Minimal reverse-shell handler for AUTHORIZED TESTING ONLY.

Binds a TCP port, streams the connecting shell's raw output to a log file, and
forwards the operator's raw keystrokes — base64-encoded one-per-line in a .cmd
file — straight to the socket. Behaves like `nc -lvnp <port>` wired to the web
console, so the remote shell's own prompt and interactivity come through.
argv = <port> <logfile> <cmdfile>.
"""
import base64
import os
import socket
import sys
import threading
import time


def _log_bytes(path, data: bytes) -> None:
    try:
        with open(path, "ab") as f:
            f.write(data)
    except OSError:
        pass


def main() -> int:
    if len(sys.argv) < 4:
        return 2
    port, logf, cmdf = int(sys.argv[1]), sys.argv[2], sys.argv[3]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
    except OSError as e:
        _log_bytes(logf, f"[!] cannot listen on {port}: {e}\r\n".encode())
        return 1
    _log_bytes(logf, f"[*] listening on 0.0.0.0:{port} — waiting for a reverse shell…\r\n".encode())

    try:
        conn, addr = srv.accept()
    except OSError:
        return 1
    _log_bytes(logf, f"[+] connection from {addr[0]}:{addr[1]}\r\n".encode())
    alive = {"v": True}

    def reader():
        while alive["v"]:
            try:
                data = conn.recv(65536)
            except OSError:
                break
            if not data:
                _log_bytes(logf, b"\r\n[*] connection closed by peer\r\n")
                alive["v"] = False
                break
            _log_bytes(logf, data)

    threading.Thread(target=reader, daemon=True).start()

    sent = 0
    while alive["v"]:
        try:
            if os.path.exists(cmdf):
                # complete (newline-terminated) base64 chunks only
                lines = open(cmdf, encoding="utf-8", errors="replace").read().split("\n")[:-1]
                while sent < len(lines):
                    try:
                        conn.sendall(base64.b64decode(lines[sent]))
                    except (OSError, ValueError):
                        alive["v"] = False
                        break
                    sent += 1
        except OSError:
            pass
        time.sleep(0.03)
    try:
        conn.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
