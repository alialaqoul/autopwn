#!/usr/bin/env python3
# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Minimal reverse-shell handler for AUTHORIZED TESTING ONLY.

Binds a TCP port, captures the connecting shell's output to a log file, and
forwards commands that the web console appends (one per line) to a .cmd file.
Deliberately simple (like `nc -lvnp <port>` with an input pipe) so the console
can drive it: argv = <port> <logfile> <cmdfile>.
"""
import os
import socket
import sys
import threading
import time


def _log(path, msg):
    with open(path, "a", encoding="utf-8", errors="replace") as f:
        f.write(msg)


def main():
    if len(sys.argv) < 4:
        return 2
    port, logf, cmdf = int(sys.argv[1]), sys.argv[2], sys.argv[3]

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
    except OSError as e:
        _log(logf, f"[!] cannot listen on {port}: {e}\n")
        return 1
    _log(logf, f"[*] listening on 0.0.0.0:{port} — waiting for a reverse shell…\n")

    try:
        conn, addr = srv.accept()
    except OSError:
        return 1
    _log(logf, f"[+] connection from {addr[0]}:{addr[1]}\n")
    alive = {"v": True}

    def reader():
        while alive["v"]:
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                _log(logf, "\n[*] connection closed by peer\n")
                alive["v"] = False
                break
            _log(logf, data.decode(errors="replace"))

    threading.Thread(target=reader, daemon=True).start()

    sent = 0
    while alive["v"]:
        try:
            if os.path.exists(cmdf):
                # complete (newline-terminated) commands only
                complete = open(cmdf, encoding="utf-8", errors="replace").read().split("\n")[:-1]
                while sent < len(complete):
                    try:
                        conn.sendall((complete[sent] + "\n").encode())
                    except OSError:
                        alive["v"] = False
                        break
                    sent += 1
        except OSError:
            pass
        time.sleep(0.3)
    try:
        conn.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
