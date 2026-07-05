#!/usr/bin/env python3
# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Persistent interactive-session wrapper (authorized testing only).

Runs a real interactive client (evil-winrm / impacket-wmiexec), captures its
output to a log, and feeds it commands appended to a .cmd file — giving the web
console a stateful shell (cd/env persist), unlike a stateless per-command exec.
argv: <client-argv-json> <logfile> <cmdfile>.
"""
import json
import os
import subprocess
import sys
import threading
import time


def _log(path, msg):
    with open(path, "a", encoding="utf-8", errors="replace") as f:
        f.write(msg)


def main():
    if len(sys.argv) < 4:
        return 2
    argv = json.loads(sys.argv[1])
    logf, cmdf = sys.argv[2], sys.argv[3]
    _log(logf, f"[*] opening session: {argv[0]} → {argv[-1] if argv else ''}\n")
    # Force unbuffered/line-buffered child output — Python tools (wmiexec) block-
    # buffer stdout when piped, so without this their output never reaches us.
    env = dict(os.environ, TERM="dumb", PYTHONUNBUFFERED="1")
    from shutil import which as _which
    if os.name == "posix" and _which("stdbuf"):
        argv = ["stdbuf", "-oL", "-eL"] + argv
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=1, text=True, env=env)
    except FileNotFoundError as e:
        _log(logf, f"[!] client not found: {e}\n")
        return 1
    except OSError as e:
        _log(logf, f"[!] cannot start client: {e}\n")
        return 1

    def reader():
        try:
            for line in p.stdout:
                _log(logf, line)
        except Exception:
            pass
        _log(logf, "\n[*] session closed\n")

    threading.Thread(target=reader, daemon=True).start()

    sent = 0
    while p.poll() is None:
        try:
            if os.path.exists(cmdf):
                lines = open(cmdf, encoding="utf-8", errors="replace").read().split("\n")[:-1]
                while sent < len(lines):
                    try:
                        p.stdin.write(lines[sent] + "\n")
                        p.stdin.flush()
                    except (OSError, ValueError):
                        break
                    sent += 1
        except OSError:
            pass
        time.sleep(0.25)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
