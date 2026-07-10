#!/usr/bin/env python3
# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Persistent interactive-session wrapper (authorized testing only).

Runs a real interactive client (evil-winrm / impacket-psexec) attached to a
pseudo-terminal, so it behaves exactly like a hands-on shell — the remote prompt,
ANSI colours, tab-completion, arrow-key history and Ctrl+C all work. Raw terminal
bytes are appended to a log the web console tails; the raw keystrokes the operator
types are base64-encoded one-per-line in a .cmd file and written straight to the
PTY master.  argv: <client-argv-json> <logfile> <cmdfile> [cols] [rows].
"""
import base64
import json
import os
import subprocess
import sys
import threading
import time


def _log_bytes(path, data: bytes) -> None:
    try:
        with open(path, "ab") as f:
            f.write(data)
    except OSError:
        pass


def _pump_cmds(cmdf, write_fn) -> None:
    """Tail the .cmd file; base64-decode each complete (newline-terminated) line
    and hand the raw bytes to write_fn. Returns once write_fn fails (PTY closed)."""
    sent = 0
    while True:
        try:
            if os.path.exists(cmdf):
                lines = open(cmdf, encoding="utf-8", errors="replace").read().split("\n")[:-1]
                while sent < len(lines):
                    try:
                        write_fn(base64.b64decode(lines[sent]))
                    except (OSError, ValueError):
                        return
                    sent += 1
        except OSError:
            pass
        time.sleep(0.03)


def _run_posix(argv, logf, cmdf, cols, rows) -> int:
    import pty, struct, fcntl, termios
    master, slave = pty.openpty()
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass
    env = dict(os.environ, TERM="xterm-256color")
    try:
        p = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                             start_new_session=True, env=env, close_fds=True)
    except FileNotFoundError as e:
        _log_bytes(logf, f"[!] client not found: {e}\r\n".encode())
        os.close(master); os.close(slave); return 1
    except OSError as e:
        _log_bytes(logf, f"[!] cannot start client: {e}\r\n".encode())
        os.close(master); os.close(slave); return 1
    os.close(slave)

    def reader():
        while True:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            _log_bytes(logf, data)

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=_pump_cmds, args=(cmdf, lambda b: os.write(master, b)),
                     daemon=True).start()
    p.wait()
    _log_bytes(logf, b"\r\n[*] session closed\r\n")
    try:
        os.close(master)
    except OSError:
        pass
    return 0


def _run_windows(argv, logf, cmdf) -> int:
    # No PTY on Windows — fall back to a raw byte pipe (dev only; the console is
    # deployed on Linux where the PTY path above gives the real experience).
    env = dict(os.environ, TERM="dumb", PYTHONUNBUFFERED="1")
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=0, env=env)
    except OSError as e:
        _log_bytes(logf, f"[!] cannot start client: {e}\r\n".encode())
        return 1

    def reader():
        while True:
            data = p.stdout.read(4096)
            if not data:
                break
            _log_bytes(logf, data)

    def _win_write(b):
        p.stdin.write(b); p.stdin.flush()

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=_pump_cmds, args=(cmdf, _win_write), daemon=True).start()
    p.wait()
    _log_bytes(logf, b"\r\n[*] session closed\r\n")
    return 0


def main() -> int:
    if len(sys.argv) < 4:
        return 2
    argv = json.loads(sys.argv[1])
    logf, cmdf = sys.argv[2], sys.argv[3]
    cols = int(sys.argv[4]) if len(sys.argv) > 4 else 120
    rows = int(sys.argv[5]) if len(sys.argv) > 5 else 34
    _log_bytes(logf, f"[*] opening session: {argv[0]} → {argv[-1] if argv else ''}\r\n".encode())
    if os.name == "posix":
        return _run_posix(argv, logf, cmdf, cols, rows)
    return _run_windows(argv, logf, cmdf)


if __name__ == "__main__":
    raise SystemExit(main())
