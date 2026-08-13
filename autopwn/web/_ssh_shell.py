# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Detached interactive SSH session for the web console (Linux targets).

The WinRM/SMB sessions run a client (evil-winrm / impacket-psexec) under a PTY
(_shell_proc.py). SSH can't use that on an offline box without sshpass, so this
wrapper drives an interactive SSH shell with paramiko directly, using the SAME
sidecar-file protocol the console already tails:

  * raw terminal bytes are appended to <logfile>  (the SSE stream base64-frames them)
  * base64-encoded keystrokes are read from <cmdfile>, one per line, and sent to
    the channel verbatim (Enter, Ctrl-C, arrows, Tab all pass through).

argv:  <host> <port> <user> <secret> <auth> <logfile> <cmdfile> [cols] [rows]
"""
from __future__ import annotations

import base64
import glob
import os
import sys
import threading
import time


def _import_paramiko():
    try:
        import paramiko
        return paramiko
    except ImportError:
        pass
    for pat in ("/usr/lib/python3/dist-packages", "/usr/lib/python3/site-packages",
                "/usr/local/lib/python3*/dist-packages", "/usr/local/lib/python3*/site-packages"):
        for d in glob.glob(pat):
            if os.path.isdir(os.path.join(d, "paramiko")) and d not in sys.path:
                sys.path.append(d)
    try:
        import paramiko
        return paramiko
    except ImportError:
        return None


def main() -> None:
    a = sys.argv
    host, port, user, secret, auth, logf, cmdf = a[1], a[2], a[3], a[4], a[5], a[6], a[7]
    cols = int(a[8]) if len(a) > 8 else 120
    rows = int(a[9]) if len(a) > 9 else 34
    port = int(port or 22)

    def wlog(b: bytes) -> None:
        with open(logf, "ab") as f:
            f.write(b)

    paramiko = _import_paramiko()
    if paramiko is None:
        wlog(b"[!] paramiko is not available for SSH sessions.\r\n")
        return

    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kw = dict(hostname=host, port=port, username=user or None,
                  look_for_keys=False, allow_agent=False, timeout=20,
                  banner_timeout=20, auth_timeout=20)
        # 'hash' auth is meaningless over SSH; treat the secret as a key path if it
        # points at a file, otherwise a password.
        if auth != "hash" or not secret:
            if secret and os.path.isfile(secret):
                kw["key_filename"] = secret
            else:
                kw["password"] = secret or None
        cli.connect(**kw)
    except Exception as e:                       # noqa: BLE001 — surface to the terminal
        wlog(f"[!] SSH connect failed: {type(e).__name__}: {e}\r\n".encode())
        return

    chan = cli.invoke_shell(term="xterm", width=cols, height=rows)
    wlog(f"[*] SSH session to {user}@{host}:{port}\r\n".encode())

    def reader() -> None:
        while not chan.closed:
            try:
                if chan.recv_ready():
                    data = chan.recv(65536)
                    if not data:
                        break
                    wlog(data)
                else:
                    time.sleep(0.03)
            except Exception:
                break

    threading.Thread(target=reader, daemon=True).start()

    pos = 0
    while not chan.closed:
        try:
            with open(cmdf, "r", encoding="utf-8") as f:
                f.seek(pos)
                new = f.read()
                pos = f.tell()
        except FileNotFoundError:
            new = ""
        for line in new.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                chan.send(base64.b64decode(line))
            except Exception:
                pass
        time.sleep(0.08)
    try:
        cli.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
