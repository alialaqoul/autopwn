# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Safe external-command execution.

Commands are always passed as an argument list (never a shell string), with a
timeout and captured output. This avoids shell injection and keeps every
invocation auditable.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

# pipx / pip --user install tools here; it is often missing from a service's PATH,
# so search it explicitly (covers coercer, certipy, impacket, netexec, …).
_EXTRA_BIN = os.pathsep.join(
    p for p in (os.path.expanduser("~/.local/bin"), "/usr/local/bin")
    if os.path.isdir(p))


def _search_path() -> str:
    path = os.environ.get("PATH", "")
    return path + (os.pathsep + _EXTRA_BIN if _EXTRA_BIN else "")


class ToolNotInstalled(Exception):
    pass


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str]


def which(binary: str) -> str | None:
    return shutil.which(binary, path=_search_path())


def run_command(argv: list[str], timeout: int = 300,
                input_text: str | None = None) -> CommandResult:
    if not argv:
        raise ValueError("empty command")
    resolved = shutil.which(argv[0], path=_search_path())
    if resolved is None:
        raise ToolNotInstalled(
            f"'{argv[0]}' is not installed or not on PATH."
        )
    try:
        proc = subprocess.run(
            [resolved, *argv[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            returncode=124,
            stdout=(e.stdout or "") if isinstance(e.stdout, str) else "",
            stderr=f"timed out after {timeout}s",
            command=argv,
        )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr, argv)
