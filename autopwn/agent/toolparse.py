# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Fallback parser for models that emit tool calls as text.

Some local models (e.g. llama3.1 via Ollama) describe a tool call as JSON inside
the assistant's message content instead of using the structured tool_calls
field. This module recovers such calls so the agent still works with them.

Recognized shapes (optionally inside a ```json fenced block, with surrounding
prose):
    {"name": "nmap_scan", "parameters": {"target": "10.0.0.1"}}
    {"name": "nmap_scan", "arguments": {"target": "10.0.0.1"}}
    {"tool": "nmap_scan", "arguments": {...}}
"""
from __future__ import annotations

import json
import uuid
from typing import Iterable, Optional

from ..llm.base import ToolCall

_NAME_KEYS = ("name", "tool", "function")
_ARG_KEYS = ("parameters", "arguments", "args", "params")


def _iter_json_objects(text: str) -> Iterable[dict]:
    """Yield top-level JSON objects found anywhere in *text*.

    Scans for balanced {...} spans (respecting strings/escapes) and attempts to
    parse each. Tolerant of prose before/after and of ```json fences.
    """
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    chunk = text[start:i + 1]
                    try:
                        obj = json.loads(chunk)
                        if isinstance(obj, dict):
                            yield obj
                    except json.JSONDecodeError:
                        pass
                    start = -1


def _extract_name(obj: dict) -> Optional[str]:
    for k in _NAME_KEYS:
        v = obj.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _extract_args(obj: dict) -> dict:
    for k in _ARG_KEYS:
        v = obj.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _walk_calls(node: object):
    """Yield dicts that look like a tool call, recursing through wrappers.

    Handles bare objects, arrays, and nested shapes like
    {"functions": [ {"name": ...}, ... ]} or {"tool_calls": [...]}. Once a dict
    is recognized as a call (has a name key), its own arguments are not
    descended into.
    """
    if isinstance(node, dict):
        if _extract_name(node):
            yield node
            return
        for v in node.values():
            yield from _walk_calls(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_calls(item)


def parse_tool_calls(content: str, valid_names: set[str]) -> list[ToolCall]:
    """Return tool calls described in free text, restricted to known tools."""
    if not content:
        return []
    calls: list[ToolCall] = []
    seen: set[str] = set()
    for obj in _iter_json_objects(content):
        for cand in _walk_calls(obj):
            name = _extract_name(cand)
            if name not in valid_names:
                continue
            args = _extract_args(cand)
            # De-dupe identical calls the model may repeat in one message.
            key = f"{name}:{json.dumps(args, sort_keys=True)}"
            if key in seen:
                continue
            seen.add(key)
            calls.append(ToolCall(id=f"txt-{uuid.uuid4().hex[:8]}",
                                  name=name, arguments=args))
    return calls
