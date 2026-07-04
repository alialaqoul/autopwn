# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""Lightweight HTTP fingerprinting — dependency-free web-service recon.

Fetches the root of a web service and reports status, server banner, title,
and security-relevant headers. A safe, passive first look before heavier web
tooling (nuclei, ZAP) is brought in.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from .base import Tool, ToolContext, ToolResult

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_SEC_HEADERS = [
    "content-security-policy", "strict-transport-security",
    "x-frame-options", "x-content-type-options", "server",
    "x-powered-by", "set-cookie",
]


class HttpProbeTool(Tool):
    category = "web"
    name = "http_probe"
    description = (
        "Fetch a URL and report HTTP status, server/technology banners, page "
        "title, and presence/absence of security headers. Passive recon."
    )
    active = True  # sends one HTTP request
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "Full URL, e.g. http://10.0.0.5:8080/"},
        },
        "required": ["url"],
    }

    def run(self, ctx: ToolContext, **kwargs: Any) -> ToolResult:
        url = kwargs["url"]
        host = httpx.URL(url).host
        self._authorize(ctx, host)

        try:
            resp = httpx.get(url, timeout=15, follow_redirects=True,
                             verify=False)
        except httpx.RequestError as e:
            return ToolResult(ok=False, summary=f"Request to {url} failed: {e}")

        title_m = _TITLE.search(resp.text or "")
        title = title_m.group(1).strip()[:120] if title_m else ""
        present = {h: resp.headers[h] for h in _SEC_HEADERS if h in resp.headers}
        missing = [h for h in _SEC_HEADERS[:4] if h not in resp.headers]

        lines = [f"HTTP {resp.status_code} {url} (final: {resp.url})"]
        if title:
            lines.append(f"title: {title}")
        for h, v in present.items():
            lines.append(f"{h}: {v[:120]}")
        if missing:
            lines.append(f"missing security headers: {', '.join(missing)}")

        return ToolResult(
            ok=True,
            summary=f"{url} -> HTTP {resp.status_code}"
                    + (f", server={present.get('server')}" if 'server' in present else ""),
            data={"status": resp.status_code, "title": title,
                  "headers": present, "missing_headers": missing},
            raw_output="\n".join(lines),
        )
