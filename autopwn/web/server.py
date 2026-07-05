# Author: Ali Alaqoul <alialaqoul@gmail.com>
"""FastAPI application for the Autopwn web console.

The web layer is a thin, stateless view over the same on-disk engagement the
CLI uses: it reads hosts/services/facts from the shared results store, launches
the AI agent as a normal detached background job, streams that job's log live
over Server-Sent Events, and lists/serves the generated reports. Nothing here
re-implements engine logic — it wraps `store`, `jobs`, `report`, `Scope`.

Bootstrap is vendored under static/vendor, so the console has no external
network dependency and works on an isolated lab network.

NOTE: this module deliberately does NOT use `from __future__ import annotations`.
FastAPI resolves parameter annotations at route-registration time; since `Request`
is imported locally inside create_app(), stringized annotations would fail to
resolve and be mistaken for query params.
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from .. import jobs, store
from ..authorization import Scope
from ..config import Config

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"

# Report artifacts the agent auto-exports next to each session transcript.
_REPORT_SUFFIXES = (".html", ".docx", ".md")


# --------------------------------------------------------------------------- #
# request bodies
# --------------------------------------------------------------------------- #
class AgentLaunch(BaseModel):
    target: str = ""
    objective: str = ""
    username: str = ""
    password: str = ""
    domain: str = ""
    nt_hash: str = ""
    engagement: str = ""
    client: str = ""
    assessor: str = ""
    authorized_by: str = ""
    report_format: str = "html,docx,md"


class ScopeEntry(BaseModel):
    entry: str


class Fact(BaseModel):
    key: str
    value: str = ""


# --------------------------------------------------------------------------- #
# app factory
# --------------------------------------------------------------------------- #
def create_app(config_path: str = "config.yaml"):
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                                   PlainTextResponse, StreamingResponse)
    from fastapi.staticfiles import StaticFiles

    cfg = Config.load(config_path)
    log_dir = Path(cfg.log_dir)
    store.configure(f"{cfg.log_dir}/results.json")
    jobs.configure(cfg.log_dir)

    app = FastAPI(title="Autopwn Console", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _scope() -> Scope:
        return Scope.load(cfg.scope_file)

    # ---- page ------------------------------------------------------------- #
    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    # ---- engagement snapshot --------------------------------------------- #
    @app.get("/api/summary")
    def summary():
        sc = _scope()
        hosts = store.host_summary()
        services = store.service_matrix()
        facts = store.facts()
        running = sum(1 for j in jobs.list_jobs(cfg.log_dir)
                      if j.get("status") == "running")
        return {
            "engagement": sc.engagement,
            "authorized_by": sc.authorized_by,
            "expires": sc.expires,
            "scope": {"allow": sc.allow, "deny": sc.deny},
            "hosts": hosts,
            "services": services,
            "facts": facts,
            "counts": {
                "hosts": len(hosts),
                "open_ports": sum(len(h["open_ports"]) for h in hosts),
                "services": len(services),
                "running_jobs": running,
            },
        }

    @app.get("/api/hosts")
    def hosts():
        return store.host_summary()

    @app.get("/api/services")
    def services():
        return store.service_matrix()

    # ---- facts (domain, creds, notes) ------------------------------------ #
    @app.get("/api/facts")
    def get_facts():
        return store.facts()

    @app.post("/api/facts")
    def set_fact(f: Fact):
        if not f.key:
            raise HTTPException(400, "key required")
        store.set_fact(f.key, f.value)
        return store.facts()

    @app.delete("/api/facts/{key}")
    def del_fact(key: str):
        store.del_fact(key)
        return store.facts()

    # ---- scope ------------------------------------------------------------ #
    @app.get("/api/scope")
    def get_scope():
        sc = _scope()
        return {"engagement": sc.engagement, "authorized_by": sc.authorized_by,
                "expires": sc.expires, "allow": sc.allow, "deny": sc.deny}

    @app.post("/api/scope/allow")
    def scope_allow(e: ScopeEntry):
        sc = _scope()
        sc.add_allow(e.entry.strip())
        return {"allow": sc.allow, "deny": sc.deny}

    @app.post("/api/scope/deny")
    def scope_deny(e: ScopeEntry):
        sc = _scope()
        sc.add_deny(e.entry.strip())
        return {"allow": sc.allow, "deny": sc.deny}

    @app.delete("/api/scope/allow/{entry}")
    def scope_remove_allow(entry: str):
        sc = _scope()
        sc.remove_allow(entry)
        return {"allow": sc.allow, "deny": sc.deny}

    # ---- jobs ------------------------------------------------------------- #
    @app.get("/api/jobs")
    def list_jobs():
        return jobs.list_jobs(cfg.log_dir)

    @app.post("/api/jobs/agent")
    def launch_agent(body: AgentLaunch):
        target = (body.target or "").strip()
        objective = (body.objective or "").strip()
        if not target and not objective:
            raise HTTPException(400, "Provide a target (autopilot) or an objective.")

        # Authorize the target the same way the CLI does: auto-add unless denied.
        sc = _scope()
        if target:
            if sc.is_denied(target):
                raise HTTPException(403, f"'{target}' is on the deny list.")
            if not sc.is_allowed(target):
                sc.add_allow(target)

        # Build the detached `autopwn agent ...` argv, carrying creds + metadata
        # so authenticated / assumed-breach runs work from step one.
        argv = ["agent"]
        pairs = [
            ("--target", target), ("--objective", objective),
            ("--username", body.username), ("--password", body.password),
            ("--domain", body.domain), ("--hash", body.nt_hash),
            ("--engagement", body.engagement), ("--client", body.client),
            ("--assessor", body.assessor), ("--authorized-by", body.authorized_by),
            ("--report-format", body.report_format),
        ]
        for flag, val in pairs:
            if val:
                argv += [flag, val]

        job_id = jobs.start(argv, label=f"agent {target or objective[:24]}",
                            log_dir=cfg.log_dir)
        return {"id": job_id, "status": "running", "args": argv}

    @app.post("/api/jobs/{job_id}/stop")
    def stop_job(job_id: str):
        ok = jobs.stop(job_id, cfg.log_dir)
        if not ok:
            raise HTTPException(404, "Job not running or not found.")
        return {"id": job_id, "status": "stopped"}

    @app.get("/api/jobs/{job_id}/log", response_class=PlainTextResponse)
    def job_log(job_id: str):
        lp = jobs.log_path(job_id)
        if not lp.exists():
            raise HTTPException(404, "No log for that job.")
        return lp.read_text(encoding="utf-8", errors="replace")

    @app.get("/api/jobs/{job_id}/stream")
    async def job_stream(job_id: str, request: Request):
        """Server-Sent Events: replay the log, then follow it until the job ends."""
        lp = jobs.log_path(job_id)

        async def gen():
            pos = 0
            # wait briefly for the log file to appear
            for _ in range(60):
                if lp.exists():
                    break
                await asyncio.sleep(0.1)
            idle = 0
            while True:
                if await request.is_disconnected():
                    break
                chunk = ""
                if lp.exists():
                    with open(lp, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(pos)
                        chunk = f.read()
                        pos = f.tell()
                if chunk:
                    idle = 0
                    for line in chunk.splitlines():
                        # SSE frame; blank line terminates the event
                        yield f"data: {line}\n\n"
                else:
                    idle += 1
                running = jobs.is_running(job_id, cfg.log_dir)
                if not running and not chunk and idle >= 2:
                    status = "finished"
                    meta = _job_meta(cfg.log_dir, job_id)
                    if meta:
                        status = meta.get("status", "finished")
                    yield f"event: end\ndata: {status}\n\n"
                    break
                await asyncio.sleep(0.6)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # ---- reports ---------------------------------------------------------- #
    @app.get("/api/reports")
    def list_reports():
        out = []
        if log_dir.exists():
            for p in sorted(log_dir.glob("session-*"), reverse=True):
                if p.suffix in _REPORT_SUFFIXES:
                    st = p.stat()
                    out.append({"name": p.name, "format": p.suffix.lstrip("."),
                                "size": st.st_size, "modified": st.st_mtime})
        return out

    @app.get("/reports/{name}")
    def get_report(name: str, download: bool = False):
        # prevent path traversal: only serve files directly in log_dir
        p = (log_dir / name).resolve()
        if p.parent != log_dir.resolve() or not p.exists():
            raise HTTPException(404, "Report not found.")
        if p.suffix not in _REPORT_SUFFIXES:
            raise HTTPException(403, "Not a report file.")
        media = {"html": "text/html", "md": "text/markdown",
                 "docx": ("application/vnd.openxmlformats-officedocument."
                          "wordprocessingml.document")}[p.suffix.lstrip(".")]
        return FileResponse(str(p), media_type=media,
                            filename=name if download else None)

    return app


def _job_meta(log_dir, job_id: str) -> Optional[dict]:
    p = Path(log_dir) / "jobs" / f"{job_id}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------- #
# uvicorn entry point
# --------------------------------------------------------------------------- #
def run(host: str = "127.0.0.1", port: int = 8000,
        config_path: str = "config.yaml") -> None:
    try:
        import uvicorn
    except ImportError:  # pragma: no cover
        raise SystemExit("The web console needs FastAPI + uvicorn. Install with:\n"
                         "  pip install 'autopwn[web]'   (or: pip install fastapi uvicorn)")
    app = create_app(config_path)
    uvicorn.run(app, host=host, port=port, log_level="info")
