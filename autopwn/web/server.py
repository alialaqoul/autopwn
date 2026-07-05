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
    mode: str = ""          # "ai" (LLM agent) | "playbook" (deterministic autorun)
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
    from ..tools import custom as custom_tools
    from . import sessions
    sessions.configure(cfg.log_dir, cfg.scope_file)

    def _sess() -> dict:
        return sessions.current()

    def _ld() -> str:
        """Point the shared store/jobs/tools at the current session and return
        its directory. Cheap + idempotent — safe to call per request."""
        s = _sess()
        store.configure(f"{s['dir']}/results.json")
        jobs.configure(s["dir"])
        custom_tools.configure(s["dir"])
        from ..llm import calllog
        calllog.configure(f"{s['dir']}/ai_calls.jsonl")
        return s["dir"]

    def _scope() -> Scope:
        return Scope.load(_sess()["scope"])

    def _session_args() -> list:
        """Global CLI overrides so a launched job writes into the current session."""
        s = _sess()
        return ["--log-dir", s["dir"], "--scope-file", s["scope"]]

    _ld()  # activate the current session at startup

    app = FastAPI(title="Autopwn Console", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def _session_context(request, call_next):
        _ld()  # every request sees the currently-selected session's data
        resp = await call_next(request)
        # Never serve a stale console: always revalidate the SPA assets.
        path = request.url.path
        if path == "/" or path.startswith("/static"):
            resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return resp

    # ---- page ------------------------------------------------------------- #
    @app.get("/", response_class=HTMLResponse)
    def index():
        return (STATIC_DIR / "index.html").read_text(encoding="utf-8")

    # ---- sessions --------------------------------------------------------- #
    @app.get("/api/sessions")
    def get_sessions():
        return {"current": _sess()["name"], "sessions": sessions.list_sessions()}

    @app.post("/api/sessions")
    def create_session(body: dict):
        try:
            s = sessions.create((body or {}).get("name", ""))
        except ValueError as e:
            raise HTTPException(400, str(e))
        except FileExistsError:
            raise HTTPException(409, "A session with that name already exists.")
        sessions.set_current(s["name"])
        return {"current": s["name"], "sessions": sessions.list_sessions()}

    @app.post("/api/sessions/select")
    def select_session(body: dict):
        try:
            sessions.set_current((body or {}).get("name", ""))
        except KeyError:
            raise HTTPException(404, "Session not found.")
        return {"current": _sess()["name"], "sessions": sessions.list_sessions()}

    @app.post("/api/sessions/{name}/clear")
    def clear_session(name: str):
        try:
            sessions.clear(name)
        except KeyError:
            raise HTTPException(404, "Session not found.")
        return {"cleared": name, "sessions": sessions.list_sessions()}

    @app.delete("/api/sessions/{name}")
    def remove_session(name: str):
        try:
            sessions.delete(name)
        except ValueError as e:
            raise HTTPException(400, str(e))
        except KeyError:
            raise HTTPException(404, "Session not found.")
        return {"current": _sess()["name"], "sessions": sessions.list_sessions()}

    # ---- settings (AI / model) ------------------------------------------- #
    @app.get("/api/settings")
    def get_settings():
        c = Config.load(config_path)
        return {
            "ai_enabled": c.ai_enabled,
            "llm": {
                "provider": c.llm.provider, "model": c.llm.model,
                "base_url": c.llm.base_url or "", "has_api_key": bool(c.llm.api_key),
                "temperature": c.llm.temperature, "max_tokens": c.llm.max_tokens,
                "embed_model": c.llm.embed_model,
                "request_timeout": c.llm.request_timeout,
            },
            "agent": {
                "max_steps": c.agent.max_steps,
                "confirm_active_actions": c.agent.confirm_active_actions,
                "use_kb": c.agent.use_kb, "prime_recon": c.agent.prime_recon,
            },
        }

    @app.put("/api/settings")
    def put_settings(body: dict):
        c = Config.load(config_path)
        if "ai_enabled" in body:
            c.ai_enabled = bool(body["ai_enabled"])
        llm = body.get("llm", {}) or {}
        for k in ("provider", "model", "embed_model"):
            if k in llm and llm[k] != "":
                setattr(c.llm, k, str(llm[k]))
        if "base_url" in llm:
            c.llm.base_url = str(llm["base_url"]) or None
        # only overwrite the API key when a new one is actually provided
        if llm.get("api_key"):
            c.llm.api_key = str(llm["api_key"])
        for k, cast in (("temperature", float), ("request_timeout", float),
                        ("max_tokens", int)):
            if k in llm and llm[k] not in ("", None):
                try:
                    setattr(c.llm, k, cast(llm[k]))
                except (TypeError, ValueError):
                    pass
        ag = body.get("agent", {}) or {}
        if "max_steps" in ag and ag["max_steps"] not in ("", None):
            try:
                c.agent.max_steps = int(ag["max_steps"])
            except (TypeError, ValueError):
                pass
        for k in ("confirm_active_actions", "use_kb", "prime_recon"):
            if k in ag:
                setattr(c.agent, k, bool(ag[k]))
        c.save(config_path)
        return get_settings()

    @app.post("/api/settings/test-ai")
    def test_ai():
        """Ping the configured LLM with a tiny request; report status + latency."""
        from ..llm.factory import build_provider
        from ..llm.base import Message
        c = Config.load(config_path)
        c.llm.request_timeout = min(float(c.llm.request_timeout or 30), 30)
        info = {"model": c.llm.model, "provider": c.llm.provider}
        t0 = time.monotonic()
        try:
            provider = build_provider(c.llm)
            info["base_url"] = provider.base_url
            provider.max_tokens = 8
            comp = provider.chat([Message(role="user",
                                          content="Reply with the single word: pong")])
            info.update(ok=True, latency_ms=int((time.monotonic() - t0) * 1000),
                        reply=(comp.content or "").strip()[:120])
        except Exception as e:
            info.update(ok=False, latency_ms=int((time.monotonic() - t0) * 1000),
                        error=str(e)[:400])
        return info

    @app.get("/api/ai-log")
    def ai_log():
        from ..llm import calllog
        return calllog.tail(f"{_ld()}/ai_calls.jsonl", n=200)

    # ---- engagement snapshot --------------------------------------------- #
    @app.get("/api/summary")
    def summary():
        sc = _scope()
        hosts = store.host_summary()
        services = store.service_matrix()
        facts = store.facts()
        running = sum(1 for j in jobs.list_jobs(_ld())
                      if j.get("status") == "running")
        return {
            "engagement": sc.engagement,
            "authorized_by": sc.authorized_by,
            "expires": sc.expires,
            "ai_enabled": Config.load(config_path).ai_enabled,
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

    @app.get("/api/vars")
    def get_vars():
        """Full canonical variable set (mirrors the CLI `vars` view): every known
        variable with its description and current value, base_dn derived from the
        domain, plus any extra harvested facts outside the canonical set."""
        from ..facts import CANONICAL, base_dn_from_domain
        f = store.facts()
        rows = []
        for name, desc in CANONICAL.items():
            val = f.get(name, "")
            derived = False
            if not val and name == "base_dn" and f.get("domain"):
                val = base_dn_from_domain(f["domain"])
                derived = True
            secret = name in ("password", "nthash")
            rows.append({"name": name, "description": desc, "value": val,
                         "set": bool(f.get(name)), "derived": derived,
                         "secret": secret})
        extra = [{"name": k, "value": v} for k, v in f.items()
                 if k not in CANONICAL]
        return {"canonical": rows, "extra": extra}

    @app.get("/api/playbook-schema")
    def playbook_schema():
        from .. import playbooks as pb
        return pb.SCHEMA

    @app.get("/api/playbooks")
    def get_playbooks():
        from .. import playbooks as pb
        return pb.annotate(store.all_hosts(), store.service_matrix(),
                           store.facts(), _ld())

    @app.get("/api/playbooks/{pb_id}")
    def get_playbook(pb_id: str):
        from .. import playbooks as pb
        for p in pb.load(_ld()):
            if p.get("id") == pb_id:
                return p
        raise HTTPException(404, "Playbook not found.")

    @app.put("/api/playbooks/{pb_id}")
    def put_playbook(pb_id: str, body: dict):
        from .. import playbooks as pb
        if not isinstance(body, dict) or not body.get("id"):
            raise HTTPException(400, "Playbook must be an object with an 'id'.")
        books = pb.load(_ld())
        idx = next((i for i, p in enumerate(books) if p.get("id") == pb_id), None)
        if idx is None:
            raise HTTPException(404, "Playbook not found.")
        # a rename must not collide with another playbook's id
        if body["id"] != pb_id and any(p.get("id") == body["id"] for p in books):
            raise HTTPException(409, f"Another playbook already uses id '{body['id']}'.")
        books[idx] = body
        pb.save(_ld(), books)
        return body

    @app.post("/api/playbooks")
    def create_playbook(body: dict):
        from .. import playbooks as pb
        if not isinstance(body, dict) or not body.get("id"):
            raise HTTPException(400, "Playbook must be an object with an 'id'.")
        books = pb.load(_ld())
        if any(p.get("id") == body["id"] for p in books):
            raise HTTPException(409, f"Playbook id '{body['id']}' already exists.")
        books.append(body)
        pb.save(_ld(), books)
        return body

    @app.delete("/api/playbooks/{pb_id}")
    def delete_playbook(pb_id: str):
        from .. import playbooks as pb
        books = pb.load(_ld())
        kept = [p for p in books if p.get("id") != pb_id]
        if len(kept) == len(books):
            raise HTTPException(404, "Playbook not found.")
        pb.save(_ld(), kept)
        return {"deleted": pb_id}

    @app.post("/api/playbooks/reset")
    def reset_playbooks():
        from .. import playbooks as pb
        return pb.reset(_ld())

    @app.post("/api/playbooks/{pb_id}/run")
    def run_playbook(pb_id: str, body: dict):
        """Launch the playbook's macro tool as a detached job against a target."""
        from .. import playbooks as pb
        target = (body or {}).get("target", "").strip()
        if not target:
            raise HTTPException(400, "A target is required to run a playbook.")
        book = next((p for p in pb.load(_ld()) if p.get("id") == pb_id), None)
        if not book:
            raise HTTPException(404, "Playbook not found.")
        tool = (book.get("run") or {}).get("tool", "").strip()
        if not tool:
            raise HTTPException(400, "This playbook has no runnable macro tool.")
        sc = _scope()
        if sc.is_denied(target):
            raise HTTPException(403, f"'{target}' is on the deny list.")
        if not sc.is_allowed(target):
            sc.add_allow(target)
        argv = _session_args() + ["run", "--tool", tool, "--set", f"target={target}"]
        job_id = jobs.start(argv, label=f"{pb_id} {target}", log_dir=_ld())
        return {"id": job_id, "status": "running", "tool": tool, "args": argv}

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
        return jobs.list_jobs(_ld())

    @app.post("/api/jobs/agent")
    def launch_agent(body: AgentLaunch):
        ai_enabled = Config.load(config_path).ai_enabled
        # Default mode follows the AI switch: deterministic when AI is off.
        mode = (body.mode or ("ai" if ai_enabled else "playbook")).strip()
        target = (body.target or "").strip()
        objective = (body.objective or "").strip()

        if mode == "ai" and not ai_enabled:
            raise HTTPException(403, "AI is disabled in Settings. Use the "
                                "Playbook (no-AI) mode, or enable AI.")
        if mode == "playbook" and not target:
            raise HTTPException(400, "Playbook autopilot needs a target/range.")
        if mode == "ai" and not target and not objective:
            raise HTTPException(400, "Provide a target (autopilot) or an objective.")

        # Authorize each target (single IP, comma/space list, range, or CIDR).
        sc = _scope()
        for t in target.replace(",", " ").split():
            if sc.is_denied(t):
                raise HTTPException(403, f"'{t}' is on the deny list.")
            if not sc.is_allowed(t):
                sc.add_allow(t)

        cmd = "autorun" if mode == "playbook" else "agent"
        argv = _session_args() + [cmd]
        pairs = [("--target", target)]
        if mode == "ai":
            pairs.append(("--objective", objective))
        pairs += [
            ("--username", body.username), ("--password", body.password),
            ("--domain", body.domain), ("--hash", body.nt_hash),
            ("--engagement", body.engagement), ("--client", body.client),
            ("--assessor", body.assessor), ("--authorized-by", body.authorized_by),
            ("--report-format", body.report_format),
        ]
        for flag, val in pairs:
            if val:
                argv += [flag, val]

        label = f"{'playbook' if mode == 'playbook' else 'agent'} {target or objective[:24]}"
        job_id = jobs.start(argv, label=label, log_dir=_ld())
        return {"id": job_id, "status": "running", "mode": mode, "args": argv}

    @app.post("/api/jobs/{job_id}/stop")
    def stop_job(job_id: str):
        ok = jobs.stop(job_id, _ld())
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
                running = jobs.is_running(job_id, _ld())
                if not running and not chunk and idle >= 2:
                    status = "finished"
                    meta = _job_meta(_ld(), job_id)
                    if meta:
                        status = meta.get("status", "finished")
                    yield f"event: end\ndata: {status}\n\n"
                    break
                await asyncio.sleep(0.6)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # ---- findings / results ---------------------------------------------- #
    @app.get("/api/findings")
    def get_findings():
        """Surface what runs discovered: security findings, recovered credentials,
        and enumerated usernames — built from the store plus the latest transcript."""
        from ..analysis import build_findings
        ld = Path(_ld())
        hosts = store.all_hosts()
        facts = store.facts()
        sess = sorted(ld.glob("session-*.json"))
        transcript = []
        if sess:
            try:
                transcript = json.loads(sess[-1].read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                transcript = []
        from ..analysis import extract_results
        findings = build_findings(hosts, facts, transcript, str(ld))
        # Credentials/users come ONLY from actual tool output (the transcript) —
        # not from the transient username/password facts, which mutate during a
        # run and can pair values that were never a real login.
        _res = extract_results(transcript)
        return {"findings": findings, "credentials": _res["credentials"],
                "users": _res["users"],
                "transcript": sess[-1].name if sess else None}

    # ---- tools (actions) -------------------------------------------------- #
    def _introspect_tool(tool, custom_names) -> dict:
        spec = getattr(tool, "_spec", None)
        info = {
            "name": tool.name,
            "description": getattr(tool, "description", ""),
            "category": getattr(tool, "category", "misc"),
            "active": getattr(tool, "active", False),
            "parameters": getattr(tool, "parameters", {}),
            "custom": tool.name in custom_names,
        }
        try:
            info["installed"] = tool.available()
        except Exception:
            info["installed"] = True
        if spec is None:
            info.update(binary="(native module)", kind="native",
                        template=None, programmatic=True, harvest=[])
        else:
            programmatic = spec.build_args is not None
            harvest = [{"var": r.var, "regex": r.regex, "scope": r.scope,
                        "multi": r.multi} for r in (spec.harvest or [])]
            info.update(
                binary=spec.binary, kind="custom" if info["custom"] else "catalog",
                programmatic=programmatic,
                template=None if programmatic else custom_tools.command_template(spec),
                subcommand=spec.subcommand, positional=spec.positional,
                flags=spec.flags, fixed=spec.fixed, harvest=harvest,
                install_hint=spec.install_hint)
        return info

    @app.get("/api/tools")
    def list_tools():
        from ..tools.registry import default_registry
        reg = default_registry(cfg.tools, include_unavailable=True)
        custom_names = {d.get("name") for d in custom_tools.load()}
        tools = [_introspect_tool(t, custom_names) for t in reg.all()]
        tools.sort(key=lambda t: (not t["custom"], t["category"], t["name"]))
        return tools

    @app.get("/api/tools/custom")
    def list_custom_tools():
        return custom_tools.load()

    @app.get("/api/tools/custom/{name}")
    def get_custom_tool(name: str):
        for d in custom_tools.load():
            if d.get("name") == name:
                return d
        raise HTTPException(404, "Custom tool not found.")

    def _valid_tool(body: dict):
        if not isinstance(body, dict) or not body.get("name") or not body.get("binary"):
            raise HTTPException(400, "A tool needs at least a 'name' and 'binary'.")
        if not str(body["name"]).replace("_", "").replace("-", "").isalnum():
            raise HTTPException(400, "Tool name must be alphanumeric (with _ or -).")

    @app.post("/api/tools/custom")
    def create_custom_tool(body: dict):
        _valid_tool(body)
        tools = custom_tools.load()
        if any(t.get("name") == body["name"] for t in tools):
            raise HTTPException(409, f"Custom tool '{body['name']}' already exists.")
        tools.append(body)
        custom_tools.save(tools)
        return body

    @app.put("/api/tools/custom/{name}")
    def update_custom_tool(name: str, body: dict):
        _valid_tool(body)
        tools = custom_tools.load()
        idx = next((i for i, t in enumerate(tools) if t.get("name") == name), None)
        if idx is None:
            raise HTTPException(404, "Custom tool not found.")
        if body["name"] != name and any(t.get("name") == body["name"] for t in tools):
            raise HTTPException(409, f"Another tool already uses '{body['name']}'.")
        tools[idx] = body
        custom_tools.save(tools)
        return body

    @app.delete("/api/tools/custom/{name}")
    def delete_custom_tool(name: str):
        tools = custom_tools.load()
        kept = [t for t in tools if t.get("name") != name]
        if len(kept) == len(tools):
            raise HTTPException(404, "Custom tool not found.")
        custom_tools.save(kept)
        return {"deleted": name}

    # ---- reports ---------------------------------------------------------- #
    @app.get("/api/reports")
    def list_reports():
        out = []
        log_dir = Path(_ld())
        if log_dir.exists():
            for p in sorted(log_dir.glob("session-*"), reverse=True):
                if p.suffix in _REPORT_SUFFIXES:
                    st = p.stat()
                    out.append({"name": p.name, "format": p.suffix.lstrip("."),
                                "size": st.st_size, "modified": st.st_mtime})
        return out

    @app.get("/reports/{name}")
    def get_report(name: str, download: bool = False):
        # prevent path traversal: only serve files directly in the session dir
        log_dir = Path(_ld())
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
