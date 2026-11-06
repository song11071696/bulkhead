"""FastAPI app: Claude Code hook endpoint, generic check API, and the audit dashboard."""
from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import claude, runner, scenarios
from .clocked import ClockedClient
from .config import Settings
from .engine import Engine
from .store import Store

STATIC = Path(__file__).parent / "static"


def build_engine(db_path: Optional[str] = None, mode: Optional[str] = None) -> Engine:
    data_dir = Path(os.environ.get("BULKHEAD_DATA", ".bulkhead"))
    client = ClockedClient(mode=mode, ledger_path=data_dir / "credits.jsonl")
    store = Store(db_path or os.environ.get("BULKHEAD_DB", str(data_dir / "bulkhead.db")))
    return Engine(client, store, Settings())


class InboundReq(BaseModel):
    session_id: str = "api"
    tool: str = "content"
    label: str = ""
    text: str


class CommandReq(BaseModel):
    session_id: str = "api"
    command: str
    description: str = ""


class OutboundReq(BaseModel):
    session_id: str = "api"
    tool: str = "message"
    text: str
    file_path: str = ""


class FinalReq(BaseModel):
    session_id: str = "api"
    message: str


class TaskReq(BaseModel):
    session_id: str = "api"
    task: str


def _out(o) -> dict:
    return {"action": o.verdict.action, "reasons": o.verdict.reasons, "uncertain": o.verdict.uncertain,
            "signals": o.verdict.signals, "text": o.text, "note": o.note, "event_id": o.event_id, "calls": o.calls}


def create_app(engine: Optional[Engine] = None) -> FastAPI:
    app = FastAPI(title="Bulkhead", version="0.1.0")
    eng = engine or build_engine()
    app.state.engine = eng
    lock = threading.Lock()  # one agent event at a time keeps session state (taint, history) consistent

    @app.post("/hooks/claude")
    async def hook(request: Request):
        payload = await request.json()
        with lock:
            return JSONResponse(claude.handle(eng, payload))

    # ---- generic API for any agent framework -------------------------------------------
    @app.post("/v1/task")
    def v1_task(r: TaskReq):
        with lock:
            return _out(eng.on_prompt(r.session_id, r.task))

    @app.post("/v1/inbound")
    def v1_inbound(r: InboundReq):
        with lock:
            return _out(eng.on_inbound(r.session_id, r.tool, r.label, r.text))

    @app.post("/v1/command")
    def v1_command(r: CommandReq):
        with lock:
            return _out(eng.on_command(r.session_id, r.command, r.description))

    @app.post("/v1/outbound")
    def v1_outbound(r: OutboundReq):
        with lock:
            return _out(eng.on_outbound(r.session_id, r.tool, r.text, r.file_path))

    @app.post("/v1/final")
    def v1_final(r: FinalReq):
        with lock:
            return _out(eng.on_stop(r.session_id, r.message))

    # ---- dashboard API -------------------------------------------------------------------
    @app.get("/api/status")
    def status():
        return {"mode": eng.c.mode, "totals": eng.store.totals(), "spent_live": eng.c.spent,
                "settings": eng.s.public(), "pipeline": eng.s.use_pipeline}

    @app.get("/api/sessions")
    def sessions():
        return eng.store.sessions()

    @app.get("/api/sessions/{sid}")
    def session(sid: str, after: int = 0):
        s = eng.store.session(sid)
        s.pop("inbound", None)
        return {"session": s, "events": eng.store.events(sid, after)}

    @app.delete("/api/sessions/{sid}")
    def delete_session(sid: str):
        eng.store.delete_session(sid)
        return {"ok": True}

    @app.get("/api/scenarios")
    def list_scenarios():
        return [{"id": k, "title": v["title"], "blurb": v["blurb"]} for k, v in scenarios.SCENARIOS.items()]

    @app.post("/api/scenarios/{name}/run")
    def run_scenario(name: str, delay: float = 1.2):
        if name not in scenarios.SCENARIOS:
            raise HTTPException(404, "unknown scenario")
        sid = f"{name}-{uuid.uuid4().hex[:6]}"

        def work():
            runner.run(eng, name, sid, delay=delay)

        threading.Thread(target=work, daemon=True).start()
        time.sleep(0.05)
        return {"session_id": sid}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "mode": eng.c.mode}

    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    return app
