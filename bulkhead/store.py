"""SQLite audit log: sessions (task goal, taint) and events (every hook decision)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, created REAL, label TEXT, goal TEXT, cwd TEXT,
  taint TEXT DEFAULT '[]', inbound TEXT DEFAULT '[]', commands TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts REAL, hook TEXT, tool TEXT,
  stage TEXT, action TEXT, summary TEXT, credits REAL, data TEXT
);
CREATE INDEX IF NOT EXISTS ev_session ON events(session_id, id);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    # sessions -----------------------------------------------------------------
    def session(self, sid: str, cwd: str = "", label: str = "") -> dict:
        with self.lock:
            row = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            if row is None:
                self.db.execute("INSERT INTO sessions(id, created, label, goal, cwd) VALUES (?,?,?,?,?)",
                                (sid, time.time(), label, "", cwd))
                self.db.commit()
                row = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        return _session(row)

    def update_session(self, sid: str, **fields) -> None:
        cols, vals = [], []
        for k, v in fields.items():
            cols.append(f"{k}=?")
            vals.append(json.dumps(v) if isinstance(v, (list, dict)) else v)
        with self.lock:
            self.db.execute(f"UPDATE sessions SET {', '.join(cols)} WHERE id=?", (*vals, sid))
            self.db.commit()

    def sessions(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("""SELECT s.*, COUNT(e.id) n, COALESCE(SUM(e.credits),0) credits,
                 SUM(CASE WHEN e.action IN ('deny','withhold') THEN 1 ELSE 0 END) blocked,
                 SUM(CASE WHEN e.action='ask' THEN 1 ELSE 0 END) asked,
                 MAX(e.ts) last FROM sessions s LEFT JOIN events e ON e.session_id=s.id
                 GROUP BY s.id ORDER BY COALESCE(MAX(e.ts), s.created) DESC""").fetchall()
        out = []
        for r in rows:
            d = _session(r)
            d.update(events=r["n"], credits=r["credits"], blocked=r["blocked"] or 0, asked=r["asked"] or 0, last=r["last"])
            d.pop("inbound", None)
            out.append(d)
        return out

    def delete_session(self, sid: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM events WHERE session_id=?", (sid,))
            self.db.execute("DELETE FROM sessions WHERE id=?", (sid,))
            self.db.commit()

    # events -------------------------------------------------------------------
    def add_event(self, sid: str, hook: str, tool: str, stage: str, action: str, summary: str,
                  credits: float, data: dict) -> int:
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO events(session_id, ts, hook, tool, stage, action, summary, credits, data) VALUES (?,?,?,?,?,?,?,?,?)",
                (sid, time.time(), hook, tool, stage, action, summary, credits, json.dumps(data, ensure_ascii=False)))
            self.db.commit()
            return cur.lastrowid

    def annotate(self, event_id: int, **extra) -> None:
        with self.lock:
            row = self.db.execute("SELECT data FROM events WHERE id=?", (event_id,)).fetchone()
            if row is None:
                return
            data = json.loads(row["data"] or "{}")
            data.update(extra)
            self.db.execute("UPDATE events SET data=? WHERE id=?", (json.dumps(data, ensure_ascii=False), event_id))
            self.db.commit()

    def last_event_id(self) -> int:
        with self.lock:
            r = self.db.execute("SELECT COALESCE(MAX(id),0) m FROM events").fetchone()
        return r["m"]

    def events(self, sid: str, after: int = 0) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT * FROM events WHERE session_id=? AND id>? ORDER BY id", (sid, after)).fetchall()
        return [_event(r) for r in rows]

    def totals(self) -> dict:
        with self.lock:
            r = self.db.execute("""SELECT COUNT(*) n, COALESCE(SUM(credits),0) c,
               SUM(CASE WHEN action IN ('deny','withhold') THEN 1 ELSE 0 END) b,
               SUM(CASE WHEN action='ask' THEN 1 ELSE 0 END) a,
               SUM(CASE WHEN action IN ('quarantine','redact') THEN 1 ELSE 0 END) q FROM events""").fetchone()
        return {"events": r["n"], "credits": r["c"], "blocked": r["b"] or 0, "asked": r["a"] or 0, "sanitized": r["q"] or 0}


def _session(row: Optional[sqlite3.Row]) -> dict:
    d = dict(row)
    for k in ("taint", "inbound", "commands"):
        if k in d:
            d[k] = json.loads(d[k] or "[]")
    return d


def _event(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["data"] = json.loads(d["data"] or "{}")
    return d
