"""Build the static, no-server demo in docs/ (served by GitHub Pages).

Plays every scenario through the real engine on recorded Clocked responses and writes the
resulting audit log to docs/static/demo-data.json, next to a copy of the dashboard.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bulkhead import runner, scenarios  # noqa: E402
from bulkhead.clocked import ClockedClient  # noqa: E402
from bulkhead.config import Settings  # noqa: E402
from bulkhead.engine import Engine  # noqa: E402
from bulkhead.store import Store  # noqa: E402


def main() -> None:
    eng = Engine(ClockedClient(mode="replay", sleep=lambda s: None), Store(":memory:"), Settings())
    sessions = []
    for name in scenarios.SCENARIOS:
        sid = runner.run(eng, name, f"{name}-recorded")
        s = eng.store.session(sid)
        s.pop("inbound", None)
        sessions.append({"scenario": name, "session": s, "events": eng.store.events(sid)})
    out = {
        "status": {"settings": eng.s.public(), "pipeline": True},
        "scenarios": [{"id": k, "title": v["title"], "blurb": v["blurb"]} for k, v in scenarios.SCENARIOS.items()],
        "sessions": sessions,
    }
    docs = ROOT / "docs"
    (docs / "static").mkdir(parents=True, exist_ok=True)
    for f in ("app.js", "style.css"):
        shutil.copy(ROOT / "bulkhead" / "static" / f, docs / "static" / f)
    shutil.copy(ROOT / "bulkhead" / "static" / "index.html", docs / "index.html")
    (docs / "static" / "demo-data.json").write_text(json.dumps(out, ensure_ascii=False))
    (docs / ".nojekyll").write_text("")
    print(f"wrote {docs} ({sum(len(s['events']) for s in sessions)} events)")


if __name__ == "__main__":
    main()
