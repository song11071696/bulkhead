"""bulkhead command line.

  bulkhead serve                 dashboard + hook endpoint on http://127.0.0.1:8787
  bulkhead install-claude        write .claude/settings.json hooks for this project
  bulkhead hook                  command-hook mode: Claude Code hook JSON on stdin -> decision JSON on stdout
  bulkhead check "<command>"     judge one shell command
  bulkhead scan <file|->         screen content an agent is about to read
  bulkhead demo [scenario|all]   replay the synthetic sessions and print every decision
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from pathlib import Path


def _engine(mode=None, db=None):
    from .server import build_engine
    return build_engine(db_path=db, mode=mode)


def cmd_serve(a):
    import uvicorn
    from .server import create_app
    app = create_app(_engine(a.mode))
    print(f"Bulkhead on http://{a.host}:{a.port}  (Clocked mode: {app.state.engine.c.mode})", file=sys.stderr)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


def cmd_install(a):
    from .claude import settings_json
    target = Path(a.dir) / ".claude" / "settings.json"
    cfg = json.loads(settings_json(a.url, command=a.command))
    if target.exists():
        cur = json.loads(target.read_text() or "{}")
        cur.setdefault("hooks", {}).update(cfg["hooks"])
        cfg = cur
    if a.print:
        print(json.dumps(cfg, indent=2))
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"wrote {target}")


def cmd_hook(a):
    payload = json.load(sys.stdin)
    url = os.environ.get("BULKHEAD_URL")
    if url:
        import requests
        try:
            r = requests.post(url.rstrip("/") + "/hooks/claude", json=payload, timeout=55)
            sys.stdout.write(json.dumps(r.json()))
            return
        except Exception as exc:  # server down: fall through to in-process
            print(f"bulkhead: server unreachable ({exc}); checking in-process", file=sys.stderr)
    from . import claude
    sys.stdout.write(json.dumps(claude.handle(_engine(), payload)))


def _print_outcome(o):
    print(json.dumps({"action": o.verdict.action, "reasons": o.verdict.reasons, "signals": o.verdict.signals,
                      "credits": sum(c.get("credits") or 0 for c in o.calls)}, indent=2))


def cmd_check(a):
    e = _engine(a.mode, ":memory:")
    sid = "cli-" + uuid.uuid4().hex[:6]
    if a.task:
        e.on_prompt(sid, a.task)
    if a.untrusted:
        e.on_inbound(sid, "file", a.untrusted, Path(a.untrusted).read_text())
    o = e.on_command(sid, a.command)
    _print_outcome(o)
    sys.exit(2 if o.verdict.action == "deny" else 0)


def cmd_scan(a):
    e = _engine(a.mode, ":memory:")
    sid = "cli-" + uuid.uuid4().hex[:6]
    if a.task:
        e.on_prompt(sid, a.task)
    text = sys.stdin.read() if a.file == "-" else Path(a.file).read_text()
    o = e.on_inbound(sid, "file", a.file, text)
    _print_outcome(o)
    if o.text is not None and a.show:
        print("\n--- what the agent would see ---\n" + o.text)


def cmd_demo(a):
    from . import runner, scenarios
    e = _engine(a.mode, a.db or ":memory:")
    names = list(scenarios.SCENARIOS) if a.scenario == "all" else [a.scenario]
    colors = {"deny": "31", "withhold": "31", "quarantine": "35", "ask": "33", "redact": "36", "caution": "33", "allow": "32"}
    for name in names:
        print(f"\n=== {scenarios.SCENARIOS[name]['title']} ===")
        sid = runner.run(e, name, f"{name}-demo")
        for ev in e.store.events(sid):
            act = ev["action"]
            c = colors.get(act, "0")
            reasons = " ".join((ev["data"].get("verdict") or {}).get("reasons") or [])
            print(f"\033[{c}m{act.upper():<10}\033[0m {ev['stage']:<8} {ev['tool'] or ev['hook']:<22} "
                  f"{ev['credits']:>4.0f} cr  {reasons[:150]}")
    print(f"\nTotal credits (reported by Clocked for these calls): {e.store.totals()['credits']:.0f}  mode={e.c.mode}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="bulkhead", description="Session-aware firewall for AI coding agents (Clocked).")
    p.add_argument("--mode", choices=["live", "record", "replay"], default=None,
                   help="live = call Clocked, replay = recorded fixtures only (default: live if CLOCKED_API_KEY is set)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8787)
    s.set_defaults(fn=cmd_serve)
    s = sub.add_parser("install-claude"); s.add_argument("--dir", default="."); s.add_argument("--url", default="http://127.0.0.1:8787")
    s.add_argument("--command", action="store_true", help="use command hooks (bulkhead hook) instead of http hooks")
    s.add_argument("--print", action="store_true"); s.set_defaults(fn=cmd_install)
    s = sub.add_parser("hook"); s.set_defaults(fn=cmd_hook)
    s = sub.add_parser("check"); s.add_argument("command"); s.add_argument("--task", default="")
    s.add_argument("--untrusted", help="file the agent read earlier (screened first; taints the session)")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("scan"); s.add_argument("file"); s.add_argument("--task", default=""); s.add_argument("--show", action="store_true")
    s.set_defaults(fn=cmd_scan)
    s = sub.add_parser("demo"); s.add_argument("scenario", nargs="?", default="all"); s.add_argument("--db")
    s.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
