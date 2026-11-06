"""Replay a synthetic session through the exact Claude Code hook path."""
from __future__ import annotations

import time
from typing import Callable, Optional

from . import claude, scenarios
from .engine import Engine


def describe_response(event: str, resp: dict) -> str:
    """What Claude Code does with the hook's JSON reply, in words."""
    hso = resp.get("hookSpecificOutput") or {}
    if event == "PreToolUse":
        d = hso.get("permissionDecision")
        if d == "deny":
            return "Claude Code blocks the tool call and shows the agent the reason."
        if d == "ask":
            return ("Claude Code shows the user the redacted version and asks for approval." if "updatedInput" in hso
                    else "Claude Code pauses and asks the user to approve or reject.")
        if d == "allow":
            return "Claude Code runs the tool without prompting."
        return "No objection: the tool call continues through Claude Code's normal permission rules."
    if event == "PostToolUse":
        if "updatedToolOutput" in hso:
            return "The agent receives the sanitized tool output plus a warning, never the original."
        if "additionalContext" in hso:
            return "The agent receives the output with a caution note attached."
        return "The agent receives the output unchanged."
    if event == "Stop":
        return ("The agent is not allowed to finish: it must correct its report." if resp.get("decision") == "block"
                else "The agent finishes.")
    if event == "UserPromptSubmit":
        return "Task recorded as the session's source of authority."
    return ""


def run(engine: Engine, name: str, sid: Optional[str] = None, delay: float = 0.0,
        on_step: Optional[Callable[[int, dict, dict], None]] = None) -> str:
    steps = scenarios.build(name, sid)
    sid = steps[0]["payload"]["session_id"]
    engine.store.session(sid, scenarios.CWD, label=scenarios.SCENARIOS[name]["title"])
    engine.store.update_session(sid, label=scenarios.SCENARIOS[name]["title"])
    for i, st in enumerate(steps):
        payload = st["payload"]
        if st.get("faults"):
            engine.c.inject_faults(list(st["faults"]))
        before = engine.store.last_event_id()
        resp = claude.handle(engine, payload)
        engine.c.faults.clear()
        explain = describe_response(payload["hook_event_name"], resp)
        new = [e for e in engine.store.events(sid, after=before)]
        if new:
            for e in new:
                engine.store.annotate(e["id"], caption=st["caption"], hook_response=resp, effect=explain, step=i + 1)
        else:
            engine.store.add_event(sid, payload["hook_event_name"], payload.get("tool_name", ""), "note", "allow",
                                   st["caption"], 0, {"caption": st["caption"], "hook_response": resp, "effect": explain,
                                                      "step": i + 1, "verdict": {"action": "allow", "reasons": []}, "calls": []})
        if on_step:
            on_step(i, st, resp)
        if delay:
            time.sleep(delay)
    return sid
