"""Claude Code hook adapter.

Claude Code POSTs the hook input JSON to /hooks/claude (``"type": "http"`` hooks) or pipes it to
``bulkhead hook`` (command hooks). The JSON returned here is the enforcement:

  PreToolUse   Bash              -> permissionDecision deny / ask (+ reason); nothing for allow
  PreToolUse   Write/Edit/Web*/MCP -> deny, or ask with updatedInput holding the Protect-redacted content
  PostToolUse  Read/WebFetch/Bash/Grep/MCP -> updatedToolOutput (quarantined / redacted) + additionalContext
  UserPromptSubmit               -> records the task (no output)
  Stop                           -> decision "block" with the contradicted claims (once)
"""
from __future__ import annotations

import copy
import json
from typing import Any, Optional

from . import policy
from .engine import Engine

INBOUND_TOOLS = {"Read", "WebFetch", "WebSearch", "Bash", "Grep"}
OUTBOUND_TEXT_TOOLS = {"Write": "content", "Edit": "new_string"}


def _largest_string(obj: Any, path=()) -> tuple[tuple, str]:
    """Find the longest string inside a tool response (the part the model actually reads)."""
    best: tuple[tuple, str] = ((), "")
    if isinstance(obj, str):
        return path, obj
    if isinstance(obj, dict):
        items = obj.items()
    elif isinstance(obj, list):
        items = enumerate(obj)
    else:
        return best
    for k, v in items:
        p, s = _largest_string(v, path + (k,))
        if len(s) > len(best[1]):
            best = (p, s)
    return best


def _set_path(obj: Any, path: tuple, value: str) -> Any:
    if not path:
        return value
    obj = copy.deepcopy(obj)
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return obj


def _bash_output(resp: Any) -> Optional[str]:
    if isinstance(resp, dict) and ("stdout" in resp or "stderr" in resp):
        return "\n".join(x for x in (resp.get("stdout") or "", resp.get("stderr") or "") if x)
    return None


def _label(tool: str, tool_input: dict) -> str:
    for k in ("file_path", "url", "query", "pattern", "command", "path"):
        if isinstance(tool_input.get(k), str):
            return tool_input[k][:200]
    return ""


def pre_tool_use(engine: Engine, sid: str, tool: str, tool_input: dict) -> dict:
    if tool == "Bash":
        out = engine.on_command(sid, tool_input.get("command", ""), tool_input.get("description", ""))
        return _permission(out.verdict, engine.s.auto_approve)
    if tool in OUTBOUND_TEXT_TOOLS or tool == "WebFetch" or tool.startswith("mcp__"):
        if tool in OUTBOUND_TEXT_TOOLS:
            field = OUTBOUND_TEXT_TOOLS[tool]
            path, text = (field,), tool_input.get(field, "") or ""
        elif tool == "WebFetch":
            path, text = ("url",), tool_input.get("url", "")
        else:
            path, text = _largest_string(tool_input)
        out = engine.on_outbound(sid, tool, text, tool_input.get("file_path", ""))
        resp = _permission(out.verdict, engine.s.auto_approve)
        if out.verdict.action == policy.REDACT and out.text is not None and path:
            hso = resp.setdefault("hookSpecificOutput", {"hookEventName": "PreToolUse"})
            hso["permissionDecision"] = "allow" if engine.s.auto_approve else "ask"
            hso["permissionDecisionReason"] = " ".join(out.verdict.reasons)
            hso["updatedInput"] = _set_path(tool_input, path, out.text)
        return resp
    return {}


def _permission(v: policy.Verdict, auto_approve: bool) -> dict:
    reason = "Bulkhead: " + " ".join(v.reasons)
    if v.action == policy.DENY:
        decision = "deny"
    elif v.action == policy.ASK:
        decision = "ask"
    elif v.action == policy.ALLOW and auto_approve:
        decision = "allow"
    else:
        return {}  # defer to Claude Code's normal permission flow
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason[:2000]}}


def post_tool_use(engine: Engine, sid: str, tool: str, tool_input: dict, tool_response: Any) -> dict:
    if tool not in INBOUND_TOOLS and not tool.startswith("mcp__"):
        return {}
    if tool == "Bash" and (text := _bash_output(tool_response)) is not None:
        path = None
    else:
        path, text = _largest_string(tool_response)
    if not text:
        return {}
    out = engine.on_inbound(sid, tool, _label(tool, tool_input), text)
    hso: dict = {"hookEventName": "PostToolUse"}
    if out.text is not None:
        if tool == "Bash" and path is None and isinstance(tool_response, dict):
            new = dict(tool_response)
            new.update(stdout=out.text, stderr="")
        else:
            new = _set_path(tool_response, path or (), out.text)
        hso["updatedToolOutput"] = new
    if out.note:
        hso["additionalContext"] = out.note[:9000]
    return {"hookSpecificOutput": hso} if len(hso) > 1 else {}


def handle(engine: Engine, payload: dict) -> dict:
    event = payload.get("hook_event_name", "")
    sid = payload.get("session_id") or "default"
    engine.store.session(sid, payload.get("cwd", ""))
    if event == "UserPromptSubmit":
        engine.on_prompt(sid, payload.get("prompt", ""), payload.get("cwd", ""))
        return {}
    if event == "PreToolUse":
        return pre_tool_use(engine, sid, payload.get("tool_name", ""), payload.get("tool_input") or {})
    if event == "PostToolUse":
        return post_tool_use(engine, sid, payload.get("tool_name", ""), payload.get("tool_input") or {},
                             payload.get("tool_response"))
    if event == "Stop":
        out = engine.on_stop(sid, payload.get("last_assistant_message") or "", bool(payload.get("stop_hook_active")))
        if out.verdict.action == policy.DENY:
            return {"decision": "block", "reason": "Bulkhead: " + " ".join(out.verdict.reasons)}
        return {}
    return {}


SETTINGS_TEMPLATE = {
    "hooks": {
        "UserPromptSubmit": [{"hooks": [{"type": "http", "url": "{base}/hooks/claude", "timeout": 30}]}],
        "PreToolUse": [{"matcher": "Bash|Write|Edit|WebFetch|mcp__.*",
                        "hooks": [{"type": "http", "url": "{base}/hooks/claude", "timeout": 60}]}],
        "PostToolUse": [{"matcher": "Read|WebFetch|WebSearch|Bash|Grep|mcp__.*",
                         "hooks": [{"type": "http", "url": "{base}/hooks/claude", "timeout": 60}]}],
        "Stop": [{"hooks": [{"type": "http", "url": "{base}/hooks/claude", "timeout": 60}]}],
    }
}


def settings_json(base: str = "http://127.0.0.1:8787", command: bool = False) -> str:
    s = json.loads(json.dumps(SETTINGS_TEMPLATE).replace("{base}", base))
    if command:  # older Claude Code without http hooks: pipe through the CLI instead
        for groups in s["hooks"].values():
            for g in groups:
                g["hooks"] = [{"type": "command", "command": "bulkhead hook", "timeout": 60}]
    return json.dumps(s, indent=2)
