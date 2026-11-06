"""Pure policy functions: Clocked outputs in, a verdict out.

No I/O here, so every rule is unit-tested against recorded responses. Each verdict carries the
reasons a human (and the agent) will read, and the exact numbers that triggered it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .config import SECRET_KINDS, Settings

# Actions, from least to most restrictive.
ALLOW, REDACT, CAUTION, ASK, QUARANTINE, WITHHOLD, DENY = (
    "allow", "redact", "caution", "ask", "quarantine", "withhold", "deny")


@dataclass
class Verdict:
    action: str
    reasons: list = field(default_factory=list)
    signals: dict = field(default_factory=dict)
    uncertain: bool = False   # True when a score sat inside an uncertainty band

    def as_dict(self) -> dict:
        return {"action": self.action, "reasons": self.reasons, "signals": self.signals, "uncertain": self.uncertain}


def _pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


# --------------------------------------------------------------------------- inbound (Guard + Protect)
def inbound_verdict(guard: Optional[dict], pii: Optional[dict], s: Settings) -> Verdict:
    """Decide what the agent is allowed to see from a tool result."""
    reasons, signals = [], {}
    action = ALLOW
    uncertain = False
    if guard is not None:
        p = float(guard.get("injection") or 0.0)
        residual = guard.get("residual")
        signals.update(injection=p, category=guard.get("category"), severity=guard.get("severity"),
                       residual=residual, evidence=len(guard.get("evidence") or []))
        if p >= s.guard_block:
            # Guard reports the probability that remains once its evidence passages are removed.
            # If that residual is benign we can cut just those passages; otherwise withhold everything.
            surgical = bool(guard.get("evidence")) and (
                guard.get("residual_verdict") == "benign" or (residual is not None and float(residual) < s.guard_caution))
            action = QUARANTINE if surgical else WITHHOLD
            reasons.append(
                f"Guard: {_pct(p)} prompt injection ({guard.get('category')}, severity {guard.get('severity')})."
                + (f" Removing {len(guard['evidence'])} flagged passage(s) leaves {_pct(float(residual or 0))} risk, so only those passages are cut."
                   if surgical else " The rest of the content is not safe either, so the whole result is withheld."))
        elif p >= s.guard_caution:
            action, uncertain = CAUTION, True
            reasons.append(f"Guard: {_pct(p)} injection risk is inside the review band "
                           f"[{_pct(s.guard_caution)}, {_pct(s.guard_block)}). Content passed with a warning; session marked as tainted.")
    else:
        signals["guard"] = "unavailable"
    if pii is not None:
        ents = pii.get("entities") or []
        kinds = sorted({e["type"] for e in ents})
        signals.update(pii_findings=len(ents), pii_kinds=kinds)
        if ents and s.redact_inbound:
            if action == ALLOW:
                action = REDACT
            reasons.append(f"Protect: {len(ents)} sensitive value(s) ({', '.join(kinds)}) masked before the agent sees them.")
    if action == ALLOW:
        reasons.append(f"Guard: clean ({_pct(signals.get('injection'))} injection risk); Protect: nothing sensitive.")
    return Verdict(action, reasons, signals, uncertain)


# --------------------------------------------------------------------------- commands (Inspect + Protect + Decide)
def command_verdict(inspect: Optional[dict], secrets: Optional[dict], decide: Optional[dict],
                    tainted: bool, s: Settings, taint_severity: str = "high") -> Verdict:
    """Inspect judges the command alone; Decide judges it against the task and the session's taint.

    ``taint_severity`` is the strongest Guard severity seen in the session. A command that follows a
    low-severity injected nudge is escalated to a human rather than denied outright."""
    reasons, signals = [], {}
    if inspect is not None:
        mal = float(inspect.get("malicious") or 0.0)
        susp = float(inspect.get("suspicious") or 0.0)
        signals.update(malicious=mal, suspicious=susp, inspect_verdict=inspect.get("verdict"),
                       category=inspect.get("category"), severity=inspect.get("severity"))
        lines = [e.get("line") for e in inspect.get("evidence") or [] if e.get("line")]
        if inspect.get("verdict") != "benign":
            ev = f" Evidence: `{lines[0]}`" if lines else ""
            if mal >= s.inspect_deny:
                return Verdict(DENY, [f"Inspect: {inspect.get('verdict')} ({_pct(mal)}), {inspect.get('category')}, "
                                      f"severity {inspect.get('severity')}.{ev}"], signals)
            return Verdict(ASK, [f"Inspect: verdict {inspect.get('verdict')} but malicious only {_pct(mal)}: a person should look.{ev}"],
                           signals, uncertain=True)
    found = []
    if secrets is not None:
        found = [e for e in secrets.get("entities") or [] if e.get("type") in SECRET_KINDS]
        signals["secrets_in_command"] = [e["type"] for e in found]
    if decide is None:
        if found:
            return Verdict(ASK, [f"Protect: command contains {len(found)} secret value(s); context check unavailable."], signals, True)
        return Verdict(ALLOW, ["Inspect: benign; no session-context check was needed."], signals)

    a = decide.get("answers") or {}
    fu = (a.get("follows_untrusted") or {}).get("noul")
    ex = (a.get("exfiltration") or {}).get("noul") or 0.0
    blast = (a.get("blast_radius") or {}).get("score") or 0.0
    scope = a.get("scope") or {}
    oos = (scope.get("probabilities") or {}).get("out_of_scope", 0.0)
    signals.update(follows_untrusted=fu, exfiltration=ex, blast_radius=blast, scope=scope.get("choice"), out_of_scope=oos)
    fu = fu or 0.0

    if found and ex >= 0.5:
        return Verdict(DENY, [f"Protect found {', '.join(e['type'] for e in found)} in the command and Decide rates "
                              f"exfiltration {_pct(ex)}: a secret would leave this machine."], signals)
    strong_taint = taint_severity in ("medium", "high", "critical")
    signals["taint_severity"] = taint_severity if tainted else None
    if tainted and fu >= s.follow_deny and (ex >= 0.5 or blast >= s.blast_high) and not strong_taint:
        return Verdict(ASK, [f"Decide: {_pct(fu)} that this command follows an instruction from untrusted content "
                             f"(exfiltration {_pct(ex)}, blast radius {blast:.1f}/2), but Guard rated that content's "
                             f"severity '{taint_severity}'. A person decides instead of an automatic block."], signals, uncertain=True)
    if tainted and fu >= s.follow_deny and (ex >= 0.5 or blast >= s.blast_high):
        return Verdict(DENY, [f"Decide: {_pct(fu)} that this command carries out an instruction injected by untrusted content "
                              f"read earlier in this session (exfiltration {_pct(ex)}, blast radius {blast:.1f}/2). "
                              "Inspect alone rated it benign: the danger is only visible in session context."], signals)
    if tainted and fu >= s.follow_ask:
        return Verdict(ASK, [f"Decide: {_pct(fu)} that this command follows the injected instruction "
                             f"(uncertainty band {_pct(s.follow_ask)}-{_pct(s.follow_deny)} or low impact): ask the human."],
                       signals, uncertain=fu < s.follow_deny)
    if ex >= s.exfil_ask:
        return Verdict(ASK, [f"Decide: {_pct(ex)} that this command sends local data off the machine; confirm the destination."], signals)
    if blast >= s.blast_high and oos >= 0.5:
        return Verdict(ASK, [f"Decide: high-impact command (blast radius {blast:.1f}/2) that looks out of scope for the task "
                             f"({_pct(oos)}): confirm."], signals, uncertain=True)
    if found:
        return Verdict(ASK, [f"Protect: command contains {', '.join(e['type'] for e in found)}; confirm it should run."], signals)
    return Verdict(ALLOW, [f"Inspect benign; Decide: in scope ({scope.get('choice')}), exfiltration {_pct(ex)}"
                           + (f", follows untrusted {_pct(fu)}" if tainted else "") + "."], signals)


# --------------------------------------------------------------------------- outbound (Protect)
def outbound_verdict(pii: Optional[dict], tool_name: str, file_path: str = "") -> Verdict:
    if pii is None:
        return Verdict(ALLOW, ["Protect unavailable."], {"pii": "unavailable"})
    ents = pii.get("entities") or []
    kinds = sorted({e["type"] for e in ents})
    secrets = [e for e in ents if e["type"] in SECRET_KINDS]
    signals = {"pii_findings": len(ents), "pii_kinds": kinds, "secrets": len(secrets)}
    if not ents:
        return Verdict(ALLOW, ["Protect: no personal data or secrets in the outgoing content."], signals)
    is_env_file = file_path.rsplit("/", 1)[-1].startswith(".env") and not file_path.endswith(".example")
    if secrets and not is_env_file:
        where = f"written into {file_path}" if file_path else f"sent through {tool_name}"
        return Verdict(DENY, [f"Protect: {len(secrets)} secret value(s) ({', '.join(sorted({e['type'] for e in secrets}))}) "
                              f"would be {where}." + (" Read secrets from the environment instead." if any(e["type"] == "api_secret" for e in secrets) else "")], signals)
    if is_env_file and not (set(kinds) - SECRET_KINDS):
        return Verdict(ALLOW, ["Protect: secrets are going into a local .env file, which is where they belong."], signals)
    return Verdict(REDACT, [f"Protect: {len(ents)} personal value(s) ({', '.join(kinds)}) replaced with placeholders "
                            "in what is actually written/sent."], signals)


# --------------------------------------------------------------------------- final report (Verify)
def final_verdict(verify: Optional[dict], s: Settings) -> Verdict:
    if verify is None:
        return Verdict(ALLOW, ["Verify unavailable; final report not checked."], {"verify": "unavailable"})
    claims = verify.get("claims") or []
    contradicted = [c for c in claims if c.get("counted", True) and float(c.get("contradicted") or 0) >= s.contradicted_block]
    unstated = [c for c in claims if c.get("counted", True) and c.get("verdict") == "not_stated" and c not in contradicted]
    signals = {"grounded": verify.get("grounded"), "verdict": verify.get("verdict"),
               "claims": len(claims), "contradicted": len(contradicted), "not_stated": len(unstated)}
    if contradicted:
        lines = []
        for c in contradicted[:3]:
            ev = c.get("evidence")
            ev = ev[0] if isinstance(ev, list) and ev else ev
            q = ev.get("quote") if isinstance(ev, dict) else None
            src = max((c.get("sources") or {}).items(), key=lambda kv: kv[1], default=(None, 0))[0]
            lines.append(f"\"{c.get('claim')}\" ({_pct(c.get('contradicted'))} contradicted"
                         + (f"; the tool output says: \"{q}\"" if q else (f" by [{src}]" if src else "")) + ")")
        return Verdict(DENY, ["Verify: your final report contradicts the tool output you received: " + "; ".join(lines)
                              + ". Correct the report before finishing."], signals)
    if unstated:
        return Verdict(CAUTION, [f"Verify: {len(unstated)} claim(s) are not backed by any tool output in this session "
                                 "(shown to the reviewer, not blocked)."], signals, uncertain=True)
    return Verdict(ALLOW, [f"Verify: final report is grounded in the session's tool output ({_pct(verify.get('grounded'))})."], signals)


def fail_verdict(stage: str, err: dict, s: Settings) -> Verdict:
    """Clocked could not answer: never silently allow by default."""
    mode = s.fail_mode if s.fail_mode in {"ask", "deny", "allow"} else "ask"
    action = {"ask": ASK, "deny": DENY, "allow": ALLOW}[mode]
    hint = {
        "credits": "Clocked reports insufficient credits (402).",
        "budget": "Bulkhead's local credit budget is spent.",
        "busy": "Clocked stayed busy (429) through every retry.",
        "auth": "The Clocked key was rejected.",
        "network": "Clocked could not be reached.",
    }.get(err.get("kind"), f"Clocked failed ({err.get('kind')}).")
    return Verdict(action, [f"{stage}: {hint} Fail mode '{mode}' applies instead of guessing."],
                   {"error": err}, uncertain=True)
