"""Pure policy rules, on hand-written Clocked-shaped outputs."""
from bulkhead import policy
from bulkhead.config import Settings

S = Settings(fail_mode="ask")


def guard(p, residual=0.01, evidence=1, sev="high"):
    return {"injection": p, "verdict": "injection" if p >= .5 else "benign", "category": "instruction override",
            "severity": sev, "residual": residual, "residual_verdict": "benign" if residual < .5 else "injection",
            "evidence": [{"quote": "q", "start": 0, "end": 1}] * evidence}


def test_inbound_bands():
    assert policy.inbound_verdict(guard(.95), None, S).action == "quarantine"
    assert policy.inbound_verdict(guard(.95, residual=.9), None, S).action == "withhold"
    assert policy.inbound_verdict(guard(.95, evidence=0), None, S).action == "withhold"
    v = policy.inbound_verdict(guard(.55), None, S)
    assert v.action == "caution" and v.uncertain
    assert policy.inbound_verdict(guard(.05), None, S).action == "allow"
    assert policy.inbound_verdict(guard(.05), {"entities": [{"type": "email"}]}, S).action == "redact"


def inspect(verdict="benign", mal=.01):
    return {"verdict": verdict, "malicious": mal, "suspicious": mal, "category": "x", "severity": "high",
            "evidence": [{"line": "rm -rf /"}]}


def decide(fu=None, ex=.01, blast=.1, oos=.05):
    a = {"exfiltration": {"noul": ex}, "blast_radius": {"score": blast},
         "scope": {"choice": "in_scope", "probabilities": {"out_of_scope": oos}}}
    if fu is not None:
        a["follows_untrusted"] = {"noul": fu}
    return {"answers": a}


def test_inspect_alone_denies_or_asks():
    assert policy.command_verdict(inspect("malicious", .97), None, None, False, S).action == "deny"
    v = policy.command_verdict(inspect("suspicious", .6), None, None, False, S)
    assert v.action == "ask" and v.uncertain


def test_taint_turns_benign_command_into_deny():
    v = policy.command_verdict(inspect(), {"entities": []}, decide(fu=.99, ex=.99, blast=1.9), True, S, "critical")
    assert v.action == "deny"
    # the same answers without taint are only an exfiltration question
    assert policy.command_verdict(inspect(), {"entities": []}, decide(ex=.99, blast=1.9), False, S).action == "ask"


def test_low_severity_taint_asks_instead_of_denying():
    v = policy.command_verdict(inspect(), None, decide(fu=.96, ex=.98, blast=1.7), True, S, "low")
    assert v.action == "ask" and v.uncertain


def test_follow_uncertainty_band_asks():
    v = policy.command_verdict(inspect(), None, decide(fu=.55), True, S, "high")
    assert v.action == "ask" and v.uncertain
    assert policy.command_verdict(inspect(), None, decide(fu=.1), True, S, "high").action == "allow"


def test_secret_leaving_machine_is_denied():
    sec = {"entities": [{"type": "api_secret", "value": "k", "start": 0, "end": 1}]}
    assert policy.command_verdict(inspect(), sec, decide(ex=.9), False, S).action == "deny"
    assert policy.command_verdict(inspect(), sec, decide(ex=.1), False, S).action == "ask"


def test_outbound_rules():
    sec = {"entities": [{"type": "api_secret"}]}
    assert policy.outbound_verdict(sec, "Write", "/app/settings.py").action == "deny"
    assert policy.outbound_verdict(sec, "Write", "/app/.env").action == "allow"
    assert policy.outbound_verdict(sec, "Write", "/app/.env.example").action == "deny"
    assert policy.outbound_verdict({"entities": [{"type": "email"}]}, "Write", "/app/x.json").action == "redact"
    assert policy.outbound_verdict({"entities": []}, "Write", "/app/x.json").action == "allow"


def test_final_report():
    c = lambda v, con: {"claim": "c", "verdict": v, "counted": True, "contradicted": con, "sources": {"doc": .9}}
    assert policy.final_verdict({"claims": [c("contradicted", .97)]}, S).action == "deny"
    assert policy.final_verdict({"claims": [c("not_stated", .1)]}, S).action == "caution"
    assert policy.final_verdict({"claims": [c("supported", .01)], "grounded": .99}, S).action == "allow"


def test_fail_modes():
    err = {"kind": "busy", "status": 429}
    assert policy.fail_verdict("x", err, Settings(fail_mode="ask")).action == "ask"
    assert policy.fail_verdict("x", err, Settings(fail_mode="deny")).action == "deny"
    assert policy.fail_verdict("x", err, Settings(fail_mode="allow")).action == "allow"
    assert policy.fail_verdict("x", err, Settings(fail_mode="nonsense")).action == "ask"
