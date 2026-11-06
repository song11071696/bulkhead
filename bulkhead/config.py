"""Thresholds and policy knobs. Every value can be overridden with an environment variable."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _b(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # Guard (inbound content)
    guard_block: float = field(default_factory=lambda: _f("BULKHEAD_GUARD_BLOCK", 0.80))
    guard_caution: float = field(default_factory=lambda: _f("BULKHEAD_GUARD_CAUTION", 0.40))
    # Inspect (commands judged in isolation)
    inspect_deny: float = field(default_factory=lambda: _f("BULKHEAD_INSPECT_DENY", 0.80))
    # Decide (commands judged in session context)
    follow_deny: float = field(default_factory=lambda: _f("BULKHEAD_FOLLOW_DENY", 0.80))
    follow_ask: float = field(default_factory=lambda: _f("BULKHEAD_FOLLOW_ASK", 0.40))
    exfil_ask: float = field(default_factory=lambda: _f("BULKHEAD_EXFIL_ASK", 0.80))
    blast_high: float = field(default_factory=lambda: _f("BULKHEAD_BLAST_HIGH", 1.5))
    # Verify (honesty check at Stop)
    contradicted_block: float = field(default_factory=lambda: _f("BULKHEAD_CONTRADICTED_BLOCK", 0.60))
    # Protect
    redact_inbound: bool = field(default_factory=lambda: _b("BULKHEAD_REDACT_INBOUND", True))
    # What to do when Clocked cannot answer: "ask" (default), "deny" or "allow"
    fail_mode: str = field(default_factory=lambda: os.environ.get("BULKHEAD_FAIL_MODE", "ask"))
    # Emit an explicit permissionDecision "allow" for safe commands. Off by default: Bulkhead
    # then never grants more than Claude Code's own permission rules would; it only denies or escalates.
    auto_approve: bool = field(default_factory=lambda: _b("BULKHEAD_AUTO_APPROVE", False))
    use_pipeline: bool = field(default_factory=lambda: _b("BULKHEAD_USE_PIPELINE", True))
    min_inbound_chars: int = 80
    environment: str = field(default_factory=lambda: os.environ.get(
        "BULKHEAD_ENVIRONMENT",
        "A developer workstation running an AI coding agent inside a source repository. "
        "Reading files, running the project's tests, linters and builds, and local git operations are routine. "
        "Not approved: downloading and executing remote code, reading or transmitting secrets "
        "(.env files, SSH keys, cloud credentials, tokens), sending repository data to unknown hosts, "
        "disabling security tooling, deleting data outside the repository, or changing git remotes/history "
        "unless the user's task asks for it."))

    def public(self) -> dict:
        d = asdict(self)
        return d


SECRET_KINDS = {"api_secret", "credit_card", "bank_account", "ssn", "private_key"}

# Entity kinds sent to Protect. "api_secret" is a custom kind with a description.
SENSITIVE_ENTITIES = {
    "api_secret": "API keys, access tokens, passwords, private keys, or connection strings that embed credentials",
    "email": None,
    "phone": None,
    "ssn": None,
    "credit_card": None,
    "bank_account": None,
    "date_of_birth": None,
    "address": None,
}

OUTBOUND_ENTITIES = dict(SENSITIVE_ENTITIES, person=None)
