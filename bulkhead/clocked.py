"""Thin, failure-aware client for the Clocked API.

Every request:
  * carries one UUID Idempotency-Key that is reused for every retry of the same attempt,
  * retries 429 / 5xx / network errors with bounded exponential backoff + jitter,
  * never retries 400/401/403/402/413/422 (they cannot succeed unchanged),
  * treats 409 as "maybe still running": waits and replays the SAME key once,
  * honours ``retryAsNew``: the old attempt is over, so at most one fresh attempt with a new key,
  * records the credits the gateway reports (X-Clocked-Credits) in a local ledger and refuses
    new work once the configured credit budget is spent.

Modes (env ``BULKHEAD_MODE``):
  live    - call the API (default when CLOCKED_API_KEY is set)
  record  - call the API and save request+response to fixtures/clocked/
  replay  - never touch the network; answer from fixtures (offline tests / demo)

The API key is only ever read from the CLOCKED_API_KEY environment variable.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import requests

BASE_URL = os.environ.get("CLOCKED_BASE_URL", "https://clocked.rezolve.ai/clocked")
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = ROOT / "fixtures" / "clocked"

RETRYABLE = {429, 500, 502, 503, 504}
NO_RETRY = {400, 401, 403, 402, 404, 413, 422}


class ClockedError(Exception):
    """A Clocked call that did not produce a usable answer."""

    def __init__(self, kind: str, message: str, status: Optional[int] = None, attempts: int = 0):
        super().__init__(message)
        self.kind = kind          # invalid | auth | credits | conflict | busy | upstream | network | budget | no_fixture
        self.status = status
        self.attempts = attempts

    def as_dict(self) -> dict:
        return {"kind": self.kind, "status": self.status, "message": str(self), "attempts": self.attempts}


@dataclass
class ClockedResult:
    endpoint: str
    data: dict
    credits: float = 0.0
    model_ms: Optional[float] = None
    latency_ms: float = 0.0
    attempts: int = 1
    idempotency_key: str = ""
    source: str = "live"      # live | replay
    retries: list = field(default_factory=list)

    def meta(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "credits": self.credits,
            "model_ms": self.model_ms,
            "latency_ms": round(self.latency_ms),
            "attempts": self.attempts,
            "retries": self.retries,
            "source": self.source,
        }


def payload_hash(endpoint: str, payload: dict) -> str:
    blob = json.dumps({"e": endpoint, "p": payload}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


class CreditLedger:
    """Counts credits reported by the gateway; persisted as JSON lines."""

    def __init__(self, path: Optional[Path], budget: Optional[float]):
        self.path = path
        self.budget = budget
        self.lock = threading.Lock()
        self.spent = 0.0
        if path and path.exists():
            for line in path.read_text().splitlines():
                try:
                    self.spent += float(json.loads(line).get("credits") or 0)
                except Exception:
                    pass

    def check(self) -> None:
        if self.budget is not None and self.spent >= self.budget:
            raise ClockedError("budget", f"local credit budget of {self.budget:g} reached ({self.spent:g} spent)")

    def add(self, endpoint: str, credits: float, key: str) -> None:
        with self.lock:
            self.spent += credits
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as fh:
                    fh.write(json.dumps({"t": time.time(), "endpoint": endpoint, "credits": credits, "key": key}) + "\n")


class ClockedClient:
    def __init__(
        self,
        mode: Optional[str] = None,
        fixtures_dir: Optional[Path] = None,
        ledger_path: Optional[Path] = None,
        budget: Optional[float] = None,
        max_attempts: int = 4,
        timeout: float = 120.0,
        concurrency: int = 4,
        transport: Optional[Callable[..., Any]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ):
        env_mode = os.environ.get("BULKHEAD_MODE")
        has_key = bool(os.environ.get("CLOCKED_API_KEY"))
        self.mode = (mode or env_mode or ("live" if has_key else "replay")).lower()
        self.fixtures_dir = Path(fixtures_dir or os.environ.get("BULKHEAD_FIXTURES", DEFAULT_FIXTURES))
        if budget is None and os.environ.get("BULKHEAD_CREDIT_BUDGET"):
            budget = float(os.environ["BULKHEAD_CREDIT_BUDGET"])
        self.ledger = CreditLedger(ledger_path, budget)
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.sem = threading.Semaphore(concurrency)  # Build plan allows 4 requests in flight
        self.transport = transport or requests.post
        self.sleep = sleep
        self.faults: list[int] = []

    # ---------------------------------------------------------------- fixtures
    def _fixture_path(self, endpoint: str, payload: dict) -> Path:
        return self.fixtures_dir / f"{endpoint}-{payload_hash(endpoint, payload)}.json"

    def _record(self, endpoint: str, payload: dict, res: ClockedResult) -> None:
        self.fixtures_dir.mkdir(parents=True, exist_ok=True)
        rec = {"endpoint": endpoint, "request": payload, "response": res.data, "credits": res.credits,
               "model_ms": res.model_ms, "latency_ms": round(res.latency_ms),
               "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self._fixture_path(endpoint, payload).write_text(json.dumps(rec, indent=1, ensure_ascii=False))

    # ---------------------------------------------------------------- calls
    def inject_faults(self, statuses: list[int]) -> None:
        """Make the next requests answer with these HTTP statuses (resilience drills and tests)."""
        self.faults.extend(statuses)

    def call(self, endpoint: str, payload: dict) -> ClockedResult:
        if self.mode != "replay":
            self.ledger.check()
        key = str(uuid.uuid4())
        retries: list = []
        new_attempt_used = False
        conflict_replays = 0
        attempt = 0
        start = time.monotonic()
        while True:
            attempt += 1
            status, body, headers, err = self._send(endpoint, payload, key)
            if status == 200 and isinstance(body, dict):
                credits = _num(headers.get("X-Clocked-Credits") or headers.get("x-clocked-credits")) or 0.0
                model_ms = _num(headers.get("X-Clocked-Model-Ms") or headers.get("x-clocked-model-ms"))
                source = headers.get("X-Bulkhead-Source", "live")
                if source == "live":
                    self.ledger.add(endpoint, credits, key)
                latency = (time.monotonic() - start) * 1000
                if source == "replay" and headers.get("X-Bulkhead-Latency") is not None:
                    latency += float(headers["X-Bulkhead-Latency"])  # recorded latency + any retry wait now
                res = ClockedResult(endpoint, body, credits=credits, model_ms=model_ms,
                                    latency_ms=latency, attempts=attempt,
                                    idempotency_key=key, retries=retries, source=source)
                if self.mode == "record" and source == "live":
                    self._record(endpoint, payload, res)
                return res

            retry_as_new = isinstance(body, dict) and bool(body.get("retryAsNew"))
            msg = _err_msg(body, err, status)
            retries.append({"attempt": attempt, "status": status, "error": msg[:160], "key": key[:8]})
            if status in NO_RETRY:
                kind = {402: "credits", 401: "auth", 403: "auth", 413: "invalid", 404: "no_fixture"}.get(status, "invalid")
                raise ClockedError(kind, msg, status, attempt)
            if retry_as_new:
                # The previous attempt has definitively ended. Our calls are read-only analyses, so one
                # fresh attempt (billed again) is acceptable; never more than one.
                if new_attempt_used or attempt >= self.max_attempts:
                    raise ClockedError("upstream", f"attempt ended (retryAsNew): {msg}", status, attempt)
                new_attempt_used = True
                key = str(uuid.uuid4())
                self.sleep(_backoff(attempt))
                continue
            if status == 409:
                # A matching request may still be running: wait, then replay the SAME key once.
                if conflict_replays >= 1 or attempt >= self.max_attempts:
                    raise ClockedError("conflict", msg, status, attempt)
                conflict_replays += 1
                self.sleep(2.0)
                continue
            if status is None or status in RETRYABLE or status >= 500:
                if attempt >= self.max_attempts:
                    kind = "busy" if status == 429 else ("network" if status is None else "upstream")
                    raise ClockedError(kind, msg, status, attempt)
                retry_after = _num((headers or {}).get("Retry-After") or (headers or {}).get("retry-after"))
                self.sleep(min(retry_after, 10.0) if retry_after else _backoff(attempt))
                continue  # same Idempotency-Key, identical payload
            raise ClockedError("upstream", msg, status, attempt)

    def _send(self, endpoint: str, payload: dict, key: str):
        if self.faults:
            st = self.faults.pop(0)
            return st, {"error": f"injected fault {st} (resilience drill)"}, {}, None
        if self.mode == "replay":
            path = self._fixture_path(endpoint, payload)
            if not path.exists():
                return 404, {"error": f"no recorded response for {endpoint} ({path.name}); run with BULKHEAD_MODE=record"}, {}, None
            rec = json.loads(path.read_text())
            return 200, rec["response"], {"X-Clocked-Credits": rec.get("credits", 0),
                                          "X-Clocked-Model-Ms": rec.get("model_ms"), "X-Bulkhead-Source": "replay",
                                          "X-Bulkhead-Latency": rec.get("latency_ms")}, None
        headers = {"Idempotency-Key": key, "Content-Type": "application/json"}
        api_key = os.environ.get("CLOCKED_API_KEY", "")
        # "proxy-managed" = the key is injected by an egress proxy (sandboxed dev environments)
        if api_key and api_key != "proxy-managed":
            headers["Authorization"] = "Bearer " + api_key
        try:
            with self.sem:
                r = self.transport(f"{BASE_URL}/{endpoint}", json=payload, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:  # network failure: outcome unknown, keep the key
            return None, None, {}, str(exc)
        try:
            body = r.json()
        except ValueError:
            body = {"error": (r.text or "")[:300]}
        return r.status_code, body, dict(r.headers), None

    @property
    def spent(self) -> float:
        return self.ledger.spent


def _num(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _backoff(attempt: int) -> float:
    return min(8.0, 0.5 * (2 ** (attempt - 1))) + random.uniform(0, 0.25)


def _err_msg(body, err, status) -> str:
    if err:
        return f"network error: {err}"
    if isinstance(body, dict):
        m = body.get("error") or body.get("detail") or body
        return f"HTTP {status}: {m if isinstance(m, str) else json.dumps(m)[:300]}"
    return f"HTTP {status}"
