"""Retry / idempotency / failure semantics of the Clocked client, with a fake transport."""
import pytest
import requests

from bulkhead.clocked import ClockedClient, ClockedError


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers, self.text = status, body or {}, headers or {}, ""

    def json(self):
        return self._body


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "key": headers["Idempotency-Key"], "json": json})
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


OK = Resp(200, {"verdict": "benign"}, {"X-Clocked-Credits": "3", "X-Clocked-Model-Ms": "75"})


def client(t, tmp_path=None, **kw):
    return ClockedClient(mode="live", transport=t, sleep=lambda s: None,
                         ledger_path=(tmp_path / "ledger.jsonl") if tmp_path else None, **kw)


def test_429_retries_with_same_idempotency_key(tmp_path):
    t = FakeTransport(Resp(429), Resp(429), OK)
    r = client(t, tmp_path).call("script", {"script": "ls"})
    assert r.data["verdict"] == "benign" and r.attempts == 3
    assert len({c["key"] for c in t.calls}) == 1, "a retry must reuse the Idempotency-Key"
    assert all(c["json"] == {"script": "ls"} for c in t.calls), "and the identical payload"
    assert [x["status"] for x in r.retries] == [429, 429]


def test_5xx_and_network_errors_are_retried(tmp_path):
    t = FakeTransport(Resp(503), requests.ConnectionError("reset"), OK)
    r = client(t, tmp_path).call("pii", {"text": "x"})
    assert r.attempts == 3 and len({c["key"] for c in t.calls}) == 1


def test_retry_budget_is_bounded():
    t = FakeTransport(*[Resp(429)] * 10)
    with pytest.raises(ClockedError) as e:
        client(t, max_attempts=4).call("pii", {"text": "x"})
    assert e.value.kind == "busy" and len(t.calls) == 4


@pytest.mark.parametrize("status,kind", [(402, "credits"), (401, "auth"), (403, "auth"), (422, "invalid"), (400, "invalid")])
def test_non_retryable_statuses_fail_fast(status, kind):
    t = FakeTransport(Resp(status, {"error": "nope"}), OK)
    with pytest.raises(ClockedError) as e:
        client(t).call("decide", {"state": "", "questions": {}})
    assert e.value.kind == kind and len(t.calls) == 1


def test_409_replays_same_key_once():
    t = FakeTransport(Resp(409, {"error": "in flight"}), OK)
    r = client(t).call("script", {"script": "ls"})
    assert r.attempts == 2 and t.calls[0]["key"] == t.calls[1]["key"]


def test_retry_as_new_uses_a_new_key_only_once():
    t = FakeTransport(Resp(503, {"error": "ended", "retryAsNew": True}), OK)
    r = client(t).call("script", {"script": "ls"})
    assert r.attempts == 2 and t.calls[0]["key"] != t.calls[1]["key"]
    t2 = FakeTransport(Resp(503, {"retryAsNew": True}), Resp(503, {"retryAsNew": True}), OK)
    with pytest.raises(ClockedError):
        client(t2).call("script", {"script": "ls"})


def test_credits_are_ledgered_and_budget_enforced(tmp_path):
    t = FakeTransport(OK, OK, OK)
    c = client(t, tmp_path, budget=6)
    c.call("script", {"script": "a"})
    c.call("script", {"script": "b"})
    assert c.spent == 6
    with pytest.raises(ClockedError) as e:
        c.call("script", {"script": "c"})
    assert e.value.kind == "budget" and len(t.calls) == 2
    # the ledger survives a restart
    assert ClockedClient(mode="live", ledger_path=tmp_path / "ledger.jsonl").spent == 6


def test_replay_without_fixture_is_a_clear_error(tmp_path):
    c = ClockedClient(mode="replay", fixtures_dir=tmp_path, sleep=lambda s: None)
    with pytest.raises(ClockedError) as e:
        c.call("script", {"script": "never recorded"})
    assert e.value.kind == "no_fixture"


def test_injected_faults_go_through_the_same_retry_path(tmp_path):
    t = FakeTransport(OK)
    c = client(t)
    c.inject_faults([429, 503])
    r = c.call("script", {"script": "ls"})
    assert r.attempts == 3 and len(t.calls) == 1
