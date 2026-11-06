import pytest

from bulkhead.clocked import ClockedClient
from bulkhead.config import Settings
from bulkhead.engine import Engine
from bulkhead.store import Store


@pytest.fixture
def engine(monkeypatch):
    """Offline engine: every Clocked answer comes from fixtures/clocked (recorded live responses)."""
    monkeypatch.delenv("BULKHEAD_CREDIT_BUDGET", raising=False)
    client = ClockedClient(mode="replay", sleep=lambda s: None)
    return Engine(client, Store(":memory:"), Settings(fail_mode="ask"))
