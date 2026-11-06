"""Controls: the same inputs without the poisoned context are allowed (recorded live responses)."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("raf", Path(__file__).parent.parent / "scripts" / "record_api_fixtures.py")
raf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(raf)


def test_controls_offline():
    out = raf.run("replay")
    assert out["untainted_make"].verdict.action == "allow"   # vs deny after the poisoned README
    assert out["clean_readme"].verdict.action == "allow"
    assert out["clean_readme"].verdict.signals["injection"] < 0.1
