"""The generated check reference must match the check registry."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _generator():
    spec = importlib.util.spec_from_file_location("generate_check_reference", ROOT / "scripts" / "generate_check_reference.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_reference_is_up_to_date():
    gen = _generator()
    expected = gen.render()
    stale = [str(p.relative_to(ROOT)) for p in gen.TARGETS if not p.exists() or p.read_text(encoding="utf-8") != expected]
    assert not stale, f"{stale} out of date: run `python scripts/generate_check_reference.py`"
