"""Plan Layer 3: golden tenant snapshots.

Anonymised cache files (scripts/anonymize_cache.py) for one tenant per edition run through the
same path as ``--cached`` and must reproduce the pinned statuses in
tests/fixtures/golden/expected_statuses.json. Update the file only with
``python scripts/update_golden_expectations.py`` after confirming each changed verdict; entries
marked ``confirmed`` were read in the Admin console and must not drift silently.
"""

import gzip
import json
import re
from pathlib import Path

import pytest

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
SNAPSHOTS = sorted(GOLDEN.glob("*.json.gz"))
EXPECTED = json.loads((GOLDEN / "expected_statuses.json").read_text())
PLACEHOLDER_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(example\.com|example-[0-9a-f]+\.org|ext-[0-9a-f]+\.example\.net|.*google.*|.*gserviceaccount\.com)$")


def _run(path: Path) -> dict:
    from gws_auditor.checks.registry import CheckRegistry
    from gws_auditor.provider import normalize_data

    with gzip.open(path, "rb") as fh:
        data = normalize_data(json.loads(fh.read()))
    data["_options"] = {}
    data["subscription_type"] = (data.get("subscription_info") or {}).get("edition", "")
    return {r.check_id: r for r in CheckRegistry().execute_checks(data)}


@pytest.mark.parametrize("path", SNAPSHOTS, ids=[p.name[:-8] for p in SNAPSHOTS])
class TestGoldenSnapshots:
    def test_statuses_match_pinned_expectations(self, path):
        name = path.name[:-len(".json.gz")]
        expected = EXPECTED[name]
        results = _run(path)
        drift = [f"{cid}: expected {exp['status']}, got {results[cid].status.value}"
                 + (" [console-confirmed]" if exp.get("confirmed") else "")
                 for cid, exp in expected.items() if cid in results and results[cid].status.value != exp["status"]]
        missing = sorted(set(expected) - set(results))
        new = sorted(set(results) - set(expected))
        assert not drift and not missing and not new, (
            f"golden snapshot {name} drifted. drift={drift} missing={missing} new={new}. "
            "Confirm each change, then run scripts/update_golden_expectations.py")

    def test_no_check_raises(self, path):
        crashed = [cid for cid, r in _run(path).items() if "Check execution error" in (r.details or "")]
        assert crashed == []

    def test_run_is_deterministic(self, path):
        first = {cid: r.status for cid, r in _run(path).items()}
        second = {cid: r.status for cid, r in _run(path).items()}
        assert first == second

    def test_snapshot_carries_no_tenant_identity(self, path):
        with gzip.open(path, "rb") as fh:
            text = fh.read().decode()
        emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}", text))
        assert all(PLACEHOLDER_EMAIL.match(e) for e in emails), sorted(e for e in emails if not PLACEHOLDER_EMAIL.match(e))[:5]
        assert "orgUnits/0" not in text and "customers/C0" in text or "customers/" not in text


def test_every_snapshot_has_expectations():
    assert {p.name[:-8] for p in SNAPSHOTS} == set(EXPECTED)
