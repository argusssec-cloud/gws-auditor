#!/usr/bin/env python3
"""Recompute tests/fixtures/golden/expected_statuses.json from the golden snapshots.

    python scripts/update_golden_expectations.py            # rewrite expectations
    python scripts/update_golden_expectations.py --check    # exit 1 on any difference

Each snapshot's statuses are pinned per check. "confirmed" marks checks whose status was
verified against the Admin console (kept across updates); everything else is "observed".
When a status changes, the diff is printed; update only after confirming the new verdict.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
GOLDEN = ROOT / "tests" / "fixtures" / "golden"
EXPECTED = GOLDEN / "expected_statuses.json"


def load_snapshot(path: Path) -> dict:
    with gzip.open(path, "rb") as fh:
        return json.loads(fh.read())


def run_snapshot(path: Path) -> dict[str, str]:
    """Mirror the --cached path: normalize, inject options and edition, run every check."""
    from gws_auditor.checks.registry import CheckRegistry
    from gws_auditor.provider import normalize_data

    data = normalize_data(load_snapshot(path))
    data["_options"] = {}
    data["subscription_type"] = (data.get("subscription_info") or {}).get("edition", "")
    return {r.check_id: r.status.value for r in CheckRegistry().execute_checks(data)}


def main(argv: list[str]) -> int:
    check_only = "--check" in argv
    previous = json.loads(EXPECTED.read_text()) if EXPECTED.exists() else {}
    current: dict[str, dict] = {}
    changed: list[str] = []
    for path in sorted(GOLDEN.glob("*.json.gz")):
        name = path.name[: -len(".json.gz")]
        statuses = run_snapshot(path)
        prev = previous.get(name, {})
        current[name] = {}
        for cid, status in sorted(statuses.items()):
            entry = {"status": status, "confirmed": bool(prev.get(cid, {}).get("confirmed"))}
            if prev.get(cid, {}).get("note"):
                entry["note"] = prev[cid]["note"]
            if cid in prev and prev[cid]["status"] != status:
                changed.append(f"{name}: {cid} {prev[cid]['status']} -> {status}" + (" (console-confirmed!)" if prev[cid].get("confirmed") else ""))
                if prev[cid].get("confirmed"):
                    entry["confirmed"] = False
                    entry["note"] = f"status changed from console-confirmed {prev[cid]['status']}; re-confirm"
            current[name][cid] = entry
        for cid in prev:
            if cid not in statuses:
                changed.append(f"{name}: {cid} no longer produced")
    for line in changed:
        print(line)
    if check_only:
        print("golden expectations up to date" if not changed else f"{len(changed)} difference(s)")
        return 1 if changed else 0
    EXPECTED.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n")
    print(f"wrote {EXPECTED} for {len(current)} snapshot(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
