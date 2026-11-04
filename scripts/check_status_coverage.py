#!/usr/bin/env python3
"""Coverage gate: every scored check must have tests that produce PASS and FAIL (or WARN/PARTIAL).

Runs the check test suite with the status recorder in tests/conftest.py enabled, then compares
the recorded statuses with the check registry. Exit status 1 when a scored check lacks a PASS
or a negative verdict and is not in KNOWN_GAPS. Shrink KNOWN_GAPS as plan phase P1 lands.

    python scripts/check_status_coverage.py            # gate
    python scripts/check_status_coverage.py --report   # print the full matrix
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

NEGATIVE = {"FAIL", "WARN", "PARTIAL"}

# Checks whose design makes one side unreachable: they are not gaps to close. A check that
# can never PASS only ever warns or asks for review; a check that can never FAIL rewards
# evidence and otherwise asks for review. Each entry names the side and the reason.
BY_DESIGN: dict[str, str] = {
    "CIS-1.1.3": "never PASS: login-count heuristic, WARN or MANUAL review only",
    "CIS-4.2.1.2": "never PASS: third-party app review always ends in MANUAL or FAIL",
    "CIS-4.2.1.4": "never PASS: domain-wide delegation grants are always listed for review (WARN/MANUAL)",
    "ADD-20": "never FAIL: evidence-only (CAA denial events) -> PASS, else MANUAL",
    "ADD-40": "never FAIL: evidence-only (CAA denial events) -> PASS, else MANUAL",
    "GWS.COMMONCONTROLS.14.1": "never FAIL: audit log presence -> PASS, else MANUAL",
}

# check_id -> reason the gap is tolerated for now (plan phase P3: dead setting keys).
KNOWN_GAPS: dict[str, str] = {}


def main() -> int:
    report = "--report" in sys.argv
    with tempfile.TemporaryDirectory() as tmp:
        record = Path(tmp) / "statuses.json"
        env = {**os.environ, "GWS_STATUS_RECORD": str(record)}
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_checks", "-q", "-p", "no:cacheprovider"],
            cwd=ROOT, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            sys.stderr.write(proc.stdout[-3000:])
            return proc.returncode
        recorded = json.loads(record.read_text())

    from gws_auditor.checks.registry import CheckRegistry

    gaps: list[str] = []
    for meta in CheckRegistry().get_all_checks():
        statuses = set(recorded.get(meta.check_id, {}))
        if report:
            print(f"{meta.check_id:28} {'scored' if meta.scored else 'unscored':8} {', '.join(sorted(statuses)) or '-'}")
        if not meta.scored:
            continue
        missing = []
        if "PASS" not in statuses:
            missing.append("PASS")
        if not statuses & NEGATIVE:
            missing.append("FAIL/WARN/PARTIAL")
        if missing and meta.check_id in BY_DESIGN:
            continue
        if missing and meta.check_id not in KNOWN_GAPS:
            gaps.append(f"{meta.check_id}: missing {', '.join(missing)} (has {', '.join(sorted(statuses)) or 'nothing'})")

    resolved = [cid for cid in KNOWN_GAPS
                if "PASS" in recorded.get(cid, {}) and set(recorded.get(cid, {})) & NEGATIVE]
    if resolved:
        print("KNOWN_GAPS entries now fully covered; remove them: " + ", ".join(sorted(resolved)))
    if gaps:
        print("Scored checks without both a PASS and a negative test:")
        print("\n".join("  " + g for g in gaps))
        return 1
    print(f"status coverage gate passed ({len(KNOWN_GAPS)} known gaps tolerated, {len(BY_DESIGN)} one-sided by design)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
