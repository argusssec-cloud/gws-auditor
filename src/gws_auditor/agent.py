# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Agent mode: run audit and push results to ArgusSec Console."""

import json
import logging
import sys
import urllib.error
import urllib.request

from .orchestrator import Orchestrator

logger = logging.getLogger(__name__)


def _push_report(url: str, api_key: str, report_data: dict) -> dict:
    """POST the JSON report to the console API. Returns parsed response."""
    body = json.dumps(report_data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read()).get("detail", "")
        except Exception:
            pass
        print(
            f"ERROR: Console rejected the push (HTTP {e.code})"
            f"{f': {detail}' if detail else ''}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Could not reach console at {url}: {e.reason}", file=sys.stderr)
        raise SystemExit(1)


def run_agent(config: dict, console_url: str, api_key: str) -> int:
    """Run the full audit and push the JSON report to ArgusSec Console.

    Args:
        config: gws-auditor configuration dict.
        console_url: ArgusSec Console base URL.
        api_key: Tenant-scoped API key (ask_...).

    Returns:
        Exit code: 0 (all pass), 1 (failures exist), 2 (critical failures).
    """
    # 1. Run the audit
    print("Running security audit...")
    orchestrator = Orchestrator(config)
    report = orchestrator.run()

    # 2. Serialize to JSON report format
    from .reporter.json_report import JSONReporter
    report_data = JSONReporter(report).to_dict()

    # 3. Push to console
    url = f"{console_url.rstrip('/')}/api/v1/agent/push"
    print(f"Pushing results to {console_url}...")
    result = _push_report(url, api_key, report_data)

    # 4. Print summary
    grade = result.get("grade", "?")
    score = result.get("posture_score", 0)
    total = result.get("total", 0)
    passed = result.get("passed", 0)
    failed = result.get("failed", 0)
    scan_id = result.get("scan_id", "?")

    print(f"\nPushed to ArgusSec Console: {grade} {score}/100")
    print(f"  Scan ID:  {scan_id}")
    print(f"  Checks:   {total} total | {passed} passed | {failed} failed")

    # 5. Exit code
    if report.summary.critical_failed > 0:
        return 2
    if report.summary.failed > 0:
        return 1
    return 0
