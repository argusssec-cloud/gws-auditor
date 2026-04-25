# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""JSON report generator for GWS Security Auditor."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from gws_auditor.config import sanitize_config_for_report
from gws_auditor.models import AuditReport, Status


class JSONReporter:
    """Generates a full JSON export of the audit report."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate(self, output_path: str) -> None:
        """Serialize the AuditReport to a JSON file.

        Converts all CheckResult objects to plain dicts and Status enum
        members to their string values so the output is valid JSON.

        Args:
            output_path: Filesystem path for the generated JSON file.
        """
        data = self._serialize_report()
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Return the report as a plain dict (public API)."""
        return self._serialize_report()

    def _serialize_report(self) -> dict[str, Any]:
        """Convert the AuditReport dataclass tree into a plain dict."""
        report = self.report
        return {
            "timestamp": report.timestamp,
            "customer_id": report.customer_id,
            "subscription_type": report.subscription_type,
            "domains": report.domains,
            "summary": {
                "total": report.summary.total,
                "passed": report.summary.passed,
                "failed": report.summary.failed,
                "warnings": report.summary.warnings,
                "errors": report.summary.errors,
                "manual": report.summary.manual,
                "not_applicable": report.summary.not_applicable,
                "pass_rate": report.summary.pass_rate,
                "critical_failed": report.summary.critical_failed,
                "posture_score": report.summary.posture_score,
                "posture_grade": report.summary.posture_grade,
            },
            "results": [self._serialize_check(r) for r in report.results],
            "api_errors": report.api_errors,
            "config": sanitize_config_for_report(report.config),
        }

    @staticmethod
    def _serialize_check(check) -> dict[str, Any]:
        """Convert a single CheckResult to a JSON-safe dict."""
        return {
            "check_id": check.check_id,
            "title": check.title,
            "status": check.status.value if isinstance(check.status, Status) else str(check.status),
            "level": check.level,
            "source": check.source,
            "section": check.section,
            "severity": getattr(check, "severity", "MEDIUM"),
            "critical_reason": getattr(check, "critical_reason", ""),
            "details": check.details,
            "actual_value": check.actual_value,
            "expected_value": check.expected_value,
            "remediation": check.remediation,
            "org_unit": check.org_unit,
            "cis_controls": check.cis_controls,
            "scored": getattr(check, "scored", True),
        }
