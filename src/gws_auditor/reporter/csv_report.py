# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CSV report generator for GWS Security Auditor."""

import csv
from pathlib import Path

from gws_auditor.models import AuditReport, Status


# Column header names in output order.
_FIELDNAMES = [
    "Check ID",
    "Title",
    "Status",
    "Severity",
    "Level",
    "Source",
    "Section",
    "Details",
    "Critical Reason",
    "Actual Value",
    "Expected Value",
    "Remediation",
    "Org Unit",
]


class CSVReporter:
    """Generates a flat CSV export of audit check results."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate(self, output_path: str) -> None:
        """Write all check results to a CSV file.

        Each row maps to a single CheckResult.  Status enum values are
        written as their plain string representation (e.g. ``PASS``).

        Args:
            output_path: Filesystem path for the generated CSV file.
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
            writer.writeheader()
            for check in self.report.results:
                writer.writerow(self._check_to_row(check))

    @staticmethod
    def _check_to_row(check) -> dict[str, str]:
        """Convert a CheckResult into a dict keyed by CSV column names."""
        status_value = (
            check.status.value
            if isinstance(check.status, Status)
            else str(check.status)
        )
        return {
            "Check ID": check.check_id,
            "Title": check.title,
            "Status": status_value,
            "Severity": getattr(check, "severity", "MEDIUM"),
            "Level": check.level,
            "Source": check.source,
            "Section": check.section,
            "Details": check.details,
            "Critical Reason": getattr(check, "critical_reason", ""),
            "Actual Value": str(check.actual_value) if check.actual_value is not None else "",
            "Expected Value": str(check.expected_value) if check.expected_value is not None else "",
            "Remediation": check.remediation,
            "Org Unit": check.org_unit,
        }
