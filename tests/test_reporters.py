"""Tests for report generators (JSON, CSV, HTML)."""

import csv
import json
import pytest
from pathlib import Path

from gws_auditor.models import (
    AuditReport, AuditSummary, CheckResult, Status,
)


@pytest.fixture
def sample_report():
    """Create a minimal AuditReport for testing reporters."""
    results = [
        CheckResult(
            check_id="CIS-1.1.1",
            title="Test check pass",
            status=Status.PASS,
            level="L1",
            source="CIS",
            section="Directory",
            details="All good",
            actual_value=2,
            expected_value="2-4",
            remediation="",
            org_unit="Global",
        ),
        CheckResult(
            check_id="CIS-1.1.2",
            title="Test check fail",
            status=Status.FAIL,
            level="L1",
            source="CIS",
            section="Directory",
            details="Not good",
            actual_value=0,
            expected_value=1,
            remediation="Fix it",
            org_unit="Global",
        ),
        CheckResult(
            check_id="CIS-3.1.1.1",
            title="Test calendar check",
            status=Status.ERROR,
            level="L2",
            source="CIS",
            section="Calendar",
            details="Could not verify - policy data unavailable",
        ),
    ]
    summary = AuditSummary.from_results(results)
    return AuditReport(
        timestamp="2026-02-20T10:00:00Z",
        customer_id="C01234",
        domains=["example.com"],
        results=results,
        summary=summary,
        api_errors=[],
        config={"checks": {"levels": ["L1", "L2"]}},
    )


class TestJSONReporter:
    def test_generates_valid_json(self, sample_report, tmp_path):
        from gws_auditor.reporter.json_report import JSONReporter
        output = str(tmp_path / "report.json")
        reporter = JSONReporter(sample_report)
        reporter.generate(output)

        with open(output) as f:
            data = json.load(f)

        assert data["customer_id"] == "C01234"
        assert data["timestamp"] == "2026-02-20T10:00:00Z"
        assert len(data["results"]) == 3
        assert data["summary"]["total"] == 3
        assert data["summary"]["passed"] == 1
        assert data["summary"]["failed"] == 1
        assert data["summary"]["errors"] == 1

    def test_status_serialized_as_string(self, sample_report, tmp_path):
        from gws_auditor.reporter.json_report import JSONReporter
        output = str(tmp_path / "report.json")
        reporter = JSONReporter(sample_report)
        reporter.generate(output)

        with open(output) as f:
            data = json.load(f)

        statuses = [r["status"] for r in data["results"]]
        assert "PASS" in statuses
        assert "FAIL" in statuses
        assert statuses.count("FAIL") == 1
        assert statuses.count("ERROR") == 1

    def test_creates_parent_dirs(self, sample_report, tmp_path):
        from gws_auditor.reporter.json_report import JSONReporter
        output = str(tmp_path / "nested" / "dir" / "report.json")
        reporter = JSONReporter(sample_report)
        reporter.generate(output)
        assert Path(output).exists()

    def test_includes_domains(self, sample_report, tmp_path):
        from gws_auditor.reporter.json_report import JSONReporter
        output = str(tmp_path / "report.json")
        JSONReporter(sample_report).generate(output)
        with open(output) as f:
            data = json.load(f)
        assert data["domains"] == ["example.com"]


class TestCSVReporter:
    def test_generates_valid_csv(self, sample_report, tmp_path):
        from gws_auditor.reporter.csv_report import CSVReporter
        output = str(tmp_path / "report.csv")
        reporter = CSVReporter(sample_report)
        reporter.generate(output)

        with open(output, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 3
        assert rows[0]["Check ID"] == "CIS-1.1.1"
        assert rows[0]["Status"] == "PASS"
        assert rows[1]["Status"] == "FAIL"
        assert rows[2]["Status"] == "ERROR"

    def test_csv_has_correct_headers(self, sample_report, tmp_path):
        from gws_auditor.reporter.csv_report import CSVReporter
        output = str(tmp_path / "report.csv")
        CSVReporter(sample_report).generate(output)

        with open(output, newline="") as f:
            reader = csv.reader(f)
            headers = next(reader)

        expected_headers = [
            "Check ID", "Title", "Status", "Severity", "Level", "Source",
            "Section", "Details", "Critical Reason", "Actual Value",
            "Expected Value", "Remediation", "Org Unit",
        ]
        assert headers == expected_headers

    def test_csv_handles_none_values(self, sample_report, tmp_path):
        from gws_auditor.reporter.csv_report import CSVReporter
        output = str(tmp_path / "report.csv")
        CSVReporter(sample_report).generate(output)

        with open(output, newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # Third check has no actual/expected values set
        manual_row = rows[2]
        assert manual_row["Actual Value"] == ""
        assert manual_row["Expected Value"] == ""

    def test_csv_creates_parent_dirs(self, sample_report, tmp_path):
        from gws_auditor.reporter.csv_report import CSVReporter
        output = str(tmp_path / "sub" / "report.csv")
        CSVReporter(sample_report).generate(output)
        assert Path(output).exists()


class TestHTMLReporter:
    def test_generates_html_file(self, sample_report, tmp_path):
        from gws_auditor.reporter.html_report import HTMLReporter
        output = str(tmp_path / "report.html")
        reporter = HTMLReporter(sample_report)
        reporter.generate(output)
        assert Path(output).exists()

        content = Path(output).read_text()
        assert "<html" in content
        assert "CIS-1.1.1" in content
        assert "example.com" in content

    def test_html_contains_summary(self, sample_report, tmp_path):
        from gws_auditor.reporter.html_report import HTMLReporter
        output = str(tmp_path / "report.html")
        HTMLReporter(sample_report).generate(output)
        content = Path(output).read_text()
        assert "C01234" in content

    def test_html_groups_by_section(self, sample_report, tmp_path):
        from gws_auditor.reporter.html_report import HTMLReporter
        output = str(tmp_path / "report.html")
        HTMLReporter(sample_report).generate(output)
        content = Path(output).read_text()
        assert "Directory" in content
        assert "Calendar" in content

    def test_html_creates_parent_dirs(self, sample_report, tmp_path):
        from gws_auditor.reporter.html_report import HTMLReporter
        output = str(tmp_path / "deep" / "path" / "report.html")
        HTMLReporter(sample_report).generate(output)
        assert Path(output).exists()

    def test_group_by_section(self, sample_report):
        from gws_auditor.reporter.html_report import HTMLReporter
        reporter = HTMLReporter(sample_report)
        sections = reporter._group_by_section()
        assert "Directory" in sections
        assert "Calendar" in sections
        assert len(sections["Directory"]) == 2
        assert len(sections["Calendar"]) == 1
