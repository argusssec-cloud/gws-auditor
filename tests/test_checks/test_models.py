"""Tests for data models."""

import pytest

from gws_auditor.models import AuditSummary, CheckResult, Status


class TestAuditSummary:
    """Tests for AuditSummary."""

    def test_from_results_all_pass(self):
        results = [
            CheckResult(check_id=f"T-{i}", title=f"Test {i}", status=Status.PASS)
            for i in range(5)
        ]
        summary = AuditSummary.from_results(results)
        assert summary.total == 5
        assert summary.passed == 5
        assert summary.failed == 0
        assert summary.pass_rate == 100.0

    def test_from_results_mixed(self):
        results = [
            CheckResult(check_id="T-1", title="Test 1", status=Status.PASS),
            CheckResult(check_id="T-2", title="Test 2", status=Status.FAIL),
            CheckResult(check_id="T-3", title="Test 3", status=Status.WARN),
            CheckResult(check_id="T-4", title="Test 4", status=Status.ERROR),
            CheckResult(check_id="T-5", title="Test 5", status=Status.MANUAL),
        ]
        summary = AuditSummary.from_results(results)
        assert summary.total == 5
        assert summary.passed == 1
        assert summary.failed == 1
        assert summary.warnings == 1
        assert summary.errors == 1
        assert summary.manual == 1
        # pass_rate = passed / (passed + failed + warnings) = 1/3 ≈ 33.3%
        assert round(summary.pass_rate, 1) == 33.3

    def test_from_results_empty(self):
        summary = AuditSummary.from_results([])
        assert summary.total == 0
        assert summary.pass_rate == 0.0

    def test_pass_rate_no_evaluated(self):
        results = [
            CheckResult(check_id="T-1", title="Test 1", status=Status.MANUAL),
        ]
        summary = AuditSummary.from_results(results)
        assert summary.pass_rate == 0.0


class TestCheckResult:
    """Tests for CheckResult."""

    def test_defaults(self):
        result = CheckResult(check_id="T-1", title="Test", status=Status.PASS)
        assert result.level == "L1"
        assert result.source == "CIS"
        assert result.org_unit == "Global"
        assert result.cis_controls == []

    def test_full_result(self):
        result = CheckResult(
            check_id="CIS-1.1.1",
            title="Test check",
            status=Status.FAIL,
            level="L1",
            source="CIS",
            section="Directory",
            details="Only 1 super admin found",
            actual_value=1,
            expected_value="2-4",
            remediation="Add more super admins",
            org_unit="Global",
            cis_controls=["5.4"],
        )
        assert result.check_id == "CIS-1.1.1"
        assert result.status == Status.FAIL
        assert result.actual_value == 1
