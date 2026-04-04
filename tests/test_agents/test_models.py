# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for check analysis agent Pydantic models."""

import json

import pytest

from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckFix,
    CheckIssue,
    ConsolidatedReport,
    Severity,
    TestCase,
)


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"

    def test_all_members(self):
        assert len(Severity) == 4


class TestBugCategory:
    def test_values(self):
        assert BugCategory.FALSE_POSITIVE == "false_positive"
        assert BugCategory.LOGIC_ERROR == "logic_error"
        assert BugCategory.STUB_IMPLEMENTATION == "stub_implementation"

    def test_all_members(self):
        assert len(BugCategory) == 8


class TestCheckIssue:
    def test_create_minimal(self):
        issue = CheckIssue(
            check_id="CIS-3.1.4.2.1",
            severity=Severity.CRITICAL,
            category=BugCategory.FALSE_POSITIVE,
            description="len(x) >= 0 always true",
            benchmark_requirement="Must restrict external chat",
            current_behavior="Always passes",
            correct_behavior="Should check len > 0",
        )
        assert issue.check_id == "CIS-3.1.4.2.1"
        assert issue.severity == Severity.CRITICAL

    def test_serialization_roundtrip(self):
        issue = CheckIssue(
            check_id="CIS-4.1.1.1",
            severity=Severity.CRITICAL,
            category=BugCategory.TYPE_ERROR,
            description="bool(timestamp) always true",
            benchmark_requirement="Check actual login recency",
            current_behavior="bool of non-empty string is True",
            correct_behavior="Parse and compare datetime",
        )
        data = issue.model_dump()
        restored = CheckIssue.model_validate(data)
        assert restored == issue

    def test_json_roundtrip(self):
        issue = CheckIssue(
            check_id="ADD-01",
            severity=Severity.LOW,
            category=BugCategory.DATA_HANDLING,
            description="test",
            benchmark_requirement="test",
            current_behavior="test",
            correct_behavior="test",
        )
        json_str = issue.model_dump_json()
        restored = CheckIssue.model_validate_json(json_str)
        assert restored == issue

    def test_rejects_invalid_severity(self):
        with pytest.raises(Exception):
            CheckIssue(
                check_id="CIS-1.1.1",
                severity="invalid",
                category=BugCategory.FALSE_POSITIVE,
                description="t",
                benchmark_requirement="t",
                current_behavior="t",
                correct_behavior="t",
            )

    def test_rejects_invalid_category(self):
        with pytest.raises(Exception):
            CheckIssue(
                check_id="CIS-1.1.1",
                severity=Severity.LOW,
                category="invalid",
                description="t",
                benchmark_requirement="t",
                current_behavior="t",
                correct_behavior="t",
            )


class TestCheckFix:
    def test_create(self):
        fix = CheckFix(
            check_id="CIS-3.1.4.2.1",
            function_name="check_chat_external_domain_allowlist",
            fixed_code="def check_chat_external_domain_allowlist(data):\n    pass",
            explanation="Changed >= 0 to > 0",
        )
        assert fix.function_name == "check_chat_external_domain_allowlist"

    def test_serialization(self):
        fix = CheckFix(
            check_id="CIS-1.1.1",
            function_name="check_super_admin_count",
            fixed_code="def check():\n    return True",
            explanation="Example fix",
        )
        data = fix.model_dump()
        assert data["check_id"] == "CIS-1.1.1"
        assert "function_name" in data


class TestTestCase:
    def test_create(self):
        tc = TestCase(
            test_name="test_chat_domain_allowlist_empty_fails",
            test_class="TestChatAgent",
            test_code="def test_chat_domain_allowlist_empty_fails(self):\n    pass",
            is_regression=True,
        )
        assert tc.is_regression is True

    def test_default_not_regression(self):
        tc = TestCase(
            test_name="test_basic",
            test_class="TestBasic",
            test_code="pass",
        )
        assert tc.is_regression is False


class TestCheckAnalysis:
    def test_create_empty(self):
        analysis = CheckAnalysis(
            module_name="apps_chat",
            section="Google Chat",
            total_checks_analyzed=6,
            summary="No issues found",
        )
        assert analysis.issues == []
        assert analysis.fixes == []
        assert analysis.test_cases == []

    def test_create_with_issues(self):
        issue = CheckIssue(
            check_id="CIS-3.1.4.2.1",
            severity=Severity.CRITICAL,
            category=BugCategory.FALSE_POSITIVE,
            description="always true",
            benchmark_requirement="restrict external",
            current_behavior="passes always",
            correct_behavior="should check > 0",
        )
        analysis = CheckAnalysis(
            module_name="apps_chat",
            section="Google Chat",
            total_checks_analyzed=6,
            issues=[issue],
            summary="Found 1 critical issue",
        )
        assert len(analysis.issues) == 1
        assert analysis.issues[0].severity == Severity.CRITICAL

    def test_full_json_roundtrip(self):
        analysis = CheckAnalysis(
            module_name="security_auth",
            section="Security",
            total_checks_analyzed=9,
            issues=[
                CheckIssue(
                    check_id="CIS-4.1.1.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.TYPE_ERROR,
                    description="bool always true",
                    benchmark_requirement="check recency",
                    current_behavior="wrong",
                    correct_behavior="right",
                )
            ],
            fixes=[
                CheckFix(
                    check_id="CIS-4.1.1.1",
                    function_name="check_admin_login_recency",
                    fixed_code="def check(): pass",
                    explanation="Parse datetime",
                )
            ],
            test_cases=[
                TestCase(
                    test_name="test_login_recency_regression",
                    test_class="TestSecurityAuth",
                    test_code="def test(): pass",
                    is_regression=True,
                )
            ],
            summary="Found 1 critical issue in security auth checks",
        )
        json_str = analysis.model_dump_json()
        restored = CheckAnalysis.model_validate_json(json_str)
        assert restored.total_checks_analyzed == 9
        assert len(restored.issues) == 1
        assert len(restored.fixes) == 1
        assert len(restored.test_cases) == 1


class TestConsolidatedReport:
    def test_from_empty_analyses(self):
        report = ConsolidatedReport.from_analyses([])
        assert report.total_checks_analyzed == 0
        assert report.total_issues == 0

    def test_from_analyses(self):
        a1 = CheckAnalysis(
            module_name="apps_chat",
            section="Google Chat",
            total_checks_analyzed=6,
            issues=[
                CheckIssue(
                    check_id="CIS-3.1.4.2.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.FALSE_POSITIVE,
                    description="always true",
                    benchmark_requirement="req",
                    current_behavior="cur",
                    correct_behavior="fix",
                ),
            ],
            summary="1 issue",
        )
        a2 = CheckAnalysis(
            module_name="security_auth",
            section="Security",
            total_checks_analyzed=9,
            issues=[
                CheckIssue(
                    check_id="CIS-4.1.1.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.TYPE_ERROR,
                    description="bool true",
                    benchmark_requirement="req",
                    current_behavior="cur",
                    correct_behavior="fix",
                ),
                CheckIssue(
                    check_id="CIS-4.2.1.4",
                    severity=Severity.HIGH,
                    category=BugCategory.MISSING_VALIDATION,
                    description="no api err check",
                    benchmark_requirement="req",
                    current_behavior="cur",
                    correct_behavior="fix",
                ),
            ],
            summary="2 issues",
        )
        report = ConsolidatedReport.from_analyses([a1, a2])
        assert report.total_checks_analyzed == 15
        assert report.total_issues == 3
        assert report.critical_issues == 2
        assert report.high_issues == 1
        assert report.medium_issues == 0
        assert report.low_issues == 0
        assert "Google Chat" in report.summary
        assert "Security" in report.summary

    def test_json_serialization(self):
        report = ConsolidatedReport(
            total_checks_analyzed=10,
            total_issues=2,
            critical_issues=1,
            high_issues=1,
            summary="test",
        )
        data = json.loads(report.model_dump_json())
        assert data["total_checks_analyzed"] == 10
        restored = ConsolidatedReport.model_validate(data)
        assert restored.total_issues == 2
