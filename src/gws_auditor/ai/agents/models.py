# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Structured output models for check quality analysis agents."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Issue severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BugCategory(str, Enum):
    """Classification of check defect type."""
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    LOGIC_ERROR = "logic_error"
    TYPE_ERROR = "type_error"
    STUB_IMPLEMENTATION = "stub_implementation"
    MISSING_VALIDATION = "missing_validation"
    RFC_NONCOMPLIANCE = "rfc_noncompliance"
    DATA_HANDLING = "data_handling"


class CheckIssue(BaseModel):
    """A single issue found in a security check."""
    check_id: str = Field(description="The check ID (e.g. CIS-3.1.4.2.1)")
    severity: Severity
    category: BugCategory
    description: str = Field(description="What the bug is")
    benchmark_requirement: str = Field(
        description="What the benchmark/standard actually requires"
    )
    current_behavior: str = Field(
        description="What the code currently does (incorrectly)"
    )
    correct_behavior: str = Field(
        description="What the code should do instead"
    )


class CheckFix(BaseModel):
    """A proposed fix for a check defect."""
    check_id: str
    function_name: str = Field(description="Name of the function to fix")
    fixed_code: str = Field(description="Complete corrected function body")
    explanation: str = Field(description="Why this fix is correct")


class TestCase(BaseModel):
    """A generated test case for a check."""
    test_name: str = Field(description="Test method name (test_...)")
    test_class: str = Field(description="Test class name (Test...)")
    test_code: str = Field(description="Complete test method source")
    is_regression: bool = Field(
        default=False,
        description="True if this test specifically covers a fixed bug",
    )


class CheckAnalysis(BaseModel):
    """Complete analysis output for one check module / section."""
    module_name: str = Field(description="Python module name analyzed")
    section: str = Field(description="Section name (e.g. 'Google Chat')")
    total_checks_analyzed: int
    issues: list[CheckIssue] = Field(default_factory=list)
    fixes: list[CheckFix] = Field(default_factory=list)
    test_cases: list[TestCase] = Field(default_factory=list)
    summary: str = Field(description="Natural-language summary of findings")


class ConsolidatedReport(BaseModel):
    """Aggregated report from all section agents."""
    total_checks_analyzed: int = 0
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    analyses: list[CheckAnalysis] = Field(default_factory=list)
    summary: str = ""

    @classmethod
    def from_analyses(cls, analyses: list[CheckAnalysis]) -> ConsolidatedReport:
        """Build a consolidated report from individual section analyses."""
        all_issues: list[CheckIssue] = []
        total_checks = 0
        for a in analyses:
            all_issues.extend(a.issues)
            total_checks += a.total_checks_analyzed

        severity_counts = {s: 0 for s in Severity}
        for issue in all_issues:
            severity_counts[issue.severity] += 1

        sections_with_issues = [
            a.section for a in analyses if a.issues
        ]
        summary_parts = [
            f"Analyzed {total_checks} checks across {len(analyses)} sections.",
            f"Found {len(all_issues)} issues: "
            f"{severity_counts[Severity.CRITICAL]} critical, "
            f"{severity_counts[Severity.HIGH]} high, "
            f"{severity_counts[Severity.MEDIUM]} medium, "
            f"{severity_counts[Severity.LOW]} low.",
        ]
        if sections_with_issues:
            summary_parts.append(
                f"Sections with issues: {', '.join(sections_with_issues)}."
            )

        return cls(
            total_checks_analyzed=total_checks,
            total_issues=len(all_issues),
            critical_issues=severity_counts[Severity.CRITICAL],
            high_issues=severity_counts[Severity.HIGH],
            medium_issues=severity_counts[Severity.MEDIUM],
            low_issues=severity_counts[Severity.LOW],
            analyses=analyses,
            summary=" ".join(summary_parts),
        )
