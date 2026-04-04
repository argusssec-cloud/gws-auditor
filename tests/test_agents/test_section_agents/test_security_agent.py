# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for Security section agent — verifies it can find bugs #2, #7-9."""

from __future__ import annotations

import pytest
from pydantic_ai.models.test import TestModel

from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckFix,
    CheckIssue,
    Severity,
)
from gws_auditor.ai.agents.section_agents.security import (
    BENCHMARK_REQUIREMENTS,
    create_security_agent,
)


class TestSecurityAgentCreation:
    def test_create(self):
        agent = create_security_agent(model="test")
        assert agent.name == "check-analyzer-security"

    def test_benchmark_requirements(self):
        assert "CIS-4.1.1.1" in BENCHMARK_REQUIREMENTS
        assert "CIS-4.2.1.2" in BENCHMARK_REQUIREMENTS
        assert "CIS-4.2.1.4" in BENCHMARK_REQUIREMENTS
        assert "CIS-4.2.3.1" in BENCHMARK_REQUIREMENTS


class TestSecurityAgentExecution:
    @pytest.mark.anyio
    async def test_finds_multiple_security_bugs(self, security_deps):
        """Verify agent can return all known Security section bugs."""
        expected = CheckAnalysis(
            module_name="security_auth",
            section="Security",
            total_checks_analyzed=17,
            issues=[
                CheckIssue(
                    check_id="CIS-4.1.1.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.TYPE_ERROR,
                    description=(
                        "bool(timestamp_string) is always True for "
                        "non-empty strings"
                    ),
                    benchmark_requirement="Must parse and compare datetime",
                    current_behavior="Uses bool() on timestamp string",
                    correct_behavior="Parse ISO timestamp and compare to threshold",
                ),
                CheckIssue(
                    check_id="CIS-4.2.1.4",
                    severity=Severity.HIGH,
                    category=BugCategory.MISSING_VALIDATION,
                    description=(
                        "Returns PASS when DWD data is missing without "
                        "checking api_errors"
                    ),
                    benchmark_requirement="Must verify data was retrieved",
                    current_behavior="PASS on empty data",
                    correct_behavior="Check api_errors, return WARN or ERROR",
                ),
                CheckIssue(
                    check_id="CIS-4.2.1.2",
                    severity=Severity.HIGH,
                    category=BugCategory.STUB_IMPLEMENTATION,
                    description=(
                        "Lists OAuth apps but performs no validation"
                    ),
                    benchmark_requirement="Must validate against policy",
                    current_behavior="Just lists apps",
                    correct_behavior="Check against allowlist/risk criteria",
                ),
                CheckIssue(
                    check_id="CIS-4.2.3.1",
                    severity=Severity.MEDIUM,
                    category=BugCategory.MISSING_VALIDATION,
                    description="Only checks DLP exists, not rule config",
                    benchmark_requirement="Must verify rule configuration",
                    current_behavior="Checks existence only",
                    correct_behavior="Verify rules and conditions",
                ),
            ],
            summary="Found 4 issues in Security checks",
        )

        agent = create_security_agent(model="test")
        with agent.override(
            model=TestModel(custom_output_args=expected.model_dump()),
        ):
            result = await agent.run(
                "Analyze Security checks for bugs",
                deps=security_deps,
            )

        analysis = result.output
        assert analysis.section == "Security"
        assert len(analysis.issues) == 4

        ids = [i.check_id for i in analysis.issues]
        assert "CIS-4.1.1.1" in ids
        assert "CIS-4.2.1.4" in ids
        assert "CIS-4.2.1.2" in ids
        assert "CIS-4.2.3.1" in ids

        severities = {i.check_id: i.severity for i in analysis.issues}
        assert severities["CIS-4.1.1.1"] == Severity.CRITICAL
        assert severities["CIS-4.2.1.4"] == Severity.HIGH
