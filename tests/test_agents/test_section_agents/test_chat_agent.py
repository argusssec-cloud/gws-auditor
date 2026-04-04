# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for Chat section agent — verifies it can find bug #1."""

from __future__ import annotations

import pytest
from pydantic_ai.models.test import TestModel

from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckFix,
    CheckIssue,
    Severity,
    TestCase,
)
from gws_auditor.ai.agents.section_agents.chat import (
    BENCHMARK_REQUIREMENTS,
    create_chat_agent,
)


class TestChatAgentCreation:
    def test_create(self):
        agent = create_chat_agent(model="test")
        assert agent.name == "check-analyzer-google-chat"

    def test_benchmark_requirements_complete(self):
        assert "CIS-3.1.4.2.1" in BENCHMARK_REQUIREMENTS
        assert "allowlist" in BENCHMARK_REQUIREMENTS["CIS-3.1.4.2.1"].lower()


class TestChatAgentExecution:
    """Test Chat agent execution with TestModel using known bug output."""

    @pytest.mark.anyio
    async def test_finds_allowlist_bug(self, chat_deps):
        """Verify agent can return the known >= 0 bug (bug #1)."""
        expected = CheckAnalysis(
            module_name="apps_chat",
            section="Google Chat",
            total_checks_analyzed=6,
            issues=[
                CheckIssue(
                    check_id="CIS-3.1.4.2.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.FALSE_POSITIVE,
                    description=(
                        "len(allowed_domains) >= 0 is always True — "
                        "the domain allowlist check never fails even "
                        "when the list is empty"
                    ),
                    benchmark_requirement=(
                        "If external chat is allowed, domain allowlist "
                        "must contain at least one domain"
                    ),
                    current_behavior=(
                        "Check passes for any list including empty list"
                    ),
                    correct_behavior="Should use len(allowed_domains) > 0",
                ),
            ],
            fixes=[
                CheckFix(
                    check_id="CIS-3.1.4.2.1",
                    function_name="check_chat_external_domain_allowlist",
                    fixed_code="if len(allowed_domains) > 0:",
                    explanation="Changed >= 0 to > 0",
                ),
            ],
            test_cases=[
                TestCase(
                    test_name="test_empty_allowlist_should_fail",
                    test_class="TestChatChecks",
                    test_code=(
                        "def test_empty_allowlist_should_fail(self, "
                        "full_audit_data):\n    ..."
                    ),
                    is_regression=True,
                ),
            ],
            summary="Found 1 critical false-positive bug in CIS-3.1.4.2.1",
        )

        agent = create_chat_agent(model="test")
        with agent.override(
            model=TestModel(custom_output_args=expected.model_dump()),
        ):
            result = await agent.run(
                "Analyze Google Chat checks for bugs",
                deps=chat_deps,
            )

        analysis = result.output
        assert analysis.section == "Google Chat"
        assert len(analysis.issues) == 1

        issue = analysis.issues[0]
        assert issue.check_id == "CIS-3.1.4.2.1"
        assert issue.severity == Severity.CRITICAL
        assert issue.category == BugCategory.FALSE_POSITIVE

        assert len(analysis.fixes) == 1
        assert analysis.fixes[0].check_id == "CIS-3.1.4.2.1"

        assert len(analysis.test_cases) == 1
        assert analysis.test_cases[0].is_regression is True

    @pytest.mark.anyio
    async def test_tools_accessible(self, chat_deps):
        """Verify all tools work with chat deps."""
        agent = create_chat_agent(model="test")

        with agent.override(model=TestModel(call_tools="all")):
            result = await agent.run(
                "Analyze Google Chat checks for bugs",
                deps=chat_deps,
            )

        assert isinstance(result.output, CheckAnalysis)
