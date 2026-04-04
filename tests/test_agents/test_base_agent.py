# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for base section agent using TestModel/FunctionModel."""

from __future__ import annotations

import pytest
from pydantic_ai.models.test import TestModel

from gws_auditor.ai.agents.base_agent import create_section_agent
from gws_auditor.ai.agents.deps import CheckDeps
from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckFix,
    CheckIssue,
    Severity,
    TestCase,
)


@pytest.fixture
def simple_deps() -> CheckDeps:
    """Minimal deps for testing agent structure."""
    return CheckDeps(
        check_source_code='def check_foo(data):\n    return make_pass("CIS-1.1.1", ...)',
        test_source_code="def test_foo(): pass",
        module_path="checks/test.py",
        check_ids=["CIS-1.1.1"],
        benchmark_requirements={"CIS-1.1.1": "Test requirement"},
        base_helpers_source="def make_pass(): ...",
        conftest_source="import pytest",
    )


class TestCreateSectionAgent:
    def test_creates_agent_for_known_section(self):
        agent = create_section_agent("Google Chat", model="test")
        assert agent.name == "check-analyzer-google-chat"

    def test_creates_agent_for_unknown_section(self):
        agent = create_section_agent("Unknown Section", model="test")
        assert agent.name == "check-analyzer-unknown-section"

    def test_agent_has_tools(self):
        agent = create_section_agent("Google Chat", model="test")
        tool_names = set(agent._function_toolset.tools.keys())
        assert "get_check_source" in tool_names
        assert "get_existing_tests" in tool_names
        assert "get_benchmark_requirement" in tool_names
        assert "get_base_helpers" in tool_names
        assert "get_conftest" in tool_names
        assert "get_check_ids" in tool_names

    def test_agent_output_type(self):
        agent = create_section_agent("Security", model="test")
        # The output type should be CheckAnalysis
        assert agent._output_schema is not None


class TestAgentWithTestModel:
    """Test agent execution using PydanticAI TestModel."""

    @pytest.mark.anyio
    async def test_run_returns_check_analysis(self, simple_deps):
        agent = create_section_agent("Google Chat", model="test")
        result = await agent.run(
            "Analyze the check module for bugs",
            deps=simple_deps,
        )
        # TestModel returns structured output with default values
        assert isinstance(result.output, CheckAnalysis)

    @pytest.mark.anyio
    async def test_run_with_custom_output(self, simple_deps):
        """TestModel can be configured with custom structured output."""
        custom_analysis = CheckAnalysis(
            module_name="apps_chat",
            section="Google Chat",
            total_checks_analyzed=6,
            issues=[
                CheckIssue(
                    check_id="CIS-3.1.4.2.1",
                    severity=Severity.CRITICAL,
                    category=BugCategory.FALSE_POSITIVE,
                    description="len >= 0 always true",
                    benchmark_requirement="Must have entries",
                    current_behavior="Always passes",
                    correct_behavior="Use > 0",
                ),
            ],
            fixes=[
                CheckFix(
                    check_id="CIS-3.1.4.2.1",
                    function_name="check_chat_external_domain_allowlist",
                    fixed_code="if len(domains) > 0:",
                    explanation="Fixed comparison",
                ),
            ],
            summary="Found 1 critical issue",
        )

        agent = create_section_agent("Google Chat", model="test")

        with agent.override(
            model=TestModel(custom_output_args=custom_analysis.model_dump()),
        ):
            result = await agent.run(
                "Analyze the check module for bugs",
                deps=simple_deps,
            )

        assert isinstance(result.output, CheckAnalysis)
        assert result.output.total_checks_analyzed == 6
        assert len(result.output.issues) == 1
        assert result.output.issues[0].check_id == "CIS-3.1.4.2.1"
        assert result.output.issues[0].severity == Severity.CRITICAL

    @pytest.mark.anyio
    async def test_tools_are_called(self, simple_deps):
        """Verify that the agent's tools are invoked during a run."""
        agent = create_section_agent("Google Chat", model="test")

        # TestModel with call_tools='all' will call all available tools
        with agent.override(model=TestModel(call_tools="all")):
            result = await agent.run(
                "Analyze the check module for bugs",
                deps=simple_deps,
            )

        assert isinstance(result.output, CheckAnalysis)

    @pytest.mark.anyio
    async def test_different_sections_have_different_prompts(self, simple_deps):
        chat_agent = create_section_agent("Google Chat", model="test")
        security_agent = create_section_agent("Security", model="test")

        # System prompts are stored on the agent
        assert chat_agent.name != security_agent.name
        # Both should produce valid output
        for agent in [chat_agent, security_agent]:
            result = await agent.run("Analyze", deps=simple_deps)
            assert isinstance(result.output, CheckAnalysis)
