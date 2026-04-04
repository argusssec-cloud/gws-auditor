# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Base section agent factory using PydanticAI."""

from __future__ import annotations

from pydantic_ai import Agent, RunContext

from .deps import CheckDeps
from .models import CheckAnalysis
from .prompts import BASE_ANALYSIS_PROMPT, ERROR_FIX_PROMPT, SECTION_PROMPTS


def create_section_agent(
    section: str,
    model: str = "test",
    error_fix: bool = False,
) -> Agent[CheckDeps, CheckAnalysis]:
    """Create a PydanticAI agent for analyzing checks in a given section.

    Args:
        section: The section name (must be a key in SECTION_PROMPTS).
        model: PydanticAI model string (e.g. "openai:gpt-4o", "test").
        error_fix: If True, use ERROR_FIX_PROMPT instead of BASE_ANALYSIS_PROMPT.

    Returns:
        A configured Agent[CheckDeps, CheckAnalysis].
    """
    base_prompt = ERROR_FIX_PROMPT if error_fix else BASE_ANALYSIS_PROMPT
    section_prompt = SECTION_PROMPTS.get(section, "")
    system_prompts = [base_prompt]
    if section_prompt:
        system_prompts.append(section_prompt)

    agent: Agent[CheckDeps, CheckAnalysis] = Agent(
        model,
        output_type=CheckAnalysis,
        system_prompt=system_prompts,
        deps_type=CheckDeps,
        name=f"check-analyzer-{section.lower().replace(' ', '-')}",
        retries=2,
    )

    @agent.tool
    async def get_check_source(ctx: RunContext[CheckDeps]) -> str:
        """Return the full source code of the check module being analyzed."""
        return ctx.deps.check_source_code or "(no source code available)"

    @agent.tool
    async def get_existing_tests(ctx: RunContext[CheckDeps]) -> str:
        """Return the existing test source code for this check module."""
        return ctx.deps.test_source_code or "(no test code available)"

    @agent.tool
    async def get_benchmark_requirement(
        ctx: RunContext[CheckDeps], check_id: str
    ) -> str:
        """Look up the benchmark requirement description for a specific check ID."""
        reqs = ctx.deps.benchmark_requirements
        if check_id in reqs:
            return reqs[check_id]
        return f"No benchmark requirement found for {check_id}"

    @agent.tool
    async def get_base_helpers(ctx: RunContext[CheckDeps]) -> str:
        """Return the base.py helper source (make_pass, make_fail, get_ou_values, etc.)."""
        return ctx.deps.base_helpers_source or "(no helper source available)"

    @agent.tool
    async def get_conftest(ctx: RunContext[CheckDeps]) -> str:
        """Return the conftest.py test fixtures source."""
        return ctx.deps.conftest_source or "(no conftest available)"

    @agent.tool
    async def get_check_ids(ctx: RunContext[CheckDeps]) -> str:
        """Return the list of check IDs in this module."""
        ids = ctx.deps.check_ids
        if ids:
            return "\n".join(ids)
        return "(no check IDs available)"

    @agent.tool
    async def get_raw_policy_keys(ctx: RunContext[CheckDeps]) -> str:
        """Return the raw API policy key names per service from cached data."""
        return ctx.deps.raw_policy_keys or "(no raw policy keys available)"

    @agent.tool
    async def get_error_check_ids(ctx: RunContext[CheckDeps]) -> str:
        """Return the list of check IDs currently returning ERROR in the audit."""
        return ctx.deps.audit_error_checks or "(no error check data available)"

    @agent.tool
    async def get_provider_mapping_source(ctx: RunContext[CheckDeps]) -> str:
        """Return the _map_*() function source from provider.py for this section."""
        return ctx.deps.provider_mapping_source or "(no provider mapping source available)"

    return agent
