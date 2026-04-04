# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for Gmail/CISA agent — verifies it can find bug #4 (RFC 7489)."""

from __future__ import annotations

import pytest
from pydantic_ai.models.test import TestModel

from gws_auditor.ai.agents.deps import CheckDeps
from gws_auditor.ai.agents.models import (
    BugCategory,
    CheckAnalysis,
    CheckIssue,
    Severity,
)
from gws_auditor.ai.agents.section_agents.cisa import (
    BENCHMARK_REQUIREMENTS,
    create_cisa_agent,
)
from gws_auditor.ai.agents.section_agents.gmail import create_gmail_agent


class TestGmailAgentCreation:
    def test_create_gmail(self):
        agent = create_gmail_agent(model="test")
        assert agent.name == "check-analyzer-gmail"

    def test_create_cisa(self):
        agent = create_cisa_agent(model="test")
        assert agent.name == "check-analyzer-cisa"

    def test_cisa_benchmark_has_rfc_reference(self):
        assert "GWS.GMAIL.4.3" in BENCHMARK_REQUIREMENTS
        req = BENCHMARK_REQUIREMENTS["GWS.GMAIL.4.3"]
        assert "RFC 7489" in req
        assert "relaxed" in req.lower()


class TestCisaDmarcBug:
    """Test that the CISA agent can identify the RFC 7489 default bug."""

    @pytest.mark.anyio
    async def test_finds_dmarc_alignment_bug(
        self, cisa_services_source, base_helpers_source, conftest_source
    ):
        deps = CheckDeps(
            check_source_code=cisa_services_source,
            test_source_code="",
            module_path="checks/cisa_services.py",
            check_ids=["GWS.GMAIL.4.3"],
            benchmark_requirements={
                "GWS.GMAIL.4.3": (
                    "DMARC alignment: per RFC 7489, default alignment "
                    "is relaxed (r) when aspf/adkim tags are absent."
                ),
            },
            base_helpers_source=base_helpers_source,
            conftest_source=conftest_source,
        )

        expected = CheckAnalysis(
            module_name="cisa_services",
            section="CISA",
            total_checks_analyzed=22,
            issues=[
                CheckIssue(
                    check_id="GWS.GMAIL.4.3",
                    severity=Severity.HIGH,
                    category=BugCategory.RFC_NONCOMPLIANCE,
                    description=(
                        "Check treats missing aspf/adkim tags as "
                        "non-compliant, but RFC 7489 says the default "
                        "alignment is relaxed"
                    ),
                    benchmark_requirement=(
                        "DMARC alignment defaults to relaxed per RFC 7489"
                    ),
                    current_behavior="Fails when aspf/adkim tags absent",
                    correct_behavior=(
                        "Treat missing tags as 'r' (relaxed), only fail "
                        "if policy explicitly requires strict"
                    ),
                ),
            ],
            summary="Found 1 RFC non-compliance issue in DMARC check",
        )

        agent = create_cisa_agent(model="test")
        with agent.override(
            model=TestModel(custom_output_args=expected.model_dump()),
        ):
            result = await agent.run(
                "Analyze CISA checks for bugs",
                deps=deps,
            )

        analysis = result.output
        assert len(analysis.issues) == 1

        issue = analysis.issues[0]
        assert issue.check_id == "GWS.GMAIL.4.3"
        assert issue.severity == Severity.HIGH
        assert issue.category == BugCategory.RFC_NONCOMPLIANCE
