# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tests for AgentCoordinator."""

from __future__ import annotations

from pathlib import Path

import pytest

from gws_auditor.ai.agents.config import AgentConfig
from gws_auditor.ai.agents.coordinator import AgentCoordinator
from gws_auditor.ai.agents.deps import CheckDeps
from gws_auditor.ai.agents.models import CheckAnalysis, ConsolidatedReport
from gws_auditor.ai.agents.section_agents import get_section_names


class TestCoordinatorInit:
    def test_finds_project_root(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        assert coordinator.checks_dir.exists()
        assert coordinator.tests_dir.exists()

    def test_default_sections(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        sections = coordinator._get_sections()
        assert len(sections) == len(get_section_names())
        assert "Google Chat" in sections
        assert "Security" in sections

    def test_filtered_sections(self, project_root):
        config = AgentConfig(sections=["Google Chat", "Security"])
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        sections = coordinator._get_sections()
        assert sections == ["Google Chat", "Security"]

    def test_invalid_sections_filtered(self, project_root):
        config = AgentConfig(sections=["Google Chat", "NonExistent"])
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        sections = coordinator._get_sections()
        assert sections == ["Google Chat"]


class TestBuildDeps:
    def test_builds_chat_deps(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        deps = coordinator._build_deps("Google Chat")

        assert isinstance(deps, CheckDeps)
        assert deps.check_source_code  # non-empty
        assert "apps_chat" in deps.module_path
        assert deps.base_helpers_source  # non-empty
        assert deps.conftest_source  # non-empty

    def test_builds_security_deps(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        deps = coordinator._build_deps("Security")

        assert isinstance(deps, CheckDeps)
        # Security spans two modules
        assert "security_auth" in deps.module_path
        assert "security_access" in deps.module_path

    def test_builds_cisa_deps(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        deps = coordinator._build_deps("CISA")

        assert isinstance(deps, CheckDeps)
        assert deps.check_source_code
        assert "cisa_scuba" in deps.module_path

    def test_loads_benchmark_requirements(self, project_root):
        config = AgentConfig()
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        deps = coordinator._build_deps("Google Chat")

        assert "CIS-3.1.4.2.1" in deps.benchmark_requirements


class TestDryRun:
    @pytest.mark.anyio
    async def test_dry_run_skips_llm(self, project_root):
        config = AgentConfig(
            sections=["Google Chat"],
            dry_run=True,
        )
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        report = await coordinator.run()

        assert isinstance(report, ConsolidatedReport)
        assert len(report.analyses) == 1
        assert "[dry-run]" in report.analyses[0].summary

    @pytest.mark.anyio
    async def test_dry_run_all_sections(self, project_root):
        config = AgentConfig(dry_run=True)
        coordinator = AgentCoordinator(config=config, project_root=project_root)
        report = await coordinator.run()

        assert isinstance(report, ConsolidatedReport)
        assert len(report.analyses) == len(get_section_names())
        for analysis in report.analyses:
            assert "[dry-run]" in analysis.summary


class TestSaveReport:
    def test_saves_json(self, project_root, tmp_path):
        config = AgentConfig(output_dir=str(tmp_path))
        coordinator = AgentCoordinator(config=config, project_root=project_root)

        report = ConsolidatedReport(
            total_checks_analyzed=10,
            total_issues=2,
            summary="test",
        )
        filepath = coordinator.save_report(report)

        assert filepath.exists()
        assert filepath.suffix == ".json"

        import json
        data = json.loads(filepath.read_text())
        assert data["total_checks_analyzed"] == 10
        assert data["total_issues"] == 2
