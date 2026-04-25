# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""AgentCoordinator — orchestrates section agents for check quality analysis."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from .base_agent import create_section_agent
from .config import AgentConfig, get_pydantic_ai_model_string
from .deps import CheckDeps
from .models import CheckAnalysis, ConsolidatedReport
from .section_agents import (
    SECTION_REGISTRY,
    SectionMapping,
    get_section_names,
    resolve_paths,
)

logger = logging.getLogger(__name__)


class AgentCoordinator:
    """Orchestrates section agents across all check modules.

    The coordinator:
    1. Resolves source file paths for each section
    2. Builds CheckDeps by reading source files
    3. Runs each section agent
    4. Consolidates results into a ConsolidatedReport
    """

    def __init__(
        self,
        config: AgentConfig,
        project_root: Path | None = None,
    ):
        self.config = config
        self.project_root = project_root or self._find_project_root()
        self.checks_dir = self.project_root / "src" / "gws_auditor" / "checks"
        self.tests_dir = self.project_root / "tests" / "test_checks"
        self.base_helpers_path = self.checks_dir / "base.py"
        self.conftest_path = self.project_root / "tests" / "conftest.py"

    @staticmethod
    def _find_project_root() -> Path:
        """Walk up from this file to find the project root (has pyproject.toml)."""
        current = Path(__file__).resolve().parent
        for _ in range(10):
            if (current / "pyproject.toml").exists():
                return current
            current = current.parent
        return Path.cwd()

    def _get_sections(self) -> list[str]:
        """Return sections to analyze based on config."""
        if self.config.sections:
            return [s for s in self.config.sections if s in SECTION_REGISTRY]
        if self.config.mode == "error-fix":
            return self._get_error_sections()
        return get_section_names()

    def _get_error_sections(self) -> list[str]:
        """Return only sections that contain ERROR checks."""
        error_ids = self._load_error_check_ids()
        if not error_ids:
            return get_section_names()

        sections = []
        for name, mapping in SECTION_REGISTRY.items():
            for eid in error_ids:
                if any(eid.startswith(prefix) for prefix in mapping.check_id_prefixes):
                    sections.append(name)
                    break
        return sections

    def _build_deps(self, section: str) -> CheckDeps:
        """Build CheckDeps for a section by reading source files."""
        check_paths, test_paths = resolve_paths(
            section, self.checks_dir, self.tests_dir
        )

        is_error_fix = self.config.mode == "error-fix"

        # Concatenate multiple modules if a section spans several files
        check_source = ""
        for p in check_paths:
            if p.exists():
                check_source += p.read_text(encoding="utf-8") + "\n\n"

        # In error-fix mode, skip test source to save context window
        test_source = ""
        if not is_error_fix:
            for p in test_paths:
                if p.exists():
                    test_source += p.read_text(encoding="utf-8") + "\n\n"

        base_helpers = ""
        if self.base_helpers_path.exists():
            base_helpers = self.base_helpers_path.read_text(encoding="utf-8")

        # In error-fix mode, skip conftest to save context window
        conftest = ""
        if not is_error_fix and self.conftest_path.exists():
            conftest = self.conftest_path.read_text(encoding="utf-8")

        # Collect benchmark requirements from the section agent module
        mapping = SECTION_REGISTRY[section]
        benchmark_reqs = self._load_benchmark_requirements(section)

        deps = CheckDeps(
            check_source_code=check_source,
            test_source_code=test_source,
            module_path=", ".join(str(p) for p in check_paths),
            check_ids=list(benchmark_reqs.keys()),
            benchmark_requirements=benchmark_reqs,
            base_helpers_source=base_helpers,
            conftest_source=conftest,
        )

        if self.config.mode == "error-fix":
            self._populate_error_fix_deps(deps, section)

        return deps

    def _load_benchmark_requirements(self, section: str) -> dict[str, str]:
        """Load benchmark requirements from the section agent module."""
        # Import from the section agent modules which define BENCHMARK_REQUIREMENTS
        module_map = {
            "Google Chat": "gws_auditor.ai.agents.section_agents.chat",
            "Gmail": "gws_auditor.ai.agents.section_agents.gmail",
            "Drive": "gws_auditor.ai.agents.section_agents.drive",
            "Calendar": "gws_auditor.ai.agents.section_agents.calendar",
            "Directory": "gws_auditor.ai.agents.section_agents.directory",
            "Groups": "gws_auditor.ai.agents.section_agents.groups",
            "Sites": "gws_auditor.ai.agents.section_agents.sites",
            "Marketplace": "gws_auditor.ai.agents.section_agents.marketplace",
            "Security": "gws_auditor.ai.agents.section_agents.security",
            "Reporting": "gws_auditor.ai.agents.section_agents.reporting",
            "CISA": "gws_auditor.ai.agents.section_agents.cisa",
            "Additional": "gws_auditor.ai.agents.section_agents.additional",
        }
        module_name = module_map.get(section)
        if module_name is None:
            return {}

        import importlib
        try:
            mod = importlib.import_module(module_name)
            return getattr(mod, "BENCHMARK_REQUIREMENTS", {})
        except ImportError:
            logger.warning("Could not import section module %s", module_name)
            return {}

    def _find_latest_report(self) -> Path | None:
        """Find the most recent audit report JSON."""
        if self.config.report_path:
            p = Path(self.config.report_path)
            return p if p.exists() else None
        reports_dir = self.project_root / "reports"
        if not reports_dir.exists():
            return None
        jsons = sorted(reports_dir.glob("audit_*.json"))
        return jsons[-1] if jsons else None

    def _load_error_check_ids(self) -> list[str]:
        """Load ERROR check IDs from the audit report."""
        report_path = self._find_latest_report()
        if report_path is None:
            return []
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            return [
                r["check_id"]
                for r in data.get("results", [])
                if r.get("status") == "ERROR"
            ]
        except Exception as e:
            logger.warning("Could not load error checks from %s: %s", report_path, e)
            return []

    def _load_raw_policy_keys(self) -> dict[str, list[str]]:
        """Load raw policy key names per service from cached data."""
        cache_dir = Path(self.config.cache_dir) if self.config.cache_dir else (
            self.project_root / "cache"
        )
        policies_file = cache_dir / "policies.json"
        if not policies_file.exists():
            return {}
        try:
            raw = json.loads(policies_file.read_text(encoding="utf-8"))
            keys: dict[str, list[str]] = {}
            if isinstance(raw, dict):
                for service, settings in raw.items():
                    if isinstance(settings, dict):
                        keys[service] = list(settings.keys())
                    elif isinstance(settings, list):
                        # Flat list of policy objects
                        all_keys: set[str] = set()
                        for item in settings:
                            if isinstance(item, dict):
                                all_keys.update(item.keys())
                        keys[service] = sorted(all_keys)
            return keys
        except Exception as e:
            logger.warning("Could not load raw policy keys from %s: %s", policies_file, e)
            return {}

    def _load_provider_mapping_source(self, section: str) -> str:
        """Read the _map_*() functions from provider.py relevant to a section."""
        provider_path = self.project_root / "src" / "gws_auditor" / "provider.py"
        if not provider_path.exists():
            return ""
        source = provider_path.read_text(encoding="utf-8")

        # Map section names to provider function name substrings
        section_to_funcs: dict[str, list[str]] = {
            "Gmail": ["_map_gmail", "_map_policies_to_check_schema"],
            "Drive": ["_map_drive", "_map_policies_to_check_schema"],
            "Calendar": ["_map_calendar", "_map_policies_to_check_schema"],
            "Google Chat": ["_map_chat", "_map_policies_to_check_schema"],
            "Security": ["_map_security", "_map_access_control", "_map_policies_to_check_schema"],
            "Additional": ["_map_gmail", "_map_security", "_map_policies_to_check_schema"],
            "CISA": ["_map_policies_to_check_schema"],
        }
        func_names = section_to_funcs.get(section, ["_map_policies_to_check_schema"])

        # Extract function bodies
        import re
        extracted: list[str] = []
        for func_name in func_names:
            pattern = rf"(    def {func_name}\(.*?\n(?:        .*\n)*)"
            match = re.search(pattern, source)
            if match:
                extracted.append(match.group(1))
            else:
                # Try top-level function
                pattern = rf"(def {func_name}\(.*?\n(?:    .*\n)*)"
                match = re.search(pattern, source)
                if match:
                    extracted.append(match.group(1))

        return "\n\n".join(extracted) if extracted else ""

    def _populate_error_fix_deps(self, deps: CheckDeps, section: str) -> None:
        """Populate error-fix specific fields on CheckDeps."""
        error_ids = self._load_error_check_ids()
        # Filter to this section's error IDs
        mapping = SECTION_REGISTRY.get(section)
        if mapping:
            section_errors = [
                eid for eid in error_ids
                if any(eid.startswith(prefix) for prefix in mapping.check_id_prefixes)
            ]
        else:
            section_errors = error_ids

        deps.audit_error_checks = json.dumps(section_errors)
        deps.raw_policy_keys = json.dumps(self._load_raw_policy_keys(), indent=2)
        deps.provider_mapping_source = self._load_provider_mapping_source(section)

    async def _run_section(self, section: str) -> CheckAnalysis | None:
        """Run a single section agent."""
        logger.info("Analyzing section: %s", section)

        deps = self._build_deps(section)
        if not deps.check_source_code.strip():
            logger.warning("No source code found for section %s, skipping", section)
            return None

        if self.config.dry_run:
            logger.info("[dry-run] Would analyze section: %s", section)
            return CheckAnalysis(
                module_name=deps.module_path,
                section=section,
                total_checks_analyzed=len(deps.check_ids),
                summary=f"[dry-run] Skipped analysis for {section}",
            )

        model_str = get_pydantic_ai_model_string(self.config)
        is_error_fix = self.config.mode == "error-fix"
        agent = create_section_agent(section, model=model_str, error_fix=is_error_fix)

        if is_error_fix:
            prompt = (
                f"Fix the ERROR-status checks in the {section} module(s). "
                f"Use the available tools to inspect source code, raw policy keys, "
                f"error check IDs, provider mappings, benchmark requirements, and "
                f"test fixtures. Produce CheckFix entries for each ERROR check."
            )
        else:
            prompt = (
                f"Analyze the {section} check module(s) for bugs, false positives, "
                f"and incomplete logic. Use the available tools to inspect source code, "
                f"tests, benchmark requirements, and helper functions."
            )

        result = await agent.run(prompt, deps=deps)
        return result.output

    async def run(self) -> ConsolidatedReport:
        """Run all section agents and return a consolidated report."""
        sections = self._get_sections()
        logger.info(
            "Starting analysis of %d sections: %s",
            len(sections),
            ", ".join(sections),
        )

        analyses: list[CheckAnalysis] = []
        for section in sections:
            try:
                analysis = await self._run_section(section)
                if analysis is not None:
                    analyses.append(analysis)
            except Exception as e:
                logger.exception("Section %s failed: %s", section, e)
                analyses.append(
                    CheckAnalysis(
                        module_name=section,
                        section=section,
                        total_checks_analyzed=0,
                        summary=f"Analysis failed: {e}",
                    )
                )

        report = ConsolidatedReport.from_analyses(analyses)
        logger.info(
            "Analysis complete: %d issues found across %d checks",
            report.total_issues,
            report.total_checks_analyzed,
        )
        return report

    def save_report(self, report: ConsolidatedReport) -> Path:
        """Save the consolidated report to JSON."""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"agent_report_{timestamp}.json"
        filepath = output_dir / filename

        filepath.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        logger.info("Report saved to %s", filepath)
        return filepath
