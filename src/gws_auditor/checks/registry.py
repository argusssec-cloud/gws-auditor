# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Check discovery and registration for GWS Security Auditor."""

import importlib
import logging

from ..models import CheckMetadata, CheckResult
from .base import get_registered_checks

logger = logging.getLogger(__name__)

# All check modules to auto-discover
CHECK_MODULES = [
    "gws_auditor.checks.directory",
    "gws_auditor.checks.apps_calendar",
    "gws_auditor.checks.apps_drive",
    "gws_auditor.checks.apps_gmail",
    "gws_auditor.checks.apps_chat",
    "gws_auditor.checks.apps_groups",
    "gws_auditor.checks.apps_sites",
    "gws_auditor.checks.apps_marketplace",
    "gws_auditor.checks.security_auth",
    "gws_auditor.checks.security_access",
    "gws_auditor.checks.reporting",
    "gws_auditor.checks.rules",
    "gws_auditor.checks.additional",
    "gws_auditor.checks.cisa_scuba",
    "gws_auditor.checks.cisa_commoncontrols",
    "gws_auditor.checks.cisa_services",
]


class CheckRegistry:
    """Registry for discovering, filtering, and executing security checks."""

    def __init__(self):
        self._checks: list[CheckMetadata] = []
        self._loaded = False

    def load(self):
        """Import all check modules to trigger decorator registration."""
        if self._loaded:
            return

        for module_name in CHECK_MODULES:
            try:
                importlib.import_module(module_name)
                logger.debug("Loaded check module: %s", module_name)
            except ImportError as e:
                logger.exception("Failed to import check module %s: %s", module_name, e)

        self._checks = get_registered_checks()
        self._loaded = True
        logger.info("Loaded %d checks from %d modules", len(self._checks), len(CHECK_MODULES))

    def get_all_checks(self) -> list[CheckMetadata]:
        """Return all registered checks."""
        self.load()
        return list(self._checks)

    def get_by_section(self, section: str) -> list[CheckMetadata]:
        """Return checks matching a given section."""
        self.load()
        return [c for c in self._checks if c.section == section]

    def get_by_level(self, level: str) -> list[CheckMetadata]:
        """Return checks matching a given level (L1, L2)."""
        self.load()
        return [c for c in self._checks if c.level == level]

    def get_by_source(self, source: str) -> list[CheckMetadata]:
        """Return checks matching a given source (CIS, OTHER, GOOGLE)."""
        self.load()
        return [c for c in self._checks if c.source == source]

    def get_by_id(self, check_id: str) -> CheckMetadata | None:
        """Return a check by its ID."""
        self.load()
        for c in self._checks:
            if c.check_id == check_id:
                return c
        return None

    def filter_checks(
        self,
        levels: list[str] | None = None,
        sources: list[str] | None = None,
        sections: list[str] | str | None = None,
        exclude: list[str] | None = None,
        exclude_sections: list[str] | None = None,
        include_only: list[str] | None = None,
    ) -> list[CheckMetadata]:
        """Filter checks based on configuration criteria."""
        self.load()
        checks = list(self._checks)

        if include_only:
            checks = [c for c in checks if c.check_id in include_only]
            return checks

        if levels:
            checks = [c for c in checks if c.level in levels]

        if sources:
            checks = [c for c in checks if c.source in sources]

        if sections and sections != "all":
            if isinstance(sections, str):
                sections = [sections]
            checks = [c for c in checks if c.section in sections]

        if exclude:
            checks = [c for c in checks if c.check_id not in exclude]

        if exclude_sections:
            checks = [c for c in checks if c.section not in exclude_sections]

        return checks

    def execute_checks(
        self, data: dict, checks: list[CheckMetadata] | None = None
    ) -> list[CheckResult]:
        """Execute a set of checks against collected data."""
        if checks is None:
            checks = self.get_all_checks()

        results = []
        for meta in checks:
            logger.info("Running check %s: %s", meta.check_id, meta.title)
            try:
                result = meta.func(data)
                results.append(result)
            except Exception as e:
                logger.exception("Check %s failed with exception: %s", meta.check_id, e)
                from ..models import Status
                results.append(CheckResult(
                    check_id=meta.check_id,
                    title=meta.title,
                    status=Status.ERROR,
                    level=meta.level,
                    source=meta.source,
                    section=meta.section,
                    details=f"Execution error: {e}",
                ))

        return results
