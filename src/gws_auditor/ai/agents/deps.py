# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Dependency injection types for check analysis agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CheckDeps:
    """Dependencies injected into each section agent.

    Contains the source code of the check module, its tests,
    base helpers, and benchmark requirement descriptions so
    the agent can analyze check quality without file-system access.
    """
    check_source_code: str
    test_source_code: str
    module_path: str
    check_ids: list[str] = field(default_factory=list)
    benchmark_requirements: dict[str, str] = field(default_factory=dict)
    base_helpers_source: str = ""
    conftest_source: str = ""
    # Error-fix mode fields
    raw_policy_keys: str = ""
    audit_error_checks: str = ""
    provider_mapping_source: str = ""

    @classmethod
    def from_paths(
        cls,
        check_module: Path,
        test_module: Path | None,
        base_helpers: Path | None = None,
        conftest: Path | None = None,
        check_ids: list[str] | None = None,
        benchmark_requirements: dict[str, str] | None = None,
    ) -> CheckDeps:
        """Build deps by reading source files from disk."""

        def _read(p: Path | None) -> str:
            if p is None or not p.exists():
                return ""
            return p.read_text(encoding="utf-8")

        return cls(
            check_source_code=_read(check_module),
            test_source_code=_read(test_module),
            module_path=str(check_module),
            check_ids=check_ids or [],
            benchmark_requirements=benchmark_requirements or {},
            base_helpers_source=_read(base_helpers),
            conftest_source=_read(conftest),
        )
