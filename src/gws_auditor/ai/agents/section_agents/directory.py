# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Directory section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-1.1.1": (
        "Ensure that between two and four super admin accounts are designated "
        "(CIS v1.4.1 merged the former 1.1.1 and 1.1.2)."
    ),
    "CIS-1.1.2": (
        "Ensure super admin accounts are used only for super admin activities: "
        "no account holds both the Super admin role and a delegated admin role "
        "(1.1.3 in CIS v1.3.0)."
    ),
    "CIS-1.2.1": (
        "Ensure external directory sharing is restricted."
    ),
}


def create_directory_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Directory section analysis agent."""
    return create_section_agent("Directory", model=model)
