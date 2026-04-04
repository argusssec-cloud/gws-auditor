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
        "Ensure more than one but no more than four super admin "
        "accounts exist."
    ),
    "CIS-1.1.2": (
        "Ensure all super admin accounts have 2-Step Verification "
        "enforced."
    ),
    "CIS-1.1.3": (
        "Ensure that super admin accounts are not used for "
        "day-to-day operations."
    ),
    "CIS-1.2.1": (
        "Ensure external directory sharing is restricted."
    ),
}


def create_directory_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Directory section analysis agent."""
    return create_section_agent("Directory", model=model)
