# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Groups section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.6.1": (
        "Ensure no groups are publicly accessible. Groups should "
        "not have whoCanViewGroup/whoCanJoin set to ANYONE_CAN_*."
    ),
    "CIS-3.1.6.2": (
        "Ensure group creation is restricted to admins."
    ),
    "CIS-3.1.6.3": (
        "Ensure external group membership is disabled."
    ),
}


def create_groups_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Groups section analysis agent."""
    return create_section_agent("Groups", model=model)
