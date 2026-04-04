# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Calendar section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.1.1.1": (
        "Ensure external sharing for primary calendars is set to "
        "'Only free/busy information' or more restrictive."
    ),
    "CIS-3.1.1.1.2": (
        "Ensure external invitation warnings are enabled."
    ),
    "CIS-3.1.1.2.1": (
        "Ensure external sharing for secondary calendars is "
        "restricted."
    ),
}


def create_calendar_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Calendar section analysis agent."""
    return create_section_agent("Calendar", model=model)
