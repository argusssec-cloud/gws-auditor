# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Sites section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.7.1.1": (
        "Ensure Google Sites creation is disabled or restricted "
        "to prevent unauthorized content publication."
    ),
}


def create_sites_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Sites section analysis agent."""
    return create_section_agent("Sites", model=model)
