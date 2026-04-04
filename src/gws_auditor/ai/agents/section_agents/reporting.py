# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Reporting section agent (CIS 5 + 6)."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-6.1": (
        "Ensure alert rules are configured for critical security events."
    ),
}


def create_reporting_agent(
    model: str = "test",
) -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Reporting section analysis agent."""
    return create_section_agent("Reporting", model=model)
