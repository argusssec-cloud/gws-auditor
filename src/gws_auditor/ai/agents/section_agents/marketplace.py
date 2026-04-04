# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Marketplace section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.9.1.1": (
        "Ensure Marketplace app installation is restricted to "
        "allowlisted apps only. The setting must equal 'allowlist' "
        "exactly — substring matches like 'not_allowlisted' are wrong."
    ),
    "CIS-3.1.9.2.1": (
        "Ensure Marketplace apps require admin approval before "
        "installation."
    ),
}


def create_marketplace_agent(
    model: str = "test",
) -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Marketplace section analysis agent."""
    return create_section_agent("Marketplace", model=model)
