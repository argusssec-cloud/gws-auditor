# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Drive section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.2.1.1.1": (
        "Ensure external sharing is restricted to specific domains "
        "or disabled."
    ),
    "CIS-3.1.2.1.1.3": (
        "Ensure allowlisted domains are configured when external "
        "sharing is restricted to domain allowlist."
    ),
    "CIS-3.1.2.1.1.5": (
        "Ensure the access checker is set to recipients only or "
        "target audience with domain."
    ),
    "CIS-3.1.2.2.1": (
        "Ensure Drive offline access is disabled. The check reads "
        "policies.drive.general.offline_access_enabled. Returns ERROR "
        "when this key is None because the policy mapping in provider.py "
        "does not extract the offline access setting from raw API data."
    ),
    "CIS-3.1.2.2.3": (
        "Ensure Drive SDK is disabled. The check reads "
        "policies.drive.features.drive_sdk_enabled. Returns MANUAL when "
        "this key is None because the Policy API may not expose the "
        "Drive SDK setting."
    ),
}


def create_drive_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Drive section analysis agent."""
    return create_section_agent("Drive", model=model)
