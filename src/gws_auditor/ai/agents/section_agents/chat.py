# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Google Chat section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.4.2.1": (
        "If external chat is permitted, ensure a domain allowlist is "
        "configured with at least one trusted domain. An empty allowlist "
        "means no restriction is enforced."
    ),
    "CIS-3.1.4.4.1": (
        "Ensure installation of Chat apps/bots is restricted to "
        "allowlisted apps only."
    ),
    "CIS-3.1.4.4.2": (
        "Ensure incoming webhooks for Chat are disabled to prevent "
        "unauthorized message injection."
    ),
}


def create_chat_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Chat section analysis agent."""
    return create_section_agent("Google Chat", model=model)
