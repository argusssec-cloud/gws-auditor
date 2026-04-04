# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Additional checks section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "ADD-01": (
        "Ensure MX records point to Google mail servers for all domains."
    ),
    "ADD-02": (
        "Ensure Gmail Security Sandbox is enabled for suspicious "
        "attachments. The check reads "
        "policies.gmail.safety.security_sandbox_enabled. Returns ERROR "
        "when this key is None because the policy mapping in provider.py "
        "does not extract the sandbox setting from the raw API response."
    ),
    "ADD-03": (
        "Ensure advanced phishing and malware protection is enabled."
    ),
    "ADD-04": (
        "Ensure email allowlist/blocklist is properly configured."
    ),
    "ADD-05": (
        "Ensure inbound gateway configuration is secure."
    ),
    "ADD-06": (
        "Ensure compliance rules are configured."
    ),
    "ADD-07": (
        "Ensure routing rules are reviewed."
    ),
    "ADD-08": (
        "Ensure spam settings are configured."
    ),
    "ADD-09": (
        "Ensure Google Takeout is restricted for users. The check reads "
        "policies.security.data_export.takeout_enabled. Returns ERROR "
        "when this key is None because the policy mapping in provider.py "
        "does not extract the Takeout restriction from the raw API data."
    ),
    "ADD-10": (
        "Ensure account recovery options are restricted for admins."
    ),
    "ADD-11": (
        "Ensure client-side encryption (CSE) is enabled. The check reads "
        "policies.security.encryption.cse_enabled. Returns ERROR when "
        "this key is None because the policy mapping does not extract "
        "the CSE setting. CSE requires Enterprise Plus license."
    ),
    "ADD-12": (
        "Ensure DLP rules are configured for Gmail. The check reads "
        "policies.gmail.compliance.dlp_rules. Returns ERROR when this "
        "key is None because the policy mapping does not extract Gmail "
        "DLP configuration from the raw API response."
    ),
}


def create_additional_agent(
    model: str = "test",
) -> Agent[CheckDeps, CheckAnalysis]:
    """Create an Additional checks section analysis agent."""
    return create_section_agent("Additional", model=model)
