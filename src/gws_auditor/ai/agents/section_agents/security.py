# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Security section agent (auth + access control)."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-4.1.1.1": (
        "Ensure all admin accounts have logged in within the last "
        "defined period. The check must parse the timestamp string "
        "and compare it against a threshold — bool(timestamp) is "
        "always True for non-empty strings."
    ),
    "CIS-4.1.2.1": (
        "Ensure 2-Step Verification is enforced for all admin accounts."
    ),
    "CIS-4.1.3.1": (
        "Ensure hardware security keys are required for admin accounts."
    ),
    "CIS-4.2.1.1": (
        "Ensure third-party app access to core Google services is "
        "restricted."
    ),
    "CIS-4.2.1.2": (
        "Ensure OAuth applications are reviewed. The check must "
        "validate apps against an allowlist or risk policy — simply "
        "listing OAuth apps is a stub, not a real check."
    ),
    "CIS-4.2.1.4": (
        "Ensure domain-wide delegation (DWD) is not granted or is "
        "reviewed. The check must verify API data was actually "
        "returned — a PASS when data is missing masks real risk."
    ),
    "CIS-4.2.2.1": (
        "Ensure context-aware access / geo-blocking is configured. The "
        "check reads policies.access_control.context_aware.geo_blocking. "
        "Returns ERROR when this key is None because the policy mapping "
        "does not extract the geo-blocking configuration from raw API data."
    ),
    "CIS-4.2.3.1": (
        "Ensure DLP rules are properly configured. The check must "
        "verify rule configuration, not just that DLP policies exist. "
        "Also returns ERROR when policies.security.dlp.drive_rules is "
        "None because the policy mapping does not extract DLP config."
    ),
    "CIS-4.2.5.1": (
        "Ensure cloud session control duration is configured. The check "
        "reads policies.security.session.session_control_enabled. Returns "
        "ERROR when this key is None because the policy mapping does not "
        "extract the session control setting from the raw API data."
    ),
}


def create_security_agent(
    model: str = "test",
) -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Security section analysis agent."""
    return create_section_agent("Security", model=model)
