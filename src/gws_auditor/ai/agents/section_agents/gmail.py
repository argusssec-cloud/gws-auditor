# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Gmail section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "CIS-3.1.3.1.1": "Ensure mail delegation is disabled.",
    "CIS-3.1.3.1.2": (
        "Ensure offline Gmail access is disabled. The check reads "
        "policies.gmail.general.offline_access_enabled. Returns ERROR "
        "when this key is None because the policy mapping in provider.py "
        "does not extract the offline access setting from the raw API data."
    ),
    "CIS-3.1.3.2.1": (
        "Ensure POP and IMAP access is disabled for all users."
    ),
    "CIS-3.1.3.3.1": (
        "Ensure automatic email forwarding is disabled. Also ensure "
        "quarantine notification is properly configured. Returns ERROR "
        "when the quarantine notification setting is None because the "
        "policy mapping does not extract it from the raw API response."
    ),
    "CIS-3.1.3.5.1": (
        "Ensure comprehensive mail storage is enabled."
    ),
    "CIS-3.1.3.5.4": (
        "Ensure external recipient warning is enabled. The check reads "
        "policies.gmail.general.external_recipient_warning_enabled. "
        "Returns ERROR when this key is None because the policy mapping "
        "does not extract the external recipient warning setting."
    ),
    "CIS-3.1.3.6.2": (
        "Ensure internal sender spam filter bypass is disabled. The check "
        "reads policies.gmail.spam.internal_sender_bypass_enabled. Returns "
        "ERROR when this key is None because the policy mapping does not "
        "extract the internal sender bypass setting."
    ),
    "CIS-3.1.3.7.1": (
        "Ensure email attachment safety protections are enabled."
    ),
    "CIS-3.1.3.7.2": (
        "Ensure TLS enforcement is configured for mail delivery. The check "
        "reads policies.gmail.routing.tls_required. Returns ERROR when "
        "this key is None because the policy mapping does not extract "
        "the TLS enforcement setting from the raw API data."
    ),
    "CIS-3.1.3.8.1": (
        "Ensure spoofing and authentication safety settings are enabled."
    ),
}


def create_gmail_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a Gmail section analysis agent."""
    return create_section_agent("Gmail", model=model)
