# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CISA SCuBA section agent."""

from __future__ import annotations

from pydantic_ai import Agent

from ..base_agent import create_section_agent
from ..deps import CheckDeps
from ..models import CheckAnalysis

BENCHMARK_REQUIREMENTS: dict[str, str] = {
    "GWS.GMAIL.4.3": (
        "Ensure DMARC alignment is configured. Per RFC 7489, the "
        "default alignment mode when aspf/adkim tags are absent is "
        "'relaxed' (r), not 'strict' (s). Treating absent tags as "
        "non-compliant is a false positive."
    ),
    "GWS.COMMONCONTROLS.1.1": (
        "Ensure MFA is enforced for all users."
    ),
    "GWS.COMMONCONTROLS.1.3": (
        "Ensure phishing-resistant MFA (hardware keys) is required "
        "for admin accounts."
    ),
    # --- COMMONCONTROLS ERROR checks ---
    "GWS.COMMONCONTROLS.3.1": (
        "Ensure post-SSO verification is configured. The check reads "
        "policies.security.login.post_sso_verification. Returns ERROR "
        "when this key is None because the policy mapping does not "
        "extract the post-SSO verification setting."
    ),
    "GWS.COMMONCONTROLS.3.2": (
        "Ensure third-party SSO profile verification is configured. "
        "The check reads policies.security.login.third_party_sso_verification. "
        "Returns ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.7.1": (
        "Ensure conflicting account management is configured to "
        "automatically invite conflicting accounts. The check reads "
        "policies.security.account.conflicting_account_management. "
        "Returns ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.10.2": (
        "Ensure user consent for low-risk third-party app scopes is "
        "restricted. The check reads "
        "policies.security.api_access.user_consent_low_risk. Returns "
        "ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.14.2": (
        "Ensure audit log retention is set to the maximum period. "
        "The check reads policies.security.reporting.audit_log_retention. "
        "Returns ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.15.2": (
        "Ensure data processing region is configured (data regionality). "
        "The check reads policies.security.data_region.processing_region. "
        "Returns ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.16.1": (
        "Ensure unused Google services are disabled for users. The "
        "check reads policies.security.services.unused_services_disabled. "
        "Returns ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.16.2": (
        "Ensure early access to new Google features (Rapid Release) is "
        "disabled. The check reads "
        "policies.security.services.early_access_apps_disabled. Returns "
        "ERROR when this key is None."
    ),
    "GWS.COMMONCONTROLS.18.1": (
        "Ensure DLP rules are configured for Google Drive. The check "
        "reads policies.security.dlp.drive_rules. Returns ERROR when "
        "this key is None."
    ),
    "GWS.COMMONCONTROLS.18.2": (
        "Ensure DLP rules are configured for Google Chat. The check "
        "reads policies.security.dlp.chat_rules. Returns ERROR when "
        "this key is None."
    ),
    "GWS.COMMONCONTROLS.18.3": (
        "Ensure DLP rules are configured for Gmail. The check reads "
        "policies.security.dlp.gmail_rules. Returns ERROR when this "
        "key is None."
    ),
    "GWS.COMMONCONTROLS.18.4": (
        "Ensure DLP default action is configured to block or warn. "
        "The check reads policies.security.dlp.default_action. Returns "
        "ERROR when this key is None."
    ),
    # --- CISA Services ERROR checks ---
    "GWS.CHAT.5.1": (
        "Ensure Chat content reporting is enabled. The check reads "
        "policies.chat.reporting.content_reporting_enabled. Returns "
        "ERROR when this key is None because the policy mapping does "
        "not extract Chat reporting settings."
    ),
    "GWS.CHAT.5.2": (
        "Ensure Chat reporting categories are properly configured. "
        "The check reads policies.chat.reporting.categories. Returns "
        "ERROR when this key is None."
    ),
    "GWS.ASSUREDCONTROLS.1.1": (
        "Ensure access approvals are enabled. The check reads "
        "policies.security.assured_controls.access_approvals_enabled. "
        "Returns ERROR when this key is None. Access Approvals requires "
        "Assured Controls add-on license."
    ),
    "GWS.ASSUREDCONTROLS.1.2": (
        "Ensure support access region is restricted. The check reads "
        "policies.security.assured_controls.support_access_region. "
        "Returns ERROR when this key is None. Requires Assured Controls."
    ),
    "GWS.ASSUREDCONTROLS.2.1": (
        "Ensure multi-region data processing is restricted. The check "
        "reads policies.security.assured_controls.multi_region_processing. "
        "Returns ERROR when this key is None. Requires Assured Controls."
    ),
    "GWS.GEMINI.1.1": (
        "Ensure Gemini access is restricted for unlicensed users. The "
        "check reads policies.security.gemini.unlicensed_access_enabled. "
        "Returns ERROR when this key is None."
    ),
    "GWS.GEMINI.2.1": (
        "Ensure alpha/experimental Gemini features are disabled. The "
        "check reads policies.security.gemini.alpha_features_enabled. "
        "Returns ERROR when this key is None."
    ),
}


def create_cisa_agent(model: str = "test") -> Agent[CheckDeps, CheckAnalysis]:
    """Create a CISA section analysis agent."""
    return create_section_agent("CISA", model=model)
