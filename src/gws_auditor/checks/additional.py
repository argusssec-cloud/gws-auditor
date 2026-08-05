# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Non-CIS additional checks for GWS Security Auditor.

Custom security checks from OTHER and GOOGLE best practices
that supplement the CIS Benchmark controls.
"""

from datetime import datetime, timedelta, timezone

from .base import (
    check,
    make_pass,
    make_fail,
    make_warn,
    make_manual,
    make_review,
    make_not_applicable,
    get_ou_values,
    format_ou_values_readable,
)
from ..models import CheckResult, Status
from ..constants import DANGEROUS_OAUTH_SCOPES, OAUTH_SCOPE_RISK_LEVELS


@check(
    check_id="ADD-02",
    title="Ensure Security Sandbox is enabled for Gmail",
    level="L1",
    source="OTHER",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Security Sandbox. Enable Security Sandbox to scan attachments "
        "in a virtual environment. Note: requires Business Standard or higher license. https://knowledge.workspace.google.com/admin/gmail/advanced/gmail-security-sandbox-overview"
    ),
    requires_license="business_standard",
)
def check_security_sandbox(data: dict) -> CheckResult:
    """Gmail Security Sandbox should be enabled for advanced threat protection."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    safety = gmail.get("safety", {})
    sandbox_enabled = safety.get("security_sandbox_enabled", None)

    if sandbox_enabled is True:
        return make_pass(
            check_id="ADD-02",
            title="Ensure Security Sandbox is enabled for Gmail",
            level="L1", source="OTHER", section="Gmail",
            details="Security Sandbox is enabled for Gmail.",
            actual_value=sandbox_enabled,
            expected_value="Enabled for all OUs",
        )

    if sandbox_enabled is None:
        return make_review(
            check_id="ADD-02",
            title="Ensure Security Sandbox is enabled for Gmail",
            level="L1", source="OTHER", section="Gmail",
            details=(
                "Security Sandbox status is not exposed by the Cloud Identity "
                "Policy API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Safety > "
                "Security Sandbox. Enable Security Sandbox to scan attachments "
                "in a virtual environment. Requires Business Standard or higher license. https://knowledge.workspace.google.com/admin/gmail/advanced/gmail-security-sandbox-overview"
            ),
        )

    return make_fail(
        check_id="ADD-02",
        title="Ensure Security Sandbox is enabled for Gmail",
        level="L1", source="OTHER", section="Gmail",
        details="Security Sandbox is not enabled for Gmail.",
        actual_value=sandbox_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Safety > "
            "Security Sandbox. Enable Security Sandbox to scan attachments "
            "in a virtual environment. Note: requires Business Standard or higher license. https://knowledge.workspace.google.com/admin/gmail/advanced/gmail-security-sandbox-overview"
        ),
    )


@check(
    check_id="ADD-05",
    title="Ensure MX records point to Google",
    level="L1",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Update MX records in your DNS provider to point to Google mail servers: "
        "ASPMX.L.GOOGLE.COM (priority 1), ALT1.ASPMX.L.GOOGLE.COM (priority 5), etc. https://knowledge.workspace.google.com/admin/gmail/activate-gmail-with-google-workspace-your-company"
    ),
)
def check_mx_records(data: dict) -> CheckResult:
    """MX records should point to Google for proper mail delivery."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="ADD-05",
            title="Ensure MX records point to Google",
            level="L1", source="GOOGLE", section="Gmail",
            details="No domains found to check MX records.",
            remediation="Verify MX records for all domains point to Google mail servers. https://knowledge.workspace.google.com/admin/gmail/activate-gmail-with-google-workspace-your-company",
        )

    non_google_mx = []
    google_mx_patterns = ("google.com", "googlemail.com", "smtp.google.com")

    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        # The DNS client returns {"mx": {"records": [...], "uses_google": bool}}
        # in current versions, but older caches may store the records list
        # directly under "mx". Handle both shapes.
        mx_data = domain_dns.get("mx", [])
        if isinstance(mx_data, dict):
            uses_google = mx_data.get("uses_google")
            mx_records = mx_data.get("records", [])
        else:
            uses_google = None
            mx_records = mx_data

        if not mx_records:
            non_google_mx.append(f"{domain_name} (no MX records)")
            continue

        # Trust the DNSClient.uses_google flag when present.
        if uses_google is True:
            continue
        if uses_google is False:
            non_google_mx.append(domain_name)
            continue

        # Legacy cache: re-derive from host strings.
        has_google_mx = False
        for mx in mx_records:
            mx_host = mx.get("host", "").lower() if isinstance(mx, dict) else str(mx).lower()
            if any(pattern in mx_host for pattern in google_mx_patterns):
                has_google_mx = True
                break

        if not has_google_mx:
            non_google_mx.append(domain_name)

    if not non_google_mx:
        return make_pass(
            check_id="ADD-05",
            title="Ensure MX records point to Google",
            level="L1", source="GOOGLE", section="Gmail",
            details=f"MX records for all {len(domains)} domain(s) point to Google.",
            actual_value={"domains_checked": len(domains), "all_google": True},
            expected_value="All MX records pointing to Google",
        )

    return make_fail(
        check_id="ADD-05",
        title="Ensure MX records point to Google",
        level="L1", source="GOOGLE", section="Gmail",
        details=f"MX records not pointing to Google for: {', '.join(non_google_mx)}",
        actual_value={"non_google_domains": non_google_mx},
        expected_value="All MX records pointing to Google",
        remediation=(
            "Update MX records in your DNS provider to point to Google mail servers: "
            "ASPMX.L.GOOGLE.COM (priority 1), ALT1.ASPMX.L.GOOGLE.COM (priority 5), etc. https://knowledge.workspace.google.com/admin/gmail/activate-gmail-with-google-workspace-your-company"
        ),
    )


@check(
    check_id="ADD-06",
    title="Ensure inbound gateway SPF configuration is correct",
    level="L2",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing "
        "and Malware > Inbound gateway. If using an inbound gateway, ensure "
        "'Reject all mail not from gateway IPs' and SPF checks are enabled. https://knowledge.workspace.google.com/admin/security/set-up-spf"
    ),
)
def check_inbound_gateway_spf(data: dict) -> CheckResult:
    """Inbound gateway should be correctly configured for SPF checks."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    gateway = gmail.get("inbound_gateway", {})
    spf_check = gateway.get("reject_if_spf_fail", None)
    gateway_configured = gateway.get("configured", None)

    if gateway_configured is False:
        # No inbound gateway configured, SPF handled by Google directly
        return make_pass(
            check_id="ADD-06",
            title="Ensure inbound gateway SPF configuration is correct",
            level="L2", source="GOOGLE", section="Gmail",
            details="No inbound gateway is configured; Google handles SPF checks directly.",
            actual_value={"gateway_configured": False},
            expected_value="SPF checks active",
        )

    if spf_check is True:
        return make_pass(
            check_id="ADD-06",
            title="Ensure inbound gateway SPF configuration is correct",
            level="L2", source="GOOGLE", section="Gmail",
            details="Inbound gateway is configured to reject on SPF failure.",
            actual_value={"reject_if_spf_fail": True},
            expected_value="SPF rejection enabled",
        )

    if gateway_configured is None:
        return make_manual(
            check_id="ADD-06",
            title="Ensure inbound gateway SPF configuration is correct",
            level="L2", source="GOOGLE", section="Gmail",
            details="Could not determine inbound gateway SPF configuration.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing "
                "and Malware > Inbound gateway. If using an inbound gateway, ensure "
                "'Reject all mail not from gateway IPs' and SPF checks are enabled. https://knowledge.workspace.google.com/admin/security/set-up-spf"
            ),
        )

    return make_fail(
        check_id="ADD-06",
        title="Ensure inbound gateway SPF configuration is correct",
        level="L2", source="GOOGLE", section="Gmail",
        details="Inbound gateway is configured but SPF rejection on failure is not enabled.",
        actual_value={"reject_if_spf_fail": spf_check, "gateway_configured": gateway_configured},
        expected_value="SPF rejection enabled on gateway",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing "
            "and Malware > Inbound gateway. Enable SPF rejection for messages "
            "that fail SPF checks through the gateway. https://knowledge.workspace.google.com/admin/security/set-up-spf"
        ),
    )


@check(
    check_id="ADD-07",
    title="Ensure TLS is enforced for partner domains",
    level="L2",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Compliance. "
        "Add secure transport (TLS) compliance rules for critical partner domains "
        "to ensure encrypted email delivery. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_partner_tls(data: dict) -> CheckResult:
    """TLS should be enforced for email communication with partner domains."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    compliance = gmail.get("compliance", {})
    partner_tls = compliance.get("partner_domain_tls_rules", [])
    tls_required_default = compliance.get("tls_required", None)

    if isinstance(partner_tls, list) and len(partner_tls) > 0:
        return make_pass(
            check_id="ADD-07",
            title="Ensure TLS is enforced for partner domains",
            level="L2", source="GOOGLE", section="Gmail",
            details=f"TLS enforcement rules configured for {len(partner_tls)} partner domain(s).",
            actual_value={"partner_tls_rule_count": len(partner_tls)},
            expected_value="TLS rules configured for partner domains",
        )

    if tls_required_default is True:
        return make_pass(
            check_id="ADD-07",
            title="Ensure TLS is enforced for partner domains",
            level="L2", source="GOOGLE", section="Gmail",
            details="TLS is required for all email delivery, including partner domains.",
            actual_value={"tls_required_default": True},
            expected_value="TLS enforced",
        )

    if partner_tls is None and tls_required_default is None:
        return make_manual(
            check_id="ADD-07",
            title="Ensure TLS is enforced for partner domains",
            level="L2", source="GOOGLE", section="Gmail",
            details="Could not determine partner domain TLS settings.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Compliance. "
                "Add TLS compliance rules for key partner domains. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="ADD-07",
        title="Ensure TLS is enforced for partner domains",
        level="L2", source="GOOGLE", section="Gmail",
        details="No TLS enforcement rules configured for partner domains.",
        actual_value={"partner_tls_rules": 0, "tls_required_default": tls_required_default},
        expected_value="TLS rules configured for partner domains",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Compliance. "
            "Add secure transport (TLS) compliance rules for critical partner domains "
            "to ensure encrypted email delivery. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


@check(
    check_id="ADD-08",
    title="Ensure password protection warning is enabled",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Devices > Chrome > Settings > Users & browsers > "
        "Password Alert. Set password protection warning to warn on "
        "password reuse. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_password_alert(data: dict) -> CheckResult:
    """Chrome password protection warning should be enabled to detect password reuse."""
    _ID = "ADD-08"
    _TITLE = "Ensure password protection warning is enabled"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Devices > Chrome > Settings > Users & browsers > "
        "Password Alert. Set password protection warning to warn on "
        "password reuse. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})
    password_alert = security.get("password_alert", {})
    deployed = password_alert.get("deployed", None)
    trigger = password_alert.get("trigger", None)

    _TRIGGER_LABELS = {
        0: "Off",
        1: "Password reuse warning",
        2: "Phishing and password reuse warning",
    }

    if deployed is True:
        label = _TRIGGER_LABELS.get(trigger, str(trigger))
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Password protection warning is enabled: {label}.",
            actual_value={"trigger": trigger, "label": label},
            expected_value="Password reuse warning or higher",
        )

    if deployed is False:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Password protection warning is disabled.",
            actual_value={"trigger": trigger},
            expected_value="Password reuse warning or higher",
            remediation=_REMED,
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Password protection warning status could not be determined "
            "from Chrome policies. Verify in Admin console > Devices > "
            "Chrome > Settings > Users & browsers > Password Alert."
        ),
        remediation=_REMED,
    )


@check(
    check_id="ADD-09",
    title="Ensure Google Takeout is restricted",
    level="L1",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Account > Data sharing > Google Takeout. "
        "Disable Google Takeout to prevent users from bulk-exporting "
        "organizational data. https://knowledge.workspace.google.com/admin/gemini/export-google-workspace-with-gemini-data"
    ),
)
def check_takeout_restriction(data: dict) -> CheckResult:
    """Google Takeout (data export) should be restricted to prevent data exfiltration."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    data_export = security.get("data_export", {})
    takeout_enabled = data_export.get("takeout_enabled", None)

    if takeout_enabled is False:
        return make_pass(
            check_id="ADD-09",
            title="Ensure Google Takeout is restricted",
            level="L1", source="GOOGLE", section="Security",
            details="Google Takeout is disabled for users.",
            actual_value=takeout_enabled,
            expected_value="Disabled for all OUs",
        )

    if takeout_enabled is None:
        return make_review(
            check_id="ADD-09",
            title="Ensure Google Takeout is restricted",
            level="L1", source="GOOGLE", section="Security",
            details=(
                "Takeout availability is not exposed by the Cloud Identity "
                "Policy API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Account > Data sharing > Google Takeout. "
                "Disable Google Takeout to prevent users from bulk-exporting "
                "organizational data. https://knowledge.workspace.google.com/admin/gemini/export-google-workspace-with-gemini-data"
            ),
        )

    return make_fail(
        check_id="ADD-09",
        title="Ensure Google Takeout is restricted",
        level="L1", source="GOOGLE", section="Security",
        details="Google Takeout is enabled, allowing users to export organizational data.",
        actual_value=takeout_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Account > Data sharing > Google Takeout. "
            "Disable Google Takeout to prevent bulk data export by users. https://knowledge.workspace.google.com/admin/gemini/export-google-workspace-with-gemini-data"
        ),
    )


@check(
    check_id="ADD-11",
    title="Ensure client-side encryption is enabled",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > "
        "Client-side encryption. Enable CSE for Drive, Gmail, Calendar, "
        "and Meet. Configure an external key management service. "
        "Note: requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-client-side-encryption"
    ),
    requires_license="enterprise_plus",
)
def check_client_side_encryption(data: dict) -> CheckResult:
    """Client-side encryption (CSE) should be enabled for sensitive data protection."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    cse = security.get("client_side_encryption", {})
    cse_enabled = cse.get("enabled", None)

    if cse_enabled is True:
        return make_pass(
            check_id="ADD-11",
            title="Ensure client-side encryption is enabled",
            level="L2", source="GOOGLE", section="Security",
            details="Client-side encryption is enabled.",
            actual_value=cse_enabled,
            expected_value="Enabled for all OUs",
        )

    if cse_enabled is None:
        return make_manual(
            check_id="ADD-11",
            title="Ensure client-side encryption is enabled",
            level="L2", source="GOOGLE", section="Security",
            details=(
                "Could not determine client-side encryption status. "
                "CSE requires Enterprise Plus license and external key service."
            ),
            remediation=(
                "Admin console > Security > Access and data control > "
                "Client-side encryption. Enable CSE and configure an external "
                "key management service. Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-client-side-encryption"
            ),
        )

    return make_fail(
        check_id="ADD-11",
        title="Ensure client-side encryption is enabled",
        level="L2", source="GOOGLE", section="Security",
        details="Client-side encryption is not enabled.",
        actual_value=cse_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Access and data control > "
            "Client-side encryption. Enable CSE for Drive, Gmail, Calendar, "
            "and Meet. Configure an external key management service. "
            "Note: requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-client-side-encryption"
        ),
    )


@check(
    check_id="ADD-12",
    title="Ensure DLP rules are configured for Gmail",
    level="L1",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules to detect PII, financial data, and other "
        "sensitive content in outbound emails. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
    ),
    requires_license="enterprise_standard",
)
def check_gmail_dlp(data: dict) -> CheckResult:
    """Data Loss Prevention rules should be configured for Gmail."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    compliance = gmail.get("compliance", {})
    dlp_rules = compliance.get("dlp_rules", [])
    content_compliance = compliance.get("content_compliance_rules", [])

    # Also check the security-level DLP settings
    security = policies.get("security", {})
    dlp = security.get("dlp", {})
    gmail_dlp_enabled = dlp.get("gmail_dlp_enabled", None)

    total_rules = len(dlp_rules) + len(content_compliance)

    if gmail_dlp_enabled is True or total_rules > 0:
        return make_pass(
            check_id="ADD-12",
            title="Ensure DLP rules are configured for Gmail",
            level="L1", source="GOOGLE", section="Gmail",
            details=f"DLP is configured for Gmail ({total_rules} rule(s) found).",
            actual_value={
                "gmail_dlp_enabled": gmail_dlp_enabled,
                "dlp_rules": len(dlp_rules),
                "content_compliance_rules": len(content_compliance),
            },
            expected_value="DLP rules configured for Gmail",
        )

    if gmail_dlp_enabled is None and total_rules == 0:
        return make_review(
            check_id="ADD-12",
            title="Ensure DLP rules are configured for Gmail",
            level="L1", source="GOOGLE", section="Gmail",
            details=(
                "Gmail DLP rules are not exposed by the Cloud Identity Policy "
                "API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
                "Create DLP rules for Gmail to detect and prevent sensitive "
                "data from being sent via email. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
            ),
        )

    return make_fail(
        check_id="ADD-12",
        title="Ensure DLP rules are configured for Gmail",
        level="L1", source="GOOGLE", section="Gmail",
        details="No DLP rules are configured for Gmail.",
        actual_value={
            "gmail_dlp_enabled": gmail_dlp_enabled,
            "dlp_rules": 0,
            "content_compliance_rules": 0,
        },
        expected_value="DLP rules configured for Gmail",
        remediation=(
            "Admin console > Security > Data protection > Manage rules. "
            "Create DLP rules to detect PII, financial data, and other "
            "sensitive content in outbound emails. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
        ),
    )


# ---------------------------------------------------------------------------
# ADD-13 to ADD-27: New 2025-2026 checks
# ---------------------------------------------------------------------------


@check(
    check_id="ADD-13",
    title="Ensure Gemini features in Workspace apps are controlled",
    level="L1",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Apps > Google Workspace > Gemini. "
        "Disable or restrict Gemini features in Workspace apps "
        "to control AI-generated content and data processing. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_gemini_workspace_features(data: dict) -> CheckResult:
    """Gemini features within Workspace apps (Docs, Sheets, Gmail) should be controlled."""
    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})
    workspace_features = gemini.get("workspace_features", {})
    enabled = workspace_features.get("enabled", None)

    if enabled is False:
        return make_pass(
            check_id="ADD-13",
            title="Ensure Gemini features in Workspace apps are controlled",
            level="L1", source="GOOGLE", section="Gemini",
            details="Gemini features in Workspace apps are disabled.",
            actual_value=enabled,
            expected_value="Disabled for all OUs",
        )

    if enabled is None:
        return make_review(
            check_id="ADD-13",
            title="Ensure Gemini features in Workspace apps are controlled",
            level="L1", source="GOOGLE", section="Gemini",
            details=(
                "Gemini Workspace features setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gemini. "
                "Review and control Gemini features in Docs, Sheets, "
                "Slides, and Gmail to meet organizational AI policies. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
            ),
        )

    return make_fail(
        check_id="ADD-13",
        title="Ensure Gemini features in Workspace apps are controlled",
        level="L1", source="GOOGLE", section="Gemini",
        details="Gemini features in Workspace apps are enabled without restriction.",
        actual_value=enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gemini. "
            "Disable or restrict Gemini features in Workspace apps "
            "to control AI-generated content and data processing. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
        ),
    )


@check(
    check_id="ADD-14",
    title="Ensure Gemini in Chrome is disabled",
    level="L2",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Devices > Chrome > Settings > Users & browsers. "
        "Disable Gemini in Chrome to prevent browser-based AI from "
        "processing organizational data. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_gemini_chrome(data: dict) -> CheckResult:
    """Gemini in Chrome should be disabled to prevent uncontrolled AI data processing."""
    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})
    chrome = gemini.get("chrome", {})
    enabled = chrome.get("enabled", None)

    if enabled is False:
        return make_pass(
            check_id="ADD-14",
            title="Ensure Gemini in Chrome is disabled",
            level="L2", source="GOOGLE", section="Gemini",
            details="Gemini in Chrome is disabled.",
            actual_value=enabled,
            expected_value="Disabled for all OUs",
        )

    if enabled is None:
        return make_fail(
            check_id="ADD-14",
            title="Ensure Gemini in Chrome is disabled",
            level="L2", source="GOOGLE", section="Gemini",
            details="Gemini in Chrome is not explicitly disabled via Chrome policy.",
            actual_value=None,
            expected_value="Disabled for all OUs",
            remediation=(
                "Admin console > Devices > Chrome > Settings > Users & browsers. "
                "Disable Gemini in Chrome to prevent browser-level AI data processing. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
            ),
        )

    return make_fail(
        check_id="ADD-14",
        title="Ensure Gemini in Chrome is disabled",
        level="L2", source="GOOGLE", section="Gemini",
        details="Gemini in Chrome is enabled.",
        actual_value=enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Devices > Chrome > Settings > Users & browsers. "
            "Disable Gemini in Chrome to prevent browser-based AI from "
            "processing organizational data. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
        ),
    )


@check(
    check_id="ADD-15",
    title="Ensure Google Workspace Studio access is controlled",
    level="L2",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Apps > Google Workspace > Gemini > "
        "Workspace Studio. Disable or restrict access to prevent "
        "uncontrolled AI app creation by users. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_workspace_studio(data: dict) -> CheckResult:
    """Google Workspace Studio access should be controlled."""
    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})
    studio = gemini.get("workspace_studio", {})
    enabled = studio.get("enabled", None)

    if enabled is False:
        return make_pass(
            check_id="ADD-15",
            title="Ensure Google Workspace Studio access is controlled",
            level="L2", source="GOOGLE", section="Gemini",
            details="Google Workspace Studio access is disabled.",
            actual_value=enabled,
            expected_value="Disabled for all OUs",
        )

    if enabled is None:
        return make_review(
            check_id="ADD-15",
            title="Ensure Google Workspace Studio access is controlled",
            level="L2", source="GOOGLE", section="Gemini",
            details=(
                "Workspace Studio setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gemini > "
                "Workspace Studio. Disable or restrict Workspace Studio "
                "access to control AI app creation. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
            ),
        )

    return make_fail(
        check_id="ADD-15",
        title="Ensure Google Workspace Studio access is controlled",
        level="L2", source="GOOGLE", section="Gemini",
        details="Google Workspace Studio access is enabled without restriction.",
        actual_value=enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gemini > "
            "Workspace Studio. Disable or restrict access to prevent "
            "uncontrolled AI app creation by users. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
        ),
    )


@check(
    check_id="ADD-16",
    title="Ensure Apple Intelligence Writing Tools are disabled for Workspace",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Devices > Mobile & endpoints > Settings > iOS > "
        "Data sharing > Apple Intelligence. Turn off 'Allow users to use "
        "Apple Intelligence Writing Tools within Google Workspace apps on "
        "iOS devices'. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_apple_writing_tools(data: dict) -> CheckResult:
    """Apple Intelligence Writing Tools on iOS should be disabled for Workspace.

    This is a mobile device management setting not available via the Cloud
    Identity Policy API.  The check always requires manual verification.
    """
    _ID = "ADD-16"
    _TITLE = "Ensure Apple Intelligence Writing Tools are disabled for Workspace"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Devices > Mobile & endpoints > Settings > iOS > "
        "Data sharing > Apple Intelligence. Turn off 'Allow users to use "
        "Apple Intelligence Writing Tools within Google Workspace apps on "
        "iOS devices'. https://knowledge.workspace.google.com/admin/gemini/manage-access-to-gemini-features-in-workspace-services"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Apple Intelligence Writing Tools setting is managed under "
            "mobile device settings and is not available via the Cloud "
            "Identity Policy API. Verify manually in Admin console."
        ),
        remediation=_REMED,
    )


@check(
    check_id="ADD-18",
    title="Ensure passkeys are enforced as primary authentication",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Passwordless. "
        "Enable 'Allow users to skip their password and authenticate "
        "with a passkey' to enforce passkeys as primary authentication. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_passkeys_enforced(data: dict) -> CheckResult:
    """Passkeys should be enforced as primary authentication method.

    The 'Skip passwords' setting (passwordless authentication) is not
    available via the Cloud Identity Policy API.  This check always
    requires manual verification.
    """
    _ID = "ADD-18"
    _TITLE = "Ensure passkeys are enforced as primary authentication"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Passwordless. "
        "Enable 'Allow users to skip their password and authenticate "
        "with a passkey' to enforce passkeys as primary authentication. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Passkey enforcement (Skip passwords) setting is not available "
            "via the Cloud Identity Policy API. Verify manually in "
            "Admin console > Security > Authentication > Passwordless."
        ),
        remediation=_REMED,
    )


# ---------------------------------------------------------------------------
# Context-Aware Access (CAA) for SAML / OIDC apps — ADD-20 and ADD-40
# ---------------------------------------------------------------------------
# The Workspace admin-console toggles "apply CAA to OIDC apps" (ADD-20) and
# "apply default CAA policy to all SAML apps" (ADD-40) are NOT exposed by any
# Workspace policy API today (verified empirically against Cloud Identity
# Policy API v1/v1beta1 and Access Context Manager).  The audit log surfaces
# are the only programmatic signal available:
#   - Reports API ``applicationName=token`` → reveals which OIDC OAuth
#     clients have been used in the audit window.
#   - Reports API ``applicationName=login`` → reveals SAML SSO logins via
#     ``login_type=saml``.
#   - Reports API ``applicationName=context_aware_access``,
#     ``eventName=ACCESS_DENY_EVENT`` → fires when CAA actively blocks an
#     access attempt; proof that CAA is enforcing.
# ---------------------------------------------------------------------------


def _count_third_party_oidc_apps(token_logs: list) -> tuple[int, list[str]]:
    """Count distinct third-party OAuth (OIDC) clients seen in token logs.

    Third-party heuristic: ``client_id`` ends in
    ``.apps.googleusercontent.com`` (issued from a non-Workspace GCP project)
    AND ``app_name`` does not begin with ``"Google "`` (Google's own apps).
    """
    seen: dict[str, str] = {}
    for entry in token_logs or []:
        if not isinstance(entry, dict):
            continue
        client_id = entry.get("client_id") or entry.get("parameters", {}).get("client_id", "")
        app_name = entry.get("app_name") or entry.get("parameters", {}).get("app_name", "")
        if not client_id or ".apps.googleusercontent.com" not in str(client_id):
            continue
        if isinstance(app_name, str) and app_name.startswith("Google "):
            continue
        seen[str(client_id)] = str(app_name)
    return len(seen), sorted({n for n in seen.values() if n})


def _count_saml_apps(login_logs: list) -> tuple[int, list[str]]:
    """Count distinct SAML SSO apps seen in login logs.

    Detected via ``parameters.login_type == "saml"``.  The destination app
    name is read from ``parameters.application_name`` when present, falling
    back to ``parameters.saml_idp`` and finally a generic ``"<unknown SAML>"``
    bucket so the count is still meaningful when the param is absent.
    """
    seen: set[str] = set()
    for entry in login_logs or []:
        if not isinstance(entry, dict):
            continue
        params = entry.get("parameters", {}) or {}
        if params.get("login_type") != "saml":
            continue
        app = (
            params.get("application_name")
            or params.get("saml_idp")
            or params.get("idp_initiated_url")
            or "<unknown SAML>"
        )
        seen.add(str(app))
    return len(seen), sorted(seen)


def _caa_denials(caa_events: list, app_class: str) -> tuple[int, list[str]]:
    """Count CAA denial events relevant to ``app_class`` (``"oidc"`` or ``"saml"``).

    The ``ACCESS_DENY_EVENT`` parameters that disambiguate app class are not
    rigidly documented, so this function is intentionally conservative:
    it accepts any of several plausible signals
    (``application_type`` / ``is_third_party_oauth`` / ``application_name``).
    When no per-event signal is present, the event is counted toward both
    classes — better to report "CAA is enforcing somewhere" than to miss it.
    """
    matched: list[str] = []
    for entry in caa_events or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("event_name") != "ACCESS_DENY_EVENT":
            continue
        params = entry.get("parameters", {}) or {}
        app_type = str(params.get("application_type", "")).lower()
        app_name = str(params.get("application_name", "")) or "<unknown>"

        if app_class == "oidc":
            keep = (
                "oauth" in app_type
                or "oidc" in app_type
                or params.get("is_third_party_oauth") is True
                or not app_type  # ambiguous → count for both classes
            )
        elif app_class == "saml":
            keep = "saml" in app_type or not app_type
        else:
            keep = False

        if keep:
            matched.append(app_name)
    return len(matched), sorted(set(matched))


@check(
    check_id="ADD-20",
    title="Ensure Context-Aware Access is applied to OIDC apps",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > "
        "Context-Aware Access. Enable context-aware policies for "
        "OIDC third-party apps to enforce device and location-based access. https://knowledge.workspace.google.com/admin/security/assign-context-aware-access-levels-to-apps"
    ),
    requires_license="enterprise_standard",
)
def check_caa_oidc(data: dict) -> CheckResult:
    """Context-Aware Access policies should cover OIDC third-party apps.

    The Workspace policy APIs do not expose the CAA-for-OIDC toggle, so the
    check infers status from audit logs:

      Step 1 — Inventory: count distinct third-party OIDC clients in
        ``data["token_logs"]``.  If zero, return NOT_APPLICABLE — the toggle
        has nothing to apply to.
      Step 2 — Enforcement evidence: count ACCESS_DENY_EVENT entries in
        ``data["caa_events"]`` that match the OIDC app class.  Any match
        means CAA is actively blocking OIDC access attempts → PASS.
      Step 3 — Inconclusive: OIDC apps exist but no denial events in the
        audit window → MANUAL (REVIEW).  "No denials" is not proof that
        CAA is off; it may simply mean nothing was blocked.

    Caveat: "Detected" means seen in the Reports API retention window
    (~180 days).  An app configured but never used will not appear.
    """
    _ID, _TITLE = "ADD-20", "Ensure Context-Aware Access is applied to OIDC apps"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMEDIATION = (
        "Admin console > Security > Access and data control > "
        "Context-Aware Access. Enable context-aware policies for "
        "OIDC third-party apps to enforce device and location-based access. "
        "https://knowledge.workspace.google.com/admin/security/assign-context-aware-access-levels-to-apps"
    )

    oidc_count, oidc_apps = _count_third_party_oidc_apps(data.get("token_logs", []))

    if oidc_count == 0:
        return make_not_applicable(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "No third-party OIDC apps detected in the audit-log window; "
                "the CAA-for-OIDC control has nothing to apply to."
            ),
            actual_value=0,
        )

    deny_count, denied_apps = _caa_denials(data.get("caa_events", []), "oidc")
    if deny_count > 0:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"CAA is actively enforcing on OIDC traffic: {deny_count} "
                f"ACCESS_DENY_EVENT(s) in the window across "
                f"{len(denied_apps)} app(s)."
            ),
            actual_value={"oidc_apps": oidc_count, "denials": deny_count},
            expected_value="CAA denial events present for OIDC apps",
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{oidc_count} third-party OIDC app(s) detected "
            f"({', '.join(oidc_apps[:5])}{'...' if len(oidc_apps) > 5 else ''}) "
            "but no CAA ACCESS_DENY_EVENT was logged in the window. "
            "Absence of denials does not prove CAA is disabled — verify the "
            "policy assignment in Admin console > Security > "
            "Context-Aware Access."
        ),
        remediation=_REMEDIATION,
        actual_value={"oidc_apps": oidc_count, "denials": 0},
    )


@check(
    check_id="ADD-40",
    title="Ensure default Context-Aware Access policy is enabled for SAML applications",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Context-Aware Access > General settings. "
        "Enable a default CAA policy for all SAML applications so apps "
        "without specific assignments inherit a secure baseline. "
        "https://knowledge.workspace.google.com/admin/security/apply-caa-policy-for-all-saml-apps"
    ),
    requires_license="enterprise_standard",
)
def check_caa_saml_default(data: dict) -> CheckResult:
    """Default CAA policy should be enabled for all SAML applications.

    Mirrors ADD-20's three-state log-driven logic for SAML:

      Step 1 — Inventory: count distinct SAML SSO apps in
        ``data["login_logs"]`` (events where ``parameters.login_type ==
        "saml"``).  If zero, return NOT_APPLICABLE — the default-SAML-CAA
        toggle has nothing to apply to.
      Step 2 — Enforcement evidence: count ACCESS_DENY_EVENT entries in
        ``data["caa_events"]`` that match the SAML app class.  Any match
        means CAA is actively blocking SAML access attempts → PASS.
      Step 3 — Inconclusive: SAML apps exist but no denial events in the
        audit window → MANUAL (REVIEW).
    """
    _ID = "ADD-40"
    _TITLE = (
        "Ensure default Context-Aware Access policy is enabled for "
        "SAML applications"
    )
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMEDIATION = (
        "Admin console > Security > Context-Aware Access > General settings. "
        "Enable a default CAA policy for all SAML applications so apps "
        "without specific assignments inherit a secure baseline. "
        "https://knowledge.workspace.google.com/admin/security/apply-caa-policy-for-all-saml-apps"
    )

    saml_count, saml_apps = _count_saml_apps(data.get("login_logs", []))

    if saml_count == 0:
        return make_not_applicable(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "No SAML SSO logins detected in the audit-log window; the "
                "default-CAA-for-SAML control has nothing to apply to."
            ),
            actual_value=0,
        )

    deny_count, denied_apps = _caa_denials(data.get("caa_events", []), "saml")
    if deny_count > 0:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"CAA is actively enforcing on SAML traffic: {deny_count} "
                f"ACCESS_DENY_EVENT(s) in the window across "
                f"{len(denied_apps)} app(s)."
            ),
            actual_value={"saml_apps": saml_count, "denials": deny_count},
            expected_value="CAA denial events present for SAML apps",
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{saml_count} SAML app(s) detected "
            f"({', '.join(saml_apps[:5])}{'...' if len(saml_apps) > 5 else ''}) "
            "but no CAA ACCESS_DENY_EVENT was logged in the window. "
            "Absence of denials does not prove CAA is disabled — verify the "
            "default policy in Admin console > Security > Context-Aware "
            "Access > General settings."
        ),
        remediation=_REMEDIATION,
        actual_value={"saml_apps": saml_count, "denials": 0},
    )


@check(
    check_id="ADD-21",
    title="Ensure Multi-Party Approval covers Vault exports",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Multi-Party Approval. "
        "Add Vault exports to the MPA-covered actions to prevent "
        "unauthorized export of eDiscovery data. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
    ),
    requires_license="enterprise_standard",
)
def check_mpa_vault_exports(data: dict) -> CheckResult:
    """Multi-Party Approval should cover Vault exports to protect sensitive data."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    mpa = security.get("multi_party_approval", {})
    vault_covered = mpa.get("vault_exports_covered", None)

    if vault_covered is True:
        return make_pass(
            check_id="ADD-21",
            title="Ensure Multi-Party Approval covers Vault exports",
            level="L2", source="GOOGLE", section="Security",
            details="Multi-Party Approval covers Vault exports.",
            actual_value=vault_covered,
            expected_value="Enabled for all OUs",
        )

    if vault_covered is None:
        return make_fail(
            check_id="ADD-21",
            title="Ensure Multi-Party Approval covers Vault exports",
            level="L2", source="GOOGLE", section="Security",
            details="Multi-Party Approval is not configured for Vault exports.",
            actual_value=None,
            expected_value="Enabled for all OUs",
            remediation=(
                "Admin console > Security > Multi-Party Approval. "
                "Enable MPA for Vault export operations to require "
                "additional approval before sensitive data can be exported. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
            ),
        )

    return make_fail(
        check_id="ADD-21",
        title="Ensure Multi-Party Approval covers Vault exports",
        level="L2", source="GOOGLE", section="Security",
        details="Multi-Party Approval does not cover Vault exports.",
        actual_value=vault_covered,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Multi-Party Approval. "
            "Add Vault exports to the MPA-covered actions to prevent "
            "unauthorized export of eDiscovery data. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
        ),
    )


@check(
    check_id="ADD-22",
    title="Ensure data classification labels are enabled for Gmail",
    level="L1",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Security > Data protection > Data classification. "
        "Enable classification labels for Gmail to categorize emails by "
        "sensitivity and apply DLP rules accordingly. https://knowledge.workspace.google.com/admin/security/create-classification-labels-for-your-organization"
    ),
    requires_license="business_standard",
)
def check_gmail_classification_labels(data: dict) -> CheckResult:
    """Data classification labels should be enabled for Gmail."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    compliance = gmail.get("compliance", {})
    labels_enabled = compliance.get("classification_labels_enabled", None)

    if labels_enabled is True:
        return make_pass(
            check_id="ADD-22",
            title="Ensure data classification labels are enabled for Gmail",
            level="L1", source="GOOGLE", section="Gmail",
            details="Data classification labels are enabled for Gmail.",
            actual_value=labels_enabled,
            expected_value="Enabled for all OUs",
        )

    if labels_enabled is None:
        return make_review(
            check_id="ADD-22",
            title="Ensure data classification labels are enabled for Gmail",
            level="L1", source="GOOGLE", section="Gmail",
            details=(
                "Gmail classification labels setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Security > Data protection > Data classification. "
                "Enable classification labels for Gmail to allow DLP rules "
                "based on sensitivity labels. https://knowledge.workspace.google.com/admin/security/create-classification-labels-for-your-organization"
            ),
        )

    return make_fail(
        check_id="ADD-22",
        title="Ensure data classification labels are enabled for Gmail",
        level="L1", source="GOOGLE", section="Gmail",
        details="Data classification labels are not enabled for Gmail.",
        actual_value=labels_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Data protection > Data classification. "
            "Enable classification labels for Gmail to categorize emails by "
            "sensitivity and apply DLP rules accordingly. https://knowledge.workspace.google.com/admin/security/create-classification-labels-for-your-organization"
        ),
    )


@check(
    check_id="ADD-23",
    title="Ensure DLP rules are configured for Calendar",
    level="L2",
    source="GOOGLE",
    section="Calendar",
    remediation=(
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules for Calendar to detect sensitive information "
        "in event titles, descriptions, and attachments. https://knowledge.workspace.google.com/admin/security/about-dlp-for-calendar"
    ),
    requires_license="enterprise_standard",
)
def check_calendar_dlp(data: dict) -> CheckResult:
    """DLP rules should be configured for Calendar event details."""
    policies = data.get("policies", {})
    calendar = policies.get("calendar", {})
    cal_dlp_rules = calendar.get("dlp_rules", None)

    # Also check security-level DLP settings
    security = policies.get("security", {})
    dlp = security.get("dlp", {})
    calendar_dlp_enabled = dlp.get("calendar_dlp_enabled", None)

    if calendar_dlp_enabled is True or (isinstance(cal_dlp_rules, list) and len(cal_dlp_rules) > 0):
        rule_count = len(cal_dlp_rules) if isinstance(cal_dlp_rules, list) else 0
        return make_pass(
            check_id="ADD-23",
            title="Ensure DLP rules are configured for Calendar",
            level="L2", source="GOOGLE", section="Calendar",
            details=f"DLP is configured for Calendar ({rule_count} rule(s) found).",
            actual_value={
                "calendar_dlp_enabled": calendar_dlp_enabled,
                "dlp_rules": rule_count,
            },
            expected_value="DLP rules configured for Calendar",
        )

    if calendar_dlp_enabled is None and cal_dlp_rules is None:
        return make_fail(
            check_id="ADD-23",
            title="Ensure DLP rules are configured for Calendar",
            level="L2", source="GOOGLE", section="Calendar",
            details="No DLP rules are configured for Calendar.",
            actual_value=None,
            expected_value="DLP rules configured for Calendar",
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
                "Create DLP rules for Calendar to detect sensitive information "
                "in event titles, descriptions, and attachments. https://knowledge.workspace.google.com/admin/security/about-dlp-for-calendar"
            ),
        )

    return make_fail(
        check_id="ADD-23",
        title="Ensure DLP rules are configured for Calendar",
        level="L2", source="GOOGLE", section="Calendar",
        details="No DLP rules are configured for Calendar.",
        actual_value={
            "calendar_dlp_enabled": calendar_dlp_enabled,
            "dlp_rules": len(cal_dlp_rules) if isinstance(cal_dlp_rules, list) else 0,
        },
        expected_value="DLP rules configured for Calendar",
        remediation=(
            "Admin console > Security > Data protection > Manage rules. "
            "Create DLP rules for Calendar to protect sensitive information "
            "shared in meeting details. https://knowledge.workspace.google.com/admin/security/about-dlp-for-calendar"
        ),
    )


@check(
    check_id="ADD-24",
    title="Ensure AI-powered data classification is enabled for Drive",
    level="L2",
    source="GOOGLE",
    section="Drive and Docs",
    remediation=(
        "Admin console > Security > Data protection > Data classification. "
        "Enable AI-powered classification for Drive to automatically "
        "detect and label sensitive files. https://knowledge.workspace.google.com/admin/security/label-google-drive-files-automatically-using-ai-classification"
    ),
)
def check_drive_ai_classification(data: dict) -> CheckResult:
    """AI-powered data classification should be enabled for Drive."""
    policies = data.get("policies", {})
    drive = policies.get("drive", {})
    classification = drive.get("classification", {})
    ai_enabled = classification.get("ai_classification_enabled", None)

    if ai_enabled is True:
        return make_pass(
            check_id="ADD-24",
            title="Ensure AI-powered data classification is enabled for Drive",
            level="L2", source="GOOGLE", section="Drive and Docs",
            details="AI-powered data classification is enabled for Drive.",
            actual_value=ai_enabled,
            expected_value="Enabled for all OUs",
        )

    if ai_enabled is None:
        return make_review(
            check_id="ADD-24",
            title="Ensure AI-powered data classification is enabled for Drive",
            level="L2", source="GOOGLE", section="Drive and Docs",
            details=(
                "Drive AI classification setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Security > Data protection > Data classification. "
                "Enable AI-powered classification for Drive to automatically "
                "label files based on content sensitivity. https://knowledge.workspace.google.com/admin/security/label-google-drive-files-automatically-using-ai-classification"
            ),
        )

    return make_fail(
        check_id="ADD-24",
        title="Ensure AI-powered data classification is enabled for Drive",
        level="L2", source="GOOGLE", section="Drive and Docs",
        details="AI-powered data classification is not enabled for Drive.",
        actual_value=ai_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Security > Data protection > Data classification. "
            "Enable AI-powered classification for Drive to automatically "
            "detect and label sensitive files. https://knowledge.workspace.google.com/admin/security/label-google-drive-files-automatically-using-ai-classification"
        ),
    )


@check(
    check_id="ADD-25",
    title="Ensure Drive trust rules are configured",
    level="L2",
    source="GOOGLE",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Trust rules. Create trust rules to enable context-based sharing "
        "policies integrated with DLP. https://knowledge.workspace.google.com/admin/security/create-and-manage-trust-rules-for-drive-sharing"
    ),
)
def check_drive_trust_rules(data: dict) -> CheckResult:
    """Drive trust rules should be configured for context-based sharing policies."""
    policies = data.get("policies", {})
    drive = policies.get("drive", {})
    trust_rules = drive.get("trust_rules", None)

    if isinstance(trust_rules, list) and len(trust_rules) > 0:
        return make_pass(
            check_id="ADD-25",
            title="Ensure Drive trust rules are configured",
            level="L2", source="GOOGLE", section="Drive and Docs",
            details=f"Drive trust rules are configured ({len(trust_rules)} rule(s)).",
            actual_value={"trust_rule_count": len(trust_rules)},
            expected_value="Trust rules configured",
        )

    if trust_rules is None:
        return make_review(
            check_id="ADD-25",
            title="Ensure Drive trust rules are configured",
            level="L2", source="GOOGLE", section="Drive and Docs",
            details=(
                "Drive trust rules setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Trust rules. Configure trust rules to control sharing based "
                "on organizational context and DLP labels. https://knowledge.workspace.google.com/admin/security/create-and-manage-trust-rules-for-drive-sharing"
            ),
        )

    return make_fail(
        check_id="ADD-25",
        title="Ensure Drive trust rules are configured",
        level="L2", source="GOOGLE", section="Drive and Docs",
        details="No Drive trust rules are configured.",
        actual_value={"trust_rule_count": 0},
        expected_value="Trust rules configured",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Trust rules. Create trust rules to enable context-based sharing "
            "policies integrated with DLP. https://knowledge.workspace.google.com/admin/security/create-and-manage-trust-rules-for-drive-sharing"
        ),
    )


@check(
    check_id="ADD-26",
    title="Ensure CSE is enabled for Gmail",
    level="L2",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Security > Access and data control > "
        "Client-side encryption > Gmail. Enable CSE for Gmail to "
        "provide end-to-end encryption for sensitive emails. "
        "Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/turn-client-side-encryption-on-or-off-for-users"
    ),
)
def check_gmail_cse(data: dict) -> CheckResult:
    """Client-side encryption should be enabled for Gmail (E2EE)."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    compliance = gmail.get("compliance", {})
    cse_enabled = compliance.get("cse_enabled", None)

    if cse_enabled is True:
        return make_pass(
            check_id="ADD-26",
            title="Ensure CSE is enabled for Gmail",
            level="L2", source="GOOGLE", section="Gmail",
            details="Client-side encryption is enabled for Gmail.",
            actual_value=cse_enabled,
            expected_value="Enabled for all OUs",
        )

    if cse_enabled is None:
        return make_review(
            check_id="ADD-26",
            title="Ensure CSE is enabled for Gmail",
            level="L2", source="GOOGLE", section="Gmail",
            details=(
                "Gmail CSE setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Security > Access and data control > "
                "Client-side encryption > Gmail. Enable CSE for Gmail "
                "to provide end-to-end encryption. Requires Enterprise Plus. https://knowledge.workspace.google.com/admin/security/turn-client-side-encryption-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="ADD-26",
        title="Ensure CSE is enabled for Gmail",
        level="L2", source="GOOGLE", section="Gmail",
        details="Client-side encryption is not enabled for Gmail.",
        actual_value=cse_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Access and data control > "
            "Client-side encryption > Gmail. Enable CSE for Gmail to "
            "provide end-to-end encryption for sensitive emails. "
            "Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/turn-client-side-encryption-on-or-off-for-users"
        ),
    )


@check(
    check_id="ADD-27",
    title="Ensure Meet compliance recording is configured",
    level="L2",
    source="GOOGLE",
    section="Google Meet",
    requires_license="assured_controls",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet compliance settings. Enable compliance recording for "
        "users subject to regulatory recording requirements. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
    ),
)
def check_meet_compliance_recording(data: dict) -> CheckResult:
    """Meet compliance recording should be configured for regulatory requirements."""
    _ID = "ADD-27"
    _TITLE = "Ensure Meet compliance recording is configured"
    _L, _S, _SEC = "L2", "GOOGLE", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet compliance settings. Enable compliance recording for "
        "users subject to regulatory recording requirements. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    ou_values = get_ou_values(meet, "video_recording")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enabled = entry["value"].get("enableRecording", None)
            if enabled is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not have compliance recording enabled: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="Enabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Meet compliance recording configured.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Enabled for all OUs",
        )

    # Fallback: mapped root-level value
    compliance = meet.get("compliance", {})
    recording_enabled = compliance.get("recording_enabled", None)

    if recording_enabled is True:
        return make_pass(
            check_id="ADD-27",
            title="Ensure Meet compliance recording is configured",
            level="L2", source="GOOGLE", section="Google Meet",
            details="Meet compliance recording is configured.",
            actual_value=recording_enabled,
            expected_value="Enabled for all OUs",
        )

    if recording_enabled is None:
        return make_review(
            check_id="ADD-27",
            title="Ensure Meet compliance recording is configured",
            level="L2", source="GOOGLE", section="Google Meet",
            details=(
                "Meet compliance recording setting requires manual verification. "
                "No programmatic API is available for this control."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet compliance settings. Enable compliance recording for "
                "users subject to regulatory recording requirements. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
            ),
        )

    return make_fail(
        check_id="ADD-27",
        title="Ensure Meet compliance recording is configured",
        level="L2", source="GOOGLE", section="Google Meet",
        details="Meet compliance recording is not configured.",
        actual_value=recording_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet compliance settings. Enable compliance recording to "
            "automatically record meetings for regulatory compliance. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
        ),
    )


# -----------------------------------------------------------------------
# ADD-28: Groups with no active members
# -----------------------------------------------------------------------

@check(
    check_id="ADD-28",
    title="Ensure groups have active members",
    level="L1",
    source="OTHER",
    section="Groups",
    remediation=(
        "Admin console > Directory > Groups. Review empty or all-inactive "
        "groups and either remove them or add active members. https://knowledge.workspace.google.com/admin/groups/get-started-managing-groups-for-an-organization"
    ),
    scored=False,
)
def check_groups_no_active_users(data: dict) -> CheckResult:
    """Report groups with zero members or where all members are inactive."""
    _ID = "ADD-28"
    _TITLE = "Ensure groups have active members"
    _L, _S, _SEC = "L1", "OTHER", "Groups"
    _REMED = (
        "Admin console > Directory > Groups. Review empty or all-inactive "
        "groups and either remove them or add active members. https://knowledge.workspace.google.com/admin/groups/get-started-managing-groups-for-an-organization"
    )

    groups = data.get("groups", [])
    group_members = data.get("group_members", {})
    users = data.get("users", [])

    if not groups:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No groups found to analyze.",
            actual_value={"empty_groups": [], "all_inactive_groups": [], "total_analyzed": 0},
            expected_value="All groups have active members",
        )

    # Build set of inactive user emails (suspended or archived)
    inactive_emails = set()
    user_emails = set()
    for u in users:
        email = u.get("primary_email") or u.get("primaryEmail", "")
        if email:
            user_emails.add(email.lower())
            if u.get("suspended") or u.get("archived"):
                inactive_emails.add(email.lower())

    empty_groups = []
    all_inactive_groups = []

    for group in groups:
        group_email = group.get("email", "")
        direct_count = int(group.get("directMembersCount", 0))
        members = group_members.get(group_email, [])

        if direct_count == 0 and not members:
            empty_groups.append(group_email)
            continue

        if members:
            member_emails = [
                m.get("email", "").lower() for m in members
                if m.get("email")
            ]
            # Check if all members with known user accounts are inactive
            known_members = [e for e in member_emails if e in user_emails]
            if known_members and all(e in inactive_emails for e in known_members):
                all_inactive_groups.append(group_email)

    if empty_groups or all_inactive_groups:
        total_problematic = len(empty_groups) + len(all_inactive_groups)
        details_parts = []
        if empty_groups:
            details_parts.append(f"{len(empty_groups)} empty group(s)")
        if all_inactive_groups:
            details_parts.append(f"{len(all_inactive_groups)} group(s) with only inactive members")
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Found {'; '.join(details_parts)} out of {len(groups)} total groups.",
            actual_value={
                "empty_groups": empty_groups,
                "all_inactive_groups": all_inactive_groups,
                "total_analyzed": len(groups),
            },
            expected_value="All groups have active members",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(groups)} group(s) have active members.",
        actual_value={
            "empty_groups": [],
            "all_inactive_groups": [],
            "total_analyzed": len(groups),
        },
        expected_value="All groups have active members",
    )


# -----------------------------------------------------------------------
# ADD-29: Chat spaces with no recent activity
# -----------------------------------------------------------------------

def _parse_timestamp(ts: str) -> datetime | None:
    """Parse an ISO-8601 timestamp string to a timezone-aware datetime."""
    if not ts:
        return None
    try:
        # Handle various formats from Google APIs
        ts = ts.rstrip("Z")
        if "." in ts:
            ts = ts.split(".")[0]
        return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


@check(
    check_id="ADD-29",
    title="Ensure Chat spaces have recent activity",
    level="L2",
    source="OTHER",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat. "
        "Review inactive Chat spaces and archive or delete those "
        "no longer in use to reduce the attack surface. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
    scored=False,
)
def check_chat_spaces_inactive(data: dict) -> CheckResult:
    """Report Chat spaces with no activity in the configured window."""
    _ID = "ADD-29"
    _TITLE = "Ensure Chat spaces have recent activity"
    _L, _S, _SEC = "L2", "OTHER", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat. "
        "Review inactive Chat spaces and archive or delete those "
        "no longer in use to reduce the attack surface. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    chat_spaces = data.get("chat_spaces", [])
    options = data.get("_options", {})
    threshold_days = options.get("chat_inactive_days", 90)

    if not chat_spaces:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "No Chat spaces data available. The Chat Admin API may not be "
                "enabled or the scope may not be delegated."
            ),
            remediation=_REMED,
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    inactive_spaces = []

    for space in chat_spaces:
        last_active = _parse_timestamp(
            space.get("lastActiveTime", space.get("last_active_time", ""))
        )
        if last_active is None or last_active < cutoff:
            inactive_spaces.append({
                "name": space.get("displayName", space.get("name", "unknown")),
                "space_id": space.get("name", ""),
                "last_active": space.get("lastActiveTime", "unknown"),
                "owners": space.get("owner_emails", []),
            })

    if inactive_spaces:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(inactive_spaces)} Chat space(s) have no activity in "
                f"the last {threshold_days} days out of {len(chat_spaces)} total."
            ),
            actual_value={
                "inactive_spaces": inactive_spaces,
                "threshold_days": threshold_days,
                "total_spaces": len(chat_spaces),
            },
            expected_value=f"All spaces active within {threshold_days} days",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(chat_spaces)} Chat space(s) have recent activity.",
        actual_value={
            "inactive_spaces": [],
            "threshold_days": threshold_days,
            "total_spaces": len(chat_spaces),
        },
        expected_value=f"All spaces active within {threshold_days} days",
    )


# -----------------------------------------------------------------------
# ADD-30: Mobile devices not synced recently
# -----------------------------------------------------------------------

@check(
    check_id="ADD-30",
    title="Ensure mobile devices are syncing recently",
    level="L1",
    source="OTHER",
    section="Devices",
    remediation=(
        "Admin console > Devices > Mobile devices. Review stale devices "
        "and wipe or remove those that have not synced recently. https://knowledge.workspace.google.com/admin/devices"
    ),
    scored=False,
)
def check_mobile_devices_stale(data: dict) -> CheckResult:
    """Report mobile devices not synced within the configured window."""
    _ID = "ADD-30"
    _TITLE = "Ensure mobile devices are syncing recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Mobile devices. Review stale devices "
        "and wipe or remove those that have not synced recently. https://knowledge.workspace.google.com/admin/devices"
    )

    devices = data.get("mobile_devices", [])
    options = data.get("_options", {})
    threshold_days = options.get("device_inactive_days", 90)

    if not devices:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No mobile devices enrolled.",
            actual_value={"stale_devices": [], "total_devices": 0},
            expected_value=f"All devices synced within {threshold_days} days",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    stale = []

    for dev in devices:
        last_sync = _parse_timestamp(
            dev.get("lastSync", dev.get("last_sync", ""))
        )
        if last_sync is None or last_sync < cutoff:
            stale.append({
                "model": dev.get("model", "unknown"),
                "user": dev.get("email", dev.get("name", ["unknown"])),
                "last_sync": dev.get("lastSync", "unknown"),
                "status": dev.get("status", "unknown"),
            })

    if stale:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(stale)} mobile device(s) have not synced in "
                f"the last {threshold_days} days out of {len(devices)} total."
            ),
            actual_value={
                "stale_devices": stale,
                "threshold_days": threshold_days,
                "total_devices": len(devices),
            },
            expected_value=f"All devices synced within {threshold_days} days",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(devices)} mobile device(s) have synced recently.",
        actual_value={
            "stale_devices": [],
            "threshold_days": threshold_days,
            "total_devices": len(devices),
        },
        expected_value=f"All devices synced within {threshold_days} days",
    )


# -----------------------------------------------------------------------
# ADD-31: ChromeOS devices not active recently
# -----------------------------------------------------------------------

@check(
    check_id="ADD-31",
    title="Ensure ChromeOS devices are active recently",
    level="L1",
    source="OTHER",
    section="Devices",
    remediation=(
        "Admin console > Devices > Chrome devices. Review stale ChromeOS "
        "devices and deprovision or disable those no longer in use. https://knowledge.workspace.google.com/admin/devices"
    ),
    scored=False,
)
def check_chromeos_devices_stale(data: dict) -> CheckResult:
    """Report ChromeOS devices not synced within the configured window."""
    _ID = "ADD-31"
    _TITLE = "Ensure ChromeOS devices are active recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Chrome devices. Review stale ChromeOS "
        "devices and deprovision or disable those no longer in use. https://knowledge.workspace.google.com/admin/devices"
    )

    devices = data.get("chromeos_devices", [])
    options = data.get("_options", {})
    threshold_days = options.get("device_inactive_days", 90)

    if not devices:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No ChromeOS devices enrolled.",
            actual_value={"stale_devices": [], "total_devices": 0},
            expected_value=f"All devices active within {threshold_days} days",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    stale = []

    for dev in devices:
        last_sync = _parse_timestamp(
            dev.get("lastSync", dev.get("last_sync", ""))
        )
        if last_sync is None or last_sync < cutoff:
            stale.append({
                "model": dev.get("model", "unknown"),
                "user": dev.get("annotatedUser", dev.get("annotated_user", "unknown")),
                "serial": dev.get("serialNumber", dev.get("serial_number", "unknown")),
                "last_sync": dev.get("lastSync", "unknown"),
                "status": dev.get("status", "unknown"),
            })

    if stale:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(stale)} ChromeOS device(s) have not been active in "
                f"the last {threshold_days} days out of {len(devices)} total."
            ),
            actual_value={
                "stale_devices": stale,
                "threshold_days": threshold_days,
                "total_devices": len(devices),
            },
            expected_value=f"All devices active within {threshold_days} days",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(devices)} ChromeOS device(s) have been active recently.",
        actual_value={
            "stale_devices": [],
            "threshold_days": threshold_days,
            "total_devices": len(devices),
        },
        expected_value=f"All devices active within {threshold_days} days",
    )


# -----------------------------------------------------------------------
# ADD-38: Endpoint verification devices not synced recently
# -----------------------------------------------------------------------

@check(
    check_id="ADD-38",
    title="Ensure endpoint verification devices are syncing recently",
    level="L1",
    source="OTHER",
    section="Devices",
    remediation=(
        "Admin console > Devices > Endpoint verification. Review stale "
        "endpoint devices (Windows/Mac/Linux) and remove those that have "
        "not synced recently. https://knowledge.workspace.google.com/admin/devices"
    ),
    scored=False,
)
def check_endpoint_devices_stale(data: dict) -> CheckResult:
    """Report endpoint verification devices not synced within the configured window."""
    _ID = "ADD-38"
    _TITLE = "Ensure endpoint verification devices are syncing recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Endpoint verification. Review stale "
        "endpoint devices (Windows/Mac/Linux) and remove those that have "
        "not synced recently. https://knowledge.workspace.google.com/admin/devices"
    )

    devices = data.get("endpoint_devices", [])
    options = data.get("_options", {})
    threshold_days = options.get("device_inactive_days", 90)

    if not devices:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No endpoint verification devices enrolled.",
            actual_value={"stale_devices": [], "total_devices": 0},
            expected_value=f"All devices synced within {threshold_days} days",
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    stale = []

    for dev in devices:
        last_sync = _parse_timestamp(
            dev.get("lastSyncTime", dev.get("last_sync_time", ""))
        )
        create_time = _parse_timestamp(
            dev.get("createTime", dev.get("create_time", ""))
        )

        is_stale = False
        if last_sync is not None and last_sync < cutoff:
            is_stale = True
        elif last_sync is None and create_time is not None and create_time < cutoff:
            # Never synced but enrolled longer than threshold
            is_stale = True

        if is_stale:
            stale.append({
                "hostname": dev.get("hostname", dev.get("name", "unknown")),
                "device_type": dev.get("deviceType", "unknown"),
                "os": dev.get("osVersion", "unknown"),
                "last_sync": dev.get("lastSyncTime", "never"),
                "management_state": dev.get("managementState", "unknown"),
            })

    if stale:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(stale)} endpoint device(s) have not synced in "
                f"the last {threshold_days} days out of {len(devices)} total."
            ),
            actual_value={
                "stale_devices": stale,
                "threshold_days": threshold_days,
                "total_devices": len(devices),
            },
            expected_value=f"All devices synced within {threshold_days} days",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(devices)} endpoint device(s) have synced recently.",
        actual_value={
            "stale_devices": [],
            "threshold_days": threshold_days,
            "total_devices": len(devices),
        },
        expected_value=f"All devices synced within {threshold_days} days",
    )


# -----------------------------------------------------------------------
# ADD-39: Devices pending approval too long
# -----------------------------------------------------------------------

@check(
    check_id="ADD-39",
    title="Ensure pending devices are approved promptly",
    level="L2",
    source="OTHER",
    section="Devices",
    remediation=(
        "Admin console > Devices. Review devices stuck in 'Pending' state "
        "and either approve or block them. Unreviewed pending devices "
        "represent unmanaged access to corporate data. "
        "https://knowledge.workspace.google.com/admin/devices"
    ),
    scored=False,
)
def check_devices_pending(data: dict) -> CheckResult:
    """Report devices stuck in PENDING approval state for too long."""
    _ID = "ADD-39"
    _TITLE = "Ensure pending devices are approved promptly"
    _L, _S, _SEC = "L2", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices. Review devices stuck in 'Pending' state "
        "and either approve or block them. Unreviewed pending devices "
        "represent unmanaged access to corporate data. "
        "https://knowledge.workspace.google.com/admin/devices"
    )

    options = data.get("_options", {})
    pending_threshold = options.get("device_pending_days", 30)
    cutoff = datetime.now(timezone.utc) - timedelta(days=pending_threshold)
    pending_devices = []

    # Check mobile devices
    for dev in data.get("mobile_devices", []):
        if dev.get("status") != "PENDING":
            continue
        first_sync = _parse_timestamp(
            dev.get("firstSync", dev.get("first_sync", ""))
        )
        if first_sync is not None and first_sync < cutoff:
            pending_devices.append({
                "device_type": "Mobile",
                "model": dev.get("model", "unknown"),
                "user": dev.get("email", "unknown"),
                "first_sync": dev.get("firstSync", "unknown"),
            })

    # Check endpoint verification devices
    for dev in data.get("endpoint_devices", []):
        if dev.get("managementState") != "PENDING":
            continue
        create_time = _parse_timestamp(
            dev.get("createTime", dev.get("create_time", ""))
        )
        if create_time is not None and create_time < cutoff:
            pending_devices.append({
                "device_type": "Endpoint",
                "model": dev.get("hostname", dev.get("deviceType", "unknown")),
                "user": dev.get("owner", {}).get("userResourceName", "unknown"),
                "first_sync": dev.get("createTime", "unknown"),
            })

    if not pending_devices:
        total = len(data.get("mobile_devices", [])) + len(data.get("endpoint_devices", []))
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"No devices pending approval for more than {pending_threshold} days.",
            actual_value={"pending_devices": [], "total_devices": total},
            expected_value=f"No devices pending > {pending_threshold} days",
        )

    return make_warn(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{len(pending_devices)} device(s) have been pending approval "
            f"for more than {pending_threshold} days."
        ),
        actual_value={
            "pending_devices": pending_devices,
            "threshold_days": pending_threshold,
        },
        expected_value=f"No devices pending > {pending_threshold} days",
        remediation=_REMED,
    )


# -----------------------------------------------------------------------
# ADD-32: Users/OUs without 2SV inventory
# -----------------------------------------------------------------------

@check(
    check_id="ADD-32",
    title="Users without 2-Step Verification by OU inventory",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > 2-Step Verification. "
        "Enforce 2SV for all organizational units. "
        "Follow up with unenrolled users to complete enrollment. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
    scored=False,
)
def check_2sv_inventory(data: dict) -> CheckResult:
    """Rich per-OU breakdown of 2SV enrollment status."""
    _ID = "ADD-32"
    _TITLE = "Users without 2-Step Verification by OU inventory"
    _L, _S, _SEC = "L1", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > 2-Step Verification. "
        "Enforce 2SV for all organizational units. "
        "Follow up with unenrolled users to complete enrollment. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    users = data.get("users", [])
    if not users:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No user data available to analyze 2SV enrollment.",
            remediation=_REMED,
        )

    # Group active (non-suspended) users by OU
    ou_data: dict[str, list[dict]] = {}
    for u in users:
        if u.get("suspended"):
            continue
        ou = u.get("org_unit_path") or u.get("orgUnitPath", "/") or "/"
        ou_data.setdefault(ou, []).append(u)

    total_users = 0
    total_enrolled = 0
    total_not_enrolled = 0
    per_ou = []

    for ou_path in sorted(ou_data.keys()):
        ou_users = ou_data[ou_path]
        enrolled = []
        not_enrolled = []
        for u in ou_users:
            email = u.get("primary_email") or u.get("primaryEmail", "")
            if u.get("is_enrolled_in_2sv") or u.get("isEnrolledIn2Sv"):
                enrolled.append(email)
            else:
                not_enrolled.append(email)

        total = len(enrolled) + len(not_enrolled)
        total_users += total
        total_enrolled += len(enrolled)
        total_not_enrolled += len(not_enrolled)
        rate = (len(enrolled) / total * 100) if total > 0 else 0

        per_ou.append({
            "org_unit": ou_path,
            "total": total,
            "enrolled": len(enrolled),
            "not_enrolled": len(not_enrolled),
            "enrollment_rate": f"{rate:.1f}%",
            "users_without_2sv": not_enrolled,
        })

    overall_rate = (total_enrolled / total_users * 100) if total_users > 0 else 0
    summary = {
        "total_users": total_users,
        "enrolled": total_enrolled,
        "not_enrolled": total_not_enrolled,
        "enrollment_rate": f"{overall_rate:.1f}%",
    }

    actual_value = {"summary": summary, "per_ou": per_ou}

    if total_not_enrolled > 0:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{total_not_enrolled} active user(s) lack 2SV enrollment "
                f"({overall_rate:.1f}% enrollment rate across {len(per_ou)} OU(s))."
            ),
            actual_value=actual_value,
            expected_value="100% 2SV enrollment",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"All {total_users} active user(s) are enrolled in 2SV "
            f"across {len(per_ou)} OU(s)."
        ),
        actual_value=actual_value,
        expected_value="100% 2SV enrollment",
    )


# -----------------------------------------------------------------------
# ADD-33: OAuth apps with dangerous privileges
# -----------------------------------------------------------------------

def _classify_scope_risk(scope: str) -> str | None:
    """Return the risk level for a scope, or None if not dangerous."""
    for pattern, level in OAUTH_SCOPE_RISK_LEVELS.items():
        if pattern in scope:
            return level
    return None


_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


@check(
    check_id="ADD-33",
    title="Ensure no OAuth apps have dangerous privilege grants",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Review apps with dangerous scopes and revoke or block those "
        "that are not approved. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
    scored=False,
)
def check_oauth_dangerous_apps(data: dict) -> CheckResult:
    """Analyze OAuth token grants and flag apps with high-risk scopes."""
    _ID = "ADD-33"
    _TITLE = "Ensure no OAuth apps have dangerous privilege grants"
    _L, _S, _SEC = "L1", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Review apps with dangerous scopes and revoke or block those "
        "that are not approved. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    token_logs = data.get("token_logs", [])

    if not token_logs:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No OAuth token log data available for analysis.",
            actual_value={"dangerous_apps": {}, "total_grants": 0},
            expected_value="No apps with dangerous scopes",
            remediation=_REMED,
        )

    # Analyze token grant events
    dangerous_apps: dict[str, dict] = {}
    total_grants = 0

    for entry in token_logs:
        event_name = entry.get("event_name", "")
        if event_name != "authorize":
            continue

        total_grants += 1
        params = entry.get("parameters", {})
        app_name = params.get("app_name", entry.get("app_name", "unknown"))
        actor = entry.get("actor_email", "")
        client_id = params.get("client_id", entry.get("client_id", ""))

        # Scopes may be space or comma separated
        raw_scopes = params.get("scope", entry.get("scope", ""))
        if isinstance(raw_scopes, str):
            scopes = [s.strip() for s in raw_scopes.replace(",", " ").split() if s.strip()]
        elif isinstance(raw_scopes, list):
            scopes = raw_scopes
        else:
            scopes = []

        # Check each scope against dangerous list
        matched_dangerous = []
        highest_risk = None
        for scope in scopes:
            # Check against full scope list
            if scope in DANGEROUS_OAUTH_SCOPES:
                matched_dangerous.append(scope)
            # Also check by pattern match
            risk = _classify_scope_risk(scope)
            if risk:
                if scope not in matched_dangerous:
                    matched_dangerous.append(scope)
                if highest_risk is None or _RISK_ORDER.get(risk, 99) < _RISK_ORDER.get(highest_risk, 99):
                    highest_risk = risk

        if matched_dangerous:
            key = app_name or client_id or "unknown"
            if key not in dangerous_apps:
                dangerous_apps[key] = {
                    "app_name": app_name,
                    "client_id": client_id,
                    "dangerous_scopes": list(set(matched_dangerous)),
                    "risk_level": highest_risk or "HIGH",
                    "granted_by": [],
                    "grant_count": 0,
                }
            app_entry = dangerous_apps[key]
            # Merge scopes
            for s in matched_dangerous:
                if s not in app_entry["dangerous_scopes"]:
                    app_entry["dangerous_scopes"].append(s)
            # Update risk level to highest
            if highest_risk and _RISK_ORDER.get(highest_risk, 99) < _RISK_ORDER.get(app_entry["risk_level"], 99):
                app_entry["risk_level"] = highest_risk
            # Track actors
            if actor and actor not in app_entry["granted_by"]:
                app_entry["granted_by"].append(actor)
            app_entry["grant_count"] += 1

    if dangerous_apps:
        critical_count = sum(1 for a in dangerous_apps.values() if a["risk_level"] == "CRITICAL")
        high_count = sum(1 for a in dangerous_apps.values() if a["risk_level"] == "HIGH")
        details_parts = [f"{len(dangerous_apps)} app(s) with dangerous OAuth scopes"]
        if critical_count:
            details_parts.append(f"{critical_count} CRITICAL")
        if high_count:
            details_parts.append(f"{high_count} HIGH")

        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Found {', '.join(details_parts)} across {total_grants} token grant(s).",
            actual_value={
                "dangerous_apps": dangerous_apps,
                "total_grants": total_grants,
            },
            expected_value="No apps with dangerous scopes",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"No dangerous OAuth scope grants found across {total_grants} token grant(s).",
        actual_value={"dangerous_apps": {}, "total_grants": total_grants},
        expected_value="No apps with dangerous scopes",
    )


# -----------------------------------------------------------------------
# ADD-34: App-Specific Passwords inventory
# -----------------------------------------------------------------------

@check(
    check_id="ADD-34",
    title="Ensure no users have active App-Specific Passwords",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > Less secure apps. "
        "Review and revoke unnecessary App-Specific Passwords. "
        "ASPs bypass 2-Step Verification and pose a security risk. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    ),
    scored=False,
)
def check_app_passwords(data: dict) -> CheckResult:
    """Report users with active App-Specific Passwords (ASPs).

    ASPs bypass 2-Step Verification and are a significant security risk.
    """
    _ID = "ADD-34"
    _TITLE = "Ensure no users have active App-Specific Passwords"
    _L, _S, _SEC = "L1", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > Less secure apps. "
        "Review and revoke unnecessary App-Specific Passwords. "
        "ASPs bypass 2-Step Verification and pose a security risk. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    )

    app_passwords = data.get("app_passwords", [])

    if not app_passwords:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No App-Specific Passwords found.",
            actual_value={
                "total_asps": 0,
                "users_with_asps": 0,
                "never_used_asps": 0,
                "asps_by_user": [],
            },
            expected_value="No active ASPs",
        )

    # Group ASPs by user
    by_user: dict[str, list[dict]] = {}
    never_used = 0
    for asp in app_passwords:
        email = asp.get("userEmail", "unknown")
        by_user.setdefault(email, [])
        last_used = asp.get("lastTimeUsed", 0)
        if not last_used or last_used == 0:
            never_used += 1
        by_user[email].append({
            "code_id": str(asp.get("codeId", "")),
            "name": asp.get("name", ""),
            "created": str(asp.get("creationTime", "")),
            "last_used": str(last_used) if last_used else "Never",
        })

    asps_by_user = [
        {"user": user, "asps": asps}
        for user, asps in sorted(by_user.items())
    ]

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"Found {len(app_passwords)} App-Specific Password(s) across "
            f"{len(by_user)} user(s). {never_used} ASP(s) have never been used."
        ),
        actual_value={
            "total_asps": len(app_passwords),
            "users_with_asps": len(by_user),
            "never_used_asps": never_used,
            "asps_by_user": asps_by_user,
        },
        expected_value="No active ASPs",
        remediation=_REMED,
    )


# -----------------------------------------------------------------------
# ADD-35: Shared Drives security settings
# -----------------------------------------------------------------------

@check(
    check_id="ADD-35",
    title="Ensure Shared Drives have secure default restrictions",
    level="L1",
    source="OTHER",
    section="Drive",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive > "
        "Sharing settings > Shared drive creation. Review Shared "
        "Drives with insecure restrictions. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
    scored=False,
)
def check_shared_drive_restrictions(data: dict) -> CheckResult:
    """Report Shared Drives with insecure restriction settings."""
    _ID = "ADD-35"
    _TITLE = "Ensure Shared Drives have secure default restrictions"
    _L, _S, _SEC = "L1", "OTHER", "Drive"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive > "
        "Sharing settings > Shared drive creation. Review Shared "
        "Drives with insecure restrictions. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    shared_drives = data.get("shared_drives", [])

    if not shared_drives:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No Shared Drives found.",
            actual_value={
                "total_drives": 0,
                "insecure_drives": 0,
                "drives": [],
            },
            expected_value="All Shared Drives with secure restrictions",
        )

    drives_info = []
    insecure_count = 0

    for drive in shared_drives:
        restrictions = drive.get("restrictions", {})
        domain_users_only = restrictions.get("domainUsersOnly", False)
        drive_members_only = restrictions.get("driveMembersOnly", False)
        admin_managed = restrictions.get("adminManagedRestrictions", False)
        sharing_requires_organizer = restrictions.get(
            "sharingFoldersRequiresOrganizerPermission", False
        )

        issues = []
        if not domain_users_only:
            issues.append("domainUsersOnly not set")
        if not drive_members_only:
            issues.append("driveMembersOnly not set")
        if not admin_managed:
            issues.append("adminManagedRestrictions not set")
        if not sharing_requires_organizer:
            issues.append("sharingFoldersRequiresOrganizerPermission not set")

        if issues:
            insecure_count += 1

        drives_info.append({
            "name": drive.get("name", ""),
            "id": drive.get("id", ""),
            "domain_users_only": domain_users_only,
            "drive_members_only": drive_members_only,
            "admin_managed": admin_managed,
            "sharing_requires_organizer": sharing_requires_organizer,
            "issues": issues,
        })

    actual_value = {
        "total_drives": len(shared_drives),
        "insecure_drives": insecure_count,
        "drives": drives_info,
    }

    if insecure_count > 0:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {insecure_count} of {len(shared_drives)} Shared Drive(s) "
                f"with insecure restriction settings."
            ),
            actual_value=actual_value,
            expected_value="All Shared Drives with secure restrictions",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(shared_drives)} Shared Drive(s) have secure restriction settings.",
        actual_value=actual_value,
        expected_value="All Shared Drives with secure restrictions",
    )


# -----------------------------------------------------------------------
# ADD-36: Active OAuth tokens with dangerous scopes
# -----------------------------------------------------------------------

@check(
    check_id="ADD-36",
    title="Ensure no active OAuth tokens grant dangerous privileges",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Review and revoke active tokens with dangerous scopes. Block "
        "unverified or anonymous apps that should not have access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_active_oauth_tokens(data: dict) -> CheckResult:
    """Analyze live OAuth token grants and flag apps with high-risk scopes.

    Unlike ADD-33 which uses historical token activity logs, this check
    examines **currently active** tokens from the Directory API
    ``tokens.list()`` endpoint — showing what apps have access right now.
    """
    _ID = "ADD-36"
    _TITLE = "Ensure no active OAuth tokens grant dangerous privileges"
    _L, _S, _SEC = "L1", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Review and revoke active tokens with dangerous scopes. Block "
        "unverified or anonymous apps that should not have access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    user_tokens = data.get("user_tokens", [])

    if not user_tokens:
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No active OAuth token data available (tokens.list).",
            actual_value={
                "dangerous_apps": {},
                "total_tokens": 0,
                "anonymous_apps": 0,
            },
            expected_value="No apps with dangerous scopes",
            remediation=_REMED,
        )

    dangerous_apps: dict[str, dict] = {}
    total_non_native = 0
    anonymous_count = 0

    for tok in user_tokens:
        # Skip Google's own native apps (like the Slack repo does)
        if tok.get("nativeApp", False):
            continue

        total_non_native += 1
        client_id = tok.get("clientId", "")
        display_text = tok.get("displayText", "unknown")
        is_anonymous = tok.get("anonymous", False)
        user_email = tok.get("userEmail", "")
        scopes = tok.get("scopes", [])

        if is_anonymous:
            anonymous_count += 1

        # Check each scope against dangerous list
        matched_dangerous = []
        highest_risk = None
        for scope in scopes:
            if scope in DANGEROUS_OAUTH_SCOPES:
                matched_dangerous.append(scope)
            risk = _classify_scope_risk(scope)
            if risk:
                if scope not in matched_dangerous:
                    matched_dangerous.append(scope)
                if highest_risk is None or _RISK_ORDER.get(risk, 99) < _RISK_ORDER.get(highest_risk, 99):
                    highest_risk = risk

        if matched_dangerous:
            key = display_text or client_id or "unknown"
            if key not in dangerous_apps:
                dangerous_apps[key] = {
                    "app_name": display_text,
                    "client_id": client_id,
                    "anonymous": is_anonymous,
                    "dangerous_scopes": list(set(matched_dangerous)),
                    "risk_level": highest_risk or "HIGH",
                    "users": [],
                    "install_count": 0,
                }
            app_entry = dangerous_apps[key]
            # Merge scopes
            for s in matched_dangerous:
                if s not in app_entry["dangerous_scopes"]:
                    app_entry["dangerous_scopes"].append(s)
            # Update risk level to highest
            if highest_risk and _RISK_ORDER.get(highest_risk, 99) < _RISK_ORDER.get(app_entry["risk_level"], 99):
                app_entry["risk_level"] = highest_risk
            # Track anonymous
            if is_anonymous:
                app_entry["anonymous"] = True
            # Track users
            if user_email and user_email not in app_entry["users"]:
                app_entry["users"].append(user_email)
            app_entry["install_count"] += 1

    if dangerous_apps:
        critical_count = sum(1 for a in dangerous_apps.values() if a["risk_level"] == "CRITICAL")
        high_count = sum(1 for a in dangerous_apps.values() if a["risk_level"] == "HIGH")
        anon_dangerous = sum(1 for a in dangerous_apps.values() if a.get("anonymous"))
        details_parts = [f"{len(dangerous_apps)} app(s) with dangerous OAuth scopes"]
        if critical_count:
            details_parts.append(f"{critical_count} CRITICAL")
        if high_count:
            details_parts.append(f"{high_count} HIGH")
        if anon_dangerous:
            details_parts.append(f"{anon_dangerous} anonymous/unverified")

        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {', '.join(details_parts)} across "
                f"{total_non_native} active third-party token(s). "
                f"See the OAuth Risk tab in the Inventory page for details."
            ),
            actual_value={
                "dangerous_apps": dangerous_apps,
                "total_tokens": total_non_native,
                "anonymous_apps": anonymous_count,
                "_dashboard_link": "/inventory?tab=ADD-33",
            },
            expected_value="No apps with dangerous scopes",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"No dangerous OAuth scopes found across {total_non_native} "
            f"active third-party token(s). "
            f"{anonymous_count} anonymous app(s) detected."
        ),
        actual_value={
            "dangerous_apps": {},
            "total_tokens": total_non_native,
            "anonymous_apps": anonymous_count,
        },
        expected_value="No apps with dangerous scopes",
    )
