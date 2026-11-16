# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Non-CIS additional checks for GWS Security Auditor.

Custom security checks from OTHER and GOOGLE best practices
that supplement the CIS Benchmark controls.
"""

import json
from datetime import datetime, timedelta, timezone

from .base import (
    check,
    make_pass,
    make_fail,
    make_warn,
    make_manual,
    make_review,
    is_default_policy,
    make_not_applicable,
    get_ou_values,
    format_ou_values_readable,
    field_value,
    ou_verdict,
    chrome_ou_verdict,
    chrome_policy_unset,
    result_from_setting_changes,
    latest_setting_changes,
    latest_setting_changes_by_app,
    latest_service_toggles,
    gmail_rule_settings,
)
from ..google_defaults import CHROME_POLICY_DEFAULTS
from ..constants import (
    EDITIONS_AI_CLASSIFICATION, EDITIONS_CAA, EDITIONS_CSE, EDITIONS_DLP, EDITIONS_DLP_CALENDAR, EDITIONS_GEMINI_WORKSPACE, EDITIONS_GMAIL_LABELS, EDITIONS_MEET_RECORDING, EDITIONS_MPA, EDITIONS_SECURITY_SANDBOX, EDITIONS_TRUST_RULES,
)
from ..models import CheckResult, Status
from ..constants import DANGEROUS_OAUTH_SCOPES, OAUTH_SCOPE_RISK_LEVELS


# Admin-log SETTING_NAME for the Gmail Security sandbox toggle, as read by CISA ScubaGoggles
# (GWS.GMAIL.16.1: AttachmentDeepScanningSettingsProto deep_scanning_enabled, NEW_VALUE true/false).
# Not yet observed on this tenant; a wrong name leaves the check MANUAL, never wrong.
_SECURITY_SANDBOX_SETTING_NAME = "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
# Admin-log names confirmed by live flips on 2026-11-07 (see check-correctness-test-plan.md).
_TLS_COMPLIANCE_SETTING_NAME = "TLS_COMPLIANCE"  # CREATE/CHANGE/DELETE_GMAIL_SETTING rule family
_GENAI_FEATURES_SETTING_SUFFIX = "GenAiEnablementSettingsProto genai_features_enabled"  # per <service>_genai app
_SKIP_PASSWORD_SETTING_NAME = "Skip password enrollment state"  # APPLICATION_NAME "Security", "allow"
_GEMINI_WS_REMED = (
    "Admin console > Generative AI > Gemini in Workspace > Feature access. "
    "Turn Gemini features off for services that must not process content with AI, or keep them on only "
    "after review. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
)


@check(
    check_id="ADD-02",
    title="Ensure Security Sandbox is enabled for Gmail",
    level="L1",
    source="OTHER",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > "
        "Security sandbox. Enable Security Sandbox to scan attachments "
        "in a virtual environment. Note: requires Business Standard or higher license. https://knowledge.workspace.google.com/admin/gmail/advanced/gmail-security-sandbox-overview"
    ),
    requires_license=EDITIONS_SECURITY_SANDBOX,
)
def check_security_sandbox(data: dict) -> CheckResult:
    """Gmail Security Sandbox should be enabled for advanced threat protection."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    safety = gmail.get("safety", {})
    sandbox_enabled = safety.get("security_sandbox_enabled", None)

    if sandbox_enabled is None:
        # Not in the Policy API: the latest admin-log change per OU decides (mechanism A).
        inferred = result_from_setting_changes(
            data, _SECURITY_SANDBOX_SETTING_NAME, ("false",),
            check_id="ADD-02", title="Ensure Security Sandbox is enabled for Gmail",
            level="L1", source="OTHER", section="Gmail", what="Gmail Security sandbox",
            remediation=("Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > Security sandbox. "
                         "Enable Security Sandbox. https://knowledge.workspace.google.com/admin/gmail/advanced/gmail-security-sandbox-overview"),
        )
        if inferred is not None:
            return inferred

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
                "Security Sandbox is not exposed by the Cloud Identity Policy API and no change to it "
                "appears in the admin-log window — verify in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > "
                "Security sandbox. Enable Security Sandbox to scan attachments "
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
            "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > "
            "Security sandbox. Enable Security Sandbox to scan attachments "
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
            if isinstance(mx, dict):
                mx_host = str(mx.get("host") or mx.get("exchange") or "")
            else:
                mx_host = str(mx)
            mx_host = mx_host.lower().rstrip(".")
            if mx_host in google_mx_patterns or any(
                    mx_host.endswith("." + pattern) for pattern in google_mx_patterns):
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

    if spf_check is None:
        # A spam-filter IP allowlist exists, but whether it is an inbound gateway and whether
        # it rejects on SPF failure is not exposed by the Policy API — do not assume a failure.
        return make_review(
            check_id="ADD-06",
            title="Ensure inbound gateway SPF configuration is correct",
            level="L2", source="GOOGLE", section="Gmail",
            details=(
                "A spam-filter IP allowlist is configured, which may indicate an inbound gateway. "
                "The gateway's SPF rejection setting is not exposed by the Cloud Identity Policy API "
                "— verify in Admin console."
            ),
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
    scored=False,  # Log evidence can prove a TLS rule exists, never that none exists: PASS or MANUAL only
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
    # Default to None (not []) so "not collected" reaches the undetermined branch below
    partner_tls = compliance.get("partner_domain_tls_rules", None)
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
        # Secure transport (TLS) compliance rules log as CREATE/CHANGE/DELETE_GMAIL_SETTING with
        # SETTING_NAME "TLS_COMPLIANCE" and the rule id in USER_DEFINED_SETTING_NAME (observed live
        # 2026-11-07). A rule created or changed in the window and not deleted since proves at least
        # one TLS rule exists. The window cannot prove that none exists (older rules log nothing), so
        # the only other outcome is MANUAL.
        rules = gmail_rule_settings(data, _TLS_COMPLIANCE_SETTING_NAME)
        alive = {rid: r for rid, r in rules.items() if not r["event"].startswith("DELETE_")}
        if alive:
            return make_pass(
                check_id="ADD-07",
                title="Ensure TLS is enforced for partner domains",
                level="L2", source="GOOGLE", section="Gmail",
                details=(f"{len(alive)} secure transport (TLS) compliance rule(s) created or changed in the "
                         f"admin-log window and not deleted since: "
                         + "; ".join(f"{rid} ({r['description'] or 'no description'}, {r['org_unit']})"
                                     for rid, r in sorted(alive.items()))),
                actual_value={"tls_compliance_rules": alive},
                expected_value="At least one TLS compliance rule for partner domains",
            )
        return make_review(
            check_id="ADD-07",
            title="Ensure TLS is enforced for partner domains",
            level="L2", source="GOOGLE", section="Gmail",
            details=(
                "Partner domain TLS compliance rules are not exposed by the Cloud Identity Policy API and "
                + ("the only TLS compliance rule(s) touched in the admin-log window were deleted"
                   if rules else "no TLS compliance rule was created or changed in the admin-log window")
                + "; rules older than the window are invisible. Verify in Admin console."
            ),
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
        "Admin console > Devices > Chrome > Settings > User & browser settings > "
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
        "Admin console > Devices > Chrome > Settings > User & browser settings > "
        "Password Alert. Set password protection warning to warn on "
        "password reuse. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    # chrome.users.PasswordAlert.passwordProtectionWarningTrigger (live schema 2026-11-15), judged per OU
    # from data["chrome_policies"] (root values + "_ou_policies"); the provider's legacy mapping
    # policies.security.password_alert is read only when the raw root key is absent.
    _KEY = "password_protection_warning_trigger"
    _OFF = "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_NO_WARNING"
    _REUSE = "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PASSWORD_REUSE"
    _PHISHING = "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PHISHING_REUSE"
    _TRIGGER_LABELS = {
        _OFF: "No password protection warning",
        _REUSE: "Trigger on password reuse",
        _PHISHING: "Trigger on password reuse on phishing page",
    }
    expected = "Trigger on password reuse (warn whenever the corporate password is entered on an unauthorized site)"
    common = dict(check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC)

    chrome = data.get("chrome_policies")
    mapped = (data.get("policies", {}).get("security", {}) or {}).get("password_alert", {}) or {}
    if isinstance(chrome, dict) and chrome.get(_KEY) is None and mapped.get("deployed") is not None:
        trigger = mapped.get("trigger")
        if trigger is None:
            trigger = _REUSE if mapped["deployed"] else _OFF
        data = {**data, "chrome_policies": {**chrome, _KEY: trigger}}

    def judge(values: dict) -> tuple:
        trigger = values.get(_KEY)
        if trigger == _PHISHING:
            return "warn", ("Password alert is set to 'Trigger on password reuse on phishing page': users are warned only "
                            "when the corporate password is typed on a page Safe Browsing flags as phishing. Google's "
                            "checklist wants a warning on any reuse of the corporate password on another site "
                            "('Trigger on password reuse')."), {"trigger": trigger, "label": _TRIGGER_LABELS[_PHISHING]}
        if trigger == _OFF:
            return "fail", "Password protection warning is disabled ('No password protection warning').", {"trigger": trigger}
        if trigger is not None:
            label = _TRIGGER_LABELS.get(trigger, str(trigger))
            return "pass", f"Password protection warning is enabled: {label}.", {"trigger": trigger, "label": label}
        if chrome_policy_unset(data, "chrome.users.PasswordAlert"):
            default = CHROME_POLICY_DEFAULTS["chrome.users.PasswordAlert"]
            return "warn", ("Password alert is not set by policy, so Chrome's default applies: " + default["unset"]
                            + f" Google's checklist wants 'Trigger on password reuse' (source: {default['source']})."), \
                {"trigger": default["default_value"], "source": "chrome default"}
        return "unknown", "", None

    return chrome_ou_verdict(
        data, (_KEY,), judge, common=common, expected_value=expected, remediation=_REMED,
        unknown_details=("Password protection warning status could not be determined "
                         "(Chrome policies were not collected or the resolve call failed). Verify in Admin console > "
                         "Devices > Chrome > Settings > Users & browsers > Password alert."),
    )


@check(
    check_id="ADD-09",
    title="Ensure Google Takeout is restricted",
    level="L1",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Apps > Additional Google services > Google Takeout. "
        "Disable Google Takeout to prevent users from bulk-exporting "
        "organizational data. https://knowledge.workspace.google.com/admin/users/advanced/turn-on-or-off-additional-google-services"
    ),
)
def check_takeout_restriction(data: dict) -> CheckResult:
    """Google Takeout (data export) should be restricted to prevent data exfiltration."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    data_export = security.get("data_export", {})
    takeout_enabled = data_export.get("takeout_enabled", None)

    # Policy API: takeout.service_status.serviceState plus one <service>.user_takeout.takeoutStatus
    # per service. Admin-set values win over Google defaults for the same OU and setting.
    statuses: dict[tuple[str, str], tuple[bool, str]] = {}
    takeout = policies.get("takeout", {})
    for policy in takeout.get("_ou_policies", []) if isinstance(takeout, dict) else []:
        setting = policy.get("setting", {}) if isinstance(policy, dict) else {}
        stype = str(setting.get("type", "")).replace("settings/", "")
        value = setting.get("value", {}) or {}
        state = value.get("takeoutStatus", value.get("serviceState"))
        if state is None or not (stype.endswith(".user_takeout") or stype.startswith("takeout.")):
            continue
        is_default = is_default_policy({"_raw": policy.get("_raw", {}), "name": policy.get("name", "")})
        key = (policy.get("orgUnit", "/"), stype.split(".", 1)[0])
        if key not in statuses or (statuses[key][0] and not is_default):
            statuses[key] = (is_default, str(state).upper())
    if statuses:
        enabled = sorted(f"{ou}: {service}" for (ou, service), (_, state) in statuses.items()
                         if state != "DISABLED")
        if enabled:
            return make_fail(
                check_id="ADD-09",
                title="Ensure Google Takeout is restricted",
                level="L1", source="GOOGLE", section="Security",
                details=f"Takeout (data export) is allowed for {len(enabled)} service/OU pair(s): "
                        + ", ".join(enabled[:12]) + ("..." if len(enabled) > 12 else ""),
                actual_value={"takeout_enabled_for": enabled},
                expected_value="Takeout disabled for all services",
                remediation=(
                    "Admin console > Data > Data import & export > Google Takeout > User access. "
                    "Set each service to 'Don't allow'."
                ),
            )
        return make_pass(
            check_id="ADD-09",
            title="Ensure Google Takeout is restricted",
            level="L1", source="GOOGLE", section="Security",
            details=f"Takeout is disabled for all {len(statuses)} service/OU setting(s) returned.",
            actual_value={"takeout_enabled_for": []},
            expected_value="Takeout disabled for all services",
        )

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
                "Admin console > Apps > Additional Google services > Google Takeout. "
                "Disable Google Takeout to prevent users from bulk-exporting "
                "organizational data. https://knowledge.workspace.google.com/admin/users/advanced/turn-on-or-off-additional-google-services"
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
            "Admin console > Apps > Additional Google services > Google Takeout. "
            "Disable Google Takeout to prevent bulk data export by users. https://knowledge.workspace.google.com/admin/users/advanced/turn-on-or-off-additional-google-services"
        ),
    )


@check(
    check_id="ADD-11",
    scored=False,  # P3: client-side encryption is not exposed by the Policy API; MANUAL by design
    title="Ensure client-side encryption is enabled",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Data > Compliance > "
        "Client-side encryption. Enable CSE for Drive, Gmail, Calendar, "
        "and Meet. Configure an external key management service. "
        "Note: requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-client-side-encryption"
    ),
    requires_license=EDITIONS_CSE,
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
                "Admin console > Data > Compliance > "
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
            "Admin console > Data > Compliance > "
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
        "Admin console > Security > Access and data control > Data protection > Manage rules. "
        "Create DLP rules to detect PII, financial data, and other "
        "sensitive content in outbound emails. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
    ),
    requires_license=EDITIONS_DLP,
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
            details=(
                f"DLP is configured for Gmail: {len(dlp.get('gmail_dlp_rules') or [])} active data protection rule(s) "
                f"apply to Gmail, plus {total_rules} content compliance rule(s)."
            ),
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
                "Admin console > Security > Access and data control > Data protection > Manage rules. "
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
            "Admin console > Security > Access and data control > Data protection > Manage rules. "
            "Create DLP rules to detect PII, financial data, and other "
            "sensitive content in outbound emails. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
        ),
    )


# ---------------------------------------------------------------------------
# ADD-13 to ADD-27: New 2025-2026 checks
# ---------------------------------------------------------------------------


@check(
    check_id="ADD-13",
    requires_license=EDITIONS_GEMINI_WORKSPACE,
    scored=False,  # Log evidence covers only services an admin touched; PASS/FAIL are informational
    title="Ensure Gemini features in Workspace apps are controlled",
    level="L1",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Generative AI > Gemini in Workspace. "
        "Disable or restrict Gemini features in Workspace apps "
        "to control AI-generated content and data processing. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_gemini_workspace_features(data: dict) -> CheckResult:
    """Gemini features within Workspace apps (Docs, Sheets, Gmail) should be controlled.

    Generative AI > Gemini in Workspace > Feature access has one switch per service. Saving one logs
    CREATE/CHANGE_APPLICATION_SETTING with APPLICATION_NAME "<service>_genai" (e.g. "calendar_genai")
    and SETTING_NAME "<Service>GenAiEnablementSettingsProto genai_features_enabled" (observed live
    2026-11-07). Google's default is on for every service, so a logged "false" is the only evidence of
    control; a logged "true" re-enables a service. Services without an event in the window are unknown.
    """
    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})
    workspace_features = gemini.get("workspace_features", {})
    enabled = workspace_features.get("enabled", None)

    if enabled is None:
        toggles = latest_setting_changes_by_app(data, _GENAI_FEATURES_SETTING_SUFFIX)
        if toggles:
            def _svc(app: str) -> str:
                return app[:-len("_genai")] if app.endswith("_genai") else app
            on = sorted(f"{_svc(app)} ({ou})" for (app, ou), v in toggles.items() if v.lower() == "true")
            off = sorted(f"{_svc(app)} ({ou})" for (app, ou), v in toggles.items() if v.lower() == "false")
            if on:
                return make_fail(
                    check_id="ADD-13",
                    title="Ensure Gemini features in Workspace apps are controlled",
                    level="L1", source="GOOGLE", section="Gemini",
                    details=(f"Gemini features were turned on per the latest admin-log change for {len(on)} "
                             f"service(s): {', '.join(on)}"
                             + (f"; turned off for: {', '.join(off)}" if off else "")
                             + ". Services without a logged change keep Google's default (on)."),
                    actual_value={"on": on, "off": off}, expected_value="Gemini features off, or on only for reviewed services",
                    remediation=_GEMINI_WS_REMED,
                )
            return make_pass(
                check_id="ADD-13",
                title="Ensure Gemini features in Workspace apps are controlled",
                level="L1", source="GOOGLE", section="Gemini",
                details=(f"Gemini features are turned off per the latest admin-log change for {len(off)} "
                         f"service(s): {', '.join(off)}. Services without a logged change keep Google's "
                         "default (on); review them."),
                actual_value={"off": off}, expected_value="Gemini features off, or on only for reviewed services",
            )

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
                "Admin console > Generative AI > Gemini in Workspace. "
                "Review and control Gemini features in Docs, Sheets, "
                "Slides, and Gmail to meet organizational AI policies. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
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
            "Admin console > Generative AI > Gemini in Workspace. "
            "Disable or restrict Gemini features in Workspace apps "
            "to control AI-generated content and data processing. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
        ),
    )


@check(
    check_id="ADD-14",
    title="Ensure Gemini in Chrome is disabled",
    level="L2",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Devices > Chrome > Settings > User & browser settings. "
        "Disable Gemini in Chrome to prevent browser-based AI from "
        "processing organizational data. https://support.google.com/chrome/a/answer/16291696"
    ),
)
def check_gemini_chrome(data: dict) -> CheckResult:
    """Gemini in Chrome should be disabled to prevent uncontrolled AI data processing.

    ``policies.gemini.chrome.enabled`` is derived by the provider from the Chrome Policy API:
    ``chrome.users.GeminiSettings`` (ENABLED / DISABLED) or, when that is UNSET or absent, the
    ``chrome.users.GenAiDefaultSettings`` value it falls back to. Both unset means Chrome's
    default, which allows Gemini; a failed Chrome collection is MANUAL, not FAIL.
    """
    _REMED = (
        "Admin console > Devices > Chrome > Settings > Users & browsers > Generative AI > Gemini integrations: "
        "'Do not allow Gemini integrations' (or set the Generative AI policy defaults to 'Do not allow GenAI "
        "features'). https://support.google.com/chrome/a/answer/16291696"
    )
    common = dict(check_id="ADD-14", title="Ensure Gemini in Chrome is disabled",
                  level="L2", source="GOOGLE", section="Gemini")
    expected = "Disabled for all OUs"
    _KEY = "gemini_in_chrome_disabled"
    chrome = data.get("chrome_policies")
    mapped = (data.get("policies", {}).get("gemini", {}) or {}).get("chrome", {}) or {}
    if isinstance(chrome, dict) and chrome.get(_KEY) is None and isinstance(mapped.get("enabled"), bool):
        data = {**data, "chrome_policies": {**chrome, _KEY: not mapped["enabled"]}}

    def judge(values: dict) -> tuple:
        disabled = values.get(_KEY)
        if disabled is True:
            return "pass", "Gemini in Chrome is disabled.", False
        if disabled is False:
            return "fail", ("Gemini in Chrome is allowed: GeminiSettings permits Gemini integrations, or it is unset and "
                            "the Generative AI policy default allows GenAI features."), True
        if chrome_policy_unset(data, "chrome.users.GeminiSettings") and chrome_policy_unset(data, "chrome.users.GenAiDefaultSettings"):
            default = CHROME_POLICY_DEFAULTS["chrome.users.GeminiSettings"]
            return "fail", ("Gemini in Chrome is not set by policy, so Chrome's default applies: " + default["unset"]
                            + f" (source: {default['source']})"), {"gemini_settings": None, "source": "chrome default"}
        return "unknown", "", None

    return chrome_ou_verdict(
        data, (_KEY, "gemini_settings", "gen_ai_default_settings"), judge, common=common, expected_value=expected,
        remediation=_REMED,
        unknown_details=("Gemini in Chrome could not be determined (Chrome policies were not collected or the resolve "
                         "call failed). Verify in Admin console > Devices > Chrome > Settings > Users & browsers > "
                         "Generative AI."),
    )


@check(
    check_id="ADD-15",
    requires_license=EDITIONS_GEMINI_WORKSPACE,
    title="Ensure Google Workspace Studio access is controlled",
    level="L2",
    source="GOOGLE",
    section="Gemini",
    remediation=(
        "Admin console > Apps > Google Workspace > "
        "Workspace Studio. Disable or restrict access to prevent "
        "uncontrolled AI app creation by users. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
    ),
)
def check_workspace_studio(data: dict) -> CheckResult:
    """Google Workspace Studio access should be controlled."""
    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})
    studio = gemini.get("workspace_studio", {})
    enabled = studio.get("enabled", None)

    if enabled is None:
        # Workspace Studio is a core app (Apps > Google Workspace > Workspace Studio); its on/off switch
        # logs as TOGGLE_SERVICE_ENABLED with SERVICE_NAME "Workspace Studio" and NEW_VALUE "false"/"true"
        # (observed live 2026-11-07). Latest toggle per OU decides; no event -> MANUAL.
        toggles = latest_service_toggles(data, "Workspace Studio")
        if toggles:
            on = sorted(ou for ou, v in toggles.items() if v == "true")
            if on:
                return make_fail(
                    check_id="ADD-15", title="Ensure Google Workspace Studio access is controlled",
                    level="L2", source="GOOGLE", section="Gemini",
                    details=f"Workspace Studio is turned on per the latest admin-log service toggle in {len(on)} OU(s): {', '.join(on)}.",
                    actual_value={"toggles": toggles}, expected_value="Service off, or on only for a reviewed OU",
                    remediation=("Admin console > Apps > Google Workspace > Workspace Studio. Turn the service off, or on only for "
                                 "the OUs that need it. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"),
                )
            return make_pass(
                check_id="ADD-15", title="Ensure Google Workspace Studio access is controlled",
                level="L2", source="GOOGLE", section="Gemini",
                details=f"Workspace Studio is turned off per the latest admin-log service toggle in {len(toggles)} OU(s).",
                actual_value={"toggles": toggles}, expected_value="Service off, or on only for a reviewed OU",
            )

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
                "Workspace Studio is not in the Policy API and no service toggle for it appears in the "
                "admin-log window; verify its Service status in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > "
                "Workspace Studio. Disable or restrict Workspace Studio "
                "access to control AI app creation. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
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
            "Admin console > Apps > Google Workspace > "
            "Workspace Studio. Disable or restrict access to prevent "
            "uncontrolled AI app creation by users. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/manage-access-to-gemini-features-in-workspace-services"
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
        "iOS devices'. https://knowledge.workspace.google.com/admin/devices/prevent-accidental-data-leaks-on-ios-devices"
    ),
)
def check_apple_writing_tools(data: dict) -> CheckResult:
    """Apple Intelligence Writing Tools on iOS should be disabled for Workspace.

    The Policy API returns ``devices.ios_apple_intelligence.writingToolsAllowed`` (seen live
    2026-11-07 on an Enterprise Standard tenant; the setting lives under Devices > Mobile &
    endpoints > Settings > iOS > Data sharing). PASS when every OU has it false, FAIL when any OU
    allows it, MANUAL only when the API returned nothing for the setting.
    """
    _ID = "ADD-16"
    _TITLE = "Ensure Apple Intelligence Writing Tools are disabled for Workspace"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Devices > Mobile & endpoints > Settings > iOS > "
        "Data sharing > Apple Intelligence. Turn off 'Allow users to use "
        "Apple Intelligence Writing Tools within Google Workspace apps on "
        "iOS devices'. https://knowledge.workspace.google.com/admin/devices/prevent-accidental-data-leaks-on-ios-devices"
    )

    ou_values = get_ou_values(data.get("policies", {}).get("devices", {}), "ios_apple_intelligence")
    if ou_values:
        def _judge(entry):
            allowed = field_value(entry, "writingToolsAllowed")
            if allowed is None:
                return None
            return (allowed is False, allowed)
        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow Apple Intelligence Writing Tools in Workspace apps on iOS",
            pass_text="block Apple Intelligence Writing Tools in Workspace apps on iOS",
            expected_value="writingToolsAllowed false for all OUs", remediation=_REMED,
        )
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "The Policy API returned no devices.ios_apple_intelligence setting for this tenant "
            "(it is returned once the iOS data-sharing settings have been saved, or on editions with "
            "advanced mobile management). Verify in Admin console > Devices > Mobile & endpoints > "
            "Settings > iOS > Data sharing > Apple Intelligence."
        ),
        remediation=_REMED,
    )


@check(
    check_id="ADD-18",
    requires_license=EDITIONS_CAA,
    title="Ensure passkeys are enforced as primary authentication",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Passwordless. "
        "Enable 'Allow users to skip their password and authenticate "
        "with a passkey' to enforce passkeys as primary authentication. https://knowledge.workspace.google.com/admin/users/allow-users-to-skip-passwords-at-sign-in"
    ),
)
def check_passkeys_enforced(data: dict) -> CheckResult:
    """Passkeys should be enforced as primary authentication method.

    The 'Skip passwords' setting is not in the Cloud Identity Policy API. Saving it logs
    CHANGE/CREATE_APPLICATION_SETTING with APPLICATION_NAME "Security" and SETTING_NAME
    "Skip password enrollment state", NEW_VALUE "allow" when users may skip their password
    (observed live 2026-11-07; one event per edition for the same OU). The latest value per OU
    decides; no event in the log window means the state is unknown (MANUAL).
    """
    _ID = "ADD-18"
    _TITLE = "Ensure passkeys are enforced as primary authentication"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Passwordless. "
        "Enable 'Allow users to skip their password and authenticate "
        "with a passkey' to enforce passkeys as primary authentication. https://knowledge.workspace.google.com/admin/users/allow-users-to-skip-passwords-at-sign-in"
    )

    changes = {ou: v for ou, v in latest_setting_changes(data, _SKIP_PASSWORD_SETTING_NAME).items()
               if v.upper() != "INHERIT_FROM_PARENT"}
    if changes:
        bad = sorted(ou for ou, v in changes.items() if v.lower() != "allow")
        if bad:
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=(f"Skip passwords (passkey-only sign-in) is not allowed in {len(bad)} OU(s) per the "
                         f"latest admin-log change: {', '.join(bad)}"),
                actual_value=", ".join(f"{ou} → {changes[ou]}" for ou in bad),
                expected_value="allow for all OUs", remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Users may skip their password and sign in with a passkey in all {len(changes)} OU(s) with a logged change.",
            actual_value=changes, expected_value="allow for all OUs",
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "The Skip passwords setting is not in the Cloud Identity Policy API and no change to it "
            "appears in the admin-log window. Verify manually in "
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


# Context-Aware Access user events (applicationName=context_aware_access). The Reports API appendix
# documents only ACCESS_DENY_EVENT; the live tenant (2026-11-06) also writes ACCESS_LEVELS_EVALUATED for
# every allowed access ("Access Evaluated" in the Workspace help), with CAA_ACCESS_LEVEL_APPLIED /
# _SATISFIED / _UNSATISFIED (multi-value level titles), CAA_APPLICATION (upper-case app code such as
# GMAIL, DRIVE, CALENDAR, ADMIN_CONSOLE), CAA_DEVICE_ID, CAA_DEVICE_STATE ("No Device Signals", or
# "Normal" when Endpoint Verification reported for a device-based level) and PROTECTED_API_ACCESS or
# BLOCKED_API_ACCESS. ACCESS_DENY_EVENT (observed 2026-11-06 23:59Z) carries APPLIED, UNSATISFIED,
# BLOCKED_API_ACCESS and CAA_ACCESS_EVALUATION_DETAILS (a text proto with the level and its CEL AST), no
# SATISFIED list. A monitor-mode assignment writes MONITOR_MODE_ACCESS_EVALUATED_EVENT with the same
# parameters (observed 2026-11-06 23:33Z); the denied variant is assumed to follow the same naming. Any
# event name containing MONITOR is monitor mode and is never proof of enforcement.
_CAA_ACTIVE_EVENTS = ("ACCESS_DENY_EVENT", "ACCESS_LEVELS_EVALUATED")
_CAA_MONITOR_EVENTS = ("MONITOR_MODE_ACCESS_EVALUATED_EVENT", "MONITOR_MODE_ACCESS_DENY_EVENT")


def _as_title_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    text = str(value).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return [t.strip() for t in text.split(",") if t.strip()]


def _caa_enforcement_events(caa_events: list) -> list[dict]:
    """Active-mode Context-Aware Access evaluations (allowed or denied) from ``data["caa_events"]``.

    Each item: ``{"event", "denied", "app", "applied", "satisfied", "unsatisfied", "time", "actor",
    "region", "device_state"}``. ``denied`` comes from the event name only: several active levels on one
    app are OR'd (observed 2026-11-06 23:54Z: ACCESS_LEVELS_EVALUATED with one satisfied and one
    unsatisfied level, access allowed), so a non-empty ``unsatisfied`` list is not a denial. An
    evaluation with a non-empty ``applied`` list proves that an access level was enforced on that app
    at that time, whatever the outcome. Monitor-mode and unknown event names are skipped.
    """
    out: list[dict] = []
    for entry in caa_events or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("event_name", "")).upper()
        if name not in _CAA_ACTIVE_EVENTS or "MONITOR" in name:
            continue
        params = entry.get("parameters", {}) or {}
        app = str(params.get("CAA_APPLICATION") or params.get("application_name") or "").strip()
        out.append({
            "event": name,
            "denied": name == "ACCESS_DENY_EVENT",
            "app": app,
            "applied": _as_title_list(params.get("CAA_ACCESS_LEVEL_APPLIED")),
            "satisfied": _as_title_list(params.get("CAA_ACCESS_LEVEL_SATISFIED")),
            "unsatisfied": _as_title_list(params.get("CAA_ACCESS_LEVEL_UNSATISFIED")),
            "time": str(entry.get("time", "")),
            "actor": str(entry.get("actor_email", "") or ""),
            "region": str(entry.get("region_code", "") or ""),
            # "No Device Signals" when no Endpoint Verification / managed-device signal reached CAA.
            "device_state": str(params.get("CAA_DEVICE_STATE", "") or ""),
        })
    return out


def _caa_enforcement_for_apps(caa_events: list, app_names: list[str]) -> tuple[int, list[str], int]:
    """Count active-mode CAA evaluations whose ``CAA_APPLICATION`` names one of *app_names*.

    Returns ``(evaluations, matched app names, denials)``. Matching is case-insensitive on the app
    name; an evaluation for a Workspace app (GMAIL, DRIVE ...) never counts for a third-party app, so
    "CAA is enforcing somewhere" is no longer evidence that it covers these apps.
    """
    wanted = {str(n).strip().lower() for n in app_names if str(n).strip()}
    count, denials, matched = 0, 0, set()
    for ev in _caa_enforcement_events(caa_events):
        if ev["app"].lower() in wanted:
            count += 1
            denials += int(ev["denied"])
            matched.add(ev["app"])
    return count, sorted(matched), denials


# CHANGE_CAA_APP_ASSIGNMENTS MODE values seen live on argussec.io (2026-11-06): MONITOR for monitor
# mode, BLOCK for the Block action and WARN for the Warn action (23:35Z flip, assignment scoped to a
# sub-OU). The Reports API appendix also documents ACTIVE. Anything else is "unclear" (MANUAL), never
# PASS. Each event is scoped by TARGET_ENTITY_TYPE / TARGET_ENTITY_NAME (ORG_UNIT "argussec.io" for the
# root, "Workspace Guests" for a sub-OU), so state is kept per app, target and mode.
_CAA_ACTIVE_MODES = ("BLOCK", "WARN", "ACTIVE")
# Per the help article "Assign Context-Aware Access levels to apps": Block blocks access; Warn "allows
# access to the app and sends the user a warning notification". A Warn assignment is therefore an
# implemented policy but not a blocking one, and checks that promise blocking require these modes.
_CAA_BLOCKING_MODES = ("BLOCK", "ACTIVE")
_CAA_MONITOR_MODES = ("MONITOR",)


# Live events use CAA_ACCESS_ASSIGNMENTS_NEW; the Reports API appendix also documents
# CAA_ACCESS_LEVELS_NEW and CAA_ASSIGNMENTS_NEW for the same event. A change of an existing list
# carries both _OLD and _NEW (observed 2026-11-06 23:58Z); only _OLD without _NEW is a removal.
_CAA_NEW_ASSIGNMENT_KEYS = ("CAA_ACCESS_ASSIGNMENTS_NEW", "CAA_ACCESS_LEVELS_NEW", "CAA_ASSIGNMENTS_NEW")


def _caa_new_assignment_value(params: dict):
    for key in _CAA_NEW_ASSIGNMENT_KEYS:
        if key in params:
            return params.get(key)
    return None


def _caa_app_assignment_evidence(admin_logs: list, app_names: list[str]) -> dict:
    """Admin-log evidence for Context-Aware Access on the given apps.

    ``TOGGLE_CAA_ENABLEMENT`` gives the global state. ``CHANGE_CAA_APP_ASSIGNMENTS`` is written once
    per app *and* mode (observed live): ``APPLICATION_NAME`` (upper-case, e.g. ``TASKS``), ``MODE``
    (``MONITOR`` or ``BLOCK``), ``CAA_ACCESS_ASSIGNMENTS_NEW`` (multi-value list of access-level names
    now assigned in that mode) or ``CAA_ACCESS_ASSIGNMENTS_OLD`` alone when the assignment in that mode
    was removed. Events are scoped to an OU or group (``TARGET_ENTITY_TYPE`` / ``TARGET_ENTITY_NAME``,
    observed live for the root OU and a sub-OU), so the latest event per app, target and mode gives that
    target's current assignment in that mode and a sub-OU change never masks the root's. Returns
    ``{"toggle": state|None, "covered": [...], "warn_only": [...], "monitor": [...], "removed": [...],
    "unknown": [...], "unclear": [...]}`` over *app_names* (matched case-insensitively): covered = an
    active-mode assignment with levels on any target; warn_only = the subset of covered whose only active
    mode is WARN (users are warned, not blocked); monitor = levels only in monitor mode; removed = events
    exist but no target keeps levels in any mode; unknown = no event; unclear = levels only under an
    unrecognised mode.
    """
    toggle: tuple[str, str] | None = None
    state: dict[str, dict[tuple[str, str], tuple[str, bool]]] = {}
    for log in admin_logs or []:
        if not isinstance(log, dict):
            continue
        params = log.get("parameters", {}) or {}
        when = str(log.get("time", ""))
        event = log.get("event_name")
        if event == "TOGGLE_CAA_ENABLEMENT" and "NEW_VALUE" in params:
            if toggle is None or when >= toggle[0]:
                toggle = (when, str(params["NEW_VALUE"]).upper())
        elif event == "CHANGE_CAA_APP_ASSIGNMENTS":
            app = str(params.get("APPLICATION_NAME", "")).strip().lower()
            if not app:
                continue
            mode = str(params.get("MODE", "")).strip().upper()
            target = str(params.get("TARGET_ENTITY_NAME", "")).strip()
            new = _caa_new_assignment_value(params)
            has_levels = bool(new) and str(new).strip() not in ("[]", "{}", "none", "None")
            per_key = state.setdefault(app, {})
            key = (target, mode)
            if key not in per_key or when >= per_key[key][0]:
                per_key[key] = (when, has_levels)
    covered, warn_only, monitor, removed, unknown, unclear = [], [], [], [], [], []
    for name in app_names:
        per_key = state.get(str(name).strip().lower())
        if per_key is None:
            unknown.append(name)
            continue
        live = [mode for (_, mode), (_, has_levels) in per_key.items() if has_levels]
        if any(mode in _CAA_ACTIVE_MODES for mode in live):
            covered.append(name)
            if not any(mode in _CAA_BLOCKING_MODES for mode in live):
                warn_only.append(name)
        elif any(mode not in _CAA_MONITOR_MODES for mode in live):
            # Levels assigned under a mode this code does not know; not evidence of enforcement.
            other = sorted(mode or "(blank)" for mode in live if mode not in _CAA_MONITOR_MODES)
            unclear.append(f"{name} (mode {', '.join(other)})")
        elif live:
            monitor.append(name)
        else:
            removed.append(name)
    return {"toggle": toggle[1] if toggle else None, "toggle_time": toggle[0] if toggle else "", "covered": covered,
            "warn_only": warn_only, "monitor": monitor, "removed": removed, "unknown": unknown, "unclear": unclear}


_ACCESS_LEVEL_STATE_EVENTS = ("CREATE_ACCESS_LEVEL_V2", "UPDATE_ACCESS_LEVEL_V2")
_ACCESS_LEVEL_DELETE_EVENTS = ("DELETE_ACCESS_LEVEL_V2",)


def _caa_access_level_inventory(admin_logs: list) -> dict[str, dict]:
    """Access levels known from the admin audit log, keyed by ``ACCESS_LEVEL_NAME``.

    Observed live 2026-11-06 (event type ``ACCESS_LEVEL``, delivered a few minutes late):
    ``CREATE_ACCESS_LEVEL_V2`` with ``ACCESS_LEVEL_TITLE``, ``ACCESS_LEVEL_NAME``
    (``accessPolicies/<id>/accessLevels/<id>``) and ``ACCESS_LEVEL_CURR_STATE`` (JSON text of the
    level: ``basic.conditions[]`` with ``regions``, ``ipSubnetworks``, ``devicePolicy`` ... and
    ``negate``, or ``custom.expr``); ``DELETE_ACCESS_LEVEL_V2`` with ``ACCESS_LEVEL_NAME`` only.
    ``UPDATE_ACCESS_LEVEL_V2`` (observed 2026-11-06 23:31Z after editing a level's description) carries
    the same three fields plus ``ACCESS_LEVEL_PREV_STATE``; its ``ACCESS_LEVEL_CURR_STATE`` omits the
    description but keeps ``basic``/``custom``, which is all that is read. The latest event per
    name wins. Each value: ``{"title", "state" (parsed dict or None), "deleted", "time"}``. Levels
    created before the log window never appear, so an empty result means unknown, not none.
    """
    inventory: dict[str, dict] = {}
    for log in admin_logs or []:
        if not isinstance(log, dict):
            continue
        event = log.get("event_name")
        if event not in _ACCESS_LEVEL_STATE_EVENTS and event not in _ACCESS_LEVEL_DELETE_EVENTS:
            continue
        params = log.get("parameters", {}) or {}
        name = str(params.get("ACCESS_LEVEL_NAME", "")).strip()
        if not name:
            continue
        when = str(log.get("time", ""))
        current = inventory.get(name)
        if current is not None and when < current["time"]:
            continue
        if event in _ACCESS_LEVEL_DELETE_EVENTS:
            title = current["title"] if current else ""
            inventory[name] = {"title": title, "state": None, "deleted": True, "time": when}
            continue
        raw = params.get("ACCESS_LEVEL_CURR_STATE")
        state = None
        if isinstance(raw, dict):
            state = raw
        elif isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                state = parsed if isinstance(parsed, dict) else None
            except ValueError:
                state = None
        title = str(params.get("ACCESS_LEVEL_TITLE") or (state or {}).get("title") or "").strip()
        inventory[name] = {"title": title, "state": state, "deleted": False, "time": when}
    return inventory


def caa_access_levels(data: dict) -> tuple[dict[str, dict], str]:
    """Context-Aware Access level inventory and its source: ``"access_context_manager"`` or ``"admin_log"``.

    ``data["access_context"]`` (provider ``_get_access_context``) is authoritative when collected: every
    level of the organisation's access policy, whatever its age, as ``{name: {"title", "state", "deleted":
    False, "time": ""}}`` with ``state`` the AccessLevel resource (``basic`` / ``custom``), the same shape
    the admin log writes in ``ACCESS_LEVEL_CURR_STATE``. Otherwise the inventory is rebuilt from the
    admin log (180-day window, so an empty result means unknown, not none).
    """
    ctx = data.get("access_context") or {}
    if isinstance(ctx, dict) and ctx.get("collected"):
        inventory: dict[str, dict] = {}
        for level in ctx.get("access_levels") or []:
            if not isinstance(level, dict):
                continue
            name = str(level.get("name", "")).strip()
            if not name:
                continue
            state = {k: level[k] for k in ("basic", "custom") if k in level}
            inventory[name] = {"title": str(level.get("title", "")).strip(), "state": state or None,
                               "deleted": False, "time": ""}
        return inventory, "access_context_manager"
    return _caa_access_level_inventory(data.get("admin_logs", [])), "admin_log"


def _access_level_restricts_region(state: dict | None) -> bool:
    """True when an access level's state carries a geographic condition (allow-list or negated)."""
    if not isinstance(state, dict):
        return False
    for cond in (state.get("basic") or {}).get("conditions") or []:
        if isinstance(cond, dict) and cond.get("regions"):
            return True
    expr = str((state.get("custom") or {}).get("expr") or "")
    return "origin.region_code" in expr


def _caa_assigned_level_titles(admin_logs: list) -> dict[str, set[str]]:
    """Access-level titles currently assigned to at least one app, keyed by ``MODE``.

    Same per-app, per-target, per-mode reading of ``CHANGE_CAA_APP_ASSIGNMENTS`` as
    ``_caa_app_assignment_evidence``: the latest event per app, target and mode gives that
    target's current list in that mode; ``CAA_ACCESS_ASSIGNMENTS_OLD`` alone (removal) clears it.
    """
    latest: dict[tuple[str, str, str], tuple[str, list[str]]] = {}
    for log in admin_logs or []:
        if not isinstance(log, dict) or log.get("event_name") != "CHANGE_CAA_APP_ASSIGNMENTS":
            continue
        params = log.get("parameters", {}) or {}
        app = str(params.get("APPLICATION_NAME", "")).strip().lower()
        if not app:
            continue
        mode = str(params.get("MODE", "")).strip().upper()
        target = str(params.get("TARGET_ENTITY_NAME", "")).strip()
        new = _caa_new_assignment_value(params)
        if isinstance(new, str):
            new = [t.strip() for t in new.strip("[]").split(",") if t.strip()]
        titles = [str(t).strip() for t in (new or []) if str(t).strip()]
        when = str(log.get("time", ""))
        key = (app, target, mode)
        if key not in latest or when >= latest[key][0]:
            latest[key] = (when, titles)
    assigned: dict[str, set[str]] = {}
    for (_, _, mode), (_, titles) in latest.items():
        if titles:
            assigned.setdefault(mode, set()).update(titles)
    return assigned


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
    requires_license=EDITIONS_CAA,
)
def check_caa_oidc(data: dict) -> CheckResult:
    """Context-Aware Access policies should cover OIDC third-party apps.

    The Workspace policy APIs do not expose the CAA-for-OIDC toggle, so the
    check infers status from audit logs:

      Step 1 — Inventory: count distinct third-party OIDC clients in
        ``data["token_logs"]``.  If zero, return NOT_APPLICABLE — the toggle
        has nothing to apply to.
      Step 2 — Enforcement evidence: count active-mode CAA evaluations (allowed or denied) in
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

    eval_count, enforced_apps, deny_count = _caa_enforcement_for_apps(data.get("caa_events", []), oidc_apps)
    if eval_count > 0:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"CAA is actively enforcing on OIDC traffic: {eval_count} active-mode "
                f"evaluation(s) ({deny_count} denied) in the window for "
                f"{len(enforced_apps)} of the detected app(s): {', '.join(enforced_apps[:5])}."
            ),
            actual_value={"oidc_apps": oidc_count, "evaluations": eval_count, "denials": deny_count,
                          "enforced_apps": enforced_apps},
            expected_value="CAA evaluations present for OIDC apps",
        )

    # Step 2b — Configuration evidence from the admin audit log: CAA toggled off, or access
    # levels assigned to (or removed from) the detected apps, decide without a denial.
    evidence = _caa_app_assignment_evidence(data.get("admin_logs", []), oidc_apps)
    actual = {"oidc_apps": oidc_count, "denials": 0, "caa_enabled": evidence["toggle"],
              "covered": evidence["covered"], "monitor_only": evidence["monitor"],
              "levels_removed": evidence["removed"], "no_assignment_event": evidence["unknown"],
              "unrecognised_mode": evidence["unclear"]}
    if evidence["toggle"] == "DISABLED":
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access was turned off (latest admin-log change), so none of the "
                     f"{oidc_count} third-party OIDC app(s) is covered."),
            actual_value=actual, expected_value="CAA enabled with access levels assigned to OIDC apps",
            remediation=_REMEDIATION,
        )
    inventory, inventory_source = caa_access_levels(data)
    if inventory_source == "access_context_manager" and not inventory:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Access Context Manager lists no access level for the organisation, so Context-Aware "
                     f"Access cannot cover the {oidc_count} third-party OIDC app(s)."),
            actual_value=dict(actual, access_levels=0, inventory_source=inventory_source),
            expected_value="CAA enabled with access levels assigned to OIDC apps", remediation=_REMEDIATION,
        )
    if evidence["removed"] or evidence["monitor"]:
        parts = []
        if evidence["removed"]:
            parts.append(f"access levels removed from {', '.join(evidence['removed'])}")
        if evidence["monitor"]:
            parts.append(f"assigned in monitor mode only (not enforced) for {', '.join(evidence['monitor'])}")
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Latest Context-Aware Access assignment changes in the admin audit log: " + "; ".join(parts) + ".",
            actual_value=actual, expected_value="CAA enabled with access levels assigned to OIDC apps",
            remediation=_REMEDIATION,
        )
    if oidc_apps and not evidence["unknown"] and not evidence["unclear"]:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"All {len(evidence['covered'])} detected third-party OIDC app(s) have access levels assigned "
                     f"in active mode (latest CHANGE_CAA_APP_ASSIGNMENTS admin-log change): "
                     f"{', '.join(evidence['covered'])}."),
            actual_value=actual, expected_value="CAA enabled with access levels assigned to OIDC apps",
        )

    covered_note = (f" {len(evidence['covered'])} app(s) have access levels assigned per the admin log "
                    f"({', '.join(evidence['covered'][:5])}); no assignment event was found for the others." if evidence["covered"] else "")
    if evidence["unclear"]:
        covered_note += f" Assignment logged with an unrecognised mode for: {', '.join(evidence['unclear'])}."
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{oidc_count} third-party OIDC app(s) detected "
            f"({', '.join(oidc_apps[:5])}{'...' if len(oidc_apps) > 5 else ''}) "
            "but no active-mode CAA evaluation names them and no access-level assignment change for them "
            "was logged in the window. Absence of evaluations does not prove CAA is disabled — verify the "
            "policy assignment in Admin console > Security > "
            "Context-Aware Access." + covered_note
        ),
        remediation=_REMEDIATION,
        actual_value=actual,
    )


@check(
    check_id="ADD-40",
    title="Ensure default Context-Aware Access policy is enabled for SAML applications",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > Context-Aware Access > General settings. "
        "Enable a default CAA policy for all SAML applications so apps "
        "without specific assignments inherit a secure baseline. "
        "https://knowledge.workspace.google.com/admin/security/apply-caa-policy-for-all-saml-apps"
    ),
    requires_license=EDITIONS_CAA,
)
def check_caa_saml_default(data: dict) -> CheckResult:
    """Default CAA policy should be enabled for all SAML applications.

    Mirrors ADD-20's three-state log-driven logic for SAML:

      Step 1 — Inventory: count distinct SAML SSO apps in
        ``data["login_logs"]`` (events where ``parameters.login_type ==
        "saml"``).  If zero, return NOT_APPLICABLE — the default-SAML-CAA
        toggle has nothing to apply to.
      Step 2 — Enforcement evidence: count active-mode CAA evaluations (allowed or denied) in
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
        "Admin console > Security > Access and data control > Context-Aware Access > General settings. "
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

    eval_count, enforced_apps, deny_count = _caa_enforcement_for_apps(data.get("caa_events", []), saml_apps)
    if eval_count > 0:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"CAA is actively enforcing on SAML traffic: {eval_count} active-mode "
                f"evaluation(s) ({deny_count} denied) in the window for "
                f"{len(enforced_apps)} of the detected app(s): {', '.join(enforced_apps[:5])}."
            ),
            actual_value={"saml_apps": saml_count, "evaluations": eval_count, "denials": deny_count,
                          "enforced_apps": enforced_apps},
            expected_value="CAA evaluations present for SAML apps",
        )

    inventory, inventory_source = caa_access_levels(data)
    if inventory_source == "access_context_manager" and not inventory:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Access Context Manager lists no access level for the organisation, so no default "
                     f"Context-Aware Access policy can apply to the {saml_count} SAML app(s)."),
            actual_value={"saml_apps": saml_count, "evaluations": 0, "access_levels": 0,
                          "inventory_source": inventory_source},
            expected_value="A default CAA access level for SAML apps", remediation=_REMEDIATION,
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{saml_count} SAML app(s) detected "
            f"({', '.join(saml_apps[:5])}{'...' if len(saml_apps) > 5 else ''}) "
            "but no active-mode CAA evaluation (allowed or denied) names them in the window. "
            "Absence of evaluations does not prove CAA is disabled — verify the "
            "default policy in Admin console > Security > Context-Aware "
            "Access > General settings."
        ),
        remediation=_REMEDIATION,
        actual_value={"saml_apps": saml_count, "denials": 0},
    )


# ---------------------------------------------------------------------------
# ADD-53 .. ADD-56: Context-Aware Access posture from the access-level inventory
# ---------------------------------------------------------------------------
# The Access Context Manager inventory (data["access_context"], authoritative when collected) says
# what levels exist and what they require; the admin log says which apps they were assigned to in
# the window; the CAA user log says which levels were really applied. PASS always needs an
# assignment or an evaluation; the inventory alone only ever proves the negative.

# Admin console app identifier. CHANGE_CAA_APP_ASSIGNMENTS.APPLICATION_NAME and the CAA user-log
# CAA_APPLICATION use the same upper-case codes (GMAIL, DRIVE, CALENDAR, HANGOUTS_CHAT ...). Flip test
# 2026-11-06 23:23Z: assigning a level to the Admin console logged APPLICATION_NAME "ADMIN_CONSOLE",
# MODE BLOCK, and the next console loads wrote ACCESS_LEVELS_EVALUATED with CAA_APPLICATION
# "ADMIN_CONSOLE" and PROTECTED_API_ACCESS ["ADMIN_CONSOLE"] about a minute later.
_CAA_ADMIN_CONSOLE_APPS = ("ADMIN_CONSOLE",)
_CAA_ASSIGN_REMED = ("Admin console > Security > Access and data control > Context-Aware Access > "
                     "Assign access levels. https://knowledge.workspace.google.com/admin/security/assign-context-aware-access-levels-to-apps")
_CAA_NO_SIGNAL_STATES = ("", "NO DEVICE SIGNALS", "UNKNOWN")

# Access level devicePolicy fields that make a level depend on device posture (ACM AccessLevel
# resource, also written verbatim in ACCESS_LEVEL_CURR_STATE). An empty devicePolicy requires nothing.
_DEVICE_POLICY_FIELDS = ("requireScreenlock", "allowedEncryptionStatuses", "osConstraints", "requireCorpOwned",
                         "requireAdminApproval", "allowedDeviceManagementLevels")


def _caa_switched_off(evidence: dict, evaluations: list[dict]) -> bool:
    """True when the latest TOGGLE_CAA_ENABLEMENT says DISABLED and no evaluation is newer than it."""
    newest = max((e["time"] for e in evaluations), default="")
    return evidence.get("toggle") == "DISABLED" and not (evaluations and newest > evidence.get("toggle_time", ""))


def _access_level_requires_device(state: dict | None, inventory: dict | None = None, _depth: int = 0) -> bool:
    """True when an access level depends on device posture.

    ``basic.conditions[].devicePolicy`` with any requirement set, a ``custom.expr`` reading ``device.``
    attributes, or (through ``requiredAccessLevels``) another level of *inventory* that does.
    """
    if not isinstance(state, dict) or _depth > 3:
        return False
    for cond in (state.get("basic") or {}).get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        policy = cond.get("devicePolicy")
        if isinstance(policy, dict) and any(policy.get(f) for f in _DEVICE_POLICY_FIELDS):
            return True
        for required in cond.get("requiredAccessLevels") or []:
            nested = (inventory or {}).get(str(required))
            if nested and not nested.get("deleted") and _access_level_requires_device(nested.get("state"), inventory, _depth + 1):
                return True
    expr = str((state.get("custom") or {}).get("expr") or "")
    return "device." in expr


def _access_level_has_no_condition(state: dict | None) -> bool:
    """True when a level has neither a basic condition nor a custom expression (always satisfied)."""
    if not isinstance(state, dict):
        return False
    conditions = [c for c in (state.get("basic") or {}).get("conditions") or [] if isinstance(c, dict) and c]
    expr = str((state.get("custom") or {}).get("expr") or "").strip()
    return not conditions and not expr


def _caa_level_enforcement(data: dict, predicate) -> dict:
    """Shared evidence for 'a level with property *predicate* is enforced'.

    Returns ``{"inventory_source", "authoritative", "evidence", "evaluations", "matching"(titles),
    "evaluated"(matching titles applied in the CAA log), "evaluated_apps", "assigned"(mode -> titles),
    "enforced"(matching titles assigned in a blocking mode), "warned"(matching titles assigned with the
    Warn action only), "monitored"(matching titles assigned at all), "all_titles"}``.
    """
    admin_logs = data.get("admin_logs", [])
    inventory, source = caa_access_levels(data)
    evidence = _caa_app_assignment_evidence(admin_logs, [])
    evaluations = [e for e in _caa_enforcement_events(data.get("caa_events", [])) if e["applied"]]
    matching = sorted({lvl["title"] for lvl in inventory.values()
                       if not lvl["deleted"] and lvl["title"] and predicate(lvl["state"], inventory)})
    evaluated = sorted({t for e in evaluations for t in e["applied"] if t in matching})
    evaluated_apps = sorted({e["app"] for e in evaluations if e["app"] and set(e["applied"]) & set(matching)})
    assigned = _caa_assigned_level_titles(admin_logs)
    blocking_titles = set().union(*(assigned.get(mode, set()) for mode in _CAA_BLOCKING_MODES)) if assigned else set()
    warn_titles = assigned.get("WARN", set()) - blocking_titles
    all_assigned = set().union(*assigned.values()) if assigned else set()
    return {
        "inventory_source": source, "authoritative": source == "access_context_manager",
        "evidence": evidence, "evaluations": evaluations, "matching": matching, "evaluated": evaluated,
        "evaluated_apps": evaluated_apps, "assigned": assigned,
        "enforced": sorted(t for t in matching if t in blocking_titles),
        "warned": sorted(t for t in matching if t in warn_titles),
        "monitored": sorted(t for t in matching if t in all_assigned),
        "all_titles": sorted(lvl["title"] for lvl in inventory.values() if not lvl["deleted"]),
    }


@check(
    check_id="ADD-53",
    scored=False,  # Google supports it but cautions against it unless needed (lock-out risk); review, not score
    title="Ensure the Admin console is protected by a Context-Aware Access level",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > Context-Aware Access > Assign access levels. "
        "The Admin console is a separate row above the app list: Actions > Assign, choose a level (ideally "
        "device-based) in Active mode with the Block action. Google's note: only do this when you need to limit "
        "other admins' access, and keep a level you yourself satisfy, or you can be locked out. "
        "https://knowledge.workspace.google.com/admin/security/assign-context-aware-access-levels-to-apps"
    ),
    requires_license=EDITIONS_CAA,
)
def check_caa_admin_console(data: dict) -> CheckResult:
    """The Admin console is the highest-value target in the tenant. Google supports assigning access
    levels to it (help article "Assign Context-Aware Access levels to the Admin console") but adds the
    note "Do not assign access levels to the Admin console unless you specifically need to limit the
    access to the Admin console by other admins", so this is a review check, not a scored one.

    PASS needs an active-mode evaluation for the Admin console app in the CAA user log or a Block-mode
    assignment in the admin log. A Warn-only assignment warns admins without blocking them (MANUAL).
    FAIL when CAA is switched off, when the assignment was removed or left in monitor mode in the
    window, or when Access Context Manager shows that the organisation has no access level at all.
    Otherwise MANUAL naming the levels that exist.
    """
    _ID = "ADD-53"
    _TITLE = "Ensure the Admin console is protected by a Context-Aware Access level"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Security > Access and data control > Context-Aware Access > Assign access levels. "
        "The Admin console is a separate row above the app list: Actions > Assign, choose a level (ideally "
        "device-based) in Active mode with the Block action. Google's note: only do this when you need to limit "
        "other admins' access, and keep a level you yourself satisfy, or you can be locked out. "
        "https://knowledge.workspace.google.com/admin/security/assign-context-aware-access-levels-to-apps"
    )
    _EXPECTED = "An access level assigned to the Admin console in Active mode with the Block action"
    admin_logs = data.get("admin_logs", [])
    evidence = _caa_app_assignment_evidence(admin_logs, list(_CAA_ADMIN_CONSOLE_APPS))
    evaluations = [e for e in _caa_enforcement_events(data.get("caa_events", [])) if e["applied"]]
    console_evals = [e for e in evaluations if e["app"].upper() in _CAA_ADMIN_CONSOLE_APPS]
    inventory, source = caa_access_levels(data)
    titles = sorted(lvl["title"] for lvl in inventory.values() if not lvl["deleted"])

    if _caa_switched_off(evidence, evaluations):
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Context-Aware Access was turned off (latest admin-log change), so the Admin console is not protected by any access level.",
            actual_value={"caa_enabled": "DISABLED", "access_levels": titles}, expected_value=_EXPECTED, remediation=_REMED,
        )
    if console_evals:
        applied = sorted({t for e in console_evals for t in e["applied"]})
        denied = sum(e["denied"] for e in console_evals)
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access evaluated {len(console_evals)} Admin console access(es) ({denied} denied) "
                     f"in active mode, applying access level(s) {', '.join(applied)}."),
            actual_value={"evaluations": len(console_evals), "denials": denied, "access_levels": applied},
            expected_value=_EXPECTED,
        )
    if evidence["covered"] and not evidence["warn_only"]:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="An access level is assigned to the Admin console in Block mode (latest CHANGE_CAA_APP_ASSIGNMENTS in the admin log).",
            actual_value={"assigned_apps": evidence["covered"], "access_levels": titles}, expected_value=_EXPECTED,
        )
    if evidence["warn_only"]:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=("An access level is assigned to the Admin console with the Warn action only: admins who fail it are warned "
                     "but not blocked. Switch the action to Block if the level is meant to protect the console."),
            actual_value={"warn_only": evidence["warn_only"], "access_levels": titles}, expected_value=_EXPECTED, remediation=_REMED,
        )
    if evidence["monitor"] or evidence["removed"]:
        why = ("left in monitor mode only, which logs but never blocks" if evidence["monitor"]
               else "removed (latest CHANGE_CAA_APP_ASSIGNMENTS carries only the old assignment)")
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"The Admin console access-level assignment was {why}.",
            actual_value={"monitor_only": evidence["monitor"], "removed": evidence["removed"], "access_levels": titles},
            expected_value=_EXPECTED, remediation=_REMED,
        )
    if source == "access_context_manager" and not inventory:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Access Context Manager lists no access level for the organisation, so nothing can be assigned to the Admin console.",
            actual_value={"access_levels": [], "inventory_source": source}, expected_value=_EXPECTED, remediation=_REMED,
        )
    if evidence["unclear"]:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Admin console assignment logged under an unrecognised mode: {', '.join(evidence['unclear'])}. Verify in the console.",
            actual_value={"unclear": evidence["unclear"], "access_levels": titles}, expected_value=_EXPECTED, remediation=_REMED,
        )
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(("Access level(s) " + ", ".join(titles[:5]) + " exist " + ("(Access Context Manager)" if source == "access_context_manager" else "(admin log)")
                  if titles else "No access level is known from the admin-log window")
                 + ", but no Admin console assignment change and no Admin console evaluation appear in the log window. "
                 "Verify the Admin console row under Assign access levels; assignments older than the log window are not visible to the auditor."),
        actual_value={"access_levels": titles, "inventory_source": source, "evaluated_apps": sorted({e["app"] for e in evaluations if e["app"]})},
        expected_value=_EXPECTED, remediation=_REMED,
    )


@check(
    check_id="ADD-54",
    title="Ensure a device-based Context-Aware Access level is enforced",
    level="L2",
    source="GOOGLE",
    section="Security",
    severity="HIGH",
    remediation=(
        "Admin console > Security > Access and data control > Context-Aware Access > Access levels. Create a level with "
        "device conditions (screen lock, encryption, OS version, company-owned or admin-approved) and assign it to apps in "
        "Block mode; deploy Endpoint Verification so devices report their posture. "
        "https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
    ),
    requires_license=EDITIONS_CAA,
)
def check_caa_device_level(data: dict) -> CheckResult:
    """Geographic and IP conditions are defeated by any VPN; only device conditions make Context-Aware
    Access a real control. Access Context Manager exposes each level's devicePolicy, so the strict
    verdict (no device-based level exists) is provable; PASS still needs an assignment or evaluation.
    """
    _ID = "ADD-54"
    _TITLE = "Ensure a device-based Context-Aware Access level is enforced"
    _L, _S, _SEC = "L2", "GOOGLE", "Security"
    _REMED = (
        "Admin console > Security > Access and data control > Context-Aware Access > Access levels. Create a level with "
        "device conditions (screen lock, encryption, OS version, company-owned or admin-approved) and assign it to apps in "
        "Block mode; deploy Endpoint Verification so devices report their posture. "
        "https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
    )
    _EXPECTED = "An access level with device conditions assigned to apps in active mode"
    ev = _caa_level_enforcement(data, _access_level_requires_device)
    evaluations = ev["evaluations"]
    with_signals = sum(1 for e in evaluations if e["device_state"].strip().upper() not in _CAA_NO_SIGNAL_STATES)
    signals = {"evaluations": len(evaluations), "with_device_signals": with_signals}
    base = {"device_access_levels": ev["matching"], "inventory_source": ev["inventory_source"], "device_signals": signals}

    if _caa_switched_off(ev["evidence"], evaluations):
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Context-Aware Access was turned off (latest admin-log change), so no device-based access level is enforced.",
            actual_value={"caa_enabled": "DISABLED", **base}, expected_value=_EXPECTED, remediation=_REMED,
        )
    signal_note = (f" {with_signals} of {len(evaluations)} evaluation(s) carried device signals"
                   + ("; deploy Endpoint Verification or device management so the level can be satisfied." if evaluations and not with_signals else ".")
                   if evaluations else "")
    if ev["evaluated"]:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Device-based access level(s) enforced per the Context-Aware Access log: {', '.join(ev['evaluated'])} applied on "
                     f"{', '.join(ev['evaluated_apps'][:8])}." + signal_note),
            actual_value={**base, "evaluated_apps": ev["evaluated_apps"]}, expected_value=_EXPECTED,
        )
    if ev["enforced"]:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Device-based access level(s) ({ev['inventory_source'].replace('_', ' ')}) assigned to apps in active mode per the "
                     f"admin log: {', '.join(ev['enforced'])}." + signal_note),
            actual_value={**base, "assigned_modes": sorted(ev["assigned"])}, expected_value=_EXPECTED,
        )
    if ev["matching"]:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Device-based access level(s) exist ({', '.join(ev['matching'])}) "
                     + ("but are assigned with the Warn action only, which warns users and still allows access" if ev["warned"] else
                        "but are assigned in monitor mode only" if ev["monitored"] else
                        "but no Block-mode assignment to an app appears in the log window")
                     + ". Verify the assignment in Admin console > Security > Access and data control > Context-Aware Access."),
            actual_value={**base, "assigned_modes": sorted(ev["assigned"])}, expected_value=_EXPECTED, remediation=_REMED,
        )
    if ev["authoritative"]:
        titles = ev["all_titles"]
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=("Access Context Manager lists " + (f"{len(titles)} access level(s) ({', '.join(titles[:5])}), none of which "
                     "requires device posture" if titles else "no access level for the organisation")
                     + ", so access does not depend on the device's security state." + signal_note),
            actual_value={**base, "access_levels": titles}, expected_value=_EXPECTED, remediation=_REMED,
        )
    if evaluations:
        levels = sorted({t for e in evaluations for t in e["applied"]})
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access is enforcing access level(s) {', '.join(levels[:5])} (CAA log), but their conditions are not "
                     "in the admin-log window, so whether any requires device posture is unknown. Check the level in Admin console > "
                     "Security > Context-Aware Access > Access levels." + signal_note),
            actual_value={**base, "enforced_access_levels": levels}, expected_value=_EXPECTED, remediation=_REMED,
        )
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=("Access levels are not readable (Access Context Manager not collected) and no access-level event or evaluation "
                 "appears in the log window. Verify in Admin console > Security > Context-Aware Access > Access levels."),
        actual_value=base, expected_value=_EXPECTED, remediation=_REMED,
    )


@check(
    check_id="ADD-55",
    scored=False,  # hygiene review: assignments older than the admin-log window are invisible
    title="Review Context-Aware Access levels that are not assigned to any app",
    level="L2",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > Context-Aware Access. Assign each listed level to the apps it "
        "is meant to protect (Assign access levels), or delete it. A level with no condition is always satisfied and protects nothing."
    ),
    requires_license=EDITIONS_CAA,
)
def check_caa_unassigned_levels(data: dict) -> CheckResult:
    """Dangling access levels: defined (Access Context Manager or admin log) but never seen assigned
    (CHANGE_CAA_APP_ASSIGNMENTS) or applied (CAA log) in the window. Levels with no condition at all
    are flagged in the same list. Unscored because an assignment made before the window is invisible.
    """
    _ID = "ADD-55"
    _TITLE = "Review Context-Aware Access levels that are not assigned to any app"
    _L, _S, _SEC = "L2", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > Access and data control > Context-Aware Access. Assign each listed level to the apps it "
        "is meant to protect (Assign access levels), or delete it. A level with no condition is always satisfied and protects nothing."
    )
    admin_logs = data.get("admin_logs", [])
    inventory, source = caa_access_levels(data)
    live = {name: lvl for name, lvl in inventory.items() if not lvl["deleted"]}
    source_text = "Access Context Manager" if source == "access_context_manager" else "the admin-log window"
    if not live:
        return make_not_applicable(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"No access level is known from {source_text}; nothing to review"
                    + (" (see GWS.COMMONCONTROLS.2.1 for the missing configuration)." if source == "access_context_manager" else
                       " (levels created before the window are not visible)."),
            actual_value={"access_levels": [], "inventory_source": source},
        )
    assigned = _caa_assigned_level_titles(admin_logs)
    seen = set().union(*assigned.values()) if assigned else set()
    seen |= {t for e in _caa_enforcement_events(data.get("caa_events", [])) for t in e["applied"]}
    unseen = sorted(lvl["title"] or name for name, lvl in live.items() if lvl["title"] not in seen)
    empty = sorted(lvl["title"] or name for name, lvl in live.items() if _access_level_has_no_condition(lvl["state"]))
    actual = {"access_levels": sorted(l["title"] for l in live.values()), "unassigned": unseen, "without_condition": empty,
              "inventory_source": source}
    if not unseen and not empty:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(live)} access level(s) from {source_text} were assigned to an app or applied in the log window.",
            actual_value=actual, expected_value="Every access level assigned to at least one app",
        )
    parts = []
    if unseen:
        parts.append(f"{len(unseen)} of {len(live)} access level(s) from {source_text} never appear in an assignment or evaluation "
                     f"in the log window: {', '.join(unseen[:10])}")
    if empty:
        parts.append(f"level(s) with no condition (always satisfied): {', '.join(empty[:10])}")
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="; ".join(parts) + ". Confirm each is assigned under Assign access levels or remove it.",
        actual_value=actual, expected_value="Every access level assigned to at least one app", remediation=_REMED,
    )


@check(
    check_id="ADD-56",
    scored=False,  # review of enforcement outcomes, not a configuration verdict
    title="Review Context-Aware Access denials",
    level="L2",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > Investigation tool (or Reporting > Audit and investigation), data source 'Context Aware Access log events'; the Assign access levels page also offers Actions > View logs per app. Confirm each denial is "
        "legitimate (user, app, region, unsatisfied level); tune the level rather than removing it when real users are blocked."
    ),
    requires_license=EDITIONS_CAA,
)
def check_caa_denials(data: dict) -> CheckResult:
    """ACCESS_DENY_EVENT entries of the Context-Aware Access log, summarised per app, actor, region and
    unsatisfied level. No evaluation at all in the window means there is nothing to review.
    """
    _ID = "ADD-56"
    _TITLE = "Review Context-Aware Access denials"
    _L, _S, _SEC = "L2", "OTHER", "Security"
    _REMED = (
        "Admin console > Security > Investigation tool (or Reporting > Audit and investigation), data source 'Context Aware Access log events'; the Assign access levels page also offers Actions > View logs per app. Confirm each denial is "
        "legitimate (user, app, region, unsatisfied level); tune the level rather than removing it when real users are blocked."
    )
    events = _caa_enforcement_events(data.get("caa_events", []))
    denials = [e for e in events if e["denied"]]
    if not events:
        return make_not_applicable(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No Context-Aware Access evaluation in the log window; nothing to review (see GWS.COMMONCONTROLS.2.1 for enablement).",
            actual_value={"evaluations": 0, "denials": 0},
        )
    if not denials:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"No denial among {len(events)} Context-Aware Access evaluation(s) in the log window.",
            actual_value={"evaluations": len(events), "denials": 0}, expected_value="Denials reviewed",
        )

    def _count(key):
        counts: dict[str, int] = {}
        for e in denials:
            for value in (e[key] if isinstance(e[key], list) else [e[key]]):
                value = value or "(unknown)"
                counts[value] = counts.get(value, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    by_app, by_actor, by_region, by_level = _count("app"), _count("actor"), _count("region"), _count("unsatisfied")
    admins = {str(u.get("primary_email", "")).lower() for u in data.get("users", []) if isinstance(u, dict) and u.get("is_super_admin")}
    admin_denied = sorted(a for a in by_actor if a.lower() in admins)
    summary = (f"{len(denials)} of {len(events)} Context-Aware Access evaluation(s) were denied: "
               f"{len(by_actor)} user(s), apps {', '.join(f'{a} ({n})' for a, n in list(by_app.items())[:5])}; "
               f"regions {', '.join(f'{r} ({n})' for r, n in list(by_region.items())[:5])}; "
               f"unsatisfied level(s) {', '.join(f'{l} ({n})' for l, n in list(by_level.items())[:5])}.")
    if admin_denied:
        summary += f" Super admin(s) denied: {', '.join(admin_denied[:5])}."
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=summary + " Confirm the denials are expected.",
        actual_value={"evaluations": len(events), "denials": len(denials), "by_app": by_app, "by_actor": by_actor,
                      "by_region": by_region, "by_unsatisfied_level": by_level, "super_admins_denied": admin_denied},
        expected_value="Denials reviewed", remediation=_REMED,
    )


@check(
    check_id="ADD-21",
    scored=False,  # P3: Vault multi-party approval is not exposed by the Policy API; MANUAL by design
    title="Ensure Multi-Party Approval covers Vault exports",
    level="L2",
    source="GOOGLE",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Multi-party approval settings. "
        "Add Vault exports to the MPA-covered actions to prevent "
        "unauthorized export of eDiscovery data. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
    ),
    requires_license=EDITIONS_MPA,
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
        return make_review(
            check_id="ADD-21",
            title="Ensure Multi-Party Approval covers Vault exports",
            level="L2", source="GOOGLE", section="Security",
            details="Multi-Party Approval is not configured for Vault exports.",
            actual_value=None,
            expected_value="Enabled for all OUs",
            remediation=(
                "Admin console > Security > Authentication > Multi-party approval settings. "
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
            "Admin console > Security > Authentication > Multi-party approval settings. "
            "Add Vault exports to the MPA-covered actions to prevent "
            "unauthorized export of eDiscovery data. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
        ),
    )


@check(
    check_id="ADD-22",
    scored=False,  # P3: Gmail classification labels are not exposed by any API; MANUAL by design
    title="Ensure data classification labels are enabled for Gmail",
    level="L1",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Security > Access and data control > Data protection > Data classification. "
        "Enable classification labels for Gmail to categorize emails by "
        "sensitivity and apply DLP rules accordingly. https://knowledge.workspace.google.com/admin/security/create-classification-labels-for-your-organization"
    ),
    requires_license=EDITIONS_GMAIL_LABELS,
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
                "Admin console > Security > Access and data control > Data protection > Data classification. "
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
            "Admin console > Security > Access and data control > Data protection > Data classification. "
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
        "Admin console > Security > Access and data control > Data protection > Manage rules. "
        "Create DLP rules for Calendar to detect sensitive information "
        "in event titles, descriptions, and attachments. https://knowledge.workspace.google.com/admin/security/about-dlp-for-calendar"
    ),
    requires_license=EDITIONS_DLP_CALENDAR,
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
        return make_review(
            check_id="ADD-23",
            title="Ensure DLP rules are configured for Calendar",
            level="L2", source="GOOGLE", section="Calendar",
            details="No DLP rules are configured for Calendar.",
            actual_value=None,
            expected_value="DLP rules configured for Calendar",
            remediation=(
                "Admin console > Security > Access and data control > Data protection > Manage rules. "
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
            "Admin console > Security > Access and data control > Data protection > Manage rules. "
            "Create DLP rules for Calendar to protect sensitive information "
            "shared in meeting details. https://knowledge.workspace.google.com/admin/security/about-dlp-for-calendar"
        ),
    )


@check(
    check_id="ADD-24",
    requires_license=EDITIONS_AI_CLASSIFICATION,
    scored=False,  # P3: Drive AI classification is not exposed by any API; MANUAL by design
    title="Ensure AI-powered data classification is enabled for Drive",
    level="L2",
    source="GOOGLE",
    section="Drive and Docs",
    remediation=(
        "Admin console > Security > Access and data control > Data protection > Data classification. "
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
                "Admin console > Security > Access and data control > Data protection > Data classification. "
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
            "Admin console > Security > Access and data control > Data protection > Data classification. "
            "Enable AI-powered classification for Drive to automatically "
            "detect and label sensitive files. https://knowledge.workspace.google.com/admin/security/label-google-drive-files-automatically-using-ai-classification"
        ),
    )


@check(
    check_id="ADD-25",
    requires_license=EDITIONS_TRUST_RULES,
    title="Ensure Drive trust rules are configured",
    level="L2",
    source="GOOGLE",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Sharing settings > View trust rules (or Admin console > Rules > "
        "Trust rules). Create trust rules to enable context-based sharing "
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
                "Admin console > Apps > Google Workspace > Sharing settings > View trust rules (or Admin console > Rules > "
                "Trust rules). Configure trust rules to control sharing based "
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
            "Admin console > Apps > Google Workspace > Sharing settings > View trust rules (or Admin console > Rules > "
            "Trust rules). Create trust rules to enable context-based sharing "
            "policies integrated with DLP. https://knowledge.workspace.google.com/admin/security/create-and-manage-trust-rules-for-drive-sharing"
        ),
    )


@check(
    check_id="ADD-26",
    requires_license=EDITIONS_CSE,
    scored=False,  # P3: Gmail CSE is not exposed by the Policy API; MANUAL by design
    title="Ensure CSE is enabled for Gmail",
    level="L2",
    source="GOOGLE",
    section="Gmail",
    remediation=(
        "Admin console > Data > Compliance > "
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
                "Admin console > Data > Compliance > "
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
            "Admin console > Data > Compliance > "
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
    requires_license=EDITIONS_MEET_RECORDING,
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet video settings > Recording. Enable compliance recording for "
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
        "Meet video settings > Recording. Enable compliance recording for "
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
                "Meet video settings > Recording. Enable compliance recording for "
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
            "Meet video settings > Recording. Enable compliance recording to "
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
        "Admin console > Devices > Mobile & endpoints > Devices. Review stale devices "
        "and wipe or remove those that have not synced recently. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
    ),
    scored=False,
)
def check_mobile_devices_stale(data: dict) -> CheckResult:
    """Report mobile devices not synced within the configured window."""
    _ID = "ADD-30"
    _TITLE = "Ensure mobile devices are syncing recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Mobile & endpoints > Devices. Review stale devices "
        "and wipe or remove those that have not synced recently. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
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
        "Admin console > Devices > Chrome > Devices. Review stale ChromeOS "
        "devices and deprovision or disable those no longer in use. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
    ),
    scored=False,
)
def check_chromeos_devices_stale(data: dict) -> CheckResult:
    """Report ChromeOS devices not synced within the configured window."""
    _ID = "ADD-31"
    _TITLE = "Ensure ChromeOS devices are active recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Chrome > Devices. Review stale ChromeOS "
        "devices and deprovision or disable those no longer in use. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
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
        "Admin console > Devices > Mobile & endpoints > Devices (filter: Endpoint Verification). Review stale "
        "endpoint devices (Windows/Mac/Linux) and remove those that have "
        "not synced recently. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
    ),
    scored=False,
)
def check_endpoint_devices_stale(data: dict) -> CheckResult:
    """Report endpoint verification devices not synced within the configured window."""
    _ID = "ADD-38"
    _TITLE = "Ensure endpoint verification devices are syncing recently"
    _L, _S, _SEC = "L1", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Mobile & endpoints > Devices (filter: Endpoint Verification). Review stale "
        "endpoint devices (Windows/Mac/Linux) and remove those that have "
        "not synced recently. https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
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
        "Admin console > Devices > Mobile & endpoints > Device approvals. Review devices stuck in 'Pending' state "
        "and either approve or block them. Unreviewed pending devices "
        "represent unmanaged access to corporate data. "
        "https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
    ),
    scored=False,
)
def check_devices_pending(data: dict) -> CheckResult:
    """Report devices stuck in PENDING approval state for too long."""
    _ID = "ADD-39"
    _TITLE = "Ensure pending devices are approved promptly"
    _L, _S, _SEC = "L2", "OTHER", "Devices"
    _REMED = (
        "Admin console > Devices > Mobile & endpoints > Device approvals. Review devices stuck in 'Pending' state "
        "and either approve or block them. Unreviewed pending devices "
        "represent unmanaged access to corporate data. "
        "https://knowledge.workspace.google.com/admin/devices/overview-manage-devices-with-google-endpoint-management"
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
        "Admin console > Security > Authentication > 2-step verification. "
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
        "Admin console > Security > Authentication > 2-step verification. "
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
    # Longest pattern first so "drive.admin" / "drive.file" are not shadowed by "drive"
    for pattern in sorted(OAUTH_SCOPE_RISK_LEVELS, key=len, reverse=True):
        if pattern in scope:
            return OAUTH_SCOPE_RISK_LEVELS[pattern]
    return None


_RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


@check(
    check_id="ADD-33",
    title="Ensure no OAuth apps have dangerous privilege grants",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Directory > Users > (user) > Security > App passwords. "
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
        "Admin console > Directory > Users > (user) > Security > App passwords. "
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

    if not shared_drives and any(
        e.get("operation") == "get_shared_drives" for e in data.get("api_errors", []) if isinstance(e, dict)
    ):
        # An empty list after a failed enumeration is "unknown", not "no Shared Drives"
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shared Drives could not be enumerated (API error) — restrictions were not evaluated.",
            remediation=_REMED,
        )

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
        "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Security > Access and data control > API controls > App access control. "
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


@check(
    check_id="ADD-41",
    title="Ensure admin roles are not assigned to groups anyone can join",
    level="L1",
    source="OTHER",
    section="Security",
    severity="HIGH",
    remediation=(
        "Admin console > Account > Admin roles. Review roles assigned to groups: every member of the "
        "group inherits the admin role. Restrict who can join and who can add members for those groups "
        "(Groups settings), or assign the role to individual users instead. "
        "https://knowledge.workspace.google.com/admin/users/assign-specific-admin-roles"
    ),
)
def check_admin_roles_assigned_to_groups(data: dict) -> CheckResult:
    """An admin role assigned to a group is inherited by whoever can get into that group."""
    _ID = "ADD-41"
    _TITLE = "Ensure admin roles are not assigned to groups anyone can join"
    _L, _S, _SEC = "L1", "OTHER", "Security"
    _REMED = (
        "Admin console > Account > Admin roles. Review roles assigned to groups and restrict who can "
        "join or add members to those groups, or assign the role to individual users instead."
    )

    roles_data = data.get("roles")
    if not isinstance(roles_data, dict) or "assignments" not in roles_data:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Admin role assignments were not collected.", remediation=_REMED,
        )
    if any(e.get("operation") in ("list_roles", "list_role_assignments")
           for e in data.get("api_errors", []) if isinstance(e, dict)):
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Admin roles could not be fully enumerated (API error).", remediation=_REMED,
        )

    role_names = {str(r.get("roleId")): r.get("roleName", str(r.get("roleId")))
                  for r in roles_data.get("roles", [])}
    groups_by_id = {str(g.get("id")): g for g in data.get("groups", []) if g.get("id")}
    group_assignments = [a for a in roles_data["assignments"]
                         if str(a.get("assigneeType", "")).lower() == "group"]
    if not group_assignments:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No admin role is assigned to a group.",
            actual_value={"group_role_assignments": 0}, expected_value="No open group holds an admin role",
        )

    open_join = ("ANYONE_CAN_JOIN", "ALL_IN_DOMAIN_CAN_JOIN")
    risky, reviewed = [], []
    for a in group_assignments:
        group = groups_by_id.get(str(a.get("assignedTo")), {})
        settings = group.get("settings") or {}
        label = f"{group.get('email', a.get('assignedTo'))} ({role_names.get(str(a.get('roleId')), a.get('roleId'))})"
        if settings.get("whoCanJoin") in open_join or str(settings.get("allowExternalMembers")).lower() == "true":
            risky.append(label)
        else:
            reviewed.append(label)
    if risky:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"{len(risky)} admin role(s) are assigned to groups that users can join themselves or that "
                    f"allow external members: {', '.join(sorted(risky))}",
            actual_value={"open_groups_with_admin_role": sorted(risky)},
            expected_value="No open group holds an admin role", remediation=_REMED,
        )
    return make_warn(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"{len(reviewed)} admin role(s) are assigned to groups (membership is restricted). Anyone who "
                f"can add members to these groups can grant the role: {', '.join(sorted(reviewed))}",
        actual_value={"group_role_assignments": sorted(reviewed)},
        expected_value="No open group holds an admin role", remediation=_REMED,
    )
