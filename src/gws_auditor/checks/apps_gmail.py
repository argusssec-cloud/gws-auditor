# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.3: Gmail checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Gmail controls.
"""

from .base import (
    check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
    result_from_setting_changes, field_value, ou_verdict,
)
from ..models import CheckResult, Status


# ---------------------------------------------------------------------------
# 3.1.3.1 - User settings
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.1.1",
    title="Ensure mail delegation is disabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "User settings. Disable 'Mail delegation'. https://knowledge.workspace.google.com/admin/gmail/let-users-delegate-access-to-a-gmail-account"
    ),
)
def check_gmail_mail_delegation(data: dict) -> CheckResult:
    """Mail delegation should be disabled to prevent unauthorized access."""
    _ID = "CIS-3.1.3.1.1"
    _TITLE = "Ensure mail delegation is disabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > "
        "User settings. Disable 'Mail delegation'. https://knowledge.workspace.google.com/admin/gmail/let-users-delegate-access-to-a-gmail-account"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "mail_delegation")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableMailDelegation")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have mail delegation enabled",
            pass_text="have mail delegation disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    user_settings = gmail.get("user_settings", {})
    delegation_enabled = user_settings.get("mail_delegation_enabled", None)

    if delegation_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Mail delegation is disabled.",
            actual_value=delegation_enabled,
            expected_value="Disabled for all OUs",
        )

    if delegation_enabled is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine mail delegation setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Mail delegation is enabled, allowing users to grant mailbox access to others.",
        actual_value=delegation_enabled,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.1.2",
    title="Ensure offline Gmail is disabled",
    level="L2",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable offline Gmail. https://knowledge.workspace.google.com/admin/gmail/use-gmail-offline-with-google-workspace"
    ),
    requires_license="enterprise_plus",
)
def check_gmail_offline(data: dict) -> CheckResult:
    """Offline Gmail should be disabled to prevent cached data exposure."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path: real type gmail.web_offline.enabled
    ou_values = get_ou_values(gmail, "web_offline")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "enabled", "offlineAccessEnabled")
            return None if enabled is None else (enabled is False, enabled)
        return ou_verdict(
            ou_values, _judge, check_id="CIS-3.1.3.1.2", title="Ensure offline Gmail is disabled",
            level="L2", source="CIS", section="Gmail",
            fail_text="have offline Gmail enabled", pass_text="have offline Gmail disabled",
            expected_value="Disabled for all OUs",
            remediation=("Admin console > Apps > Google Workspace > Gmail > User settings. "
                         "Disable 'Enable offline Gmail'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"),
        )

    user_settings = gmail.get("user_settings", {})
    offline_enabled = user_settings.get("offline_access_enabled", None)

    if offline_enabled is False:
        return make_pass(
            check_id="CIS-3.1.3.1.2",
            title="Ensure offline Gmail is disabled",
            level="L2", source="CIS", section="Gmail",
            details="Offline Gmail is disabled.",
            actual_value=offline_enabled,
            expected_value="Disabled for all OUs",
        )

    if offline_enabled is None:
        return make_review(
            check_id="CIS-3.1.3.1.2",
            title="Ensure offline Gmail is disabled",
            level="L2", source="CIS", section="Gmail",
            details=(
                "Could not determine offline Gmail setting. "
                "The Policy API does not expose this setting. Verify manually in "
                "Admin console > Apps > Google Workspace > Gmail > User settings."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > "
                "End User Access. Disable offline Gmail. https://knowledge.workspace.google.com/admin/gmail/use-gmail-offline-with-google-workspace"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.3.1.2",
        title="Ensure offline Gmail is disabled",
        level="L2", source="CIS", section="Gmail",
        details="Offline Gmail is enabled, risking cached email data exposure.",
        actual_value=offline_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > "
            "End User Access. Disable offline Gmail. https://knowledge.workspace.google.com/admin/gmail/use-gmail-offline-with-google-workspace"
        ),
    )


# ---------------------------------------------------------------------------
# 3.1.3.2 - Email authentication (DKIM, SPF, DMARC)
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.2.1",
    title="Ensure DKIM is enabled for all domains",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "Authenticate email. Generate DKIM key and publish the DNS "
        "record for each domain. https://knowledge.workspace.google.com/admin/security/set-up-dkim"
    ),
)
def check_gmail_dkim(data: dict) -> CheckResult:
    """DKIM should be configured and enabled for every domain."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="CIS-3.1.3.2.1",
            title="Ensure DKIM is enabled for all domains",
            level="L1", source="CIS", section="Gmail",
            details="No domains found to check DKIM configuration.",
            remediation="Verify domain list is available and check DKIM settings manually. https://knowledge.workspace.google.com/admin/security/set-up-dkim",
        )

    missing_dkim = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dkim = domain_dns.get("dkim", {})
        if not dkim.get("enabled", False) and not dkim.get("record_found", False):
            missing_dkim.append(domain_name)

    if not missing_dkim:
        return make_pass(
            check_id="CIS-3.1.3.2.1",
            title="Ensure DKIM is enabled for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"DKIM is configured for all {len(domains)} domain(s).",
            actual_value={"domains_checked": len(domains), "all_configured": True},
            expected_value="DKIM enabled for all domains",
        )

    return make_fail(
        check_id="CIS-3.1.3.2.1",
        title="Ensure DKIM is enabled for all domains",
        level="L1", source="CIS", section="Gmail",
        details=f"DKIM is missing or not enabled for: {', '.join(missing_dkim)}",
        actual_value={"missing_dkim_domains": missing_dkim},
        expected_value="DKIM enabled for all domains",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > "
            "Authenticate email. Generate DKIM key and publish the DNS "
            "record for each domain. https://knowledge.workspace.google.com/admin/security/set-up-dkim"
        ),
    )


@check(
    check_id="CIS-3.1.3.2.2",
    title="Ensure SPF records are configured for all domains",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Add a TXT record with 'v=spf1 include:_spf.google.com ~all' "
        "for each domain in your DNS provider. Use '-all' for a stricter policy. https://knowledge.workspace.google.com/admin/security/set-up-spf"
    ),
)
def check_gmail_spf(data: dict) -> CheckResult:
    """SPF TXT records should be configured for every domain."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="CIS-3.1.3.2.2",
            title="Ensure SPF records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details="No domains found to check SPF configuration.",
            remediation="Verify domain list is available and check SPF records manually. https://knowledge.workspace.google.com/admin/security/set-up-spf",
        )

    missing_spf = []
    permissive_spf = []
    neutral_spf = []
    duplicate_spf = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        spf = domain_dns.get("spf", {})
        if not spf.get("record_found", False):
            missing_spf.append(domain_name)
            continue
        # A record that ends in "+all"/"all" authorises every sender, i.e. no protection;
        # "?all" (neutral) gives receivers no guidance.
        if int(spf.get("record_count") or 1) > 1:
            duplicate_spf.append(domain_name)  # RFC 7208: multiple SPF records = permerror
        terms = str(spf.get("record", "")).lower().split()
        all_term = next((t for t in reversed(terms) if t.lstrip("+-~?") == "all"), "")
        if all_term in ("+all", "all"):
            permissive_spf.append(domain_name)
        elif all_term == "?all":
            neutral_spf.append(domain_name)

    if permissive_spf:
        return make_fail(
            check_id="CIS-3.1.3.2.2",
            title="Ensure SPF records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"SPF record authorises all senders (+all) for: {', '.join(permissive_spf)}",
            actual_value={"permissive_spf_domains": permissive_spf, "missing_spf_domains": missing_spf},
            expected_value="SPF ending in -all or ~all",
            remediation="Replace '+all' with '~all' or '-all' in the SPF TXT record. https://knowledge.workspace.google.com/admin/security/set-up-spf",
        )

    if duplicate_spf:
        return make_fail(
            check_id="CIS-3.1.3.2.2",
            title="Ensure SPF records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"More than one SPF record is published (receivers treat this as a permanent error) for: {', '.join(duplicate_spf)}",
            actual_value={"duplicate_spf_domains": duplicate_spf},
            expected_value="Exactly one SPF record per domain",
            remediation="Merge the SPF TXT records into a single 'v=spf1 ...' record. https://knowledge.workspace.google.com/admin/security/set-up-spf",
        )

    if not missing_spf and neutral_spf:
        return make_warn(
            check_id="CIS-3.1.3.2.2",
            title="Ensure SPF records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"SPF record uses the neutral '?all' qualifier for: {', '.join(neutral_spf)}",
            actual_value={"neutral_spf_domains": neutral_spf},
            expected_value="SPF ending in -all or ~all",
            remediation="Replace '?all' with '~all' or '-all' in the SPF TXT record. https://knowledge.workspace.google.com/admin/security/set-up-spf",
        )

    if not missing_spf:
        return make_pass(
            check_id="CIS-3.1.3.2.2",
            title="Ensure SPF records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"SPF records are configured for all {len(domains)} domain(s).",
            actual_value={"domains_checked": len(domains), "all_configured": True},
            expected_value="SPF configured for all domains",
        )

    return make_fail(
        check_id="CIS-3.1.3.2.2",
        title="Ensure SPF records are configured for all domains",
        level="L1", source="CIS", section="Gmail",
        details=f"SPF records are missing for: {', '.join(missing_spf)}",
        actual_value={"missing_spf_domains": missing_spf},
        expected_value="SPF configured for all domains",
        remediation=(
            "Add a TXT record with 'v=spf1 include:_spf.google.com ~all' "
            "for each domain in your DNS provider. Use '-all' for a stricter policy. https://knowledge.workspace.google.com/admin/security/set-up-spf"
        ),
    )


@check(
    check_id="CIS-3.1.3.2.3",
    title="Ensure DMARC records are configured for all domains",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Add a TXT record at _dmarc.<domain> with at minimum "
        "'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'. "
        "Progress towards p=reject over time. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
    ),
)
def check_gmail_dmarc(data: dict) -> CheckResult:
    """DMARC TXT records should be configured for every domain."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="CIS-3.1.3.2.3",
            title="Ensure DMARC records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details="No domains found to check DMARC configuration.",
            remediation="Verify domain list is available and check DMARC records manually. https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
        )

    missing_dmarc = []
    weak_dmarc = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dmarc = domain_dns.get("dmarc", {})
        if not dmarc.get("record_found", False):
            missing_dmarc.append(domain_name)
        elif dmarc.get("policy", "") == "none":
            weak_dmarc.append(domain_name)

    issues = []
    if missing_dmarc:
        issues.append(f"Missing DMARC: {', '.join(missing_dmarc)}")
    if weak_dmarc:
        issues.append(f"Weak DMARC policy (p=none): {', '.join(weak_dmarc)}")

    if not issues:
        return make_pass(
            check_id="CIS-3.1.3.2.3",
            title="Ensure DMARC records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details=f"DMARC records are configured for all {len(domains)} domain(s).",
            actual_value={"domains_checked": len(domains), "all_configured": True},
            expected_value="DMARC configured for all domains",
        )

    if missing_dmarc:
        return make_fail(
            check_id="CIS-3.1.3.2.3",
            title="Ensure DMARC records are configured for all domains",
            level="L1", source="CIS", section="Gmail",
            details="; ".join(issues),
            actual_value={
                "missing_dmarc_domains": missing_dmarc,
                "weak_dmarc_domains": weak_dmarc,
            },
            expected_value="DMARC configured for all domains with reject or quarantine policy",
            remediation=(
                "Add a TXT record at _dmarc.<domain> with at minimum "
                "'v=DMARC1; p=quarantine; rua=mailto:dmarc@<domain>'. "
                "Progress towards p=reject over time. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
            ),
        )

    # Only weak DMARC
    return make_warn(
        check_id="CIS-3.1.3.2.3",
        title="Ensure DMARC records are configured for all domains",
        level="L1", source="CIS", section="Gmail",
        details="; ".join(issues),
        actual_value={"weak_dmarc_domains": weak_dmarc},
        expected_value="DMARC with quarantine or reject policy",
        remediation=(
            "Update DMARC policy from p=none to p=quarantine or p=reject "
            "after monitoring DMARC reports. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
        ),
    )


# ---------------------------------------------------------------------------
# 3.1.3.3 - Quarantine
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.3.1",
    title="Ensure quarantine admin notifications are enabled",
    level="L2",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "Manage quarantines. Enable admin notification for quarantine events. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
    requires_license="enterprise_plus",
)
def check_gmail_quarantine_notifications(data: dict) -> CheckResult:
    """Admins should be notified when messages are quarantined."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    quarantine = gmail.get("quarantine", {})
    notify_enabled = quarantine.get("admin_notifications_enabled", None)

    if notify_enabled is True:
        return make_pass(
            check_id="CIS-3.1.3.3.1",
            title="Ensure quarantine admin notifications are enabled",
            level="L2", source="CIS", section="Gmail",
            details="Quarantine admin notifications are enabled.",
            actual_value=notify_enabled,
            expected_value="Enabled for all OUs",
        )

    if notify_enabled is None:
        return make_review(
            check_id="CIS-3.1.3.3.1",
            title="Ensure quarantine admin notifications are enabled",
            level="L2", source="CIS", section="Gmail",
            details=(
                "Could not determine quarantine notification setting. "
                "Google does not expose this setting through any public API. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Gmail > Manage quarantines."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > "
                "Manage quarantines. Enable admin notification for quarantine events. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.3.3.1",
        title="Ensure quarantine admin notifications are enabled",
        level="L2", source="CIS", section="Gmail",
        details="Quarantine admin notifications are not enabled.",
        actual_value=notify_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > "
            "Manage quarantines. Enable admin notification for quarantine events. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


# ---------------------------------------------------------------------------
# 3.1.3.4.1 - Attachment protection
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.4.1.1",
    title="Ensure encrypted attachment protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against encrypted attachments from untrusted senders'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_encrypted_attachment(data: dict) -> CheckResult:
    """Protection against encrypted attachments from untrusted senders should be enabled."""
    _ID = "CIS-3.1.3.4.1.1"
    _TITLE = "Ensure encrypted attachment protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against encrypted attachments from untrusted senders'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "email_attachment_safety")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableEncryptedAttachmentProtection")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack encrypted attachment protection",
            pass_text="have encrypted attachment protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("attachments", {})
    encrypted_protection = safety.get("encrypted_attachment_protection", None)

    if encrypted_protection is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Encrypted attachment protection is enabled.",
            actual_value=encrypted_protection,
            expected_value="Enabled for all OUs",
        )

    if encrypted_protection is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine encrypted attachment protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Encrypted attachment protection is not enabled.",
        actual_value=encrypted_protection,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.1.2",
    title="Ensure script attachment protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against attachments with scripts from untrusted senders'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_script_attachment(data: dict) -> CheckResult:
    """Protection against attachments with scripts from untrusted senders should be enabled."""
    _ID = "CIS-3.1.3.4.1.2"
    _TITLE = "Ensure script attachment protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against attachments with scripts from untrusted senders'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "email_attachment_safety")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableAttachmentWithScriptsProtection")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack script attachment protection",
            pass_text="have script attachment protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("attachments", {})
    script_protection = safety.get("script_attachment_protection", None)

    if script_protection is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Script attachment protection is enabled.",
            actual_value=script_protection,
            expected_value="Enabled for all OUs",
        )

    if script_protection is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine script attachment protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Script attachment protection is not enabled.",
        actual_value=script_protection,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.1.3",
    title="Ensure anomalous attachment protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against anomalous attachment types in emails'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_anomalous_attachment(data: dict) -> CheckResult:
    """Protection against anomalous attachment types in emails should be enabled."""
    _ID = "CIS-3.1.3.4.1.3"
    _TITLE = "Ensure anomalous attachment protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Attachments. Enable 'Protect against anomalous attachment types in emails'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "email_attachment_safety")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableAnomalousAttachmentProtection")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack anomalous attachment protection",
            pass_text="have anomalous attachment protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("attachments", {})
    anomalous_protection = safety.get("anomalous_attachment_protection", None)

    if anomalous_protection is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Anomalous attachment protection is enabled.",
            actual_value=anomalous_protection,
            expected_value="Enabled for all OUs",
        )

    if anomalous_protection is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine anomalous attachment protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Anomalous attachment protection is not enabled.",
        actual_value=anomalous_protection,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


# ---------------------------------------------------------------------------
# 3.1.3.4.2 - Links and external images
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.4.2.1",
    title="Ensure shortened URL identification is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Identify links behind shortened URLs'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_shortened_urls(data: dict) -> CheckResult:
    """Identification and scanning of shortened URLs should be enabled."""
    _ID = "CIS-3.1.3.4.2.1"
    _TITLE = "Ensure shortened URL identification is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Identify links behind shortened URLs'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "links_and_external_images")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableShortenerScanning")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack shortened URL identification",
            pass_text="have shortened URL identification enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("links", {})
    shortened_url_scan = safety.get("scan_shortened_urls", None)

    if shortened_url_scan is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shortened URL identification is enabled.",
            actual_value=shortened_url_scan,
            expected_value="Enabled for all OUs",
        )

    if shortened_url_scan is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine shortened URL scanning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Shortened URL identification is not enabled.",
        actual_value=shortened_url_scan,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.2.2",
    title="Ensure linked image scanning is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Scan linked images'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_linked_image_scanning(data: dict) -> CheckResult:
    """Scanning of linked images should be enabled to detect hidden content."""
    _ID = "CIS-3.1.3.4.2.2"
    _TITLE = "Ensure linked image scanning is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Scan linked images'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "links_and_external_images")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableExternalImageScanning")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack linked image scanning",
            pass_text="have linked image scanning enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("links", {})
    image_scan = safety.get("scan_linked_images", None)

    if image_scan is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Linked image scanning is enabled.",
            actual_value=image_scan,
            expected_value="Enabled for all OUs",
        )

    if image_scan is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine linked image scanning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Linked image scanning is not enabled.",
        actual_value=image_scan,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.2.3",
    title="Ensure warning for untrusted links is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Show warning prompt for any "
        "click on links to untrusted domains'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_untrusted_link_warning(data: dict) -> CheckResult:
    """Users should see a warning prompt when clicking links to untrusted domains."""
    _ID = "CIS-3.1.3.4.2.3"
    _TITLE = "Ensure warning for untrusted links is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Links and external images. Enable 'Show warning prompt for any "
        "click on links to untrusted domains'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "links_and_external_images")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableAggressiveWarningsOnUntrustedLinks")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack untrusted link warnings",
            pass_text="have untrusted link warnings enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("links", {})
    untrusted_warning = safety.get("show_warning_for_untrusted_links", None)

    if untrusted_warning is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Warnings for untrusted links are enabled.",
            actual_value=untrusted_warning,
            expected_value="Enabled for all OUs",
        )

    if untrusted_warning is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine untrusted link warning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Warnings for untrusted links are not enabled.",
        actual_value=untrusted_warning,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


# ---------------------------------------------------------------------------
# 3.1.3.4.3 - Spoofing and authentication
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.4.3.1",
    title="Ensure domain spoofing protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against domain spoofing "
        "based on similar domain names'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_domain_spoofing(data: dict) -> CheckResult:
    """Protection against spoofing of domain names should be enabled."""
    _ID = "CIS-3.1.3.4.3.1"
    _TITLE = "Ensure domain spoofing protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against domain spoofing "
        "based on similar domain names'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spoofing_and_authentication")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "detectDomainNameSpoofing")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack domain spoofing protection",
            pass_text="have domain spoofing protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("spoofing", {})
    domain_spoof = safety.get("domain_spoofing_protection", None)

    if domain_spoof is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Domain spoofing protection is enabled.",
            actual_value=domain_spoof,
            expected_value="Enabled for all OUs",
        )

    if domain_spoof is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine domain spoofing protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Domain spoofing protection is not enabled.",
        actual_value=domain_spoof,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.3.2",
    title="Ensure employee name spoofing protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against spoofing of "
        "employee names'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_employee_spoofing(data: dict) -> CheckResult:
    """Protection against spoofing of employee names should be enabled."""
    _ID = "CIS-3.1.3.4.3.2"
    _TITLE = "Ensure employee name spoofing protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against spoofing of "
        "employee names'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spoofing_and_authentication")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "detectEmployeeNameSpoofing")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack employee name spoofing protection",
            pass_text="have employee name spoofing protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("spoofing", {})
    employee_spoof = safety.get("employee_name_spoofing_protection", None)

    if employee_spoof is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Employee name spoofing protection is enabled.",
            actual_value=employee_spoof,
            expected_value="Enabled for all OUs",
        )

    if employee_spoof is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine employee name spoofing protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Employee name spoofing protection is not enabled.",
        actual_value=employee_spoof,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.3.3",
    title="Ensure inbound domain spoofing protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against inbound emails "
        "spoofing your domain'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_inbound_spoofing(data: dict) -> CheckResult:
    """Protection against inbound emails spoofing your domain should be enabled."""
    _ID = "CIS-3.1.3.4.3.3"
    _TITLE = "Ensure inbound domain spoofing protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against inbound emails "
        "spoofing your domain'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spoofing_and_authentication")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "detectDomainSpoofingFromUnauthenticatedSenders")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack inbound domain spoofing protection",
            pass_text="have inbound domain spoofing protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("spoofing", {})
    inbound_spoof = safety.get("inbound_domain_spoofing_protection", None)

    if inbound_spoof is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Inbound domain spoofing protection is enabled.",
            actual_value=inbound_spoof,
            expected_value="Enabled for all OUs",
        )

    if inbound_spoof is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine inbound domain spoofing protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Inbound domain spoofing protection is not enabled.",
        actual_value=inbound_spoof,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.3.4",
    title="Ensure unauthenticated email protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against any unauthenticated emails'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_unauthenticated_email(data: dict) -> CheckResult:
    """Protection against unauthenticated emails should be enabled."""
    _ID = "CIS-3.1.3.4.3.4"
    _TITLE = "Ensure unauthenticated email protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect against any unauthenticated emails'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spoofing_and_authentication")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "detectUnauthenticatedEmails")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack unauthenticated email protection",
            pass_text="have unauthenticated email protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("spoofing", {})
    unauth_protection = safety.get("unauthenticated_email_protection", None)

    if unauth_protection is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Unauthenticated email protection is enabled.",
            actual_value=unauth_protection,
            expected_value="Enabled for all OUs",
        )

    if unauth_protection is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine unauthenticated email protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Unauthenticated email protection is not enabled.",
        actual_value=unauth_protection,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.4.3.5",
    title="Ensure Groups inbound spoofing protection is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect your Groups from "
        "inbound emails spoofing your domain'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_groups_spoofing(data: dict) -> CheckResult:
    """Protection against inbound emails spoofing Google Groups should be enabled."""
    _ID = "CIS-3.1.3.4.3.5"
    _TITLE = "Ensure Groups inbound spoofing protection is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety > "
        "Spoofing and authentication. Enable 'Protect your Groups from "
        "inbound emails spoofing your domain'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spoofing_and_authentication")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "detectGroupsSpoofing")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack Groups spoofing protection",
            pass_text="have Groups spoofing protection enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {}).get("spoofing", {})
    groups_spoof = safety.get("groups_spoofing_protection", None)

    if groups_spoof is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Groups inbound spoofing protection is enabled.",
            actual_value=groups_spoof,
            expected_value="Enabled for all OUs",
        )

    if groups_spoof is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Groups spoofing protection setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Groups inbound spoofing protection is not enabled.",
        actual_value=groups_spoof,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


# ---------------------------------------------------------------------------
# 3.1.3.5 - Access and routing
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.5.1",
    title="Ensure POP and IMAP access is disabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable POP and IMAP access. https://knowledge.workspace.google.com/admin/gmail/control-gmail-access-for-your-organizations-users"
    ),
)
def check_gmail_pop_imap(data: dict) -> CheckResult:
    """POP and IMAP access should be disabled to force use of secure clients."""
    _ID = "CIS-3.1.3.5.1"
    _TITLE = "Ensure POP and IMAP access is disabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable POP and IMAP access. https://knowledge.workspace.google.com/admin/gmail/control-gmail-access-for-your-organizations-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path: check both pop_access and imap_access settings
    pop_ou_values = get_ou_values(gmail, "pop_access")
    imap_ou_values = get_ou_values(gmail, "imap_access")
    if pop_ou_values or imap_ou_values:
        # Merge the two settings per OU so one verdict covers both protocols.
        merged: dict[str, dict] = {}
        for entry in pop_ou_values:
            pop_enabled = field_value(entry, "enablePopAccess", "enablePop3Access")
            ou = merged.setdefault(entry["org_unit"], {"org_unit": entry["org_unit"], "value": {}})
            if pop_enabled is not None:
                ou["value"]["enablePopAccess"] = pop_enabled
        for entry in imap_ou_values:
            imap_enabled = field_value(entry, "enableImapAccess")
            ou = merged.setdefault(entry["org_unit"], {"org_unit": entry["org_unit"], "value": {}})
            if imap_enabled is not None:
                ou["value"]["enableImapAccess"] = imap_enabled

        def _judge(entry: dict):
            flags = (("POP", field_value(entry, "enablePopAccess")),
                     ("IMAP", field_value(entry, "enableImapAccess")))
            enabled = [name for name, flag in flags if flag is True]
            if enabled:
                return False, ", ".join(f"{name}=True" for name in enabled)
            if any(flag is None for _, flag in flags):
                return None  # one protocol's state is unknown for this OU
            return True

        return ou_verdict(
            list(merged.values()), _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have POP/IMAP enabled",
            pass_text="have POP and IMAP access disabled",
            expected_value={"pop": False, "imap": False}, remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    access = gmail.get("end_user_access", {})
    pop_enabled = access.get("pop_enabled", None)
    imap_enabled = access.get("imap_enabled", None)

    if pop_enabled is False and imap_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Both POP and IMAP access are disabled.",
            actual_value={"pop": pop_enabled, "imap": imap_enabled},
            expected_value={"pop": False, "imap": False},
        )

    if pop_enabled is None and imap_enabled is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine POP/IMAP access settings.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"POP enabled: {pop_enabled}, IMAP enabled: {imap_enabled}. Both should be disabled.",
        actual_value={"pop": pop_enabled, "imap": imap_enabled},
        expected_value={"pop": False, "imap": False},
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.5.2",
    title="Ensure automatic email forwarding is disabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable 'Allow users to automatically forward "
        "incoming email to another address'. https://knowledge.workspace.google.com/admin/gmail/let-users-automatically-forward-their-own-gmail-emails"
    ),
)
def check_gmail_auto_forwarding(data: dict) -> CheckResult:
    """Automatic email forwarding should be disabled to prevent data exfiltration."""
    _ID = "CIS-3.1.3.5.2"
    _TITLE = "Ensure automatic email forwarding is disabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable 'Allow users to automatically forward "
        "incoming email to another address'. https://knowledge.workspace.google.com/admin/gmail/let-users-automatically-forward-their-own-gmail-emails"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "auto_forwarding")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableAutoForwarding")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have auto-forwarding enabled",
            pass_text="have auto-forwarding disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    routing = gmail.get("routing", {})
    auto_forwarding = routing.get("auto_forwarding_enabled", None)

    if auto_forwarding is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Automatic email forwarding is disabled.",
            actual_value=auto_forwarding,
            expected_value="Disabled for all OUs",
        )

    if auto_forwarding is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine automatic forwarding setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Automatic email forwarding is enabled, risking data exfiltration.",
        actual_value=auto_forwarding,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.5.3",
    title="Ensure per-user outbound gateways are disabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable 'Allow per-user outbound gateways'. https://knowledge.workspace.google.com/admin/gmail/advanced/allow-per-user-outbound-gateways"
    ),
)
def check_gmail_outbound_gateway(data: dict) -> CheckResult:
    """Per-user outbound gateways should be disabled to maintain mail flow control."""
    _ID = "CIS-3.1.3.5.3"
    _TITLE = "Ensure per-user outbound gateways are disabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable 'Allow per-user outbound gateways'. https://knowledge.workspace.google.com/admin/gmail/advanced/allow-per-user-outbound-gateways"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "per_user_outbound_gateway")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowUsersToUseExternalSmtpServers",
                                "enablePerUserOutboundGateway")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have per-user outbound gateways enabled",
            pass_text="have per-user outbound gateways disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    routing = gmail.get("routing", {})
    outbound_gateway = routing.get("per_user_outbound_gateway_enabled", None)

    if outbound_gateway is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Per-user outbound gateways are disabled.",
            actual_value=outbound_gateway,
            expected_value="Disabled for all OUs",
        )

    if outbound_gateway is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine per-user outbound gateway setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Per-user outbound gateways are enabled.",
        actual_value=outbound_gateway,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.5.4",
    title="Ensure external recipient warnings are enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access > Warn for external recipients. Enable 'Warn users when sending emails to "
        "external recipients'. https://knowledge.workspace.google.com/admin/gmail/advanced/control-gmail-external-recipient-warnings"
    ),
    requires_license="enterprise_plus",
)
def check_gmail_external_recipient_warning(data: dict) -> CheckResult:
    """Users should be warned when sending emails to external recipients."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    user_settings = gmail.get("user_settings", {})
    ext_warning = user_settings.get("external_recipient_warning_enabled", None)

    if ext_warning is None:
        # Not exposed by the Policy API (SCuBA GWS.GMAIL.13.1): infer from the latest admin-log
        # change of the "disable warning" setting; "true" means the warning was turned off.
        inferred = result_from_setting_changes(
            data, "OutOfDomainWarningProto disable_untrusted_recipient_warning", ("true",),
            check_id="CIS-3.1.3.5.4", title="Ensure external recipient warnings are enabled",
            level="L1", source="CIS", section="Gmail", what="External recipient warning",
            remediation="Admin console > Apps > Google Workspace > Gmail > End User Access. Enable 'Warn for external recipients'.",
        )
        if inferred is not None:
            return inferred

    if ext_warning is True:
        return make_pass(
            check_id="CIS-3.1.3.5.4",
            title="Ensure external recipient warnings are enabled",
            level="L1", source="CIS", section="Gmail",
            details="External recipient warnings are enabled.",
            actual_value=ext_warning,
            expected_value="Enabled for all OUs",
        )

    if ext_warning is None:
        return make_manual(
            check_id="CIS-3.1.3.5.4",
            title="Ensure external recipient warnings are enabled",
            level="L1", source="CIS", section="Gmail",
            details="Could not determine external recipient warning setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > "
                "End User Access > Warn for external recipients. Enable 'Warn users when sending emails to "
                "external recipients'. https://knowledge.workspace.google.com/admin/gmail/advanced/control-gmail-external-recipient-warnings"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.3.5.4",
        title="Ensure external recipient warnings are enabled",
        level="L1", source="CIS", section="Gmail",
        details="External recipient warnings are not enabled.",
        actual_value=ext_warning,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > "
            "End User Access > Warn for external recipients. Enable 'Warn users when sending emails to "
            "external recipients'. https://knowledge.workspace.google.com/admin/gmail/advanced/control-gmail-external-recipient-warnings"
        ),
    )


# ---------------------------------------------------------------------------
# 3.1.3.6 - Advanced protections
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.6.1",
    title="Ensure enhanced pre-delivery message scanning is enabled",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > "
        "Enhanced pre-delivery message scanning. Enable 'Enhanced pre-delivery "
        "message scanning'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_gmail_predelivery_scanning(data: dict) -> CheckResult:
    """Enhanced pre-delivery message scanning should be enabled for phishing detection."""
    _ID = "CIS-3.1.3.6.1"
    _TITLE = "Ensure enhanced pre-delivery message scanning is enabled"
    _L, _S, _SEC = "L1", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Spam, Phishing and Malware > "
        "Enhanced pre-delivery message scanning. Enable 'Enhanced pre-delivery "
        "message scanning'. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "enhanced_pre_delivery_message_scanning")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "enableImprovedSuspiciousContentDetection")
            return None if value is None else value is True

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack enhanced pre-delivery scanning",
            pass_text="have enhanced pre-delivery scanning enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    safety = gmail.get("safety", {})
    predelivery = safety.get("enhanced_predelivery_scanning", None)

    if predelivery is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Enhanced pre-delivery message scanning is enabled.",
            actual_value=predelivery,
            expected_value="Enabled for all OUs",
        )

    if predelivery is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine pre-delivery scanning setting. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Gmail > Spam, Phishing and Malware > Enhanced pre-delivery message scanning."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Enhanced pre-delivery message scanning is not enabled.",
        actual_value=predelivery,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.6.2",
    title="Ensure spam filters are not bypassed for internal senders",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Uncheck 'Bypass spam filters for messages "
        "from internal senders'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
    requires_license="enterprise_plus",
)
def check_gmail_internal_spam_filter(data: dict) -> CheckResult:
    """Spam filtering should not be bypassed for messages from internal senders."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    spam = gmail.get("spam_settings", {})
    bypass_internal = spam.get("bypass_spam_for_internal_senders", None)

    if bypass_internal is False:
        return make_pass(
            check_id="CIS-3.1.3.6.2",
            title="Ensure spam filters are not bypassed for internal senders",
            level="L1", source="CIS", section="Gmail",
            details="Spam filters are not bypassed for internal senders.",
            actual_value=bypass_internal,
            expected_value="Disabled for all OUs",
        )

    if bypass_internal is None:
        return make_review(
            check_id="CIS-3.1.3.6.2",
            title="Ensure spam filters are not bypassed for internal senders",
            level="L1", source="CIS", section="Gmail",
            details=(
                "Could not determine internal sender spam bypass setting. "
                "Google does not expose this setting through any public API. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Gmail > Spam, Phishing and Malware."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, "
                "Phishing and Malware. Ensure 'Bypass spam filters for messages "
                "from internal senders' is unchecked. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.3.6.2",
        title="Ensure spam filters are not bypassed for internal senders",
        level="L1", source="CIS", section="Gmail",
        details="Spam filters are bypassed for internal senders, which could allow compromised accounts to distribute spam.",
        actual_value=bypass_internal,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, "
            "Phishing and Malware. Uncheck 'Bypass spam filters for messages "
            "from internal senders'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


# ---------------------------------------------------------------------------
# 3.1.3.7 - Compliance and storage
# ---------------------------------------------------------------------------

@check(
    check_id="CIS-3.1.3.7.1",
    title="Ensure comprehensive mail storage is enabled",
    level="L2",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Compliance. "
        "Enable 'Comprehensive mail storage'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_gmail_comprehensive_storage(data: dict) -> CheckResult:
    """Comprehensive mail storage should be enabled to capture all sent mail."""
    _ID = "CIS-3.1.3.7.1"
    _TITLE = "Ensure comprehensive mail storage is enabled"
    _L, _S, _SEC = "L2", "CIS", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Compliance. "
        "Enable 'Comprehensive mail storage'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "comprehensive_mail_storage")
    if ou_values:
        # The Policy API returns only a ruleId for this setting; whether that rule is
        # switched on lives in gmail.rule_states.ruleStates[] (ruleId, enabled) for the OU.
        rule_states: dict[str, dict[str, bool]] = {}
        for st in get_ou_values(gmail, "rule_states"):
            for rs in (st.get("value") or {}).get("ruleStates", []) or []:
                if isinstance(rs, dict) and rs.get("ruleId") is not None:
                    rule_states.setdefault(st["org_unit"], {})[str(rs["ruleId"])] = rs.get("enabled")

        def _judge(entry: dict):
            enabled = field_value(entry, "enableComprehensiveMailStorage", "enabled")
            if enabled is None:
                rule_id = field_value(entry, "ruleId")
                if rule_id is not None:
                    enabled = rule_states.get(entry["org_unit"], rule_states.get("/", {})).get(str(rule_id))
            return None if enabled is None else (enabled is True, enabled)

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack comprehensive mail storage",
            pass_text="have comprehensive mail storage enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
            unknown_text=(
                "A comprehensive mail storage policy exists but the Policy API does not "
                "expose whether it is enabled. Verify manually in Admin console > Apps > "
                "Google Workspace > Gmail > Compliance."
            ),
        )

    # Fallback: existing mapped value logic
    compliance = gmail.get("compliance", {})
    comprehensive_storage = compliance.get("comprehensive_mail_storage", None)

    if comprehensive_storage is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Comprehensive mail storage is enabled.",
            actual_value=comprehensive_storage,
            expected_value="Enabled for all OUs",
        )

    if comprehensive_storage is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine comprehensive mail storage setting. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Gmail > Compliance."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Comprehensive mail storage is not enabled. Some sent mail may not be stored.",
        actual_value=comprehensive_storage,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.3.7.2",
    scored=False,  # P3: TLS compliance rules are not exposed by the Policy API; MANUAL by design
    title="Ensure secure TLS connection is enforced",
    level="L1",
    source="CIS",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Compliance. "
        "Add a compliance rule requiring TLS encryption for all mail. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
    requires_license="enterprise_plus",
)
def check_gmail_tls_enforcement(data: dict) -> CheckResult:
    """TLS encryption should be enforced for email transmission."""
    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})
    compliance = gmail.get("compliance", {})
    tls_enforced = compliance.get("tls_required", None)

    if tls_enforced is True:
        return make_pass(
            check_id="CIS-3.1.3.7.2",
            title="Ensure secure TLS connection is enforced",
            level="L1", source="CIS", section="Gmail",
            details="TLS connection is enforced for email transmission.",
            actual_value=tls_enforced,
            expected_value="Enabled for all OUs",
        )

    if tls_enforced is None:
        return make_review(
            check_id="CIS-3.1.3.7.2",
            title="Ensure secure TLS connection is enforced",
            level="L1", source="CIS", section="Gmail",
            details=(
                "Could not determine TLS enforcement setting. "
                "Google does not expose this setting through any public API. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Gmail > Compliance."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Compliance. "
                "Add a compliance rule requiring TLS encryption. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="CIS-3.1.3.7.2",
        title="Ensure secure TLS connection is enforced",
        level="L1", source="CIS", section="Gmail",
        details="TLS is not enforced, allowing unencrypted email transmission.",
        actual_value=tls_enforced,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Compliance. "
            "Add a compliance rule requiring TLS encryption for all mail. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )
