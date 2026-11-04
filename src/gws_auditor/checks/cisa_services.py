# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CISA SCuBA service-specific checks for Gmail, Drive, Chat, Calendar, and Groups.

Only checks NOT already covered by CIS/OTHER/GOOGLE or the main cisa_scuba module.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   format_ou_values_readable, latest_setting_changes, field_value, ou_verdict)
from ..models import CheckResult, Status


def _flag_judge(*names: str, expected: bool):
    """``judge`` for a single boolean field: compliant when it equals *expected*, unknown when absent."""
    def judge(entry: dict):
        value = field_value(entry, *names)
        return None if value is None else value is expected
    return judge


# ===========================================================================
# Gmail - CISA SCuBA service-specific checks
# ===========================================================================


# gmail.email_attachment_safety consequence enums (SPAM_FOLDER / QUARANTINE / WARNING ...)
_ATTACHMENT_CONSEQUENCE_FIELDS = (
    "anomalousAttachmentProtectionConsequence",
    "encryptedAttachmentProtectionConsequence",
    "attachmentWithScriptsProtectionConsequence",
)


def _spam_override_rules(value: dict) -> list[dict]:
    """Return the rule dicts of a gmail.spam_override_lists policy value (``spamOverride[]``)."""
    rules = value.get("spamOverride", [])
    return [r for r in rules if isinstance(r, dict)] if isinstance(rules, list) else []


def _rule_bypasses_all_senders(rule: dict) -> bool:
    """True if a spam override rule bypasses filters for internal or all senders."""
    if rule.get("bypassInternalSenders") is True:
        return True
    # The "all internal and external senders" option; exact field name is not documented
    return any(v is True for k, v in rule.items()
               if "all" in k.lower() and ("bypass" in k.lower() or "hidewarning" in k.lower()))


@check(
    check_id="GWS.GMAIL.4.1",
    title="Ensure DMARC policy is published for all domains",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Publish a DMARC TXT record at _dmarc.<domain> for each "
        "domain listed. Example: v=DMARC1; p=reject; rua=mailto:dmarc@<domain> https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
    ),
)
def check_dmarc_published(data: dict) -> CheckResult:
    """Every domain must have a published DMARC DNS record."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="GWS.GMAIL.4.1",
            title="Ensure DMARC policy is published for all domains",
            level="L1", source="CISA", section="Gmail",
            details="No domains found to check DMARC records.",
            remediation="Verify DMARC records are published for all domains. https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
        )

    missing_dmarc = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dmarc = domain_dns.get("dmarc", {})
        if not dmarc.get("record_found", False):
            missing_dmarc.append(domain_name)

    if not missing_dmarc:
        return make_pass(
            check_id="GWS.GMAIL.4.1",
            title="Ensure DMARC policy is published for all domains",
            level="L1", source="CISA", section="Gmail",
            details="DMARC records are published for all domains.",
            actual_value={"all_published": True},
            expected_value="DMARC record published for every domain",
        )

    return make_fail(
        check_id="GWS.GMAIL.4.1",
        title="Ensure DMARC policy is published for all domains",
        level="L1", source="CISA", section="Gmail",
        details=f"DMARC record missing for: {', '.join(missing_dmarc)}",
        actual_value={"missing_dmarc_domains": missing_dmarc},
        expected_value="DMARC record published for every domain",
        remediation=(
            "Publish a DMARC TXT record at _dmarc.<domain> for each "
            "domain listed. Example: v=DMARC1; p=reject; rua=mailto:dmarc@<domain> https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
        ),
    )


@check(
    check_id="GWS.GMAIL.4.2",
    title="Ensure DMARC policy is set to reject",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Update the DMARC DNS record for each listed domain to set "
        "the policy to reject (p=reject). This instructs receiving "
        "mail servers to reject unauthenticated messages. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
    ),
)
def check_dmarc_reject(data: dict) -> CheckResult:
    """DMARC policy must be set to 'reject' for all domains."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="GWS.GMAIL.4.2",
            title="Ensure DMARC policy is set to reject",
            level="L1", source="CISA", section="Gmail",
            details="No domains found to check DMARC policy.",
            remediation="Verify DMARC policy is set to reject for all domains. https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
        )

    non_reject = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dmarc = domain_dns.get("dmarc", {})
        policy = dmarc.get("policy", "")
        if policy != "reject":
            non_reject.append(domain_name)

    if not non_reject:
        return make_pass(
            check_id="GWS.GMAIL.4.2",
            title="Ensure DMARC policy is set to reject",
            level="L1", source="CISA", section="Gmail",
            details="DMARC policy is 'reject' for all domains.",
            actual_value={"all_reject": True},
            expected_value="p=reject for all domains",
        )

    return make_fail(
        check_id="GWS.GMAIL.4.2",
        title="Ensure DMARC policy is set to reject",
        level="L1", source="CISA", section="Gmail",
        details=f"DMARC policy is not 'reject' for: {', '.join(non_reject)}",
        actual_value={"non_reject_domains": non_reject},
        expected_value="p=reject for all domains",
        remediation=(
            "Update the DMARC DNS record for each listed domain to set "
            "the policy to reject (p=reject). This instructs receiving "
            "mail servers to reject unauthenticated messages. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
        ),
    )


@check(
    check_id="GWS.GMAIL.5.5",
    title="Ensure flagged emails are moved out of inbox",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Safety. "
        "Configure flagged emails to be quarantined or sent to spam. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    ),
)
def check_flagged_email_action(data: dict) -> CheckResult:
    """Flagged emails should be moved to quarantine or spam, not left in inbox."""
    _ID = "GWS.GMAIL.5.5"
    _TITLE = "Ensure flagged emails are moved out of inbox"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Safety. "
        "Configure flagged emails to be quarantined or sent to spam. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    # Policy API: gmail.email_attachment_safety carries one *Consequence enum per protection
    ou_values = get_ou_values(gmail, "email_attachment_safety")
    if not any(k in e["value"] for e in ou_values for k in _ATTACHMENT_CONSEQUENCE_FIELDS):
        ou_values = get_ou_values(gmail, "spam_override_lists") or ou_values  # legacy shape
    if ou_values:
        def judge(entry: dict):
            value = entry.get("value") or {}
            present = [k for k in _ATTACHMENT_CONSEQUENCE_FIELDS if k in value]
            if present:
                consequences = {k: field_value(entry, k) for k in present}
                left_in_inbox = sorted(f"{k}={v}" for k, v in consequences.items()
                                       if v is not None and v not in ("SPAM_FOLDER", "QUARANTINE"))
                if left_in_inbox:
                    return False, ", ".join(left_in_inbox)
                if any(v is None for v in consequences.values()):
                    return None  # *_UNSPECIFIED consequence: cannot judge
                return True
            act = field_value(entry, "flaggedEmailAction", "flagged_email_action")
            if act is None:
                return None  # entry says nothing about this control
            return act in ("quarantine", "spam"), act

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not quarantine/spam flagged emails",
            pass_text="move flagged emails to quarantine/spam",
            expected_value="quarantine or spam", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    safety = gmail.get("safety", {})
    action = safety.get("flagged_email_action", None)

    if action in ("quarantine", "spam"):
        return make_pass(
            check_id="GWS.GMAIL.5.5",
            title="Ensure flagged emails are moved out of inbox",
            level="L1", source="CISA", section="Gmail",
            details=f"Flagged emails are moved to '{action}'.",
            actual_value=action,
            expected_value="quarantine or spam",
        )

    if action is None:
        return make_manual(
            check_id="GWS.GMAIL.5.5",
            title="Ensure flagged emails are moved out of inbox",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine the flagged email action setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Safety. "
                "Configure flagged emails to be quarantined or sent to spam. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
            ),
        )

    return make_fail(
        check_id="GWS.GMAIL.5.5",
        title="Ensure flagged emails are moved out of inbox",
        level="L1", source="CISA", section="Gmail",
        details=f"Flagged emails action is '{action}' instead of quarantine or spam.",
        actual_value=action,
        expected_value="quarantine or spam",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Safety. "
            "Set the flagged email action to 'Move email to spam' or "
            "'Move email to quarantine' to prevent suspicious messages "
            "from reaching user inboxes. https://knowledge.workspace.google.com/admin/gmail/advanced/advanced-phishing-and-malware-protection"
        ),
    )


@check(
    check_id="GWS.GMAIL.18.1",
    title="Ensure no domains bypass spam filters",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all domains from the approved "
        "senders list. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_spam_approved_senders_domains(data: dict) -> CheckResult:
    """No domains should be configured to bypass spam filters."""
    _ID = "GWS.GMAIL.18.1"
    _TITLE = "Ensure no domains bypass spam filters"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all domains from the approved "
        "senders list. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spam_override_lists")
    if ou_values:
        def judge(entry: dict):
            # spamOverride[] absent -> documented default [] (no override rules), judged as compliant
            rules = [r for r in _spam_override_rules(entry["value"])
                     if r.get("bypassSelectedSenders") is True]
            if rules:
                return False, len(rules)
            domains = field_value(entry, "approvedSendersDomains", "approved_senders_domains")
            if isinstance(domains, list) and len(domains) > 0:
                return False, len(domains)
            return True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have approved sender domains",
            pass_text="have no approved sender domains",
            expected_value="No approved sender domains", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    spam_settings = gmail.get("spam_settings", {})
    approved = spam_settings.get("approved_senders_domains", None)

    if isinstance(approved, list) and len(approved) == 0:
        return make_pass(
            check_id="GWS.GMAIL.18.1",
            title="Ensure no domains bypass spam filters",
            level="L1", source="CISA", section="Gmail",
            details="No domains are configured to bypass spam filters.",
            actual_value={"approved_domains_count": 0},
            expected_value="No approved sender domains",
        )

    if approved is None:
        return make_manual(
            check_id="GWS.GMAIL.18.1",
            title="Ensure no domains bypass spam filters",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine approved senders domain list.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, "
                "Phishing and Malware. Remove all domains from the approved "
                "senders list. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    count = len(approved) if isinstance(approved, list) else "unknown"
    return make_fail(
        check_id="GWS.GMAIL.18.1",
        title="Ensure no domains bypass spam filters",
        level="L1", source="CISA", section="Gmail",
        details=f"{count} domain(s) are configured to bypass spam filters.",
        actual_value={"approved_domains_count": count},
        expected_value="No approved sender domains",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, "
            "Phishing and Malware. Remove all domains from the approved "
            "senders list. Allowing domains to bypass spam filters "
            "increases the risk of phishing and malware delivery. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.GMAIL.18.2",
    title="Ensure no domains bypass spam filters and hide warnings",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all domains that bypass spam "
        "filters and hide warnings from users. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_spam_domains_bypass_hide_warnings(data: dict) -> CheckResult:
    """No domains should bypass spam filters while also hiding warnings."""
    _ID = "GWS.GMAIL.18.2"
    _TITLE = "Ensure no domains bypass spam filters and hide warnings"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all domains that bypass spam "
        "filters and hide warnings from users. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spam_override_lists")
    if ou_values:
        def judge(entry: dict):
            # spamOverride[] absent -> documented default [] (no override rules), judged as compliant
            rules = [r for r in _spam_override_rules(entry["value"])
                     if r.get("bypassSelectedSenders") is True
                     and r.get("hideWarningBannerFromSelectedSenders") is True]
            if rules:
                return False, len(rules)
            bypass = field_value(entry, "domainsBypassAndHideWarnings", "domains_bypass_and_hide_warnings")
            if isinstance(bypass, list) and len(bypass) > 0:
                return False, len(bypass)
            return True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have domains bypassing and hiding warnings",
            pass_text="have no domains bypassing and hiding warnings",
            expected_value="No domains bypass and hide warnings", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    spam_settings = gmail.get("spam_settings", {})
    bypass_hide = spam_settings.get("domains_bypass_and_hide_warnings", None)

    if isinstance(bypass_hide, list) and len(bypass_hide) == 0:
        return make_pass(
            check_id="GWS.GMAIL.18.2",
            title="Ensure no domains bypass spam filters and hide warnings",
            level="L1", source="CISA", section="Gmail",
            details="No domains bypass spam filters while hiding warnings.",
            actual_value={"bypass_hide_count": 0},
            expected_value="No domains bypass and hide warnings",
        )

    if bypass_hide is None:
        return make_manual(
            check_id="GWS.GMAIL.18.2",
            title="Ensure no domains bypass spam filters and hide warnings",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine domains that bypass and hide spam warnings.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, "
                "Phishing and Malware. Remove all domains that bypass spam "
                "filters and hide warnings from users. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    count = len(bypass_hide) if isinstance(bypass_hide, list) else "unknown"
    return make_fail(
        check_id="GWS.GMAIL.18.2",
        title="Ensure no domains bypass spam filters and hide warnings",
        level="L1", source="CISA", section="Gmail",
        details=f"{count} domain(s) bypass spam filters and hide warnings.",
        actual_value={"bypass_hide_count": count},
        expected_value="No domains bypass and hide warnings",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, "
            "Phishing and Malware. Remove all domains that bypass spam "
            "filters and suppress warnings. This is especially dangerous "
            "as users will not see any indication of suspicious mail. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.GMAIL.18.3",
    title="Ensure global spam filter bypass is disabled",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Disable 'Bypass spam filters for "
        "messages from internal senders'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_spam_bypass_internal(data: dict) -> CheckResult:
    """Spam filter bypass for internal senders should be disabled."""
    _ID = "GWS.GMAIL.18.3"
    _TITLE = "Ensure global spam filter bypass is disabled"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Disable 'Bypass spam filters for "
        "messages from internal senders'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "spam_override_lists")
    if ou_values:
        def judge(entry: dict):
            # spamOverride[] absent -> documented default [] (no override rules), judged as compliant
            if any(_rule_bypasses_all_senders(r) for r in _spam_override_rules(entry["value"])):
                return False, True
            bypass = field_value(entry, "bypassSpamFiltersForInternal", "bypass_internal")
            return bypass is not True, bypass

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="bypass spam filters for internal senders",
            pass_text="do not bypass spam filters for internal senders",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    spam_settings = gmail.get("spam_settings", {})
    bypass_internal = spam_settings.get("bypass_spam_filters_for_internal", None)

    if bypass_internal is False:
        return make_pass(
            check_id="GWS.GMAIL.18.3",
            title="Ensure global spam filter bypass is disabled",
            level="L1", source="CISA", section="Gmail",
            details="Spam filter bypass for internal senders is disabled.",
            actual_value=bypass_internal,
            expected_value="Disabled for all OUs",
        )

    if bypass_internal is None:
        return make_manual(
            check_id="GWS.GMAIL.18.3",
            title="Ensure global spam filter bypass is disabled",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine internal spam filter bypass setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, "
                "Phishing and Malware. Disable 'Bypass spam filters for "
                "messages from internal senders'. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.GMAIL.18.3",
        title="Ensure global spam filter bypass is disabled",
        level="L1", source="CISA", section="Gmail",
        details="Spam filter bypass for internal senders is enabled.",
        actual_value=bypass_internal,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, "
            "Phishing and Malware. Disable 'Bypass spam filters for "
            "messages from internal senders'. Compromised internal "
            "accounts could be used to distribute spam or phishing "
            "internally if this bypass is enabled. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


# ===========================================================================
# Drive and Docs - CISA SCuBA service-specific checks
# ===========================================================================

@check(
    check_id="GWS.DRIVEDOCS.1.3",
    title="Ensure sharing warnings for non-allowlisted domains are enabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable warnings when users share files "
        "with people outside allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_external_sharing_warning(data: dict) -> CheckResult:
    """Users should receive warnings when sharing files with non-allowlisted domains."""
    _ID = "GWS.DRIVEDOCS.1.3"
    _TITLE = "Ensure sharing warnings for non-allowlisted domains are enabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable warnings when users share files "
        "with people outside allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def judge(entry: dict):
            mode = field_value(entry, "externalSharingMode")
            if mode is None:
                return None  # cannot tell which warning setting applies
            if mode == "DISALLOWED":
                return True  # no external sharing, nothing to warn about
            if mode == "ALLOWLISTED_DOMAINS":
                warn = field_value(entry, "warnForSharingOutsideAllowlistedDomains")
            else:
                warn = field_value(entry, "warnForExternalSharing", "warn_for_external_sharing")
            return None if warn is None else warn is True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack external sharing warnings",
            pass_text="have external sharing warnings enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    warn_external = sharing.get("warn_for_external_sharing", None)

    if warn_external is True:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.3",
            title="Ensure sharing warnings for non-allowlisted domains are enabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Sharing warnings for non-allowlisted domains are enabled.",
            actual_value=warn_external,
            expected_value="Enabled for all OUs",
        )

    if warn_external is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.3",
            title="Ensure sharing warnings for non-allowlisted domains are enabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine external sharing warning setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Enable warnings when users share files "
                "with people outside allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.3",
        title="Ensure sharing warnings for non-allowlisted domains are enabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="Sharing warnings for non-allowlisted domains are not enabled.",
        actual_value=warn_external,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Enable 'Warn when files owned by users or "
            "shared drives in your organization are shared with users in "
            "non-allowlisted domains'. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.6",
    title="Ensure access checking is set to recipients only",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set access checker to 'Recipients only' "
        "to prevent broad sharing suggestions. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
    ),
)
def check_drive_access_checker(data: dict) -> CheckResult:
    """Access checker suggestions should be limited to recipients only."""
    _ID = "GWS.DRIVEDOCS.1.6"
    _TITLE = "Ensure access checking is set to recipients only"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set access checker to 'Recipients only' "
        "to prevent broad sharing suggestions. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
    )
    _SAFE = ("recipients_only", "target_audience_only")

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def judge(entry: dict):
            raw = field_value(entry, "accessCheckerSuggestions", "access_checker_suggestions")
            if raw is None:
                return None
            checker = raw.lower() if isinstance(raw, str) else raw
            return checker in _SAFE, checker

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have access checker not set to recipients only",
            pass_text="have access checker set to recipients only",
            expected_value="recipients_only", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    access_checker = sharing.get("access_checker_suggestions", None)

    if access_checker in ("recipients_only", "target_audience_only"):
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.6",
            title="Ensure access checking is set to recipients only",
            level="L1", source="CISA", section="Drive and Docs",
            details=f"Access checker is set to '{access_checker}'.",
            actual_value=access_checker,
            expected_value="recipients_only or target_audience_only",
        )

    if access_checker is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.6",
            title="Ensure access checking is set to recipients only",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine access checker suggestion setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Set access checker to 'Recipients only' "
                "to prevent broad sharing suggestions. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.6",
        title="Ensure access checking is set to recipients only",
        level="L1", source="CISA", section="Drive and Docs",
        details=f"Access checker is set to '{access_checker}' instead of recipients only.",
        actual_value=access_checker,
        expected_value="recipients_only or target_audience_only",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Set the access checker to 'Recipients only' "
            "to limit sharing suggestions and reduce accidental data exposure. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.7",
    title="Ensure users cannot upload to external shared drives",
    level="L2",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable uploading to shared drives owned "
        "by other organizations. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_external_upload(data: dict) -> CheckResult:
    """Users should not be able to upload files to shared drives owned by other organizations."""
    _ID = "GWS.DRIVEDOCS.1.7"
    _TITLE = "Ensure users cannot upload to external shared drives"
    _L, _S, _SEC = "L2", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable uploading to shared drives owned "
        "by other organizations. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def judge(entry: dict):
            mode = field_value(entry, "externalSharingMode")
            # External sharing fully off -> content cannot leave the organization
            if mode == "DISALLOWED":
                return True
            # Policy API field is allowedPartiesForDistributingContent; only NONE ("No one")
            # is compliant. allowReceivingExternalFiles is the *receiving* setting (1.2).
            parties = field_value(entry, "allowedPartiesForDistributingContent")
            if parties is not None:
                if parties == "NONE":
                    return True
                # an unspecified sharing mode could still be DISALLOWED -> cannot judge
                return (None if mode is None else False), parties
            upload = field_value(entry, "allowUploadToExternalDrives", "allow_upload_to_external_drives")
            return None if upload is None else upload is False

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow uploading to external shared drives",
            pass_text="block uploading to external shared drives",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    allow_upload = sharing.get("allow_upload_to_external_drives", None)

    if allow_upload is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.7",
            title="Ensure users cannot upload to external shared drives",
            level="L2", source="CISA", section="Drive and Docs",
            details="Uploading to external shared drives is disabled.",
            actual_value=allow_upload,
            expected_value="Disabled for all OUs",
        )

    if allow_upload is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.7",
            title="Ensure users cannot upload to external shared drives",
            level="L2", source="CISA", section="Drive and Docs",
            details="Could not determine external shared drive upload setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Disable uploading to shared drives owned "
                "by other organizations. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.7",
        title="Ensure users cannot upload to external shared drives",
        level="L2", source="CISA", section="Drive and Docs",
        details="Users can upload files to external shared drives.",
        actual_value=allow_upload,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Disable 'Allow users to upload files to "
            "shared drives owned by another organization' to prevent "
            "data exfiltration via external drives. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.9",
    title="Ensure out-of-domain file-level warnings are enabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable out-of-domain warnings for files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_ood_warning(data: dict) -> CheckResult:
    """Out-of-domain warnings should be shown when users open files shared from outside."""
    _ID = "GWS.DRIVEDOCS.1.9"
    _TITLE = "Ensure out-of-domain file-level warnings are enabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable out-of-domain warnings for files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path — check external_file_warning setting
    ou_values = get_ou_values(drive, "external_file_warning")
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("highlightingEnabled", "outOfDomainWarningEnabled",
                                   "out_of_domain_warning_enabled", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack out-of-domain warnings",
            pass_text="have out-of-domain warnings enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    ood_warning = sharing.get("out_of_domain_warning_enabled", None)

    if ood_warning is True:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.9",
            title="Ensure out-of-domain file-level warnings are enabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Out-of-domain file-level warnings are enabled.",
            actual_value=ood_warning,
            expected_value="Enabled for all OUs",
        )

    if ood_warning is None:
        return make_review(
            check_id="GWS.DRIVEDOCS.1.9",
            title="Ensure out-of-domain file-level warnings are enabled",
            level="L1", source="CISA", section="Drive and Docs",
            details=(
                "External-file warning state is not exposed by the Cloud "
                "Identity Policy API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Enable out-of-domain warnings for files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.9",
        title="Ensure out-of-domain file-level warnings are enabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="Out-of-domain file-level warnings are not enabled.",
        actual_value=ood_warning,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Enable 'Warn users when they open files "
            "from outside the organization' to alert users about "
            "potentially untrusted external content. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.2.1",
    title="Ensure shared drive manager override is disabled",
    level="L2",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. Disable "
        "'Allow managers to override settings below'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
)
def check_drive_manager_override(data: dict) -> CheckResult:
    """Shared drive managers should not be able to override sharing settings."""
    _ID = "GWS.DRIVEDOCS.2.1"
    _TITLE = "Ensure shared drive manager override is disabled"
    _L, _S, _SEC = "L2", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. Disable "
        "'Allow managers to override settings below'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("allowManagersToOverrideSettings", "allowManagerOverride",
                                   "allow_manager_override", expected=False),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow manager override of sharing settings",
            pass_text="disable manager override",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    shared_drive = drive.get("shared_drive_settings", {})
    allow_override = shared_drive.get("allow_manager_override", None)

    if allow_override is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.2.1",
            title="Ensure shared drive manager override is disabled",
            level="L2", source="CISA", section="Drive and Docs",
            details="Shared drive manager override is disabled.",
            actual_value=allow_override,
            expected_value="Disabled for all OUs",
        )

    if allow_override is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.2.1",
            title="Ensure shared drive manager override is disabled",
            level="L2", source="CISA", section="Drive and Docs",
            details="Could not determine shared drive manager override setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings > Shared drive creation. Disable "
                "'Allow managers to override settings below'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.2.1",
        title="Ensure shared drive manager override is disabled",
        level="L2", source="CISA", section="Drive and Docs",
        details="Shared drive managers can override sharing settings.",
        actual_value=allow_override,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings > Shared drive creation. Disable 'Allow "
            "managers to override settings below' to enforce consistent "
            "sharing policies across all shared drives. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.2.2",
    title="Ensure non-members can be added to shared drive files",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. Enable "
        "'Allow non-members to be added to files'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
)
def check_drive_non_member_access(data: dict) -> CheckResult:
    """Non-members should be allowed access to individual files in shared drives."""
    _ID = "GWS.DRIVEDOCS.2.2"
    _TITLE = "Ensure non-members can be added to shared drive files"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. Enable "
        "'Allow non-members to be added to files'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("allowNonMemberAccess", "allow_non_member_access", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="don't allow non-member access to shared drive files",
            pass_text="allow non-member access to shared drive files",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    shared_drive = drive.get("shared_drive_settings", {})
    allow_non_member = shared_drive.get("allow_non_member_access", None)

    if allow_non_member is True:
        return make_pass(
            check_id="GWS.DRIVEDOCS.2.2",
            title="Ensure non-members can be added to shared drive files",
            level="L1", source="CISA", section="Drive and Docs",
            details="Non-members can be added to individual shared drive files.",
            actual_value=allow_non_member,
            expected_value="Enabled for all OUs",
        )

    if allow_non_member is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.2.2",
            title="Ensure non-members can be added to shared drive files",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine non-member access setting for shared drives.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings > Shared drive creation. Enable "
                "'Allow non-members to be added to files'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.2.2",
        title="Ensure non-members can be added to shared drive files",
        level="L1", source="CISA", section="Drive and Docs",
        details="Non-members cannot be added to shared drive files.",
        actual_value=allow_non_member,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings > Shared drive creation. Enable 'Allow "
            "non-members to be added to files' to support granular "
            "file-level sharing with collaborators who are not full "
            "shared drive members. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.5.1",
    title="Ensure Google Drive Add-Ons are disabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable Google Drive Add-Ons. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
    ),
)
def check_drive_add_ons_disabled(data: dict) -> CheckResult:
    """Google Drive Add-Ons should be disabled to reduce third-party attack surface."""
    _ID = "GWS.DRIVEDOCS.5.1"
    _TITLE = "Ensure Google Drive Add-Ons are disabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable Google Drive Add-Ons. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # Add-ons are not exposed by the Policy API (drive_sdk.enableDriveSdkApiAccess is the
    # separate Drive SDK setting). Infer from the latest ENABLE_DOCS_ADD_ONS admin-log change.
    changes = latest_setting_changes(data, "ENABLE_DOCS_ADD_ONS")
    changes = {ou: v for ou, v in changes.items() if v.upper() != "INHERIT_FROM_PARENT"}
    if changes:
        enabled_ous = sorted(ou for ou, v in changes.items() if v.lower() != "false")
        if enabled_ous:
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(enabled_ous)} OU(s) have Drive Add-Ons enabled (from admin logs): {', '.join(enabled_ous)}",
                actual_value=", ".join(f"{ou} → enabled" for ou in enabled_ous),
                expected_value="Disabled for all OUs", remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Drive Add-Ons were disabled in {len(changes)} OU(s) (latest admin-log change).",
            actual_value=f"{len(changes)} OU(s) safe", expected_value="Disabled for all OUs",
        )

    # Legacy shape (older caches / explicit addOnsEnabled field)
    ou_values = [e for e in get_ou_values(drive, "drive_sdk")
                 if "addOnsEnabled" in e["value"] or "add_ons_enabled" in e["value"]]
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("addOnsEnabled", "add_ons_enabled", expected=False),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Drive Add-Ons enabled",
            pass_text="have Drive Add-Ons disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    features = drive.get("features", {})
    add_ons_enabled = features.get("add_ons_enabled", None)

    if add_ons_enabled is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.5.1",
            title="Ensure Google Drive Add-Ons are disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Google Drive Add-Ons are disabled.",
            actual_value=add_ons_enabled,
            expected_value="Disabled for all OUs",
        )

    if add_ons_enabled is None:
        return make_review(
            check_id="GWS.DRIVEDOCS.5.1",
            title="Ensure Google Drive Add-Ons are disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details=(
                "Drive Add-Ons availability is not exposed by the Cloud "
                "Identity Policy API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Features and Applications. Disable Google Drive Add-Ons. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.5.1",
        title="Ensure Google Drive Add-Ons are disabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="Google Drive Add-Ons are enabled.",
        actual_value=add_ons_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Features and Applications. Disable Google Drive Add-Ons "
            "to reduce the third-party integration attack surface and "
            "prevent unauthorized data access by add-on providers. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.6.1",
    title="Ensure Drive for Desktop is restricted to authorized devices",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications > Google Drive for Desktop. "
        "Restrict to authorized devices or disable entirely. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    ),
)
def check_drive_desktop_restricted(data: dict) -> CheckResult:
    """Drive for Desktop should be restricted to authorized devices or disabled entirely."""
    _ID = "GWS.DRIVEDOCS.6.1"
    _TITLE = "Ensure Drive for Desktop is restricted to authorized devices"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications > Google Drive for Desktop. "
        "Restrict to authorized devices or disable entirely. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "drive_for_desktop")
    if ou_values:
        def judge(entry: dict):
            auth_only = field_value(entry, "restrictToAuthorizedDevices", "desktopAuthorizedOnly",
                                    "desktop_authorized_only")
            allowed = field_value(entry, "allowDriveForDesktop", "desktopAllowed", "desktop_allowed")
            if auth_only is True or allowed is False:
                return True
            if auth_only is None or allowed is None:
                return None  # the missing flag could still make the OU compliant
            return False, {"authorized_only": auth_only, "allowed": allowed}

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="don't restrict Drive for Desktop",
            pass_text="restrict Drive for Desktop",
            expected_value="desktop_authorized_only=True or desktop_allowed=False", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    features = drive.get("features", {})
    desktop_authorized_only = features.get("desktop_authorized_only", None)
    desktop_allowed = features.get("desktop_allowed", None)

    if desktop_authorized_only is True or desktop_allowed is False:
        detail = (
            "Drive for Desktop is disabled."
            if desktop_allowed is False
            else "Drive for Desktop is restricted to authorized devices."
        )
        return make_pass(
            check_id="GWS.DRIVEDOCS.6.1",
            title="Ensure Drive for Desktop is restricted to authorized devices",
            level="L1", source="CISA", section="Drive and Docs",
            details=detail,
            actual_value={
                "desktop_authorized_only": desktop_authorized_only,
                "desktop_allowed": desktop_allowed,
            },
            expected_value="desktop_authorized_only=True or desktop_allowed=False",
        )

    if desktop_authorized_only is None and desktop_allowed is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.6.1",
            title="Ensure Drive for Desktop is restricted to authorized devices",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine Drive for Desktop device restriction setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Features and Applications > Google Drive for Desktop. "
                "Restrict to authorized devices or disable entirely. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.6.1",
        title="Ensure Drive for Desktop is restricted to authorized devices",
        level="L1", source="CISA", section="Drive and Docs",
        details="Drive for Desktop is not restricted to authorized devices.",
        actual_value={
            "desktop_authorized_only": desktop_authorized_only,
            "desktop_allowed": desktop_allowed,
        },
        expected_value="desktop_authorized_only=True or desktop_allowed=False",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Features and Applications > Google Drive for Desktop. "
            "Enable 'Only allow Drive for Desktop on authorized devices' "
            "or disable Drive for Desktop entirely to prevent data syncing "
            "to unmanaged endpoints. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
        ),
    )


# ===========================================================================
# Google Chat - CISA SCuBA service-specific checks
# ===========================================================================

@check(
    check_id="GWS.CHAT.3.1",
    title="Ensure Chat space history is enabled",
    level="L2",
    source="CISA",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat history. Enable history for spaces to retain "
        "conversation records for compliance. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
)
def check_chat_space_history(data: dict) -> CheckResult:
    """Chat space history should be enabled to retain conversation records."""
    _ID = "GWS.CHAT.3.1"
    _TITLE = "Ensure Chat space history is enabled"
    _L, _S, _SEC = "L2", "CISA", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Chat history. Enable history for spaces to retain "
        "conversation records for compliance. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "space_history")
    if ou_values:
        def judge(entry: dict):
            # API returns historyState (e.g. "DEFAULT_HISTORY_ON"); legacy shapes carry a boolean
            state = field_value(entry, "historyState", "spaceHistoryEnabled", "space_history_enabled")
            if state is None:
                return None
            if isinstance(state, str):
                return state.upper() in ("DEFAULT_HISTORY_ON", "HISTORY_ALWAYS_ON", "ALWAYS_ON"), state
            return state is True, state

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Chat space history disabled",
            pass_text="have Chat space history enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    history = chat.get("history", {})
    space_history = history.get("space_history_enabled", None)

    if space_history is True:
        return make_pass(
            check_id="GWS.CHAT.3.1",
            title="Ensure Chat space history is enabled",
            level="L2", source="CISA", section="Google Chat",
            details="Chat space history is enabled.",
            actual_value=space_history,
            expected_value="Enabled for all OUs",
        )

    if space_history is None:
        return make_manual(
            check_id="GWS.CHAT.3.1",
            title="Ensure Chat space history is enabled",
            level="L2", source="CISA", section="Google Chat",
            details="Could not determine Chat space history setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "Chat history. Enable history for spaces to retain "
                "conversation records for compliance. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.CHAT.3.1",
        title="Ensure Chat space history is enabled",
        level="L2", source="CISA", section="Google Chat",
        details="Chat space history is not enabled.",
        actual_value=space_history,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Chat history. Enable space history to ensure conversations "
            "in Chat spaces are retained for audit and compliance purposes. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )


@check(
    check_id="GWS.CHAT.5.2",
    scored=False,  # P3: reporting categories are not exposed by the Policy API; MANUAL by design
    title="Ensure all Chat reporting categories are selected",
    level="L2",
    source="CISA",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Content reporting. Select all reporting categories to "
        "ensure comprehensive content monitoring. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
    ),
    requires_license="enterprise_plus",
)
def check_chat_reporting_categories(data: dict) -> CheckResult:
    """All Chat content reporting categories should be selected."""
    _ID = "GWS.CHAT.5.2"
    _TITLE = "Ensure all Chat reporting categories are selected"
    _L, _S, _SEC = "L2", "CISA", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Content reporting. Select all reporting categories to "
        "ensure comprehensive content monitoring. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = []  # P3: "chat.chat_reporting (and chat.content_reporting carries no category list)" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("allCategoriesSelected", "all_categories_selected", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack all Chat reporting categories",
            pass_text="have all Chat reporting categories selected",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    reporting = chat.get("content_reporting", {})
    all_selected = reporting.get("all_categories_selected", None)

    if all_selected is True:
        return make_pass(
            check_id="GWS.CHAT.5.2",
            title="Ensure all Chat reporting categories are selected",
            level="L2", source="CISA", section="Google Chat",
            details="All Chat reporting categories are selected.",
            actual_value=all_selected,
            expected_value="Enabled for all OUs",
        )

    if all_selected is None:
        return make_manual(
            check_id="GWS.CHAT.5.2",
            title="Ensure all Chat reporting categories are selected",
            level="L2", source="CISA", section="Google Chat",
            details="Could not determine Chat reporting categories setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "Content reporting. Select all reporting categories to "
                "ensure comprehensive content monitoring. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
            ),
        )

    return make_fail(
        check_id="GWS.CHAT.5.2",
        title="Ensure all Chat reporting categories are selected",
        level="L2", source="CISA", section="Google Chat",
        details="Not all Chat reporting categories are selected.",
        actual_value=all_selected,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Content reporting. Enable all reporting categories including "
            "harassment, discrimination, explicit content, spam, "
            "confidential information, and other abuse types. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
        ),
    )


# ===========================================================================
# Calendar - CISA SCuBA service-specific checks
# ===========================================================================

@check(
    check_id="GWS.CALENDAR.3.2",
    scored=False,  # P3: the interop authentication method is not exposed by the Policy API; MANUAL by design
    title="Ensure Calendar Interop uses Microsoft 365 Graph API",
    level="L2",
    source="CISA",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > "
        "Calendar Interop management. Switch the endpoint from "
        "legacy EWS to the Microsoft 365 Graph API. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    ),
)
def check_calendar_interop_auth_method(data: dict) -> CheckResult:
    """Calendar Interop should use the Microsoft 365 Graph API, not legacy EWS.

    If no Interop endpoint is configured (interop disabled), this check
    is NOT_APPLICABLE.  When an endpoint *is* configured, Graph API is
    PASS and legacy EWS (basic auth) is FAIL.
    """
    _ID = "GWS.CALENDAR.3.2"
    _TITLE = "Ensure Calendar Interop uses Microsoft 365 Graph API"
    _L, _S, _SEC = "L2", "CISA", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > "
        "Calendar Interop management. Switch the endpoint from "
        "legacy EWS to the Microsoft 365 Graph API. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    )
    _SAFE = ("graph_api", "ms365")
    _LEGACY = ("ews", "basic_auth", "basic", "legacy")

    # Calendar Interop is a global setting, not per-OU.
    policies = data.get("policies", {})
    cal = policies.get("calendar", {})
    interop = cal.get("interop", {})

    # If interop is disabled, no endpoint is configured → N/A
    interop_enabled = interop.get("exchange_interop_enabled", None)
    if interop_enabled is False:
        return CheckResult(
            check_id=_ID, title=_TITLE, status=Status.NOT_APPLICABLE,
            level=_L, source=_S, section=_SEC,
            details="Calendar Interop is disabled; no endpoint configured.",
        )

    auth_method = interop.get("auth_method", None)

    if auth_method in _SAFE:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Calendar Interop uses Microsoft 365 Graph API ('{auth_method}').",
            actual_value=auth_method, expected_value="graph_api or ms365",
        )

    if auth_method in _LEGACY:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Calendar Interop uses legacy EWS ('{auth_method}') instead of Graph API.",
            actual_value=auth_method, expected_value="graph_api or ms365",
            remediation=_REMED,
        )

    if auth_method is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Calendar Interop authentication method.",
            remediation=_REMED,
        )

    # Unknown method — flag as fail
    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Calendar Interop uses unrecognised method '{auth_method}' instead of Graph API.",
        actual_value=auth_method, expected_value="graph_api or ms365",
        remediation=_REMED,
    )


# ===========================================================================
# Groups - CISA SCuBA service-specific checks
# ===========================================================================

@check(
    check_id="GWS.GROUPS.1.1",
    title="Ensure external group access is disabled by default",
    level="L1",
    source="CISA",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set the default for external access to "
        "'disabled' to prevent groups from being accessible to users "
        "outside the organization by default. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_external_access_default(data: dict) -> CheckResult:
    """External access to groups should be disabled by default."""
    _ID = "GWS.GROUPS.1.1"
    _TITLE = "Ensure external group access is disabled by default"
    _L, _S, _SEC = "L1", "CISA", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set the default for external access to "
        "'disabled' to prevent groups from being accessible to users "
        "outside the organization by default. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def judge(entry: dict):
            # Real API exposes collaborationCapability as the master toggle
            # (DOMAIN_USERS_ONLY = safe; ANYONE_CAN_ACCESS / external = unsafe).
            # ownersCanAllowExternalMembers further refines it.
            collab = field_value(entry, "collaborationCapability")
            owners_external = field_value(entry, "ownersCanAllowExternalMembers")
            if collab is not None:
                if collab != "DOMAIN_USERS_ONLY":
                    return False, collab
                if owners_external is True:
                    return False, owners_external
                return None if owners_external is None else True
            legacy = field_value(entry, "externalAccessDefault", "external_access_default")
            if legacy in ("disabled", False, "DISABLED"):
                if owners_external is True:
                    return False, owners_external
                return None if owners_external is None else True
            return None if legacy is None else (False, legacy)

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have external group access enabled",
            pass_text="have external group access disabled by default",
            expected_value="disabled", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = groups_policy.get("sharing", {})
    external_default = sharing.get("external_access_default", None)

    if external_default in ("disabled", False):
        return make_pass(
            check_id="GWS.GROUPS.1.1",
            title="Ensure external group access is disabled by default",
            level="L1", source="CISA", section="Groups",
            details="External group access is disabled by default.",
            actual_value=external_default,
            expected_value="disabled",
        )

    if external_default is None:
        return make_manual(
            check_id="GWS.GROUPS.1.1",
            title="Ensure external group access is disabled by default",
            level="L1", source="CISA", section="Groups",
            details="Could not determine external group access default setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Disable external access to groups by default. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    return make_fail(
        check_id="GWS.GROUPS.1.1",
        title="Ensure external group access is disabled by default",
        level="L1", source="CISA", section="Groups",
        details=f"External group access default is '{external_default}' instead of disabled.",
        actual_value=external_default,
        expected_value="disabled",
        remediation=(
            "Admin console > Apps > Google Workspace > Groups for Business > "
            "Sharing settings. Set the default for external access to "
            "'disabled' to prevent groups from being accessible to users "
            "outside the organization by default. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
        ),
    )


@check(
    check_id="GWS.GROUPS.1.2",
    title="Ensure external group members are disabled by default",
    level="L2",
    source="CISA",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Disable 'Allow external members' to prevent "
        "users outside the organization from being added to groups, "
        "which could expose internal communications and resources. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_external_members(data: dict) -> CheckResult:
    """External users should not be allowed as group members by default."""
    _ID = "GWS.GROUPS.1.2"
    _TITLE = "Ensure external group members are disabled by default"
    _L, _S, _SEC = "L2", "CISA", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Disable 'Allow external members' to prevent "
        "users outside the organization from being added to groups, "
        "which could expose internal communications and resources. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def judge(entry: dict):
            owners_allow = field_value(entry, "ownersCanAllowExternalMembers")
            if owners_allow is not None:
                return owners_allow is False, owners_allow
            # collaborationCapability: FULL_COLLABORATION means external members allowed
            collab = field_value(entry, "collaborationCapability")
            if collab is not None:
                return collab != "FULL_COLLABORATION", collab
            val = field_value(entry, "allowExternalMembers", "allow_external_members")
            if val is None:
                return None
            return val in (False, "false", "FALSE"), val

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow external group members",
            pass_text="have external group members disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = groups_policy.get("sharing", {})
    allow_external = sharing.get("allow_external_members", None)

    if allow_external is False:
        return make_pass(
            check_id="GWS.GROUPS.1.2",
            title="Ensure external group members are disabled by default",
            level="L2", source="CISA", section="Groups",
            details="External group members are disabled by default.",
            actual_value=allow_external,
            expected_value="Disabled for all OUs",
        )

    if allow_external is None:
        return make_manual(
            check_id="GWS.GROUPS.1.2",
            title="Ensure external group members are disabled by default",
            level="L2", source="CISA", section="Groups",
            details="Could not determine external group members setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Disable allowing external members in groups. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    return make_fail(
        check_id="GWS.GROUPS.1.2",
        title="Ensure external group members are disabled by default",
        level="L2", source="CISA", section="Groups",
        details="External users can be added as group members.",
        actual_value=allow_external,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Groups for Business > "
            "Sharing settings. Disable 'Allow external members' to prevent "
            "users outside the organization from being added to groups, "
            "which could expose internal communications and resources. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
        ),
    )


@check(
    check_id="GWS.GROUPS.3.1",
    title="Ensure default conversation visibility is members-only",
    level="L2",
    source="CISA",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set the default conversation visibility to "
        "'Members only' to prevent non-members from viewing group "
        "discussions, which may contain sensitive information. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
    ),
)
def check_groups_conversation_visibility(data: dict) -> CheckResult:
    """Default conversation visibility should be restricted to group members only."""
    _ID = "GWS.GROUPS.3.1"
    _TITLE = "Ensure default conversation visibility is members-only"
    _L, _S, _SEC = "L2", "CISA", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set the default conversation visibility to "
        "'Members only' to prevent non-members from viewing group "
        "discussions, which may contain sensitive information. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def judge(entry: dict):
            val = field_value(entry, "viewTopicsDefaultAccessLevel", "defaultConversationVisibility",
                              "default_conversation_visibility")
            if val is None:
                return None
            # Real enum: OWNERS, MANAGERS, GROUP_MEMBERS, DOMAIN_USERS, ANYONE_CAN_VIEW_TOPICS.
            # Stricter than members-only (owners/managers) is compliant too.
            return val in ("members_only", "ALL_MEMBERS_CAN_VIEW", "MEMBERS_ONLY",
                           "ALL_MEMBERS", "GROUP_MEMBERS", "MANAGERS", "OWNERS"), val

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have conversation visibility not set to members-only",
            pass_text="have conversation visibility set to members-only",
            expected_value="members_only", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    visibility = groups_policy.get("visibility", {})
    default_visibility = visibility.get("default_conversation_visibility", None)

    if default_visibility in ("members_only", "ALL_MEMBERS_CAN_VIEW"):
        return make_pass(
            check_id="GWS.GROUPS.3.1",
            title="Ensure default conversation visibility is members-only",
            level="L2", source="CISA", section="Groups",
            details="Default conversation visibility is members-only.",
            actual_value=default_visibility,
            expected_value="members_only",
        )

    if default_visibility is None:
        return make_manual(
            check_id="GWS.GROUPS.3.1",
            title="Ensure default conversation visibility is members-only",
            level="L2", source="CISA", section="Groups",
            details="Could not determine default conversation visibility setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Set default conversation visibility to "
                "'Members only'. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
            ),
        )

    return make_fail(
        check_id="GWS.GROUPS.3.1",
        title="Ensure default conversation visibility is members-only",
        level="L2", source="CISA", section="Groups",
        details=f"Default conversation visibility is '{default_visibility}' instead of members-only.",
        actual_value=default_visibility,
        expected_value="members_only",
        remediation=(
            "Admin console > Apps > Google Workspace > Groups for Business > "
            "Sharing settings. Set the default conversation visibility to "
            "'Members only' to prevent non-members from viewing group "
            "discussions, which may contain sensitive information. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
        ),
    )
