# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CISA SCuBA (Secure Cloud Business Applications) checks for GWS Security Auditor.

Implements checks from the CISA SCuBA Security Configuration Baselines for
Google Workspace, as automated by ScubaGoggles. These checks supplement
existing CIS, OTHER, and GOOGLE checks with CISA-specific controls.

Only checks NOT already covered by CIS/OTHER/GOOGLE sources are included here.
Check IDs use the GWS.* format from ScubaGoggles.

Reference: https://github.com/cisagov/ScubaGoggles
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   field_value, ou_verdict, result_from_setting_changes, latest_setting_changes)
from ..models import CheckResult, Status


# ===========================================================================
# Gmail - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.GMAIL.4.3",
    title="Ensure DMARC alignment mode is strict",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Update DMARC DNS records to include 'aspf=s; adkim=s' for "
        "strict SPF and DKIM alignment. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
    ),
)
def check_dmarc_strict_alignment(data: dict) -> CheckResult:
    """DMARC alignment should use strict mode (aspf=s; adkim=s)."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="GWS.GMAIL.4.3",
            title="Ensure DMARC alignment mode is strict",
            level="L1", source="CISA", section="Gmail",
            details="No domains found to check DMARC alignment.",
            remediation="Verify DMARC alignment settings for all domains. https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
        )

    relaxed_domains = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dmarc = domain_dns.get("dmarc", {})
        record = str(dmarc.get("record", "") or "").lower().replace(" ", "")
        if dmarc.get("record_found", False):
            # Per RFC 7489, missing aspf/adkim tags default to relaxed ("r").
            # Only flag domains with explicit aspf=r or adkim=r.
            # Missing tags are compliant with relaxed alignment by default.
            has_aspf_r = "aspf=r" in record
            has_adkim_r = "adkim=r" in record
            if has_aspf_r or has_adkim_r:
                relaxed_domains.append(domain_name)
        else:
            # No DMARC record at all: alignment cannot be strict.
            relaxed_domains.append(f"{domain_name} (no DMARC record)")

    if not relaxed_domains:
        return make_pass(
            check_id="GWS.GMAIL.4.3",
            title="Ensure DMARC alignment mode is strict",
            level="L1", source="CISA", section="Gmail",
            details="DMARC alignment is strict for all domains.",
            actual_value={"all_strict": True},
            expected_value="aspf=s; adkim=s",
        )

    # Strict alignment is a hardening recommendation; relaxed alignment is
    # the RFC 7489 default and remains protocol-compliant. Surface as WARN
    # rather than FAIL so it shows up for review without dropping the
    # tenant's pass rate for an explicit, working DMARC posture.
    return make_warn(
        check_id="GWS.GMAIL.4.3",
        title="Ensure DMARC alignment mode is strict",
        level="L1", source="CISA", section="Gmail",
        details=f"DMARC alignment is relaxed (not strict) for: {', '.join(relaxed_domains)}",
        actual_value={"relaxed_domains": relaxed_domains},
        expected_value="aspf=s; adkim=s for all domains",
        remediation=(
            "Update DMARC DNS records to include 'aspf=s; adkim=s' for "
            "strict SPF and DKIM alignment. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
        ),
    )


@check(
    check_id="GWS.GMAIL.4.4",
    title="Ensure DMARC reporting is configured",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Add 'rua=mailto:dmarc-reports@<domain>' to DMARC DNS records "
        "for aggregate report delivery. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
    ),
)
def check_dmarc_reporting(data: dict) -> CheckResult:
    """DMARC records should include aggregate reporting (rua) configuration."""
    domains = data.get("domains", [])
    dns_records = data.get("dns_records", {})

    if not domains:
        return make_manual(
            check_id="GWS.GMAIL.4.4",
            title="Ensure DMARC reporting is configured",
            level="L1", source="CISA", section="Gmail",
            details="No domains found to check DMARC reporting.",
            remediation="Verify DMARC reporting is configured for all domains. https://knowledge.workspace.google.com/admin/security/set-up-dmarc",
        )

    missing_rua = []
    for domain in domains:
        domain_name = domain if isinstance(domain, str) else domain.get("domainName", domain.get("domain_name", ""))
        domain_dns = dns_records.get(domain_name, {})
        dmarc = domain_dns.get("dmarc", {})
        record = str(dmarc.get("record", "") or "").lower().replace(" ", "")
        if not dmarc.get("record_found", False):
            missing_rua.append(f"{domain_name} (no DMARC record)")
        elif "rua=" not in record:
            missing_rua.append(domain_name)

    if not missing_rua:
        return make_pass(
            check_id="GWS.GMAIL.4.4",
            title="Ensure DMARC reporting is configured",
            level="L1", source="CISA", section="Gmail",
            details="DMARC aggregate reporting is configured for all domains.",
            actual_value={"all_configured": True},
            expected_value="rua= tag present in DMARC records",
        )

    return make_fail(
        check_id="GWS.GMAIL.4.4",
        title="Ensure DMARC reporting is configured",
        level="L1", source="CISA", section="Gmail",
        details=f"DMARC reporting (rua=) missing for: {', '.join(missing_rua)}",
        actual_value={"missing_rua_domains": missing_rua},
        expected_value="rua= tag in all DMARC records",
        remediation=(
            "Add 'rua=mailto:dmarc-reports@<domain>' to DMARC DNS records "
            "for aggregate report delivery. https://knowledge.workspace.google.com/admin/security/set-up-dmarc"
        ),
    )


@check(
    check_id="GWS.GMAIL.8.1",
    title="Ensure user email uploads are disabled",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Setup > "
        "User email uploads. Disable user email imports. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_gmail_email_uploads(data: dict) -> CheckResult:
    """Users should not be able to upload email from external providers."""
    _ID = "GWS.GMAIL.8.1"
    _TITLE = "Ensure user email uploads are disabled"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Setup > "
        "User email uploads. Disable user email imports. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "user_email_uploads")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "enableMailAndContactsImport", "enableMailImport", "enabled")
            if enabled is None:
                return None
            return (enabled is False, enabled)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have email uploads enabled", pass_text="have email uploads disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    user_settings = gmail.get("user_settings", {})
    uploads_enabled = user_settings.get("email_uploads_enabled", None)

    if uploads_enabled is False:
        return make_pass(
            check_id="GWS.GMAIL.8.1",
            title="Ensure user email uploads are disabled",
            level="L1", source="CISA", section="Gmail",
            details="User email uploads are disabled.",
            actual_value=uploads_enabled,
            expected_value="Disabled for all OUs",
        )

    if uploads_enabled is None:
        return make_manual(
            check_id="GWS.GMAIL.8.1",
            title="Ensure user email uploads are disabled",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine email uploads setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Setup > "
                "User email uploads. Disable user email imports. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.GMAIL.8.1",
        title="Ensure user email uploads are disabled",
        level="L1", source="CISA", section="Gmail",
        details="User email uploads are enabled.",
        actual_value=uploads_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Setup > "
            "User email uploads. Disable to prevent importing mail from "
            "external providers. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.GMAIL.10.1",
    title="Ensure Google Workspace Sync is disabled",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable Google Workspace Sync for "
        "Microsoft Outlook to prevent data syncing to local clients. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_gmail_workspace_sync(data: dict) -> CheckResult:
    """Google Workspace Sync for Microsoft Outlook should be disabled."""
    _ID = "GWS.GMAIL.10.1"
    _TITLE = "Ensure Google Workspace Sync is disabled"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > "
        "End User Access. Disable Google Workspace Sync for "
        "Microsoft Outlook to prevent data syncing to local clients. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "workspace_sync_for_outlook")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "enableGoogleWorkspaceSyncForMicrosoftOutlook", "enableWorkspaceSync")
            if enabled is None:
                return None
            return (enabled is False, enabled)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Workspace Sync enabled", pass_text="have Workspace Sync disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    end_user = gmail.get("end_user_access", {})
    sync_enabled = end_user.get("workspace_sync_enabled", None)

    if sync_enabled is False:
        return make_pass(
            check_id="GWS.GMAIL.10.1",
            title="Ensure Google Workspace Sync is disabled",
            level="L1", source="CISA", section="Gmail",
            details="Google Workspace Sync is disabled.",
            actual_value=sync_enabled,
            expected_value="Disabled for all OUs",
        )

    if sync_enabled is None:
        return make_manual(
            check_id="GWS.GMAIL.10.1",
            title="Ensure Google Workspace Sync is disabled",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine Workspace Sync setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > "
                "End User Access. Disable Google Workspace Sync. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.GMAIL.10.1",
        title="Ensure Google Workspace Sync is disabled",
        level="L1", source="CISA", section="Gmail",
        details="Google Workspace Sync is enabled.",
        actual_value=sync_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > "
            "End User Access. Disable Google Workspace Sync for "
            "Microsoft Outlook to prevent data syncing to local clients. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.GMAIL.14.1",
    title="Ensure email allowlist is not used",
    level="L1",
    source="CISA",
    section="Gmail",
    remediation=(
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all entries from the email allowlist. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    ),
)
def check_gmail_email_allowlist(data: dict) -> CheckResult:
    """Email allowlists should not bypass spam filtering."""
    _ID = "GWS.GMAIL.14.1"
    _TITLE = "Ensure email allowlist is not used"
    _L, _S, _SEC = "L1", "CISA", "Gmail"
    _REMED = (
        "Admin console > Apps > Google Workspace > Gmail > Spam, "
        "Phishing and Malware. Remove all entries from the email allowlist. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
    )

    policies = data.get("policies", {})
    gmail = policies.get("gmail", {})

    # OU-aware path
    ou_values = get_ou_values(gmail, "email_spam_filter_ip_allowlist")
    if ou_values:
        def _judge(entry):
            allowlist_val = field_value(entry, "allowedIpAddresses", "allowlist")
            if allowlist_val is None:
                return None
            if isinstance(allowlist_val, list):
                return (len(allowlist_val) == 0, len(allowlist_val))
            if isinstance(allowlist_val, str):
                return (not allowlist_val, allowlist_val)
            return None

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have email allowlist entries", pass_text="have no email allowlist entries",
            expected_value="No allowlisted addresses", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    spam = gmail.get("spam_settings", {})
    allowlist = spam.get("email_allowlist", [])
    allowlist_enabled = spam.get("email_allowlist_enabled", None)

    if allowlist_enabled is False or (isinstance(allowlist, list) and len(allowlist) == 0):
        return make_pass(
            check_id="GWS.GMAIL.14.1",
            title="Ensure email allowlist is not used",
            level="L1", source="CISA", section="Gmail",
            details="No email allowlist is configured.",
            actual_value={"allowlist_count": 0},
            expected_value="No allowlisted addresses",
        )

    if allowlist_enabled is None and not allowlist:
        return make_manual(
            check_id="GWS.GMAIL.14.1",
            title="Ensure email allowlist is not used",
            level="L1", source="CISA", section="Gmail",
            details="Could not determine email allowlist configuration.",
            remediation=(
                "Admin console > Apps > Google Workspace > Gmail > Spam, "
                "Phishing and Malware. Remove all entries from the email allowlist. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.GMAIL.14.1",
        title="Ensure email allowlist is not used",
        level="L1", source="CISA", section="Gmail",
        details=f"Email allowlist has {len(allowlist)} entries that bypass spam filtering.",
        actual_value={"allowlist_count": len(allowlist)},
        expected_value="No allowlisted addresses",
        remediation=(
            "Admin console > Apps > Google Workspace > Gmail > Spam, "
            "Phishing and Malware. Remove all email allowlist entries. "
            "Allowlisted senders bypass spam filters which could be exploited. https://knowledge.workspace.google.com/admin/gmail/manage-gmail-settings-for-your-users"
        ),
    )


# ===========================================================================
# Calendar - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.CALENDAR.3.1",
    title="Ensure Calendar Interop is disabled",
    level="L1",
    source="CISA",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > "
        "Calendar Interop management. Disable Exchange Interop "
        "unless required for mission operations. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    ),
)
def check_calendar_interop_disabled(data: dict) -> CheckResult:
    """Calendar Interop with Exchange should be disabled unless required."""
    _ID = "GWS.CALENDAR.3.1"
    _TITLE = "Ensure Calendar Interop is disabled"
    _L, _S, _SEC = "L1", "CISA", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > "
        "Calendar Interop management. Disable Exchange Interop "
        "unless required for mission operations. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    )

    # Calendar Interop is a global (org-wide) setting, not per-OU.
    policies = data.get("policies", {})
    cal = policies.get("calendar", {})
    interop = cal.get("interop", {})
    interop_enabled = interop.get("exchange_interop_enabled", None)

    if interop_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Calendar Interop with Exchange is disabled.",
            actual_value=interop_enabled, expected_value="Disabled for all OUs",
        )

    if interop_enabled is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Calendar Interop setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Calendar Interop with Exchange is enabled.",
        actual_value=interop_enabled, expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="GWS.CALENDAR.4.1",
    title="Ensure paid appointment scheduling is disabled",
    level="L1",
    source="CISA",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > "
        "General settings. Turn off 'Appointment schedules with payments'. https://knowledge.workspace.google.com/admin/calendar/allow-paid-appointment-schedules-in-calendar"
    ),
    requires_license="business_standard",
)
def check_calendar_paid_appointments(data: dict) -> CheckResult:
    """Paid appointment scheduling should be disabled to reduce attack surface."""
    _ID = "GWS.CALENDAR.4.1"
    _TITLE = "Ensure paid appointment scheduling is disabled"
    _L, _S, _SEC = "L1", "CISA", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > "
        "General settings. Turn off 'Appointment schedules with payments'. https://knowledge.workspace.google.com/admin/calendar/allow-paid-appointment-schedules-in-calendar"
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(cal, "appointment_schedules")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "enablePayments", "paidAppointmentsEnabled", "enabled")
            if enabled is None:
                return None
            return (enabled is False, enabled)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have paid appointments enabled", pass_text="have paid appointments disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    appointments = cal.get("appointments", {})
    paid_enabled = appointments.get("paid_appointments_enabled", None)

    if paid_enabled is False:
        return make_pass(
            check_id="GWS.CALENDAR.4.1",
            title="Ensure paid appointment scheduling is disabled",
            level="L1", source="CISA", section="Calendar",
            details="Paid appointment scheduling is disabled.",
            actual_value=paid_enabled,
            expected_value="Disabled for all OUs",
        )

    if paid_enabled is None:
        return make_manual(
            check_id="GWS.CALENDAR.4.1",
            title="Ensure paid appointment scheduling is disabled",
            level="L1", source="CISA", section="Calendar",
            details="Could not determine paid appointment scheduling setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Calendar > "
                "General settings. Turn off 'Appointment schedules with payments'. https://knowledge.workspace.google.com/admin/calendar/allow-paid-appointment-schedules-in-calendar"
            ),
        )

    return make_fail(
        check_id="GWS.CALENDAR.4.1",
        title="Ensure paid appointment scheduling is disabled",
        level="L1", source="CISA", section="Calendar",
        details="Paid appointment scheduling is enabled.",
        actual_value=paid_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Calendar > "
            "General settings. Disable paid appointment scheduling "
            "to minimize unnecessary functionality. https://knowledge.workspace.google.com/admin/calendar/allow-paid-appointment-schedules-in-calendar"
        ),
    )


# ===========================================================================
# Chat - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.CHAT.1.1",
    title="Ensure Chat history is enabled",
    level="L1",
    source="CISA",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "History for chats. Enable history for compliance and audit. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
)
def check_chat_history_enabled(data: dict) -> CheckResult:
    """Chat history should be enabled for information traceability."""
    _ID = "GWS.CHAT.1.1"
    _TITLE = "Ensure Chat history is enabled"
    _L, _S, _SEC = "L1", "CISA", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "History for chats. Enable history for compliance and audit. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    # chat.chat_history carries historyOnByDefault; chat.space_history (historyState)
    # is the separate spaces setting evaluated by GWS.CHAT.3.1.
    ou_values = get_ou_values(chat, "chat_history")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "historyOnByDefault", "historyEnabled")
            if enabled is None:
                # historyState kept for old caches that only had space_history
                history_state = field_value(entry, "historyState")
                if not history_state:
                    return None
                enabled = history_state in ("DEFAULT_HISTORY_ON", "HISTORY_ALWAYS_ON", "ALWAYS_ON")
            return (enabled is True, enabled)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Chat history disabled", pass_text="have Chat history enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    history = chat.get("history", {})
    history_enabled = history.get("history_enabled", None)
    if history_enabled is None:
        history_enabled = history.get("history_on_by_default", None)

    if history_enabled is True:
        return make_pass(
            check_id="GWS.CHAT.1.1",
            title="Ensure Chat history is enabled",
            level="L1", source="CISA", section="Google Chat",
            details="Chat history is enabled.",
            actual_value=history_enabled,
            expected_value="Enabled for all OUs",
        )

    if history_enabled is None:
        return make_manual(
            check_id="GWS.CHAT.1.1",
            title="Ensure Chat history is enabled",
            level="L1", source="CISA", section="Google Chat",
            details="Could not determine Chat history setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "History for chats. Enable history for compliance and audit. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.CHAT.1.1",
        title="Ensure Chat history is enabled",
        level="L1", source="CISA", section="Google Chat",
        details="Chat history is not enabled.",
        actual_value=history_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "History for chats. Enable history to ensure traceability. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )


@check(
    check_id="GWS.CHAT.1.2",
    title="Ensure users cannot change Chat history setting",
    level="L1",
    source="CISA",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "History for chats. Prevent users from changing their history setting. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    ),
)
def check_chat_history_user_control(data: dict) -> CheckResult:
    """Users should not be allowed to change their Chat history setting."""
    _ID = "GWS.CHAT.1.2"
    _TITLE = "Ensure users cannot change Chat history setting"
    _L, _S, _SEC = "L1", "CISA", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "History for chats. Prevent users from changing their history setting. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    # allowUserModification lives on chat.chat_history, not chat.space_history
    ou_values = get_ou_values(chat, "chat_history")
    if ou_values:
        def _judge(entry):
            user_mod = field_value(entry, "allowUserModification", "allow_user_modification")
            if user_mod is None:
                return None
            return (user_mod is False, user_mod)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow users to change Chat history", pass_text="prevent user Chat history modification",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    history = chat.get("history", {})
    user_can_change = history.get("allow_user_modification", None)

    if user_can_change is False:
        return make_pass(
            check_id="GWS.CHAT.1.2",
            title="Ensure users cannot change Chat history setting",
            level="L1", source="CISA", section="Google Chat",
            details="Users cannot modify their Chat history setting.",
            actual_value=user_can_change,
            expected_value="Disabled for all OUs",
        )

    if user_can_change is None:
        return make_manual(
            check_id="GWS.CHAT.1.2",
            title="Ensure users cannot change Chat history setting",
            level="L1", source="CISA", section="Google Chat",
            details="Could not determine user history modification setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "History for chats. Prevent users from changing their history setting. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.CHAT.1.2",
        title="Ensure users cannot change Chat history setting",
        level="L1", source="CISA", section="Google Chat",
        details="Users can change their Chat history setting.",
        actual_value=user_can_change,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "History for chats. Disable user ability to modify history setting. https://knowledge.workspace.google.com/admin/chat/set-up-chat-for-your-organization"
        ),
    )


@check(
    check_id="GWS.CHAT.5.1",
    title="Ensure Chat content reporting is enabled",
    level="L1",
    source="CISA",
    section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Content reporting. Enable reporting for all conversation types. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
    ),
    requires_license="enterprise_plus",
)
def check_chat_content_reporting(data: dict) -> CheckResult:
    """Chat content reporting should be enabled for all conversation types."""
    _ID = "GWS.CHAT.5.1"
    _TITLE = "Ensure Chat content reporting is enabled"
    _L, _S, _SEC = "L1", "CISA", "Google Chat"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Chat > "
        "Content reporting. Enable reporting for all conversation types. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
    )

    policies = data.get("policies", {})
    chat = policies.get("chat", {})

    # OU-aware path
    ou_values = get_ou_values(chat, "content_reporting")
    if ou_values:
        def _judge(entry):
            # Real fields: oneOnOneDirectMessagesReporting, groupDirectMessagesReporting,
            # spacesReporting (CONTENT_REPORTING_STATE_* enums). The enabled/disabled
            # members are not documented; *_UNSPECIFIED (seen live on editions without
            # the feature) is unknown.
            states = [field_value(entry, f) for f in ("oneOnOneDirectMessagesReporting",
                                                      "groupDirectMessagesReporting", "spacesReporting")]
            if any(st is None for st in states):
                return None
            off = [st for st in states if "DISABLED" in str(st).upper() or str(st).upper().endswith("_OFF")]
            on = [st for st in states if "ENABLED" in str(st).upper() or str(st).upper().endswith("_ON")]
            if off:
                return (False, ", ".join(sorted(set(off))))
            if len(on) == len(states):
                return (True, "enabled")
            return None

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Chat content reporting disabled", pass_text="have Chat content reporting enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    reporting = chat.get("content_reporting", {})
    reporting_enabled = reporting.get("enabled", None)

    if reporting_enabled is True:
        return make_pass(
            check_id="GWS.CHAT.5.1",
            title="Ensure Chat content reporting is enabled",
            level="L1", source="CISA", section="Google Chat",
            details="Chat content reporting is enabled.",
            actual_value=reporting_enabled,
            expected_value="Enabled for all OUs",
        )

    if reporting_enabled is None:
        return make_manual(
            check_id="GWS.CHAT.5.1",
            title="Ensure Chat content reporting is enabled",
            level="L1", source="CISA", section="Google Chat",
            details="Could not determine Chat content reporting setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Chat > "
                "Content reporting. Enable reporting for all conversation types. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
            ),
        )

    return make_fail(
        check_id="GWS.CHAT.5.1",
        title="Ensure Chat content reporting is enabled",
        level="L1", source="CISA", section="Google Chat",
        details="Chat content reporting is not enabled.",
        actual_value=reporting_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > "
            "Content reporting. Enable for direct messages, group "
            "conversations, and spaces. https://knowledge.workspace.google.com/admin/chat/chat-content-protection"
        ),
    )


# ===========================================================================
# Drive and Docs - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.DRIVEDOCS.1.2",
    title="Ensure receiving files from non-allowlisted domains is disabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable receiving files from non-allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_receive_non_allowlisted(data: dict) -> CheckResult:
    """Receiving files from outside allowlisted domains should be disabled."""
    _ID = "GWS.DRIVEDOCS.1.2"
    _TITLE = "Ensure receiving files from non-allowlisted domains is disabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable receiving files from non-allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry):
            mode = field_value(entry, "externalSharingMode")
            outside_allowlist = field_value(entry, "allowReceivingFilesOutsideAllowlistedDomains",
                                            "receiveFilesFromNonAllowlisted")
            external = field_value(entry, "allowReceivingExternalFiles", "receiveFilesFromNonAllowlisted")
            if mode == "ALLOWLISTED_DOMAINS":
                # Receiving from allowlisted domains is the point of allowlist mode;
                # the control is about files from OUTSIDE the allowlist.
                receive = outside_allowlist
            elif mode is None:
                # Mode unknown: only "both off" is a verdict, anything else depends on the mode.
                if external is False and outside_allowlist is False:
                    return (True, False)
                return None
            else:
                receive = external
            if receive is None:
                return None
            return (receive is False, receive)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow receiving from non-allowlisted domains",
            pass_text="block receiving from non-allowlisted domains",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    receive_external = sharing.get("receive_files_from_non_allowlisted", None)

    if receive_external is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.2",
            title="Ensure receiving files from non-allowlisted domains is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Receiving files from non-allowlisted domains is disabled.",
            actual_value=receive_external,
            expected_value="Disabled for all OUs",
        )

    if receive_external is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.2",
            title="Ensure receiving files from non-allowlisted domains is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine external file receiving setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Disable receiving files from non-allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.2",
        title="Ensure receiving files from non-allowlisted domains is disabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="Receiving files from non-allowlisted domains is enabled.",
        actual_value=receive_external,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Disable receiving files from external sources "
            "outside allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.4",
    title="Ensure sharing with non-Google accounts is disabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable sharing with non-Google account users. https://knowledge.workspace.google.com/admin/drive/allow-sharing-to-non-google-users-with-visitor-sharing"
    ),
)
def check_drive_non_google_sharing(data: dict) -> CheckResult:
    """Sharing with users who don't have Google accounts should be disabled."""
    _ID = "GWS.DRIVEDOCS.1.4"
    _TITLE = "Ensure sharing with non-Google accounts is disabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable sharing with non-Google account users. https://knowledge.workspace.google.com/admin/drive/allow-sharing-to-non-google-users-with-visitor-sharing"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry):
            mode = field_value(entry, "externalSharingMode")
            if mode == "DISALLOWED":
                return True  # no external sharing at all
            in_allowlist = field_value(entry, "allowNonGoogleInvitesInAllowlistedDomains")
            anywhere = field_value(entry, "allowNonGoogleInvites", "sharingWithNonGoogleUsers",
                                   "allowNonGoogleAccountSharing")
            if mode == "ALLOWLISTED_DOMAINS":
                non_google_val = in_allowlist
            elif mode is None:
                # Mode unknown: only "both off" is a verdict, anything else depends on the mode.
                if anywhere is False and in_allowlist is False:
                    return (True, False)
                return None
            else:
                non_google_val = anywhere
            if non_google_val is None:
                return None
            return (non_google_val is False, non_google_val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow sharing with non-Google accounts",
            pass_text="disable sharing with non-Google accounts",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    non_google = sharing.get("allow_non_google_account_sharing", None)

    if non_google is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.4",
            title="Ensure sharing with non-Google accounts is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Sharing with non-Google accounts is disabled.",
            actual_value=non_google,
            expected_value="Disabled for all OUs",
        )

    if non_google is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.4",
            title="Ensure sharing with non-Google accounts is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine non-Google account sharing setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Disable sharing with non-Google account users. https://knowledge.workspace.google.com/admin/drive/allow-sharing-to-non-google-users-with-visitor-sharing"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.4",
        title="Ensure sharing with non-Google accounts is disabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="Sharing with non-Google accounts is enabled.",
        actual_value=non_google,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Disable sharing with non-Google account "
            "users to ensure authenticated access only. https://knowledge.workspace.google.com/admin/drive/allow-sharing-to-non-google-users-with-visitor-sharing"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.5",
    title="Ensure 'anyone with the link' sharing is disabled",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable 'anyone with the link' option "
        "to prevent overly permissive link-based access. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
    ),
)
def check_drive_anyone_with_link(data: dict) -> CheckResult:
    """'Anyone with the link' sharing option should be disabled."""
    _ID = "GWS.DRIVEDOCS.1.5"
    _TITLE = "Ensure 'anyone with the link' sharing is disabled"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable 'anyone with the link' option "
        "to prevent overly permissive link-based access. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry):
            mode = field_value(entry, "externalSharingMode")
            # External sharing fully off -> nothing can be published
            if mode == "DISALLOWED":
                return True
            # Policy API field is allowPublishingFiles (drive_and_docs.external_sharing)
            anyone_link_val = field_value(entry, "allowPublishingFiles", "anyoneWithLinkEnabled", "publishToWeb")
            if anyone_link_val is None:
                return None
            if anyone_link_val is False:
                return (True, anyone_link_val)
            # Publishing allowed: unsafe unless the (unknown) mode turns out to be DISALLOWED
            return None if mode is None else (False, anyone_link_val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow 'anyone with the link' sharing",
            pass_text="disable 'anyone with the link' sharing",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    anyone_link = sharing.get("anyone_with_link_enabled", None)

    if anyone_link is False:
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.5",
            title="Ensure 'anyone with the link' sharing is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="'Anyone with the link' sharing is disabled.",
            actual_value=anyone_link,
            expected_value="Disabled for all OUs",
        )

    if anyone_link is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.5",
            title="Ensure 'anyone with the link' sharing is disabled",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine 'anyone with the link' setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Disable 'When sharing outside of your "
                "organization is allowed, users can make files accessible "
                "to anyone with the link'. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.5",
        title="Ensure 'anyone with the link' sharing is disabled",
        level="L1", source="CISA", section="Drive and Docs",
        details="'Anyone with the link' sharing is enabled, allowing unauthenticated access.",
        actual_value=anyone_link,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Disable 'anyone with the link' option "
            "to prevent overly permissive link-based access. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.1.8",
    title="Ensure default access for new items is 'private to owner'",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set default link sharing access for new "
        "items to 'Private to the owner'. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
    ),
)
def check_drive_default_access(data: dict) -> CheckResult:
    """Default access for newly created items should be 'private to the owner'."""
    _ID = "GWS.DRIVEDOCS.1.8"
    _TITLE = "Ensure default access for new items is 'private to owner'"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set default link sharing access for new "
        "items to 'Private to the owner'. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
    )
    # The Cloud Identity Policy API returns LINK_SHARING_PRIVATE as the
    # default enum value (see GOOGLE_DEFAULTS in policy.py).
    _SAFE = ("private", "private_to_owner", "PRIVATE", "PRIVATE_TO_OWNER",
             "link_sharing_private", "LINK_SHARING_PRIVATE")

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "general_access_default")
    if ou_values:
        def _judge(entry):
            access = field_value(entry, "defaultFileAccess", "defaultAccess", "generalAccessDefault")
            if access is None or access == "":
                return None
            return (str(access).lower() in ("private", "private_to_owner", "link_sharing_private"), access)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have non-private default access", pass_text="have default access set to private",
            expected_value="private_to_owner", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = drive.get("sharing_settings", {})
    default_access = sharing.get("default_link_sharing_access", "")

    if default_access in ("private", "private_to_owner", "link_sharing_private"):
        return make_pass(
            check_id="GWS.DRIVEDOCS.1.8",
            title="Ensure default access for new items is 'private to owner'",
            level="L1", source="CISA", section="Drive and Docs",
            details="Default access for new items is set to private.",
            actual_value=default_access,
            expected_value="private_to_owner",
        )

    if not default_access:
        return make_manual(
            check_id="GWS.DRIVEDOCS.1.8",
            title="Ensure default access for new items is 'private to owner'",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine default access setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Set default link sharing to 'Private to the owner'. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.1.8",
        title="Ensure default access for new items is 'private to owner'",
        level="L1", source="CISA", section="Drive and Docs",
        details=f"Default access is '{default_access}' instead of 'private to owner'.",
        actual_value=default_access,
        expected_value="private_to_owner",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings. Set default link sharing access for new "
            "items to 'Private to the owner'. https://knowledge.workspace.google.com/admin/drive/set-general-access-sharing-options-for-your-organization"
        ),
    )


@check(
    check_id="GWS.DRIVEDOCS.3.1",
    title="Ensure security updates for files are applied",
    level="L1",
    source="CISA",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Security update for files. Apply security updates to files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_security_updates(data: dict) -> CheckResult:
    """Security updates should be applied to Drive files."""
    _ID = "GWS.DRIVEDOCS.3.1"
    _TITLE = "Ensure security updates for files are applied"
    _L, _S, _SEC = "L1", "CISA", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Security update for files. Apply security updates to files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "file_security_update")
    if ou_values:
        def _judge(entry):
            raw = field_value(entry, "securityUpdate", "security_update")
            if raw is None:
                return None
            updates = raw == "APPLY_TO_IMPACTED_FILES" if isinstance(raw, str) else raw
            if updates is not True:
                return (False, updates)
            manage = field_value(entry, "allowUsersToManageUpdate")
            if manage is True:
                # Update applied, but users may remove it from their files
                return (False, "allowUsersToManageUpdate=True")
            if manage is None:
                return None
            return (True, updates)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not have file security updates applied",
            pass_text="have file security updates applied",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    features = drive.get("features", {})
    security_updates = features.get("security_update_for_files", None)

    if security_updates is True:
        return make_pass(
            check_id="GWS.DRIVEDOCS.3.1",
            title="Ensure security updates for files are applied",
            level="L1", source="CISA", section="Drive and Docs",
            details="Security updates for files are enabled.",
            actual_value=security_updates,
            expected_value="Enabled for all OUs",
        )

    if security_updates is None:
        return make_manual(
            check_id="GWS.DRIVEDOCS.3.1",
            title="Ensure security updates for files are applied",
            level="L1", source="CISA", section="Drive and Docs",
            details="Could not determine file security updates setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings > Security update for files. Apply security updates to files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.DRIVEDOCS.3.1",
        title="Ensure security updates for files are applied",
        level="L1", source="CISA", section="Drive and Docs",
        details="Security updates for files are not applied.",
        actual_value=security_updates,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Drive and Docs > "
            "Sharing settings > Security update for files. Enable security updates to "
            "apply resource key requirements to existing files. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
        ),
    )


# ===========================================================================
# Meet - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.MEET.1.1",
    title="Ensure external users must ask to join meetings",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable 'Require external participants "
        "to ask to join' to prevent uninvited attendees. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
    ),
)
def check_meet_external_join(data: dict) -> CheckResult:
    """External users who were not explicitly invited must ask to join meetings."""
    _ID = "GWS.MEET.1.1"
    _TITLE = "Ensure external users must ask to join meetings"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable 'Require external participants "
        "to ask to join' to prevent uninvited attendees. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    ou_values = get_ou_values(meet, "meet_joining")
    if ou_values:
        def _judge(entry):
            audience = field_value(entry, "allowedAudience", "externalUsersMustAskToJoin", "knockToJoinRequired")
            if audience is None:
                return None
            # Documented members: OPEN, TRUSTED, RESTRICTED (invited participants only).
            # TRUSTED and the stricter RESTRICTED satisfy the control; SAME_DOMAIN* are legacy aliases.
            if isinstance(audience, str):
                ask = audience in ("TRUSTED", "RESTRICTED", "SAME_DOMAIN", "SAME_DOMAIN_ONLY")
            else:
                ask = audience is True
            return (ask, audience)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow external users to join without asking",
            pass_text="require external users to ask to join",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    safety = meet.get("safety", {})
    external_ask = safety.get("external_users_must_ask_to_join", None)
    joining = meet.get("joining_controls", {})
    if external_ask is None:
        external_ask = joining.get("knock_to_join_required", None)

    if external_ask is True:
        return make_pass(
            check_id="GWS.MEET.1.1",
            title="Ensure external users must ask to join meetings",
            level="L1", source="CISA", section="Google Meet",
            details="External users must ask to join meetings.",
            actual_value=external_ask,
            expected_value="Enabled for all OUs",
        )

    if external_ask is None:
        return make_manual(
            check_id="GWS.MEET.1.1",
            title="Ensure external users must ask to join meetings",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine external join policy.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet safety settings. Require external participants to ask to join. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.1.1",
        title="Ensure external users must ask to join meetings",
        level="L1", source="CISA", section="Google Meet",
        details="External users can join meetings without asking.",
        actual_value=external_ask,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet safety settings. Enable 'Require external participants "
            "to ask to join' to prevent uninvited attendees. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.MEET.2.1",
    title="Ensure non-GWS tenant meeting access is disabled",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Disable meeting access for meetings "
        "created by non-Workspace tenant users. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
    ),
)
def check_meet_non_gws_access(data: dict) -> CheckResult:
    """Meeting access should be disabled for non-GWS tenant meetings."""
    _ID = "GWS.MEET.2.1"
    _TITLE = "Ensure non-GWS tenant meeting access is disabled"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Disable meeting access for meetings "
        "created by non-Workspace tenant users. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    # SCuBA 2.1 is meet.safety_access.meetingsAllowedToJoin (which meetings users may
    # join); meet.safety_domain.usersAllowedToJoin is the separate 1.1 setting.
    ou_values = (get_ou_values(meet, "safety_access")
                 or get_ou_values(meet, "safety_domain"))
    if ou_values:
        # "ALL" means anyone can join (insecure); safe values restrict to org
        _SAFE_DOMAIN = ("SAME_ORGANIZATION_ONLY", "ANY_WORKSPACE_ORGANIZATION",
                        "SAME_DOMAIN_ONLY", "TRUSTED_DOMAINS", False)

        def _judge(entry):
            users = field_value(entry, "meetingsAllowedToJoin", "usersAllowedToJoin",
                                "nonWorkspaceMeetingsAllowed", "enabled")
            if users is None:
                return None
            return (users in _SAFE_DOMAIN, users)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow non-GWS meeting access", pass_text="disable non-GWS meeting access",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    safety = meet.get("safety", {})
    non_gws_access = safety.get("non_workspace_meetings_allowed", None)

    if non_gws_access is False:
        return make_pass(
            check_id="GWS.MEET.2.1",
            title="Ensure non-GWS tenant meeting access is disabled",
            level="L1", source="CISA", section="Google Meet",
            details="Access to non-Workspace meetings is disabled.",
            actual_value=non_gws_access,
            expected_value="Disabled for all OUs",
        )

    if non_gws_access is None:
        return make_manual(
            check_id="GWS.MEET.2.1",
            title="Ensure non-GWS tenant meeting access is disabled",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine non-GWS meeting access setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet safety settings. Disable access to meetings created "
                "by non-Workspace users. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.2.1",
        title="Ensure non-GWS tenant meeting access is disabled",
        level="L1", source="CISA", section="Google Meet",
        details="Users can join meetings created by non-Workspace users.",
        actual_value=non_gws_access,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet safety settings. Disable meeting access for meetings "
            "created by non-Workspace tenant users. https://knowledge.workspace.google.com/admin/meet/manage-meeting-access-settings-for-your-users"
        ),
    )


@check(
    check_id="GWS.MEET.3.1",
    title="Ensure host management is enabled",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable host management to restrict "
        "participant controls over meeting operations. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
    ),
)
def check_meet_host_management(data: dict) -> CheckResult:
    """Host management features should be enabled for meeting control."""
    _ID = "GWS.MEET.3.1"
    _TITLE = "Ensure host management is enabled"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable host management to restrict "
        "participant controls over meeting operations. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    ou_values = get_ou_values(meet, "safety_host_management")
    if ou_values:
        def _judge(entry):
            enabled = field_value(entry, "enableHostManagement", "hostManagementEnabled", "enabled")
            if enabled is None:
                return None
            return (enabled is True, enabled)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have host management disabled", pass_text="have host management enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    safety = meet.get("safety", {})
    host_mgmt = safety.get("host_management_enabled", None)

    if host_mgmt is True:
        return make_pass(
            check_id="GWS.MEET.3.1",
            title="Ensure host management is enabled",
            level="L1", source="CISA", section="Google Meet",
            details="Host management features are enabled.",
            actual_value=host_mgmt,
            expected_value="Enabled for all OUs",
        )

    if host_mgmt is None:
        return make_manual(
            check_id="GWS.MEET.3.1",
            title="Ensure host management is enabled",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine host management setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet safety settings. Enable host management features. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.3.1",
        title="Ensure host management is enabled",
        level="L1", source="CISA", section="Google Meet",
        details="Host management features are not enabled.",
        actual_value=host_mgmt,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet safety settings. Enable host management to restrict "
            "participant controls over meeting operations. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
        ),
    )


@check(
    check_id="GWS.MEET.4.1",
    title="Ensure external participant warning is enabled",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable 'Warn for external participants' "
        "to label external or unidentified attendees. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
    ),
)
def check_meet_external_warning(data: dict) -> CheckResult:
    """Warning for external participants should be enabled."""
    _ID = "GWS.MEET.4.1"
    _TITLE = "Ensure external participant warning is enabled"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings. Enable 'Warn for external participants' "
        "to label external or unidentified attendees. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    ou_values = get_ou_values(meet, "safety_external_participants")
    if ou_values:
        def _judge(entry):
            warn = field_value(entry, "enableExternalLabel", "warnForExternalParticipants", "enabled")
            if warn is None:
                return None
            return (warn is True, warn)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack external participant warning",
            pass_text="have external participant warning enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    safety = meet.get("safety", {})
    ext_warning = safety.get("warn_for_external_participants", None)

    if ext_warning is True:
        return make_pass(
            check_id="GWS.MEET.4.1",
            title="Ensure external participant warning is enabled",
            level="L1", source="CISA", section="Google Meet",
            details="External participant warning is enabled.",
            actual_value=ext_warning,
            expected_value="Enabled for all OUs",
        )

    if ext_warning is None:
        return make_manual(
            check_id="GWS.MEET.4.1",
            title="Ensure external participant warning is enabled",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine external participant warning setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet safety settings. Enable 'Warn for external participants'. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.4.1",
        title="Ensure external participant warning is enabled",
        level="L1", source="CISA", section="Google Meet",
        details="External participant warning is not enabled.",
        actual_value=ext_warning,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet safety settings. Enable 'Warn for external participants' "
            "to label external or unidentified attendees. https://knowledge.workspace.google.com/admin/meet/manage-meet-settings"
        ),
    )


@check(
    check_id="GWS.MEET.5.1",
    title="Ensure incoming calls are restricted to organization",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings > Incoming call restrictions. Restrict incoming calls to contacts and "
        "other users in the organization. https://knowledge.workspace.google.com/admin/meet/restrict-who-can-call-my-organizations-users-with-google-meet"
    ),
)
def check_meet_incoming_calls(data: dict) -> CheckResult:
    """Incoming calls should be restricted to contacts and org users."""
    _ID = "GWS.MEET.5.1"
    _TITLE = "Ensure incoming calls are restricted to organization"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet safety settings > Incoming call restrictions. Restrict incoming calls to contacts and "
        "other users in the organization. https://knowledge.workspace.google.com/admin/meet/restrict-who-can-call-my-organizations-users-with-google-meet"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    ou_values = get_ou_values(meet, "meet_incoming_call_restrictions")
    if ou_values:
        def _judge(entry):
            callers = field_value(entry, "allowedCallers", "incomingCallsRestricted")
            if callers is None:
                return None
            # Documented members: ALL, CONTACTS_AND_ORGANIZATION_ONLY, NONE (nobody may call).
            # Anything stricter than "all callers" satisfies the control; the rest are legacy aliases.
            restricted = callers in ("CONTACTS_AND_ORGANIZATION_ONLY", "NONE", "CONTACTS_ONLY",
                                     "ORGANIZATION_ONLY", True)
            return (restricted, callers)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not restrict incoming calls", pass_text="restrict incoming calls",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    calling = meet.get("calling", {})
    incoming_restricted = calling.get("incoming_calls_restricted", None)

    if incoming_restricted is True:
        return make_pass(
            check_id="GWS.MEET.5.1",
            title="Ensure incoming calls are restricted to organization",
            level="L1", source="CISA", section="Google Meet",
            details="Incoming calls are restricted to contacts and organization.",
            actual_value=incoming_restricted,
            expected_value="Enabled for all OUs",
        )

    if incoming_restricted is None:
        return make_manual(
            check_id="GWS.MEET.5.1",
            title="Ensure incoming calls are restricted to organization",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine incoming calls restriction setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet safety settings > Incoming call restrictions. Restrict incoming calls to contacts and "
                "organization users. https://knowledge.workspace.google.com/admin/meet/restrict-who-can-call-my-organizations-users-with-google-meet"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.5.1",
        title="Ensure incoming calls are restricted to organization",
        level="L1", source="CISA", section="Google Meet",
        details="Incoming calls are not restricted to organization.",
        actual_value=incoming_restricted,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet safety settings > Incoming call restrictions. Restrict incoming calls to contacts and "
            "other users in the organization. https://knowledge.workspace.google.com/admin/meet/restrict-who-can-call-my-organizations-users-with-google-meet"
        ),
    )


@check(
    check_id="GWS.MEET.6.1",
    title="Ensure automatic recording is disabled",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet video settings > Automatic recording. Disable automatic recordings to prevent "
        "unauthorized capture of meeting content. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
    ),
    requires_license="business_standard",
)
def check_meet_auto_recording(data: dict) -> CheckResult:
    """Automatic meeting recording should be disabled."""
    _ID = "GWS.MEET.6.1"
    _TITLE = "Ensure automatic recording is disabled"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet video settings > Automatic recording. Disable automatic recordings to prevent "
        "unauthorized capture of meeting content. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    # Policy API (editions with the feature): meet.automatic_recording.enabled. Google defaults
    # are real state here, so SYSTEM entries count too. meet.video_recording only says whether
    # recording is *allowed*: enableRecording=false disables recording entirely (safe), but an
    # absent automatic-recording flag is unknown, not "disabled".
    video_entries = get_ou_values(meet, "video_recording")
    recording_off = {e["org_unit"] for e in video_entries if field_value(e, "enableRecording") is False}
    auto_entries = get_ou_values(meet, "automatic_recording")
    if auto_entries:
        def _judge_auto(entry):
            enabled = field_value(entry, "enabled")
            if enabled is None:
                return (True, False) if entry["org_unit"] in recording_off else None
            return (enabled is False, enabled)

        return ou_verdict(
            auto_entries, _judge_auto, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have automatic recording enabled", pass_text="have automatic recording disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    if video_entries:
        def _judge_video(entry):
            if field_value(entry, "enableRecording") is False:
                return (True, False)  # Recording disabled entirely = safe
            auto = field_value(entry, "autoRecordingEnabled", "autoRecording")
            if auto is None:
                return None
            return (auto is False, auto)

        return ou_verdict(
            video_entries, _judge_video, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have automatic recording enabled", pass_text="have automatic recording disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    recording = meet.get("recording", {})
    auto_record = recording.get("auto_recording_enabled", None)

    if auto_record is False:
        return make_pass(
            check_id="GWS.MEET.6.1",
            title="Ensure automatic recording is disabled",
            level="L1", source="CISA", section="Google Meet",
            details="Automatic meeting recording is disabled.",
            actual_value=auto_record,
            expected_value="Disabled for all OUs",
        )

    if auto_record is None:
        return make_manual(
            check_id="GWS.MEET.6.1",
            title="Ensure automatic recording is disabled",
            level="L1", source="CISA", section="Google Meet",
            details="Could not determine automatic recording setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet video settings > Automatic recording. Disable automatic recordings. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.6.1",
        title="Ensure automatic recording is disabled",
        level="L1", source="CISA", section="Google Meet",
        details="Automatic meeting recording is enabled.",
        actual_value=auto_record,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet video settings > Automatic recording. Disable automatic recordings to prevent "
            "unauthorized capture of meeting content. https://knowledge.workspace.google.com/admin/meet/turn-meet-recording-on-or-off-for-your-organization"
        ),
    )


@check(
    check_id="GWS.MEET.6.2",
    title="Ensure automatic transcription is disabled",
    level="L1",
    source="CISA",
    section="Google Meet",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet video settings > Automatic transcription. Disable automatic transcripts to mitigate "
        "sensitive data recording risks. https://knowledge.workspace.google.com/admin/meet/turn-meeting-transcription-on-or-off"
    ),
    requires_license="business_standard",
)
def check_meet_auto_transcription(data: dict) -> CheckResult:
    """Automatic meeting transcription should be disabled."""
    _ID = "GWS.MEET.6.2"
    _TITLE = "Ensure automatic transcription is disabled"
    _L, _S, _SEC = "L1", "CISA", "Google Meet"
    _REMED = (
        "Admin console > Apps > Google Workspace > Google Meet > "
        "Meet video settings > Automatic transcription. Disable automatic transcripts to mitigate "
        "sensitive data recording risks. https://knowledge.workspace.google.com/admin/meet/turn-meeting-transcription-on-or-off"
    )

    policies = data.get("policies", {})
    meet = policies.get("meet", {})

    # OU-aware path
    # Policy API (editions with the feature): meet.automatic_transcription.enabled. Google defaults
    # are real state here, so SYSTEM entries count too. The automatic-transcription default is not
    # part of meet.video_recording; an absent field is unknown (not "disabled").
    auto_entries = get_ou_values(meet, "automatic_transcription")
    if auto_entries:
        def _judge_auto(entry):
            enabled = field_value(entry, "enabled")
            if enabled is None:
                return None
            return (enabled is False, enabled)

        return ou_verdict(
            auto_entries, _judge_auto, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have automatic transcription enabled", pass_text="have automatic transcription disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    video_entries = get_ou_values(meet, "video_recording")
    if video_entries:
        def _judge_video(entry):
            auto = field_value(entry, "autoTranscriptionEnabled", "autoTranscription")
            if auto is None:
                return None
            return (auto is not True, auto)

        return ou_verdict(
            video_entries, _judge_video, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have automatic transcription enabled", pass_text="have automatic transcription disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    recording = meet.get("recording", {})
    auto_transcript = recording.get("auto_transcription_enabled", None)

    if auto_transcript is False:
        return make_pass(
            check_id="GWS.MEET.6.2",
            title="Ensure automatic transcription is disabled",
            level="L1", source="CISA", section="Google Meet",
            details="Automatic meeting transcription is disabled.",
            actual_value=auto_transcript,
            expected_value="Disabled for all OUs",
        )

    if auto_transcript is None:
        return make_review(
            check_id="GWS.MEET.6.2",
            title="Ensure automatic transcription is disabled",
            level="L1", source="CISA", section="Google Meet",
            details=(
                "Auto-transcription is not exposed by the Cloud Identity "
                "Policy API — verify in Admin console."
            ),
            remediation=(
                "Admin console > Apps > Google Workspace > Google Meet > "
                "Meet video settings > Automatic transcription. Disable automatic transcripts. https://knowledge.workspace.google.com/admin/meet/turn-meeting-transcription-on-or-off"
            ),
        )

    return make_fail(
        check_id="GWS.MEET.6.2",
        title="Ensure automatic transcription is disabled",
        level="L1", source="CISA", section="Google Meet",
        details="Automatic meeting transcription is enabled.",
        actual_value=auto_transcript,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Meet > "
            "Meet video settings > Automatic transcription. Disable automatic transcripts to mitigate "
            "sensitive data recording risks. https://knowledge.workspace.google.com/admin/meet/turn-meeting-transcription-on-or-off"
        ),
    )


# ===========================================================================
# Groups - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.GROUPS.1.3",
    title="Ensure external posting to groups is disabled",
    level="L1",
    source="CISA",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Uncheck 'Group owners can allow incoming "
        "mail from outside the organization'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_external_posting(data: dict) -> CheckResult:
    """Group owners should not be able to allow external posting."""
    _ID = "GWS.GROUPS.1.3"
    _TITLE = "Ensure external posting to groups is disabled"
    _L, _S, _SEC = "L1", "CISA", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Uncheck 'Group owners can allow incoming "
        "mail from outside the organization'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def _judge(entry):
            # Real API exposes ownersCanAllowIncomingMailFromPublic (the admin-console
            # toggle); legacy explicit posting flags are read after it.
            posting = field_value(entry, "ownersCanAllowIncomingMailFromPublic", "allowExternalPosting",
                                  "allowExternalMail", "ownersCanAllowIncomingMail")
            if posting is None:
                return None
            return (posting is not True, posting)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow external posting to groups", pass_text="disable external posting to groups",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    external_posting = groups_policy.get("allow_external_posting", None)

    if external_posting is False:
        return make_pass(
            check_id="GWS.GROUPS.1.3",
            title="Ensure external posting to groups is disabled",
            level="L1", source="CISA", section="Groups",
            details="External posting to groups is disabled.",
            actual_value=external_posting,
            expected_value="Disabled for all OUs",
        )

    if external_posting is None:
        return make_manual(
            check_id="GWS.GROUPS.1.3",
            title="Ensure external posting to groups is disabled",
            level="L1", source="CISA", section="Groups",
            details="Could not determine external posting setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Uncheck 'Group owners can allow incoming "
                "mail from outside the organization'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    return make_fail(
        check_id="GWS.GROUPS.1.3",
        title="Ensure external posting to groups is disabled",
        level="L1", source="CISA", section="Groups",
        details="External posting to groups is allowed.",
        actual_value=external_posting,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Groups for Business > "
            "Sharing settings. Uncheck 'Group owners can allow incoming "
            "mail from outside the organization'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
        ),
    )


@check(
    check_id="GWS.GROUPS.4.1",
    title="Ensure groups cannot be hidden from directory",
    level="L1",
    source="CISA",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Uncheck 'Group owners can hide groups "
        "from the directory' and 'Hide newly created groups from "
        "the directory'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_directory_hiding(data: dict) -> CheckResult:
    """Group owners should not be able to hide groups from the directory."""
    _ID = "GWS.GROUPS.4.1"
    _TITLE = "Ensure groups cannot be hidden from directory"
    _L, _S, _SEC = "L1", "CISA", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Uncheck 'Group owners can hide groups "
        "from the directory' and 'Hide newly created groups from "
        "the directory'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def _judge(entry):
            # Real API exposes ownersCanHideGroups + newGroupsAreHidden;
            # either being True means groups can be hidden from directory.
            owner_hide = field_value(entry, "ownersCanHideGroups")
            new_hidden = field_value(entry, "newGroupsAreHidden")
            if owner_hide is True or new_hidden is True:
                return (False, True)
            if owner_hide is False and new_hidden is False:
                return (True, False)
            hide = field_value(entry, "allowHidingFromDirectory", "hideFromDirectory")
            if hide is None:
                return None
            return (hide is not True, hide)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow hiding groups from directory", pass_text="prevent hiding groups from directory",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    hide_from_directory = groups_policy.get("allow_hiding_from_directory", None)

    if hide_from_directory is False:
        return make_pass(
            check_id="GWS.GROUPS.4.1",
            title="Ensure groups cannot be hidden from directory",
            level="L1", source="CISA", section="Groups",
            details="Groups cannot be hidden from directory.",
            actual_value=hide_from_directory,
            expected_value="Disabled for all OUs",
        )

    if hide_from_directory is None:
        return make_manual(
            check_id="GWS.GROUPS.4.1",
            title="Ensure groups cannot be hidden from directory",
            level="L1", source="CISA", section="Groups",
            details="Could not determine directory hiding setting.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Uncheck 'Group owners can hide groups "
                "from the directory'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    return make_fail(
        check_id="GWS.GROUPS.4.1",
        title="Ensure groups cannot be hidden from directory",
        level="L1", source="CISA", section="Groups",
        details="Group owners can hide groups from the directory.",
        actual_value=hide_from_directory,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Groups for Business > "
            "Sharing settings. Uncheck 'Group owners can hide groups "
            "from the directory' and 'Hide newly created groups from "
            "the directory'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
        ),
    )


# ===========================================================================
# Common Controls - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.1.3",
    title="Ensure SMS/Voice MFA methods are disabled",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Set allowed methods to exclude SMS and phone call verification, "
        "as these are vulnerable to SIM swapping and SS7 attacks. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_sms_voice_mfa_disabled(data: dict) -> CheckResult:
    """SMS and voice-based MFA should not be allowed as verification methods."""
    _ID = "GWS.COMMONCONTROLS.1.3"
    _TITLE = "Ensure SMS/Voice MFA methods are disabled"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Set allowed methods to exclude SMS and phone call verification, "
        "as these are vulnerable to SIM swapping and SS7 attacks. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_enforcement_factor")
    if ou_values:
        def _judge(entry):
            methods = field_value(entry, "allowedSignInFactorSet", "allowedMethods", "allowedMethod")
            if methods is None:
                return None
            ml = str(methods).lower()
            sms_blocked = (
                "security_key_only" in ml
                or "passkey" in ml  # PASSKEY_ONLY / PASSKEY_PLUS_* exclude SMS and voice
                or "no_telephony" in ml
                or "no_sms" in ml
                or "no_phone" in ml
            )
            return (sms_blocked, str(methods))

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="may allow SMS/Voice MFA", pass_text="have SMS/Voice MFA disabled",
            expected_value="No SMS/Voice MFA", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    twosv = security.get("two_step_verification", {})
    allowed_methods = twosv.get("allowed_methods", "")

    # Check if SMS/voice is explicitly disabled or if only hardware keys are allowed
    am = str(allowed_methods).lower()
    sms_blocked = (
        "security_key_only" in am
        or "passkey" in am  # PASSKEY_ONLY / PASSKEY_PLUS_* exclude SMS and voice
        or "no_telephony" in am
        or "no_sms" in am
        or "no_phone" in am
    )

    if sms_blocked:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.1.3",
            title="Ensure SMS/Voice MFA methods are disabled",
            level="L1", source="CISA", section="Security",
            details="SMS and voice MFA methods are disabled.",
            actual_value=allowed_methods,
            expected_value="No SMS/Voice MFA",
        )

    if not allowed_methods:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.1.3",
            title="Ensure SMS/Voice MFA methods are disabled",
            level="L1", source="CISA", section="Security",
            details="Could not determine allowed MFA methods.",
            remediation=(
                "Admin console > Security > Authentication > 2-step verification. "
                "Remove 'Text message or phone call' from allowed methods. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.1.3",
        title="Ensure SMS/Voice MFA methods are disabled",
        level="L1", source="CISA", section="Security",
        details="SMS or voice-based MFA methods may be allowed.",
        actual_value=allowed_methods,
        expected_value="No SMS/Voice MFA",
        remediation=(
            "Admin console > Security > Authentication > 2-step verification. "
            "Set allowed methods to exclude SMS and phone call verification, "
            "as these are vulnerable to SIM swapping and SS7 attacks. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.1.4",
    title="Ensure MFA enrollment period is configured",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Set new user enrollment period to 1-7 days. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_mfa_enrollment_period(data: dict) -> CheckResult:
    """New user MFA enrollment period should be 1 day to 1 week."""
    _ID = "GWS.COMMONCONTROLS.1.4"
    _TITLE = "Ensure MFA enrollment period is configured"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Set new user enrollment period to 1-7 days. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path — enrollment grace period is in two_step_verification_grace_period
    ou_values = get_ou_values(security, "two_step_verification_grace_period")
    if ou_values:
        def _judge(entry):
            # The API returns a protobuf duration string like "604800s"
            raw = field_value(entry, "enrollmentGracePeriod", "enrollment_grace_period")
            days = None
            if raw:
                secs_str = str(raw).strip().rstrip("s")
                try:
                    days = int(float(secs_str)) // 86400
                except (ValueError, TypeError):
                    pass
            # Also check legacy field names
            if days is None:
                legacy = field_value(entry, "newUserEnrollmentPeriodDays", "enrollmentPeriod")
                if legacy is not None:
                    try:
                        days = int(legacy)
                    except (ValueError, TypeError):
                        pass
            if days is None:
                return None
            return (1 <= days <= 7, days)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have improper MFA enrollment period",
            pass_text="have MFA enrollment period within 1-7 days",
            expected_value="1-7 days", remediation=_REMED,
            humanizer=lambda v: f"{v}d" if isinstance(v, int) else str(v),
        )

    # Fallback: mapped root-level value
    twosv = security.get("two_step_verification", {})
    enrollment_days = twosv.get("new_user_enrollment_period_days", None)

    if enrollment_days is not None and 1 <= enrollment_days <= 7:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.1.4",
            title="Ensure MFA enrollment period is configured",
            level="L1", source="CISA", section="Security",
            details=f"MFA enrollment period is {enrollment_days} day(s).",
            actual_value=enrollment_days,
            expected_value="1-7 days",
        )

    if enrollment_days is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.1.4",
            title="Ensure MFA enrollment period is configured",
            level="L1", source="CISA", section="Security",
            details="Could not determine MFA enrollment period.",
            remediation=(
                "Admin console > Security > Authentication > 2-step verification. "
                "Set new user enrollment period to 1-7 days. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.1.4",
        title="Ensure MFA enrollment period is configured",
        level="L1", source="CISA", section="Security",
        details=f"MFA enrollment period is {enrollment_days} days (should be 1-7).",
        actual_value=enrollment_days,
        expected_value="1-7 days",
        remediation=(
            "Admin console > Security > Authentication > 2-step verification. "
            "Set the new user enrollment period to at least 1 day and "
            "at most 1 week. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.1.5",
    title="Ensure 'trust this device' is disabled",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Disable 'Allow users to trust the device' to require MFA "
        "on every login. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_trust_device_disabled(data: dict) -> CheckResult:
    """Users should not be allowed to trust a device and skip MFA."""
    _ID = "GWS.COMMONCONTROLS.1.5"
    _TITLE = "Ensure 'trust this device' is disabled"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Disable 'Allow users to trust the device' to require MFA "
        "on every login. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_device_trust")
    if ou_values:
        def _judge(entry):
            trust = field_value(entry, "allowTrustingDevice", "allowTrustDevice", "enableDeviceTrust")
            if trust is None:
                return None
            return (trust is False, trust)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow 'trust this device'", pass_text="have 'trust this device' disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    twosv = security.get("two_step_verification", {})
    trust_device = twosv.get("allow_trust_device", None)

    if trust_device is False:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.1.5",
            title="Ensure 'trust this device' is disabled",
            level="L1", source="CISA", section="Security",
            details="'Trust this device' option is disabled.",
            actual_value=trust_device,
            expected_value="Disabled for all OUs",
        )

    if trust_device is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.1.5",
            title="Ensure 'trust this device' is disabled",
            level="L1", source="CISA", section="Security",
            details="Could not determine 'trust this device' setting.",
            remediation=(
                "Admin console > Security > Authentication > 2-step verification. "
                "Disable 'Allow users to trust the device'. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.1.5",
        title="Ensure 'trust this device' is disabled",
        level="L1", source="CISA", section="Security",
        details="'Trust this device' is enabled, allowing MFA bypass.",
        actual_value=trust_device,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Security > Authentication > 2-step verification. "
            "Disable 'Allow users to trust the device' to require MFA "
            "on every login. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.7.1",
    scored=False,  # P3: conflicting-account management is not exposed by the v1 Policy API; MANUAL by design
    title="Ensure conflicting account management is configured",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Account > Account settings > Account management > Conflicting accounts management. Enable "
        "automatic management of conflicting accounts. https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users"
    ),
)
def check_conflicting_accounts(data: dict) -> CheckResult:
    """Conflicting accounts should be automatically managed."""
    _ID = "GWS.COMMONCONTROLS.7.1"
    _TITLE = "Ensure conflicting account management is configured"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Account > Account settings > Account management > Conflicting accounts management. Enable "
        "automatic management of conflicting accounts. https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # Policy API provisioning.conflicting_accounts_management.option (the setting CISA ScubaGoggles
    # reads): REPLACE_CONFLICTING_ACCOUNT is compliant; AUTOMATICALLY_SEND_INVITATIONS (Google's
    # default) and PRESERVE_CONFLICTING_ACCOUNT are not. The API returns it only once the setting has
    # been saved; absent -> MANUAL below.
    ou_values = get_ou_values(policies.get("provisioning", {}), "conflicting_accounts_management")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "option", "conflictingAccountsManaged", "conflicting_accounts_managed")
            if val is None:
                return None
            if val is True:
                return (True, val)
            return (str(val).upper() == "REPLACE_CONFLICTING_ACCOUNT", val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not replace conflicting accounts automatically",
            pass_text="replace conflicting accounts automatically",
            expected_value="REPLACE_CONFLICTING_ACCOUNT for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    account_mgmt = security.get("account_management", {})
    conflict_mgmt = account_mgmt.get("conflicting_accounts_managed", None)

    if conflict_mgmt is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.7.1",
            title="Ensure conflicting account management is configured",
            level="L1", source="CISA", section="Security",
            details="Conflicting account management is configured.",
            actual_value=conflict_mgmt,
            expected_value="Enabled for all OUs",
        )

    if conflict_mgmt is None:
        return make_review(
            check_id="GWS.COMMONCONTROLS.7.1",
            title="Ensure conflicting account management is configured",
            level="L1", source="CISA", section="Security",
            details=(
                "The Policy API returned no provisioning.conflicting_accounts_management policy (it appears "
                "only once the setting has been saved; Google's default is to send invitations). Verify in "
                "Admin console > Account > Account settings > Account management > Conflicting accounts management."
            ),
            remediation=(
                "Admin console > Account > Account settings > Account management > Conflicting accounts management. Configure "
                "automatic handling of conflicting accounts to prevent "
                "shadow IT accounts. https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.7.1",
        title="Ensure conflicting account management is configured",
        level="L1", source="CISA", section="Security",
        details="Conflicting account management is not configured.",
        actual_value=conflict_mgmt,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Account > Account settings > Account management > Conflicting accounts management. Enable "
            "automatic management of conflicting accounts. https://knowledge.workspace.google.com/admin/users/find-and-add-unmanaged-users"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.14.1",
    title="Ensure audit logging is enabled",
    level="L1",
    source="CISA",
    section="Reporting",
    remediation=(
        "Admin console > Reporting > Audit and investigation. "
        "Verify audit logging is enabled. Consider configuring "
        "log export to BigQuery or a SIEM for long-term retention. https://knowledge.workspace.google.com/admin/reports/reports-overview"
    ),
)
def check_audit_logging_enabled(data: dict) -> CheckResult:
    """Audit logging should be enabled and collecting events."""
    admin_logs = data.get("admin_logs", [])
    login_logs = data.get("login_logs", [])

    if admin_logs or login_logs:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.14.1",
            title="Ensure audit logging is enabled",
            level="L1", source="CISA", section="Reporting",
            details=(
                f"Audit logging is active ({len(admin_logs)} admin event(s), "
                f"{len(login_logs)} login event(s) found)."
            ),
            actual_value={
                "admin_events": len(admin_logs),
                "login_events": len(login_logs),
            },
            expected_value="Audit logs present",
        )

    return make_review(
        check_id="GWS.COMMONCONTROLS.14.1",
        title="Ensure audit logging is enabled",
        level="L1", source="CISA", section="Reporting",
        details=(
            "No audit log events found. Verify that audit logging is "
            "enabled and events are being captured."
        ),
        remediation=(
            "Admin console > Reporting > Audit and investigation. "
            "Verify audit logging is enabled. Consider configuring "
            "log export to BigQuery or a SIEM for long-term retention. https://knowledge.workspace.google.com/admin/reports/reports-overview"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.15.1",
    title="Ensure data regions are configured",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Data > Compliance > Data regions. "
        "Configure data storage locations to comply with data "
        "residency requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    ),
    requires_license="business_standard",
)
def check_data_regions(data: dict) -> CheckResult:
    """Data region policies should be configured for data residency."""
    _ID = "GWS.COMMONCONTROLS.15.1"
    _TITLE = "Ensure data regions are configured"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Data > Compliance > Data regions. "
        "Configure data storage locations to comply with data "
        "residency requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = (get_ou_values(security, "data_at_rest_region"))
    if ou_values:
        def _judge(entry):
            # Policy API: data_regions.data_at_rest_region.region (US / EUROPE / ANY_REGION)
            region = field_value(entry, "region")
            if region is not None:
                r = str(region).upper()
                return (bool(r) and r not in ("ANY_REGION", "NO_PREFERENCE"), region)
            val = field_value(entry, "configured", "dataRegionsConfigured")
            if val is None:
                return None
            return (val is True, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack data region configuration", pass_text="have data regions configured",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    data_regions = security.get("data_regions", {})
    configured = data_regions.get("configured", None)

    if configured is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.15.1",
            title="Ensure data regions are configured",
            level="L2", source="CISA", section="Security",
            details="Data region policies are configured.",
            actual_value=configured,
            expected_value="Enabled for all OUs",
        )

    if configured is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.15.1",
            title="Ensure data regions are configured",
            level="L2", source="CISA", section="Security",
            details="Could not determine data region configuration.",
            remediation=(
                "Admin console > Data > Compliance > Data regions. "
                "Configure data regions to meet data residency requirements. "
                "Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.15.1",
        title="Ensure data regions are configured",
        level="L2", source="CISA", section="Security",
        details="Data region policies are not configured.",
        actual_value=configured,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Data > Compliance > Data regions. "
            "Configure data storage locations to comply with data "
            "residency requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.17.1",
    title="Ensure multi-party approval is enabled",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Multi-party approval settings. "
        "Enable to require multiple admin approvals for "
        "sensitive operations like user deletion or settings changes. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
    ),
    requires_license="enterprise_standard",
)
def check_multi_party_approval(data: dict) -> CheckResult:
    """Multi-party approval should be enabled for sensitive admin actions."""
    _ID = "GWS.COMMONCONTROLS.17.1"
    _TITLE = "Ensure multi-party approval is enabled"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Multi-party approval settings. "
        "Enable to require multiple admin approvals for "
        "sensitive operations like user deletion or settings changes. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    # Policy API: multi_party_approval.require_approvals.multiPartyApprovalState
    mpa_entries = get_ou_values(policies.get("multi_party_approval", {}), "require_approvals")
    if mpa_entries:
        def _judge_state(entry):
            state = field_value(entry, "multiPartyApprovalState")
            if state is None:
                return None
            return (str(state).upper() == "ENABLED", state)

        return ou_verdict(
            mpa_entries, _judge_state, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not require multi-party approval", pass_text="require multi-party approval",
            expected_value="ENABLED", remediation=_REMED,
        )

    ou_values = []  # P3: "multi_party_approval.multi_party_approval" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enabled", "multiPartyApprovalEnabled")
            if val is None:
                return None
            return (val is True, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack multi-party approval", pass_text="have multi-party approval enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Not exposed by the Policy API: infer from the latest admin audit-log change
    # (setting name as used by CISA ScubaGoggles). No event -> fall through to MANUAL.
    inferred = result_from_setting_changes(
        data, "Multi Party Approval (MPA) Control Multi Party Approval Control", ('disabled',),
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        what="Multi-party approval", remediation=_REMED,
    )
    if inferred is not None:
        return inferred

    # Fallback: mapped root-level value
    mpa = security.get("multi_party_approval", {})
    enabled = mpa.get("enabled", None)

    if enabled is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.17.1",
            title="Ensure multi-party approval is enabled",
            level="L2", source="CISA", section="Security",
            details="Multi-party approval is enabled for sensitive actions.",
            actual_value=enabled,
            expected_value="Enabled for all OUs",
        )

    if enabled is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.17.1",
            title="Ensure multi-party approval is enabled",
            level="L2", source="CISA", section="Security",
            details="Could not determine multi-party approval setting.",
            remediation=(
                "Admin console > Security > Authentication > Multi-party approval settings. "
                "Enable multi-party approval to require additional "
                "admin authorization for sensitive operations. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.17.1",
        title="Ensure multi-party approval is enabled",
        level="L2", source="CISA", section="Security",
        details="Multi-party approval is not enabled.",
        actual_value=enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Authentication > Multi-party approval settings. "
            "Enable to require multiple admin approvals for "
            "sensitive operations like user deletion or settings changes. https://knowledge.workspace.google.com/admin/security/multi-party-approval-for-sensitive-actions"
        ),
    )


# ===========================================================================
# Classroom - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.CLASSROOM.1.1",
    title="Ensure class membership is restricted to domain",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Set class membership to 'Domain only' or "
        "'Allowlisted domains' to prevent external access. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_class_membership_restricted(data: dict) -> CheckResult:
    """Class membership should be restricted to domain users only.

    The Cloud Identity Policy API returns enum values such as
    ``ANYONE_IN_DOMAIN`` and ``ANYONE`` for ``whoCanJoinClasses``.
    The mapped ``sharing.class_membership`` field uses these raw values.
    """
    _ID = "GWS.CLASSROOM.1.1"
    _TITLE = "Ensure class membership is restricted to domain"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Set 'Who can join classes in your domain' "
        "to 'Users in your domain only'. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )
    # Values that represent domain-restricted membership (API enum values
    # and legacy normalised forms)
    _SAFE = frozenset({
        "ANYONE_IN_DOMAIN", "anyone_in_domain",
        "ANYONE_IN_ALLOWLISTED_DOMAINS",
        "DOMAIN_ONLY", "domain_only",
        "ALLOWLISTED_DOMAINS", "allowlisted_domains",
    })

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = (get_ou_values(classroom, "class_membership"))
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "whoCanJoinClasses", "classMembership", "class_membership")
            if val is None:
                return None
            return (val in _SAFE, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow external class membership", pass_text="restrict class membership to domain",
            expected_value="ANYONE_IN_DOMAIN", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = classroom.get("sharing", {})
    membership = sharing.get("class_membership", None)

    if membership in _SAFE:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Class membership is restricted to '{membership}'.",
            actual_value=membership,
            expected_value="ANYONE_IN_DOMAIN",
        )

    if membership is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine class membership setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Class membership is set to '{membership}', allowing external users.",
        actual_value=membership,
        expected_value="ANYONE_IN_DOMAIN",
        remediation=_REMED,
    )


@check(
    check_id="GWS.CLASSROOM.1.2",
    title="Ensure classes users can join are restricted to domain",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Set to 'Domain only' or 'Allowlisted domains' "
        "to prevent joining external classes. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_classes_to_join_restricted(data: dict) -> CheckResult:
    """Classes users can join should be restricted to domain classes only.

    The Cloud Identity Policy API returns enum values such as
    ``CLASSES_IN_DOMAIN`` and ``ANY_CLASS`` for ``whichClassesCanUsersJoin``.
    """
    _ID = "GWS.CLASSROOM.1.2"
    _TITLE = "Ensure classes users can join are restricted to domain"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Set 'Which classes can users in your domain "
        "join' to 'Classes in your domain only'. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )
    # Values that represent domain-restricted classes (API enum values
    # and legacy normalised forms)
    _SAFE = frozenset({
        "CLASSES_IN_DOMAIN", "classes_in_domain",
        "CLASSES_IN_ALLOWLISTED_DOMAINS",
        "DOMAIN_ONLY", "domain_only",
        "ALLOWLISTED_DOMAINS", "allowlisted_domains",
    })

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = (get_ou_values(classroom, "class_membership"))
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "whichClassesCanUsersJoin", "classesToJoin", "classes_to_join")
            if val is None:
                return None
            return (val in _SAFE, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow joining external classes", pass_text="restrict classes to join to domain",
            expected_value="CLASSES_IN_DOMAIN", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    sharing = classroom.get("sharing", {})
    classes_to_join = sharing.get("classes_to_join", None)

    if classes_to_join in _SAFE:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Classes users can join is restricted to '{classes_to_join}'.",
            actual_value=classes_to_join,
            expected_value="CLASSES_IN_DOMAIN",
        )

    if classes_to_join is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine classes-to-join setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Classes users can join is set to '{classes_to_join}', allowing external classes.",
        actual_value=classes_to_join,
        expected_value="CLASSES_IN_DOMAIN",
        remediation=_REMED,
    )


@check(
    check_id="GWS.CLASSROOM.2.1",
    title="Ensure Classroom API access is disabled",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "API access. Disable Classroom API access to prevent "
        "unauthorized programmatic interaction. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_classroom_api_disabled(data: dict) -> CheckResult:
    """Classroom API access should be disabled to prevent programmatic access."""
    _ID = "GWS.CLASSROOM.2.1"
    _TITLE = "Ensure Classroom API access is disabled"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "API access. Disable Classroom API access to prevent "
        "unauthorized programmatic interaction. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = (get_ou_values(classroom, "api_data_access"))
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enableApiAccess", "enabled", "apiAccessEnabled")
            if val is None:
                return None
            return (val is False, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Classroom API access enabled", pass_text="have Classroom API access disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    api_access = classroom.get("api_access", {})
    enabled = api_access.get("enabled", None)

    if enabled is False:
        return make_pass(
            check_id="GWS.CLASSROOM.2.1",
            title="Ensure Classroom API access is disabled",
            level="L1", source="CISA", section="Classroom",
            details="Classroom API access is disabled.",
            actual_value=enabled,
            expected_value="Disabled for all OUs",
        )

    if enabled is None:
        return make_manual(
            check_id="GWS.CLASSROOM.2.1",
            title="Ensure Classroom API access is disabled",
            level="L1", source="CISA", section="Classroom",
            details="Could not determine Classroom API access setting.",
            remediation=(
                "Admin console > Apps > Additional Google services > Classroom > "
                "API access. Disable Classroom API access. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.CLASSROOM.2.1",
        title="Ensure Classroom API access is disabled",
        level="L1", source="CISA", section="Classroom",
        details="Classroom API access is enabled, allowing programmatic access.",
        actual_value=enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Additional Google services > Classroom > "
            "API access. Disable Classroom API access to prevent "
            "unauthorized programmatic interaction. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
        ),
    )


@check(
    check_id="GWS.CLASSROOM.3.1",
    title="Ensure roster import with Clever is disabled",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "Roster import. Disable Clever integration to prevent "
        "external roster synchronization. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_clever_roster_import_disabled(data: dict) -> CheckResult:
    """Roster import via Clever should be disabled."""
    _ID = "GWS.CLASSROOM.3.1"
    _TITLE = "Ensure roster import with Clever is disabled"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "Roster import. Disable Clever integration to prevent "
        "external roster synchronization. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = get_ou_values(classroom, "roster_import")
    if ou_values:
        def _judge(entry):
            option = field_value(entry, "rosterImportOption")
            if option is not None:
                return (str(option).upper() == "OFF", option)
            val = field_value(entry, "cleverEnabled", "clever_enabled")
            if val is None:
                return None
            return (val is False, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Clever roster import enabled", pass_text="have Clever roster import disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    roster_import = classroom.get("roster_import", {})
    clever_enabled = roster_import.get("clever_enabled", None)

    if clever_enabled is False:
        return make_pass(
            check_id="GWS.CLASSROOM.3.1",
            title="Ensure roster import with Clever is disabled",
            level="L1", source="CISA", section="Classroom",
            details="Roster import with Clever is disabled.",
            actual_value=clever_enabled,
            expected_value="Disabled for all OUs",
        )

    if clever_enabled is None:
        return make_manual(
            check_id="GWS.CLASSROOM.3.1",
            title="Ensure roster import with Clever is disabled",
            level="L1", source="CISA", section="Classroom",
            details="Could not determine Clever roster import setting.",
            remediation=(
                "Admin console > Apps > Additional Google services > Classroom > "
                "Roster import. Disable roster import with Clever. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.CLASSROOM.3.1",
        title="Ensure roster import with Clever is disabled",
        level="L1", source="CISA", section="Classroom",
        details="Roster import with Clever is enabled.",
        actual_value=clever_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Additional Google services > Classroom > "
            "Roster import. Disable Clever integration to prevent "
            "external roster synchronization. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
        ),
    )


@check(
    check_id="GWS.CLASSROOM.4.1",
    title="Ensure only teachers can unenroll students",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Restrict student unenrollment to "
        "'Teachers only' to prevent students from leaving classes. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_teachers_only_unenroll(data: dict) -> CheckResult:
    """Only teachers should be able to unenroll students from classes."""
    _ID = "GWS.CLASSROOM.4.1"
    _TITLE = "Ensure only teachers can unenroll students"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "Class settings. Restrict student unenrollment to "
        "'Teachers only' to prevent students from leaving classes. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = (get_ou_values(classroom, "student_unenrollment"))
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "whoCanUnenrollStudents", "who_can_unenroll_students")
            if val is None:
                return None
            return (str(val).lower() in ("teachers_only", "teachers"), val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow non-teacher student unenrollment",
            pass_text="restrict unenrollment to teachers only",
            expected_value="teachers_only", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    class_settings = classroom.get("class_settings", {})
    who_can_unenroll = class_settings.get("who_can_unenroll_students", None)

    if str(who_can_unenroll).lower() in ("teachers_only", "teachers"):
        return make_pass(
            check_id="GWS.CLASSROOM.4.1",
            title="Ensure only teachers can unenroll students",
            level="L1", source="CISA", section="Classroom",
            details=f"Student unenrollment is restricted to '{who_can_unenroll}'.",
            actual_value=who_can_unenroll,
            expected_value="teachers_only",
        )

    if who_can_unenroll is None:
        return make_manual(
            check_id="GWS.CLASSROOM.4.1",
            title="Ensure only teachers can unenroll students",
            level="L1", source="CISA", section="Classroom",
            details="Could not determine student unenrollment setting.",
            remediation=(
                "Admin console > Apps > Additional Google services > Classroom > "
                "Class settings. Set who can unenroll students to "
                "'Teachers only'. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.CLASSROOM.4.1",
        title="Ensure only teachers can unenroll students",
        level="L1", source="CISA", section="Classroom",
        details=f"Student unenrollment is set to '{who_can_unenroll}', not restricted to teachers.",
        actual_value=who_can_unenroll,
        expected_value="teachers_only",
        remediation=(
            "Admin console > Apps > Additional Google services > Classroom > "
            "Class settings. Restrict student unenrollment to "
            "'Teachers only' to prevent students from leaving classes. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
        ),
    )


@check(
    check_id="GWS.CLASSROOM.5.1",
    title="Ensure class creation is restricted to verified teachers",
    level="L1",
    source="CISA",
    section="Classroom",
    remediation=(
        "Admin console > Apps > Additional Google services > Classroom > "
        "General settings. Set who can create classes to "
        "'Verified teachers only' to prevent unauthorized class creation. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    ),
)
def check_class_creation_verified_teachers(data: dict) -> CheckResult:
    """Class creation should be restricted to verified teachers only."""
    _ID = "GWS.CLASSROOM.5.1"
    _TITLE = "Ensure class creation is restricted to verified teachers"
    _L, _S, _SEC = "L1", "CISA", "Classroom"
    _REMED = (
        "Admin console > Apps > Additional Google services > Classroom > "
        "General settings. Set who can create classes to "
        "'Verified teachers only' to prevent unauthorized class creation. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    classroom = policies.get("classroom", {})

    # OU-aware path
    ou_values = (get_ou_values(classroom, "teacher_permissions"))
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "whoCanCreateClasses", "who_can_create_classes")
            if val is None:
                return None
            return (str(val).lower() in ("verified_teachers", "verified_teachers_only"), val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow non-verified-teacher class creation",
            pass_text="restrict class creation to verified teachers",
            expected_value="verified_teachers", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    class_settings = classroom.get("class_settings", {})
    who_can_create = class_settings.get("who_can_create_classes", None)

    if str(who_can_create).lower() in ("verified_teachers", "verified_teachers_only"):
        return make_pass(
            check_id="GWS.CLASSROOM.5.1",
            title="Ensure class creation is restricted to verified teachers",
            level="L1", source="CISA", section="Classroom",
            details=f"Class creation is restricted to '{who_can_create}'.",
            actual_value=who_can_create,
            expected_value="verified_teachers",
        )

    if who_can_create is None:
        return make_manual(
            check_id="GWS.CLASSROOM.5.1",
            title="Ensure class creation is restricted to verified teachers",
            level="L1", source="CISA", section="Classroom",
            details="Could not determine class creation setting.",
            remediation=(
                "Admin console > Apps > Additional Google services > Classroom > "
                "General settings. Restrict class creation to verified "
                "teachers only. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.CLASSROOM.5.1",
        title="Ensure class creation is restricted to verified teachers",
        level="L1", source="CISA", section="Classroom",
        details=f"Class creation is set to '{who_can_create}', not restricted to verified teachers.",
        actual_value=who_can_create,
        expected_value="verified_teachers",
        remediation=(
            "Admin console > Apps > Additional Google services > Classroom > "
            "General settings. Set who can create classes to "
            "'Verified teachers only' to prevent unauthorized class creation. https://knowledge.workspace.google.com/admin/users/access/turn-classroom-on-or-off-for-users"
        ),
    )


# ===========================================================================
# Gemini - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.GEMINI.1.1",
    title="Ensure Gemini app access is restricted to licensed users",
    level="L1",
    source="CISA",
    section="Gemini",
    remediation=(
        "Admin console > Generative AI > Gemini app. "
        "Disable unlicensed access to ensure only licensed "
        "users can access Gemini features. https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-the-gemini-app-on-or-off"
    ),
)
def check_gemini_unlicensed_access(data: dict) -> CheckResult:
    """Gemini app access should be restricted to licensed users only."""
    _ID = "GWS.GEMINI.1.1"
    _TITLE = "Ensure Gemini app access is restricted to licensed users"
    _L, _S, _SEC = "L1", "CISA", "Gemini"
    _REMED = (
        "Admin console > Generative AI > Gemini app. "
        "Disable unlicensed access to ensure only licensed "
        "users can access Gemini features. https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-the-gemini-app-on-or-off"
    )

    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})

    # OU-aware path
    # Policy API gemini_app.unlicensed_user_access.enabled (seen live 2026-11-07); the admin-log
    # inference below stays as the fallback for tenants that do not return it.
    ou_values = get_ou_values(policies.get("gemini_app", {}), "unlicensed_user_access")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enabled", "unlicensedAccessEnabled", "unlicensed_access_enabled")
            if val is None:
                return None
            return (val is False, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow unlicensed Gemini access", pass_text="restrict Gemini to licensed users",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Not exposed by the Policy API: infer from the latest admin audit-log change
    # (setting name as used by CISA ScubaGoggles). No event -> fall through to MANUAL.
    inferred = result_from_setting_changes(
        data, "BardNonDuetEnablementProto enable_bard_non_duet_access", ('true',),
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        what="Gemini access regardless of license", remediation=_REMED,
    )
    if inferred is not None:
        return inferred

    # Fallback: mapped root-level value
    access = gemini.get("access", {})
    unlicensed_enabled = access.get("unlicensed_access_enabled", None)

    if unlicensed_enabled is False:
        return make_pass(
            check_id="GWS.GEMINI.1.1",
            title="Ensure Gemini app access is restricted to licensed users",
            level="L1", source="CISA", section="Gemini",
            details="Gemini access is restricted to licensed users only.",
            actual_value=unlicensed_enabled,
            expected_value="Disabled for all OUs",
        )

    if unlicensed_enabled is None:
        return make_review(
            check_id="GWS.GEMINI.1.1",
            title="Ensure Gemini app access is restricted to licensed users",
            level="L1", source="CISA", section="Gemini",
            details=(
                "Gemini app settings are not available via the Cloud Identity "
                "Policy API. Verify manually in Admin console."
            ),
            remediation=(
                "Admin console > Generative AI > Gemini app. "
                "Restrict Gemini app access to licensed users only. https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-the-gemini-app-on-or-off"
            ),
        )

    return make_fail(
        check_id="GWS.GEMINI.1.1",
        title="Ensure Gemini app access is restricted to licensed users",
        level="L1", source="CISA", section="Gemini",
        details="Gemini app access is available to unlicensed users.",
        actual_value=unlicensed_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Generative AI > Gemini app. "
            "Disable unlicensed access to ensure only licensed "
            "users can access Gemini features. https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-the-gemini-app-on-or-off"
        ),
    )


_GEMINI_BETA_SETTING_NAMES = (
    "Beta Gemini Features Beta Features enabled",  # live admin-log name (flip test 2026-11-06)
    "GenAiAlphaSettingsProto alpha_enabled",  # name used by CISA ScubaGoggles
)


@check(
    check_id="GWS.GEMINI.2.1",
    title="Ensure alpha Gemini features are disabled",
    level="L1",
    source="CISA",
    section="Gemini",
    remediation=(
        "Admin console > Generative AI > Gemini in Workspace > Beta features "
        "(Beta Gemini features). Disable alpha/beta features to avoid exposing "
        "users to unstable or untested functionality. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/turn-access-to-google-workspace-with-gemini-beta-on-or-off"
    ),
)
def check_gemini_alpha_features(data: dict) -> CheckResult:
    """Alpha Gemini features should be disabled in production environments."""
    _ID = "GWS.GEMINI.2.1"
    _TITLE = "Ensure alpha Gemini features are disabled"
    _L, _S, _SEC = "L1", "CISA", "Gemini"
    _REMED = (
        "Admin console > Generative AI > Gemini in Workspace > Beta features "
        "(Beta Gemini features). Disable alpha/beta features to avoid exposing "
        "users to unstable or untested functionality. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/turn-access-to-google-workspace-with-gemini-beta-on-or-off"
    )

    policies = data.get("policies", {})
    gemini = policies.get("gemini", {})

    # OU-aware path
    # Policy API gemini_for_workspace.beta_features.enabled (seen live 2026-11-07); the admin-log
    # inference below stays as the fallback.
    ou_values = get_ou_values(policies.get("gemini_for_workspace", {}), "beta_features")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "enabled", "alphaFeaturesEnabled", "alpha_features_enabled")
            if val is None:
                return None
            return (val is False, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have alpha Gemini features enabled", pass_text="have alpha Gemini features disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Not exposed by the Policy API: infer from the latest admin audit-log change. The live
    # SETTING_NAME (flip test 2026-11-06) is "Beta Gemini Features Beta Features enabled" under
    # APPLICATION_NAME "Gemini in Workspace"; the first save logs CREATE_APPLICATION_SETTING and
    # later saves CHANGE_APPLICATION_SETTING, both with NEW_VALUE "true"/"false". The ScubaGoggles
    # name is kept as a fallback. No event -> fall through to MANUAL.
    for setting_name in _GEMINI_BETA_SETTING_NAMES:
        inferred = result_from_setting_changes(
            data, setting_name, ('true',),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            what="Alpha/Beta Gemini features", remediation=_REMED,
        )
        if inferred is not None:
            return inferred

    # Fallback: mapped root-level value
    features = gemini.get("features", {})
    alpha_enabled = features.get("alpha_features_enabled", None)

    if alpha_enabled is False:
        return make_pass(
            check_id="GWS.GEMINI.2.1",
            title="Ensure alpha Gemini features are disabled",
            level="L1", source="CISA", section="Gemini",
            details="Alpha Gemini features are disabled.",
            actual_value=alpha_enabled,
            expected_value="Disabled for all OUs",
        )

    if alpha_enabled is None:
        return make_review(
            check_id="GWS.GEMINI.2.1",
            title="Ensure alpha Gemini features are disabled",
            level="L1", source="CISA", section="Gemini",
            details=(
                "Gemini app settings are not available via the Cloud Identity "
                "Policy API. Verify manually in Admin console."
            ),
            remediation=(
                "Admin console > Generative AI > Gemini in Workspace > Beta features "
                "(Beta Gemini features). Disable alpha/beta features. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/turn-access-to-google-workspace-with-gemini-beta-on-or-off"
            ),
        )

    return make_fail(
        check_id="GWS.GEMINI.2.1",
        title="Ensure alpha Gemini features are disabled",
        level="L1", source="CISA", section="Gemini",
        details="Alpha Gemini features are enabled.",
        actual_value=alpha_enabled,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Apps > Google Workspace > Gemini > "
            "Features. Disable alpha features to avoid exposing "
            "users to unstable or untested functionality. https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/turn-access-to-google-workspace-with-gemini-beta-on-or-off"
        ),
    )


# ===========================================================================
# Assured Controls - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.ASSUREDCONTROLS.1.1",
    title="Ensure access approvals are enabled",
    level="L2",
    source="CISA",
    section="Assured Controls",
    remediation=(
        "Admin console > Account > Account settings > "
        "Assured Controls. Enable access approvals to require "
        "explicit approval before Google support can access data. https://knowledge.workspace.google.com/admin/security/access-approvals-require-google-staff-to-request-approval-before-viewing-support-data"
    ),
    requires_license="assured_controls",
)
def check_access_approvals_enabled(data: dict) -> CheckResult:
    """Access approvals should be enabled for sensitive operations."""
    _ID = "GWS.ASSUREDCONTROLS.1.1"
    _TITLE = "Ensure access approvals are enabled"
    _L, _S, _SEC = "L2", "CISA", "Assured Controls"
    _REMED = (
        "Admin console > Account > Account settings > "
        "Assured Controls. Enable access approvals to require "
        "explicit approval before Google support can access data. https://knowledge.workspace.google.com/admin/security/access-approvals-require-google-staff-to-request-approval-before-viewing-support-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = []  # P3: "security.assured_controls" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "accessApprovalsEnabled", "access_approvals_enabled")
            if val is None:
                return None
            return (val is True, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack access approvals", pass_text="have access approvals enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Not exposed by the Policy API: infer from the latest "Access Approvals enabled"
    # admin audit-log change (setting name as used by CISA ScubaGoggles).
    inferred = result_from_setting_changes(
        data, "Access Approvals enabled", ("false",),
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        what="Access approvals", remediation=_REMED,
    )
    if inferred is not None:
        return inferred

    # Fallback: mapped root-level value
    assured = security.get("assured_controls", {})
    enabled = assured.get("access_approvals_enabled", None)

    if enabled is True:
        return make_pass(
            check_id="GWS.ASSUREDCONTROLS.1.1",
            title="Ensure access approvals are enabled",
            level="L2", source="CISA", section="Assured Controls",
            details="Access approvals are enabled.",
            actual_value=enabled,
            expected_value="Enabled for all OUs",
        )

    if enabled is None:
        return make_manual(
            check_id="GWS.ASSUREDCONTROLS.1.1",
            title="Ensure access approvals are enabled",
            level="L2", source="CISA", section="Assured Controls",
            details="Could not determine access approvals setting.",
            remediation=(
                "Admin console > Account > Account settings > "
                "Assured Controls. Enable access approvals. https://knowledge.workspace.google.com/admin/security/access-approvals-require-google-staff-to-request-approval-before-viewing-support-data"
            ),
        )

    return make_fail(
        check_id="GWS.ASSUREDCONTROLS.1.1",
        title="Ensure access approvals are enabled",
        level="L2", source="CISA", section="Assured Controls",
        details="Access approvals are not enabled.",
        actual_value=enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Account > Account settings > "
            "Assured Controls. Enable access approvals to require "
            "explicit approval before Google support can access data. https://knowledge.workspace.google.com/admin/security/access-approvals-require-google-staff-to-request-approval-before-viewing-support-data"
        ),
    )


@check(
    check_id="GWS.ASSUREDCONTROLS.1.2",
    title="Ensure support access is restricted to US personnel",
    level="L2",
    source="CISA",
    section="Assured Controls",
    remediation=(
        "Admin console > Account > Account settings > "
        "Assured Controls. Set support access region to "
        "'US only' to ensure only US-based personnel can "
        "provide support. https://knowledge.workspace.google.com/admin/security/access-management-limit-the-google-staff-who-can-take-support-actions-related-to-your-data"
    ),
    requires_license="assured_controls",
)
def check_support_access_region(data: dict) -> CheckResult:
    """Support access should be restricted to US personnel only."""
    _ID = "GWS.ASSUREDCONTROLS.1.2"
    _TITLE = "Ensure support access is restricted to US personnel"
    _L, _S, _SEC = "L2", "CISA", "Assured Controls"
    _REMED = (
        "Admin console > Account > Account settings > "
        "Assured Controls. Set support access region to "
        "'US only' to ensure only US-based personnel can "
        "provide support. https://knowledge.workspace.google.com/admin/security/access-management-limit-the-google-staff-who-can-take-support-actions-related-to-your-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    # Policy API: access_management.user_scoping.accessManagementRegime
    regimes = get_ou_values(policies.get("access_management", {}), "user_scoping")
    if regimes:
        _US_REGIMES = ("US_GOOGLE_STAFF", "CJIS_IRS_1075_GOOGLE_STAFF")

        def _judge_regime(entry):
            regime = field_value(entry, "accessManagementRegime")
            if regime is None:
                return None
            return (regime in _US_REGIMES, regime)

        return ou_verdict(
            regimes, _judge_regime, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not restrict Google support access to US staff",
            pass_text="restrict Google support access to US staff",
            expected_value="US_GOOGLE_STAFF for all OUs", remediation=_REMED,
        )

    ou_values = []  # P3: "security.assured_controls" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "supportAccessRegion", "support_access_region")
            if val is None:
                return None
            return (val in ("us", "us_only", "US", "US_ONLY"), val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack US-only support access", pass_text="restrict support access to US personnel",
            expected_value="us", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    assured = security.get("assured_controls", {})
    region = assured.get("support_access_region", None)

    if region in ("us", "us_only"):
        return make_pass(
            check_id="GWS.ASSUREDCONTROLS.1.2",
            title="Ensure support access is restricted to US personnel",
            level="L2", source="CISA", section="Assured Controls",
            details=f"Support access is restricted to '{region}' personnel.",
            actual_value=region,
            expected_value="us",
        )

    if region is None:
        return make_manual(
            check_id="GWS.ASSUREDCONTROLS.1.2",
            title="Ensure support access is restricted to US personnel",
            level="L2", source="CISA", section="Assured Controls",
            details="Could not determine support access region setting.",
            remediation=(
                "Admin console > Account > Account settings > "
                "Assured Controls. Restrict support access to "
                "US personnel only. https://knowledge.workspace.google.com/admin/security/access-management-limit-the-google-staff-who-can-take-support-actions-related-to-your-data"
            ),
        )

    return make_fail(
        check_id="GWS.ASSUREDCONTROLS.1.2",
        title="Ensure support access is restricted to US personnel",
        level="L2", source="CISA", section="Assured Controls",
        details=f"Support access region is '{region}', not restricted to US personnel.",
        actual_value=region,
        expected_value="us",
        remediation=(
            "Admin console > Account > Account settings > "
            "Assured Controls. Set support access region to "
            "'US only' to ensure only US-based personnel can "
            "provide support. https://knowledge.workspace.google.com/admin/security/access-management-limit-the-google-staff-who-can-take-support-actions-related-to-your-data"
        ),
    )


@check(
    check_id="GWS.ASSUREDCONTROLS.2.1",
    title="Ensure multi-region data processing is disabled",
    level="L2",
    source="CISA",
    section="Assured Controls",
    remediation=(
        "Admin console > Account > Account settings > "
        "Assured Controls. Disable multi-region data processing "
        "to ensure data is processed only in the designated region. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    ),
    requires_license="assured_controls",
)
def check_multi_region_processing_disabled(data: dict) -> CheckResult:
    """Multi-region data processing should be disabled for data residency."""
    _ID = "GWS.ASSUREDCONTROLS.2.1"
    _TITLE = "Ensure multi-region data processing is disabled"
    _L, _S, _SEC = "L2", "CISA", "Assured Controls"
    _REMED = (
        "Admin console > Account > Account settings > "
        "Assured Controls. Disable multi-region data processing "
        "to ensure data is processed only in the designated region. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = []  # P3: "security.assured_controls" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "multiRegionProcessingEnabled", "multi_region_processing_enabled")
            if val is None:
                return None
            return (val is False, val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have multi-region processing enabled", pass_text="have multi-region processing disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Not exposed by the Policy API: each app logs a "<App>NonRegionalizedFunctionality..."
    # setting change; ENABLED means data may be processed across regions for that app.
    enabled_apps: dict[str, list[str]] = {}
    seen_event = False
    for app in ("Calendar", "Docs", "Gmail", "Chat", "Meet", "Gemini"):
        changes = latest_setting_changes(data, f"{app}NonRegionalizedFunctionalityStateSettingsProto state")
        for ou, value in changes.items():
            seen_event = True
            if value.upper() == "ENABLED":
                enabled_apps.setdefault(ou, []).append(app)
    if enabled_apps:
        summary = "; ".join(f"{ou}: {', '.join(apps)}" for ou, apps in sorted(enabled_apps.items()))
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Multi-region data processing is enabled (latest admin-log change) for {summary}",
            actual_value=summary, expected_value="Disabled for all apps and OUs", remediation=_REMED,
        )
    if seen_event:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Multi-region data processing was disabled in every logged setting change.",
            actual_value="disabled", expected_value="Disabled for all apps and OUs",
        )

    # Fallback: mapped root-level value
    assured = security.get("assured_controls", {})
    multi_region = assured.get("multi_region_processing_enabled", None)

    if multi_region is False:
        return make_pass(
            check_id="GWS.ASSUREDCONTROLS.2.1",
            title="Ensure multi-region data processing is disabled",
            level="L2", source="CISA", section="Assured Controls",
            details="Multi-region data processing is disabled.",
            actual_value=multi_region,
            expected_value="Disabled for all OUs",
        )

    if multi_region is None:
        return make_manual(
            check_id="GWS.ASSUREDCONTROLS.2.1",
            title="Ensure multi-region data processing is disabled",
            level="L2", source="CISA", section="Assured Controls",
            details="Could not determine multi-region processing setting.",
            remediation=(
                "Admin console > Account > Account settings > "
                "Assured Controls. Disable multi-region data processing. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
            ),
        )

    return make_fail(
        check_id="GWS.ASSUREDCONTROLS.2.1",
        title="Ensure multi-region data processing is disabled",
        level="L2", source="CISA", section="Assured Controls",
        details="Multi-region data processing is enabled.",
        actual_value=multi_region,
        expected_value="Disabled for all OUs",
        remediation=(
            "Admin console > Account > Account settings > "
            "Assured Controls. Disable multi-region data processing "
            "to ensure data is processed only in the designated region. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
        ),
    )


# ===========================================================================
# Sites - CISA SCuBA checks
# ===========================================================================

@check(
    check_id="GWS.SITES.1.1",
    title="Ensure Sites service is disabled",
    level="L1",
    source="CISA",
    section="Sites",
    remediation=(
        "Admin console > Apps > Google Workspace > Sites. "
        "Disable the Sites service to reduce the attack surface "
        "if Google Sites is not actively used. https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off-for-users"
    ),
)
def check_sites_service_disabled(data: dict) -> CheckResult:
    """Sites service should be disabled if not required."""
    _ID = "GWS.SITES.1.1"
    _TITLE = "Ensure Sites service is disabled"
    _L, _S, _SEC = "L1", "CISA", "Sites"
    _REMED = (
        "Admin console > Apps > Google Workspace > Sites. "
        "Disable the Sites service to reduce the attack surface "
        "if Google Sites is not actively used. https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    sites = policies.get("sites", {})

    # OU-aware path
    ou_values = get_ou_values(sites, "service_status")
    if ou_values:
        def _judge(entry):
            val = field_value(entry, "serviceState", "serviceStatus", "service_status")
            if val is None:
                return None
            return (val in ("disabled", "off", "DISABLED", "OFF"), val)

        return ou_verdict(
            ou_values, _judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Sites service enabled", pass_text="have Sites service disabled",
            expected_value="disabled", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    status = sites.get("service_status", None)

    if status in ("disabled", "off"):
        return make_pass(
            check_id="GWS.SITES.1.1",
            title="Ensure Sites service is disabled",
            level="L1", source="CISA", section="Sites",
            details="Sites service is disabled.",
            actual_value=status,
            expected_value="disabled",
        )

    if status is None:
        return make_manual(
            check_id="GWS.SITES.1.1",
            title="Ensure Sites service is disabled",
            level="L1", source="CISA", section="Sites",
            details="Could not determine Sites service status.",
            remediation=(
                "Admin console > Apps > Google Workspace > Sites. "
                "Disable the Sites service if not required. https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.SITES.1.1",
        title="Ensure Sites service is disabled",
        level="L1", source="CISA", section="Sites",
        details=f"Sites service is '{status}', not disabled.",
        actual_value=status,
        expected_value="disabled",
        remediation=(
            "Admin console > Apps > Google Workspace > Sites. "
            "Disable the Sites service to reduce the attack surface "
            "if Google Sites is not actively used. https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off-for-users"
        ),
    )