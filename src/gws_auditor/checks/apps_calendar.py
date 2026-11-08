# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.1: Calendar checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Calendar controls.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   latest_setting_changes,
                   format_ou_values_readable, field_value, ou_verdict)
from ..models import CheckResult, Status


def _humanize_sharing_level(value: str) -> str:
    """Convert API sharing enum or ACL role to human-readable text."""
    mapping = {
        "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE": "All information (read, write, manage)",
        "EXTERNAL_ALL_INFO_READ_WRITE": "All information (read, write)",
        "EXTERNAL_ALL_INFO_READ": "All information (read only)",
        "EXTERNAL_FREE_BUSY_ONLY": "Free/busy information only",
        "EXTERNAL_NO_FREE_BUSY": "No external sharing",
        "FREE_BUSY_ONLY": "Free/busy information only",
        "ONLY_FREE_BUSY": "Free/busy information only",
        "ALL_INFO_READ_WRITE_MANAGE": "All information (read, write, manage)",
        "ALL_INFO_READ_WRITE": "All information (read, write)",
        "ALL_INFO_READ": "All information (read only)",
        "reader": "Can see all event details",
        "writer": "Can edit events",
        "freeBusyReader": "Can see only free/busy",
        "owner": "Full control",
    }
    return mapping.get(value, value)


@check(
    check_id="CIS-3.1.1.1.1",
    title="Ensure external sharing for primary calendars is limited",
    level="L1",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Set external sharing for primary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    ),
)
def check_primary_cal_external_sharing(data: dict) -> CheckResult:
    """Primary calendar external sharing should be limited to free/busy only."""
    _ID = "CIS-3.1.1.1.1"
    _TITLE = "Ensure external sharing for primary calendars is limited"
    _L, _S, _SEC = "L1", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Set external sharing for primary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    )
    # The Cloud Identity Policy API uses EXTERNAL_-prefixed enum values for
    # external sharing (e.g. EXTERNAL_FREE_BUSY_ONLY).  Both prefixed and
    # unprefixed forms are accepted so the check works with any API version.
    # EXTERNAL_NO_FREE_BUSY (no external sharing) is even more restrictive.
    _SAFE = (
        "FREE_BUSY_ONLY", "ONLY_FREE_BUSY",
        "EXTERNAL_FREE_BUSY_ONLY", "EXTERNAL_NO_FREE_BUSY",
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(
        cal, "primary_calendar_max_allowed_external_sharing",
    )
    if ou_values:
        def _judge(entry):
            sharing = field_value(entry, "maxAllowedExternalSharing")
            if sharing is None:
                return None  # absent or *_UNSPECIFIED: cannot judge
            return sharing in _SAFE, sharing
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unsafe external sharing",
            pass_text="limit primary calendar external sharing to free/busy",
            expected_value="Free/busy information only for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value (backward compat / cached data)
    primary = cal.get("primary_calendar", {})
    ext_sharing = primary.get("external_sharing", "")
    expected = "only_free_busy"

    if ext_sharing == expected:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Primary calendar external sharing is limited to free/busy information only.",
            actual_value=ext_sharing, expected_value=expected,
        )

    if ext_sharing is None or ext_sharing == "":
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine primary calendar external sharing setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Primary calendar external sharing is set to '{ext_sharing}' instead of '{expected}'.",
        actual_value=ext_sharing, expected_value=expected,
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.1.1.2",
    title="Ensure internal sharing for primary calendars is configured",
    level="L1",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Set internal sharing for primary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    ),
)
def check_primary_cal_internal_sharing(data: dict) -> CheckResult:
    """Internal sharing for primary calendars should share only free/busy info."""
    _ID = "CIS-3.1.1.1.2"
    _TITLE = "Ensure internal sharing for primary calendars is configured"
    _L, _S, _SEC = "L1", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Set internal sharing for primary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    )
    _SAFE = ("FREE_BUSY_ONLY", "ONLY_FREE_BUSY")

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = []  # P3: "calendar.primary_calendar_max_allowed_internal_sharing" is not a Cloud Identity Policy API setting type; nothing to look up
    # The calendar ACL sample below is the live evidence for this control.
    if ou_values:
        def _judge(entry):
            sharing = field_value(entry, "maxAllowedInternalSharing")
            if sharing is None:
                return None  # absent or *_UNSPECIFIED: cannot judge
            return sharing in _SAFE, sharing
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unsafe internal sharing",
            pass_text="limit primary calendar internal sharing to free/busy",
            expected_value="Free/busy information only for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    primary = cal.get("primary_calendar", {})
    int_sharing = primary.get("internal_sharing", "")
    expected = "only_free_busy"

    if int_sharing == expected:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Primary calendar internal sharing is configured to share only free/busy.",
            actual_value=int_sharing, expected_value=expected,
        )

    if not int_sharing:
        # ACL-based fallback: use sampled calendar ACLs per OU
        calendar_acls = data.get("calendar_acls", {})
        if calendar_acls:
            _ROLE_SAFE = ("freeBusyReader",)
            unsafe_ous = []
            for ou, acl_info in calendar_acls.items():
                role = acl_info.get("role", "")
                if role not in _ROLE_SAFE:
                    unsafe_ous.append({"org_unit": ou, "value": role})
            if unsafe_ous:
                ou_names = ", ".join(u["org_unit"] for u in unsafe_ous)
                return make_fail(
                    check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                    details=f"{len(unsafe_ous)} OU(s) have unsafe internal sharing (via ACL sampling): {ou_names}",
                    actual_value=format_ou_values_readable(unsafe_ous, _humanize_sharing_level),
                    expected_value="Can see only free/busy for all OUs",
                    remediation=_REMED,
                )
            return make_pass(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"All {len(calendar_acls)} OU(s) limit primary calendar internal sharing to free/busy (via ACL sampling).",
                actual_value=f"All {len(calendar_acls)} OU(s): Can see only free/busy",
                expected_value="Can see only free/busy",
            )

        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine primary calendar internal sharing setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Primary calendar internal sharing is set to '{int_sharing}' instead of '{expected}'.",
        actual_value=int_sharing, expected_value=expected,
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.1.1.3",
    title="Ensure external invitations show warning",
    level="L1",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > External Invitations. "
        "Enable 'Warn users when inviting guests outside of the domain'. https://knowledge.workspace.google.com/admin/calendar/allow-external-invitations-in-google-calendar-events"
    ),
)
def check_cal_external_invitation_warning(data: dict) -> CheckResult:
    """Calendar should warn users when inviting external guests."""
    _ID = "CIS-3.1.1.1.3"
    _TITLE = "Ensure external invitations show warning"
    _L, _S, _SEC = "L1", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > External Invitations. "
        "Enable 'Warn users when inviting guests outside of the domain'. https://knowledge.workspace.google.com/admin/calendar/allow-external-invitations-in-google-calendar-events"
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(cal, "external_invitations")
    if ou_values:
        def _judge(entry):
            # Real field first; warnOnExternalInvitations is a legacy alias.
            warn = field_value(entry, "warnOnInvite", "warnOnExternalInvitations")
            if warn is None:
                return None
            return warn is True
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack external invitation warning",
            pass_text="have external invitation warnings enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback
    ext_warning = cal.get("external_invitation_warning", None)

    if ext_warning is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="External invitation warnings are enabled.",
            actual_value=ext_warning, expected_value="Enabled for all OUs",
        )

    if ext_warning is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine external invitation warning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="External invitation warnings are not enabled.",
        actual_value=ext_warning, expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.1.2.1",
    title="Ensure external sharing for secondary calendars is limited",
    level="L1",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Set external sharing for secondary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    ),
)
def check_secondary_cal_external_sharing(data: dict) -> CheckResult:
    """Secondary calendar external sharing should be limited to free/busy only."""
    _ID = "CIS-3.1.1.2.1"
    _TITLE = "Ensure external sharing for secondary calendars is limited"
    _L, _S, _SEC = "L1", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Set external sharing for secondary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    )
    _SAFE = (
        "FREE_BUSY_ONLY", "ONLY_FREE_BUSY",
        "EXTERNAL_FREE_BUSY_ONLY", "EXTERNAL_NO_FREE_BUSY",
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(
        cal, "secondary_calendar_max_allowed_external_sharing",
    )
    if ou_values:
        def _judge(entry):
            sharing = field_value(entry, "maxAllowedExternalSharing")
            if sharing is None:
                return None  # absent or *_UNSPECIFIED: cannot judge
            return sharing in _SAFE, sharing
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unsafe secondary calendar external sharing",
            pass_text="limit secondary calendar external sharing to free/busy",
            expected_value="Free/busy information only for all OUs", remediation=_REMED,
        )

    # Fallback
    secondary = cal.get("secondary_calendar", {})
    ext_sharing = secondary.get("external_sharing", "")
    expected = "only_free_busy"

    if ext_sharing == expected:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Secondary calendar external sharing is limited to free/busy information only.",
            actual_value=ext_sharing, expected_value=expected,
        )

    if ext_sharing is None or ext_sharing == "":
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine secondary calendar external sharing setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Secondary calendar external sharing is set to '{ext_sharing}' instead of '{expected}'.",
        actual_value=ext_sharing, expected_value=expected,
        remediation=_REMED,
    )


_SECONDARY_INTERNAL_SHARING_SETTING = "SHARING_INSIDE_DOMAIN_FOR_SECONDARY_CALENDAR"  # CHANGE_CALENDAR_SETTING, live 2026-11-07
_LOG_SAFE = {"SHOW_ONLY_FREE_BUSY_INFORMATION"}
_LOG_UNSAFE = {"READ_ONLY_ACCESS"}


@check(
    check_id="CIS-3.1.1.2.2",
    title="Ensure internal sharing for secondary calendars is configured",
    level="L2",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Set internal sharing for secondary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    ),
)
def check_secondary_cal_internal_sharing(data: dict) -> CheckResult:
    """Internal sharing for secondary calendars should be properly configured."""
    _ID = "CIS-3.1.1.2.2"
    _TITLE = "Ensure internal sharing for secondary calendars is configured"
    _L, _S, _SEC = "L2", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Set internal sharing for secondary calendars to 'Only free/busy information'. https://knowledge.workspace.google.com/admin/calendar/set-google-calendar-sharing-options"
    )
    _SAFE = ("FREE_BUSY_ONLY", "ONLY_FREE_BUSY")

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = []  # P3: "calendar.secondary_calendar_max_allowed_internal_sharing" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry):
            sharing = field_value(entry, "maxAllowedInternalSharing")
            if sharing is None:
                return None  # absent or *_UNSPECIFIED: cannot judge
            return sharing in _SAFE, sharing
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unsafe secondary calendar internal sharing",
            pass_text="limit secondary calendar internal sharing to free/busy",
            expected_value="Free/busy information only for all OUs", remediation=_REMED,
        )

    # Admin-log path. The Policy API has no type for this setting; the console save logs
    # CHANGE_CALENDAR_SETTING with SETTING_NAME "SHARING_INSIDE_DOMAIN_FOR_SECONDARY_CALENDAR",
    # OLD_VALUE/NEW_VALUE "READ_ONLY_ACCESS" (Share all information) or
    # "SHOW_ONLY_FREE_BUSY_INFORMATION", and an empty ORG_UNIT_NAME (domain-wide), observed live in
    # both directions on 2026-11-07/08. "No sharing" has no observed value, so an unknown value is
    # reported for review rather than guessed.
    changes = {ou: v for ou, v in latest_setting_changes(data, _SECONDARY_INTERNAL_SHARING_SETTING).items()
               if v.upper() != "INHERIT_FROM_PARENT"}
    if changes:
        unsafe = sorted(ou for ou, v in changes.items() if v.upper() in _LOG_UNSAFE)
        unknown = sorted(ou for ou, v in changes.items() if v.upper() not in _LOG_UNSAFE | _LOG_SAFE)
        if unsafe:
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=(f"Secondary calendars default to sharing all event details inside the domain in "
                         f"{len(unsafe)} scope(s) per the latest admin-log change: {', '.join(unsafe)}"),
                actual_value=", ".join(f"{ou} → {changes[ou]}" for ou in unsafe),
                expected_value="SHOW_ONLY_FREE_BUSY_INFORMATION", remediation=_REMED,
            )
        if unknown:
            return make_review(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=(f"The latest admin-log change sets secondary calendar internal sharing to an "
                         f"unrecognised value: {', '.join(f'{ou} → {changes[ou]}' for ou in unknown)}. "
                         "Verify it is at most free/busy in Admin console > Apps > Google Workspace > Calendar > General settings."),
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Secondary calendar internal sharing defaults to free/busy only per the latest admin-log change.",
            actual_value=changes, expected_value="SHOW_ONLY_FREE_BUSY_INFORMATION",
        )

    # Fallback
    secondary = cal.get("secondary_calendar", {})
    int_sharing = secondary.get("internal_sharing", "")
    expected = "only_free_busy"

    if int_sharing == expected:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Secondary calendar internal sharing is configured to share only free/busy.",
            actual_value=int_sharing, expected_value=expected,
        )

    if not int_sharing:
        # NOTE: calendar_acls samples PRIMARY calendar ACLs, which do not
        # reflect the admin default for SECONDARY calendars.  The admin
        # setting is a sharing cap, not an injected domain ACL rule, so
        # ACL sampling cannot determine it.  Return MANUAL for human review.
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine secondary calendar internal sharing: the Policy API does not expose it "
                "and no change to it appears in the admin-log window. Verify manually in "
                "Admin console > Apps > Google Workspace > Calendar > General settings."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Secondary calendar internal sharing is set to '{int_sharing}' instead of '{expected}'.",
        actual_value=int_sharing, expected_value=expected,
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.1.3.1",
    scored=False,  # P6: the Policy API never returns calendar_offline_access; MANUAL by design
    title="Ensure Calendar web offline access is disabled",
    level="L2",
    source="CIS",
    section="Calendar",
    remediation=(
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Disable 'Allow Calendar offline access'. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    ),
)
def check_cal_offline_access(data: dict) -> CheckResult:
    """Calendar offline access should be disabled to reduce data leakage risk."""
    _ID = "CIS-3.1.1.3.1"
    _TITLE = "Ensure Calendar web offline access is disabled"
    _L, _S, _SEC = "L2", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > General settings. "
        "Disable 'Allow Calendar offline access'. https://knowledge.workspace.google.com/admin/calendar/manage-calendar-for-your-users"
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(cal, "calendar_offline_access")
    # SYSTEM and documented-default entries are the value in force and are judged;
    # the decorator notes the provenance in the details.
    if ou_values:
        def _judge(entry):
            # Real field first; "enabled" is a legacy alias.
            enabled = field_value(entry, "enableOfflineAccess", "enabled")
            if enabled is None:
                return None
            return enabled is not True
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Calendar offline access enabled",
            pass_text="have Calendar offline access disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback
    offline_enabled = cal.get("offline_access_enabled", None)

    if offline_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Calendar web offline access is disabled.",
            actual_value=offline_enabled, expected_value="Disabled for all OUs",
        )

    if offline_enabled is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Calendar offline access setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Calendar web offline access is enabled.",
        actual_value=offline_enabled, expected_value="Disabled for all OUs",
        remediation=_REMED,
    )
