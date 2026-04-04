# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.1: Calendar checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Calendar controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, is_default_policy
from ..models import CheckResult, Status


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
    ou_values = get_ou_values(cal, "primary_calendar_max_allowed_external_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            sharing = entry["value"].get("maxAllowedExternalSharing", "")
            if sharing not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": sharing})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unsafe external sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value="FREE_BUSY_ONLY for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) limit primary calendar external sharing to free/busy.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="FREE_BUSY_ONLY",
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
    ou_values = get_ou_values(cal, "primary_calendar_max_allowed_internal_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            sharing = entry["value"].get("maxAllowedInternalSharing", "")
            if sharing not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": sharing})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unsafe internal sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value="FREE_BUSY_ONLY for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) limit primary calendar internal sharing to free/busy.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="FREE_BUSY_ONLY",
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
                ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
                return make_fail(
                    check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                    details=f"{len(unsafe_ous)} OU(s) have unsafe internal sharing (via ACL sampling): {ou_list}",
                    actual_value=unsafe_ous, expected_value="freeBusyReader for all OUs",
                    remediation=_REMED,
                )
            return make_pass(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"All {len(calendar_acls)} OU(s) limit primary calendar internal sharing to free/busy (via ACL sampling).",
                actual_value=f"{len(calendar_acls)} OU(s) safe", expected_value="freeBusyReader",
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
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Enable 'Warn users when inviting guests outside of the domain'. https://knowledge.workspace.google.com/admin/calendar/allow-external-invitations-in-google-calendar-events"
    ),
)
def check_cal_external_invitation_warning(data: dict) -> CheckResult:
    """Calendar should warn users when inviting external guests."""
    _ID = "CIS-3.1.1.1.3"
    _TITLE = "Ensure external invitations show warning"
    _L, _S, _SEC = "L1", "CIS", "Calendar"
    _REMED = (
        "Admin console > Apps > Google Workspace > Calendar > Sharing settings. "
        "Enable 'Warn users when inviting guests outside of the domain'. https://knowledge.workspace.google.com/admin/calendar/allow-external-invitations-in-google-calendar-events"
    )

    policies = data.get("policies", {})
    cal = policies.get("calendar", {})

    # OU-aware path
    ou_values = get_ou_values(cal, "external_invitations")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            warn = entry["value"].get("warnOnInvite",
                        entry["value"].get("warnOnExternalInvitations", None))
            if warn is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": warn})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack external invitation warning: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have external invitation warnings enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback
    ext_warning = cal.get("external_invitation_warning", None)

    if ext_warning is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="External invitation warnings are enabled.",
            actual_value=ext_warning, expected_value=True,
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
        actual_value=ext_warning, expected_value=True,
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
    ou_values = get_ou_values(cal, "secondary_calendar_max_allowed_external_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            sharing = entry["value"].get("maxAllowedExternalSharing", "")
            if sharing not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": sharing})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unsafe secondary calendar external sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value="FREE_BUSY_ONLY for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) limit secondary calendar external sharing to free/busy.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="FREE_BUSY_ONLY",
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
    ou_values = get_ou_values(cal, "secondary_calendar_max_allowed_internal_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            sharing = entry["value"].get("maxAllowedInternalSharing", "")
            if sharing not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": sharing})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unsafe secondary calendar internal sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value="FREE_BUSY_ONLY for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) limit secondary calendar internal sharing to free/busy.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="FREE_BUSY_ONLY",
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
                "Could not determine secondary calendar internal sharing setting. "
                "The Policy API does not expose this setting. Verify manually in "
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
    # Filter out DEFAULT (Google system default) entries — the Policy API
    # may not reflect admin overrides for this setting.
    admin_values = [e for e in ou_values if not is_default_policy(e)]
    if admin_values:
        unsafe_ous = []
        for entry in admin_values:
            enabled = entry["value"].get("enableOfflineAccess", entry["value"].get("enabled", None))
            if enabled is True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Calendar offline access enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(admin_values)} OU(s) have Calendar offline access disabled.",
            actual_value=f"{len(admin_values)} OU(s) safe", expected_value=False,
        )

    # If we had OU entries but they were all DEFAULT (Google system
    # defaults), the Policy API may not reflect the admin's actual
    # setting.  Return MANUAL so we don't false-positive.
    if ou_values and not admin_values:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Policy API returned only Google default values for "
                "Calendar offline access. Verify manually in Admin "
                "console > Apps > Google Workspace > Calendar > "
                "Advanced settings."
            ),
            remediation=_REMED,
        )

    # Fallback
    offline_enabled = cal.get("offline_access_enabled", None)

    if offline_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Calendar web offline access is disabled.",
            actual_value=offline_enabled, expected_value=False,
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
        actual_value=offline_enabled, expected_value=False,
        remediation=_REMED,
    )
