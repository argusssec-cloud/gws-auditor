# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.6: Groups checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Groups controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
from ..models import CheckResult, Status


@check(
    check_id="CIS-3.1.6.1",
    title="Ensure external Groups access is private",
    level="L1",
    source="CIS",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set groups to private. Also review individual "
        "group settings at groups.google.com. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_external_access(data: dict) -> CheckResult:
    """Groups should be private and not accessible to external users."""
    groups = data.get("groups", [])
    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # Check org-level setting first
    default_visibility = groups_policy.get("default_group_visibility", "")
    external_access = groups_policy.get("external_members_allowed", None)

    if external_access is False and default_visibility in ("private", "members_only"):
        return make_pass(
            check_id="CIS-3.1.6.1",
            title="Ensure external Groups access is private",
            level="L1", source="CIS", section="Groups",
            details="Groups are configured as private with no external access.",
            actual_value={
                "visibility": default_visibility,
                "external_access": external_access,
            },
            expected_value="private visibility, no external members",
        )

    # Check individual groups for overly permissive settings
    public_groups_set = set()
    for group in groups:
        who_view = group.get("whoCanViewGroup", "")
        who_view_members = group.get("whoCanViewMembership", "")
        email = group.get("email", "unknown")
        if who_view in ("ANYONE_CAN_VIEW", "ALL_IN_DOMAIN_CAN_VIEW"):
            public_groups_set.add(email)
        elif who_view_members in ("ANYONE_CAN_VIEW", "ALL_IN_DOMAIN_CAN_VIEW"):
            public_groups_set.add(email)
    public_groups = sorted(public_groups_set)

    if public_groups:
        return make_fail(
            check_id="CIS-3.1.6.1",
            title="Ensure external Groups access is private",
            level="L1", source="CIS", section="Groups",
            details=(
                f"Found {len(public_groups)} group(s) with overly permissive visibility: "
                f"{', '.join(public_groups[:10])}"
                + ("..." if len(public_groups) > 10 else "")
            ),
            actual_value={"public_groups_count": len(public_groups)},
            expected_value="All groups with restricted visibility",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Set groups to private. Also review individual "
                "group settings at groups.google.com. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    if external_access is None and not groups:
        return make_manual(
            check_id="CIS-3.1.6.1",
            title="Ensure external Groups access is private",
            level="L1", source="CIS", section="Groups",
            details="Could not determine group visibility settings. Manual review required.",
            remediation=(
                "Admin console > Apps > Google Workspace > Groups for Business > "
                "Sharing settings. Set default group visibility to private. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
            ),
        )

    return make_pass(
        check_id="CIS-3.1.6.1",
        title="Ensure external Groups access is private",
        level="L1", source="CIS", section="Groups",
        details="No overly permissive groups found.",
        actual_value={"groups_checked": len(groups)},
        expected_value="All groups with restricted visibility",
    )


@check(
    check_id="CIS-3.1.6.2",
    title="Ensure group creation is restricted to admins",
    level="L1",
    source="CIS",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set 'Group creation' to 'Only organization admins "
        "can create groups'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_creation_restriction(data: dict) -> CheckResult:
    """Group creation should be restricted to administrators."""
    _ID = "CIS-3.1.6.2"
    _TITLE = "Ensure group creation is restricted to admins"
    _L, _S, _SEC = "L1", "CIS", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set 'Group creation' to 'Only organization admins "
        "can create groups'. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )
    _ACCEPTABLE = ("admins_only", "admin")

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            creator = (
                entry["value"].get("createGroupsAccessLevel", "")
                or entry["value"].get("whoCanCreateGroups", "")
                or entry["value"].get("groupCreation", "")
                or entry["value"].get("whoCanCreate", "")
            )
            # Normalize API enum: ADMIN_ONLY → admins_only, etc.
            _CREATOR_MAP = {
                "ALL_USERS_CAN_CREATE": "all_users_in_domain",
                "ADMINS_CAN_CREATE": "admins_only",
                "ADMIN_ONLY": "admins_only",
            }
            if creator:
                creator = _CREATOR_MAP.get(creator, creator)
            if not creator or creator.lower() not in _ACCEPTABLE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": creator})
        if unsafe_ous:
            ou_list = ", ".join(
                f"{u['org_unit']} ({u['value']})" for u in unsafe_ous
            )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow non-admin group creation: {ou_list}",
                actual_value=unsafe_ous, expected_value="admins_only for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict group creation to admins.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="admins_only",
        )

    # Fallback: mapped root-level value
    creation_setting = groups_policy.get("who_can_create_groups", "")

    if creation_setting.lower() in _ACCEPTABLE:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Group creation is restricted to administrators.",
            actual_value=creation_setting,
            expected_value="admins_only",
        )

    if not creation_setting:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine group creation restriction setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Group creation is set to '{creation_setting}' instead of admins only.",
        actual_value=creation_setting,
        expected_value="admins_only",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.6.3",
    title="Ensure group conversation viewing is restricted",
    level="L2",
    source="CIS",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set default conversation viewing to 'Members only'. "
        "Review individual groups at groups.google.com. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
    ),
)
def check_groups_conversation_visibility(data: dict) -> CheckResult:
    """Group conversations should not be visible to non-members."""
    _ID = "CIS-3.1.6.3"
    _TITLE = "Ensure group conversation viewing is restricted"
    _L, _S, _SEC = "L2", "CIS", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Set default conversation viewing to 'Members only'. "
        "Review individual groups at groups.google.com. https://knowledge.workspace.google.com/admin/groups/options-for-limiting-group-access-and-activity"
    )

    groups = data.get("groups", [])
    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # Check individual groups first (Groups Settings API data)
    exposed_groups = []
    for group in groups:
        settings = group.get("settings", {})
        who_can_view = settings.get("whoCanViewGroup", "")
        if who_can_view in ("ANYONE_CAN_VIEW", "ALL_IN_DOMAIN_CAN_VIEW"):
            exposed_groups.append(group.get("email", "unknown"))

    if exposed_groups:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {len(exposed_groups)} group(s) with publicly visible conversations: "
                f"{', '.join(exposed_groups[:10])}"
                + ("..." if len(exposed_groups) > 10 else "")
            ),
            actual_value={"exposed_groups_count": len(exposed_groups)},
            expected_value="All group conversations restricted to members",
            remediation=_REMED,
        )

    default_message_visibility = groups_policy.get("default_message_visibility", "")

    if default_message_visibility in ("members_only", "private"):
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Group conversations are restricted to members.",
            actual_value=default_message_visibility,
            expected_value="members_only",
        )

    if not groups and not default_message_visibility:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine group conversation visibility settings. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Groups for Business > Sharing settings."
            ),
            remediation=_REMED,
        )

    # If default_message_visibility is set but not to a safe value, fail
    if default_message_visibility:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Default group conversation visibility is '{default_message_visibility}', not restricted to members.",
            actual_value=default_message_visibility,
            expected_value="members_only",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"No groups with overly permissive conversation visibility found ({len(groups)} checked).",
        actual_value={"groups_checked": len(groups)},
        expected_value="All group conversations restricted to members",
    )


@check(
    check_id="ADD-37",
    title="Ensure group discoverability is restricted",
    level="L2",
    source="OTHER",
    section="Groups",
    remediation=(
        "Review group settings at groups.google.com. "
        "Set 'Who can discover group' to 'Members' or "
        "'Organization members only' for each group. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_groups_discoverability(data: dict) -> CheckResult:
    """Groups should not be publicly discoverable."""
    _ID = "ADD-37"
    _TITLE = "Ensure group discoverability is restricted"
    _L, _S, _SEC = "L2", "OTHER", "Groups"
    _REMED = (
        "Review group settings at groups.google.com. "
        "Set 'Who can discover group' to 'Members' or "
        "'Organization members only' for each group. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    groups = data.get("groups", [])

    if not groups:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="No groups found to check discoverability settings.",
            remediation=_REMED,
        )

    public_groups = []
    for group in groups:
        settings = group.get("settings", {})
        discover = settings.get("whoCanDiscoverGroup", "")
        if discover == "ANYONE_CAN_DISCOVER":
            public_groups.append(group.get("email", "unknown"))

    if public_groups:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {len(public_groups)} group(s) discoverable by anyone: "
                f"{', '.join(public_groups[:10])}"
                + ("..." if len(public_groups) > 10 else "")
            ),
            actual_value={"public_groups_count": len(public_groups), "public_groups": public_groups[:20]},
            expected_value="No publicly discoverable groups",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"No groups with public discoverability found ({len(groups)} checked).",
        actual_value={"groups_checked": len(groups)},
        expected_value="No publicly discoverable groups",
    )
