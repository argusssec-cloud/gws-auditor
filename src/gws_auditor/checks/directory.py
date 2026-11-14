# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 1: Directory checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.4.1 - Directory controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
from ..models import CheckResult, Status


_SA_ID = "CIS-1.1.1"
_SA_TITLE = "Ensure that between two and four Super Admin accounts are designated"
_SA_REMED = (
    "Admin console > Directory > Users, filter Admin role = Super admin. Keep between two and "
    "four Super Admin accounts: create a second dedicated admin account if there is only one, "
    "and demote accounts to delegated admin roles if there are more than four. "
    "https://knowledge.workspace.google.com/admin/users/make-a-user-an-admin"
)


@check(
    check_id=_SA_ID,
    title=_SA_TITLE,
    level="L1",
    source="CIS",
    section="Directory",
    remediation=_SA_REMED,
)
def check_super_admin_count(data: dict) -> CheckResult:
    """CIS 1.1.1 (v1.4.1, merges the former 1.1.1 and 1.1.2): more than one and no more than
    four Super Admin accounts.

    The lower bound counts active accounts only (a suspended super admin cannot sign in, so it
    gives no redundancy); the upper bound counts every account that holds the role, suspended
    included, because the role can be reactivated with a click.
    """
    users = data.get("users", [])
    super_admins = [u for u in users if u.get("is_super_admin", False)]
    active = [u for u in super_admins if not u.get("suspended", False)]
    suspended = [u for u in super_admins if u.get("suspended", False)]
    emails = sorted(u.get("primary_email", "unknown") for u in active)
    note = ""
    if suspended:
        note = (f" {len(suspended)} suspended super admin account(s) hold the role but cannot sign in: "
                f"{', '.join(sorted(u.get('primary_email', 'unknown') for u in suspended))}.")
    common = dict(check_id=_SA_ID, title=_SA_TITLE, level="L1", source="CIS", section="Directory")

    if len(active) < 2:
        return make_fail(
            **common,
            details=(f"Only {len(active)} active super admin account(s) found; at least two are required so "
                     f"that a single account is not a single point of failure.{note}"),
            actual_value=len(active), expected_value="2 to 4", remediation=_SA_REMED,
        )
    if len(super_admins) > 4:
        return make_fail(
            **common,
            details=(f"{len(super_admins)} accounts hold the Super Admin role, more than the maximum of four: "
                     f"{', '.join(sorted(u.get('primary_email', 'unknown') for u in super_admins))}. Assign "
                     f"delegated admin roles with the least privilege needed instead."),
            actual_value=len(super_admins), expected_value="2 to 4", remediation=_SA_REMED,
        )
    return make_pass(
        **common,
        details=f"{len(active)} active super admin account(s): {', '.join(emails)}.{note}",
        actual_value=len(active), expected_value="2 to 4",
    )


_SU_ID = "CIS-1.1.2"
_SU_TITLE = "Ensure Super Admin accounts are used only for super admin activities"
_SU_REMED = (
    "Give every administrator a separate standard account for daily work and keep the Super "
    "Admin account for super admin tasks only. Remove delegated admin roles from Super Admin "
    "accounts: Admin console > Account > Admin roles, or Directory > Users > the user > Admin "
    "roles and privileges. "
    "https://knowledge.workspace.google.com/admin/users/add-an-account-for-a-new-user"
)


@check(
    check_id=_SU_ID,
    title=_SU_TITLE,
    level="L1",
    source="CIS",
    section="Directory",
    remediation=_SU_REMED,
)
def check_super_admin_usage(data: dict) -> CheckResult:
    """CIS 1.1.2 (v1.4.1; 1.1.3 in v1.3.0). The benchmark's audit step: no user holds both
    the Super admin role and a delegated admin role. Judged from the Directory role
    assignments; heavy sign-in activity on a super admin account is reported as a WARN
    because it suggests the account doubles as a daily account.
    """
    users = data.get("users", [])
    login_logs = data.get("login_logs", [])
    roles = data.get("roles") or {}
    role_list = roles.get("roles", []) or []
    assignments = roles.get("assignments", []) or []
    super_admins = [u for u in users if u.get("is_super_admin", False)]
    common = dict(check_id=_SU_ID, title=_SU_TITLE, level="L1", source="CIS", section="Directory")

    if not super_admins:
        return make_manual(
            **common,
            details="No super admin accounts found to evaluate.",
            remediation="Verify super admin accounts exist and review their roles. https://knowledge.workspace.google.com/admin/users/add-an-account-for-a-new-user",
        )

    role_names = {r.get("roleId"): r.get("roleName") or r.get("roleId") for r in role_list}
    super_role_ids = {r.get("roleId") for r in role_list if r.get("isSuperAdminRole")}
    by_id = {str(u.get("id")): u for u in super_admins if u.get("id")}
    extra_roles: dict[str, list[str]] = {}
    for a in assignments:
        if a.get("assigneeType", "user") != "user":
            continue
        u = by_id.get(str(a.get("assignedTo")))
        if u is None or a.get("roleId") in super_role_ids:
            continue
        extra_roles.setdefault(u.get("primary_email", "unknown"), []).append(
            str(role_names.get(a.get("roleId"), a.get("roleId"))))
    for u in super_admins:
        email = u.get("primary_email", "unknown")
        if u.get("is_delegated_admin", False) and email not in extra_roles:
            extra_roles[email] = ["delegated admin role (isDelegatedAdmin)"]

    # Sign-in volume: more than 10 successful logins in the window suggests daily use.
    heavy_users = []
    for email in sorted(u.get("primary_email", "") for u in super_admins):
        login_count = sum(
            1 for log in login_logs
            if (log.get("actor_email") or (log.get("actor") or {}).get("email", "")) == email
            and log.get("event_name", "login_success") in ("login_success", "")
        )
        if login_count > 10:
            heavy_users.append(f"{email} ({login_count} logins)")
    heavy_note = (f" Heavy sign-in activity suggests daily use: {'; '.join(heavy_users)}." if heavy_users else "")

    if extra_roles:
        listing = "; ".join(f"{e} ({', '.join(r)})" for e, r in sorted(extra_roles.items()))
        return make_fail(
            **common,
            details=(f"{len(extra_roles)} super admin account(s) also hold delegated admin roles, so one "
                     f"account mixes everyday administration with super admin privileges: {listing}.{heavy_note}"),
            actual_value=extra_roles,
            expected_value="No account holds both the Super admin role and a delegated admin role",
            remediation=_SU_REMED,
        )
    if not role_list:
        return make_manual(
            **common,
            details=("Admin roles and role assignments were not collected (Directory API roles.list / "
                     "roleAssignments.list), so it cannot be verified that no super admin also holds a "
                     f"delegated admin role.{heavy_note}"),
            remediation=_SU_REMED,
        )
    if heavy_users:
        return make_warn(
            **common,
            details=(f"No super admin holds a delegated admin role, but {len(heavy_users)} account(s) show heavy "
                     f"sign-in activity, suggesting daily use: {'; '.join(heavy_users)}. Review whether these "
                     "accounts double as everyday accounts."),
            actual_value=heavy_users,
            expected_value="Super admins with <= 10 logins in the window and no delegated roles",
            remediation=_SU_REMED,
        )
    return make_pass(
        **common,
        details=(f"None of the {len(super_admins)} super admin account(s) holds a delegated admin role "
                 f"({len(assignments)} role assignment(s) reviewed) and sign-in activity is low."),
        actual_value={"super_admins": len(super_admins), "with_delegated_roles": 0},
        expected_value="No account holds both the Super admin role and a delegated admin role",
    )


@check(
    check_id="CIS-1.2.1.1",
    title="Ensure directory data is restricted from external access",
    level="L1",
    source="CIS",
    section="Directory",
    remediation=(
        "Admin console > Directory > Directory settings > Sharing settings > "
        "External Directory Sharing. Select 'Authenticated user basic profile "
        "fields' (REQUESTER_BASIC_PROFILE_ONLY). "
        "https://knowledge.workspace.google.com/admin/users/let-third-party-apps-access-directory-data"
    ),
)
def check_directory_external_sharing(data: dict) -> CheckResult:
    """Directory sharing settings should block external access.

    The Cloud Identity Policy API setting
    ``directory.external_directory_sharing`` exposes a ``sharing_option``
    enum:

    * ``REQUESTER_BASIC_PROFILE_ONLY`` — restricted (PASS)
    * ``ORGANIZATION_DIRECTORY_DATA`` — not restricted (FAIL)
    """
    _ID = "CIS-1.2.1.1"
    _TITLE = "Ensure directory data is restricted from external access"
    _L, _S, _SEC = "L1", "CIS", "Directory"
    _REMED = (
        "Admin console > Directory > Directory settings > Sharing settings > "
        "External Directory Sharing. Select 'Authenticated user basic profile "
        "fields' (REQUESTER_BASIC_PROFILE_ONLY). "
        "https://knowledge.workspace.google.com/admin/users/let-third-party-apps-access-directory-data"
    )
    _SAFE = "REQUESTER_BASIC_PROFILE_ONLY"

    # Directory external sharing is a global (org-wide) setting, not per-OU.
    policies = data.get("policies", {})
    directory = policies.get("directory", {})
    directory_settings = directory.get("sharing_settings", {})
    restricted = directory_settings.get("external_sharing_restricted", None)

    if restricted is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Directory sharing settings could not be retrieved. Manual review required.",
            remediation=_REMED,
        )

    if not restricted:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Directory data is accessible externally.",
            actual_value={"external_sharing_restricted": restricted},
            expected_value="External sharing restricted",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Directory data is restricted from external access.",
        actual_value={"external_sharing_restricted": restricted},
        expected_value="External sharing restricted",
    )
