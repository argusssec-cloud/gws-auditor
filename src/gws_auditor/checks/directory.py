# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 1: Directory checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Directory controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
from ..models import CheckResult, Status


@check(
    check_id="CIS-1.1.1",
    title="Ensure more than one Super Admin account exists",
    level="L1",
    source="CIS",
    section="Directory",
    remediation=(
        "Create at least 2 super admin accounts for redundancy. "
        "Admin console > Account > Admin roles > Super Admin. "
        "https://knowledge.workspace.google.com/admin/users/add-accounts"
    ),
)
def check_super_admin_count_min(data: dict) -> CheckResult:
    """At least 2 super admin accounts should exist for redundancy."""
    users = data.get("users", [])
    super_admins = [u for u in users if u.get("is_super_admin", False)]
    count = len(super_admins)

    if count >= 2:
        return make_pass(
            check_id="CIS-1.1.1",
            title="Ensure more than one Super Admin account exists",
            level="L1", source="CIS", section="Directory",
            details=f"Found {count} super admin accounts.",
            actual_value=count,
            expected_value=">=2",
        )
    return make_fail(
        check_id="CIS-1.1.1",
        title="Ensure more than one Super Admin account exists",
        level="L1", source="CIS", section="Directory",
        details=f"Only {count} super admin account(s) found. At least 2 are required.",
        actual_value=count,
        expected_value=">=2",
        remediation=(
            "Create at least 2 super admin accounts for redundancy. "
            "Admin console > Account > Admin roles > Super Admin. "
            "https://knowledge.workspace.google.com/admin/users/add-accounts"
        ),
    )


@check(
    check_id="CIS-1.1.2",
    title="Ensure fewer than 4 Super Admin accounts exist",
    level="L1",
    source="CIS",
    section="Directory",
    remediation=(
        "Reduce super admin accounts to fewer than 4. "
        "Details: https://knowledge.workspace.google.com/admin/users/make-a-user-an-admin | "
        "Remediation: https://admin.google.com/ac/list/roles"
    ),
)
def check_super_admin_count_max(data: dict) -> CheckResult:
    """No more than 3 super admin accounts should exist to limit exposure."""
    users = data.get("users", [])
    super_admins = [u for u in users if u.get("is_super_admin", False)]
    count = len(super_admins)
    sa_emails = [u.get("primary_email", "unknown") for u in super_admins]

    if count < 4:
        return make_pass(
            check_id="CIS-1.1.2",
            title="Ensure fewer than 4 Super Admin accounts exist",
            level="L1", source="CIS", section="Directory",
            details=f"Found {count} super admin accounts (within acceptable range).",
            actual_value=count,
            expected_value="<4",
        )
    return make_fail(
        check_id="CIS-1.1.2",
        title="Ensure fewer than 4 Super Admin accounts exist",
        level="L1", source="CIS", section="Directory",
        details=(
            f"Found {count} super admin accounts, which exceeds the maximum "
            f"of 3: {', '.join(sa_emails)}"
        ),
        actual_value=count,
        expected_value="<4",
        remediation=(
            "Reduce super admin accounts to fewer than 4. "
            "Details: https://knowledge.workspace.google.com/admin/users/make-a-user-an-admin | "
            "Remediation: https://admin.google.com/ac/list/roles"
        ),
    )


@check(
    check_id="CIS-1.1.3",
    title="Ensure Super Admin accounts are only used for admin tasks",
    level="L2",
    source="CIS",
    section="Directory",
    remediation=(
        "Create separate standard user accounts for daily tasks. "
        "Super admin accounts should only be used for administrative duties. "
        "Admin console > Directory > Users. "
        "https://knowledge.workspace.google.com/admin/users/add-accounts"
    ),
)
def check_super_admin_usage(data: dict) -> CheckResult:
    """Super admin accounts should not be used for daily activities."""
    users = data.get("users", [])
    login_logs = data.get("login_logs", [])
    super_admins = [u for u in users if u.get("is_super_admin", False)]
    sa_emails = {u.get("primary_email", "") for u in super_admins}

    # Heuristic: check if any super admin has more than 10 login events
    # in the available log window (roughly 30 days)
    heavy_users = []
    for email in sa_emails:
        login_count = sum(
            1 for log in login_logs
            if log.get("actor", {}).get("email", "") == email
        )
        if login_count > 10:
            heavy_users.append(f"{email} ({login_count} logins)")

    if not sa_emails:
        return make_manual(
            check_id="CIS-1.1.3",
            title="Ensure Super Admin accounts are only used for admin tasks",
            level="L2", source="CIS", section="Directory",
            details="No super admin accounts found to evaluate.",
            remediation="Verify super admin accounts exist and review their usage. https://knowledge.workspace.google.com/admin/users/add-accounts",
        )

    if heavy_users:
        return make_warn(
            check_id="CIS-1.1.3",
            title="Ensure Super Admin accounts are only used for admin tasks",
            level="L2", source="CIS", section="Directory",
            details=(
                "The following super admin accounts show heavy login activity, "
                f"suggesting possible daily use: {'; '.join(heavy_users)}. "
                "Manual review recommended."
            ),
            actual_value=heavy_users,
            expected_value="Super admins with <= 10 logins in 30 days",
            remediation=(
                "Create separate standard user accounts for daily tasks. "
                "Super admin accounts should only be used for administrative duties. "
                "Admin console > Directory > Users. "
                "https://knowledge.workspace.google.com/admin/users/add-accounts"
            ),
        )

    return make_review(
        check_id="CIS-1.1.3",
        title="Ensure Super Admin accounts are only used for admin tasks",
        level="L2", source="CIS", section="Directory",
        details=(
            f"Login activity for {len(sa_emails)} super admin account(s) appears low. "
            "Manual review is still recommended to confirm accounts are not used "
            "for routine tasks."
        ),
        remediation=(
            "Review super admin activity in the Admin console > Reporting > "
            "Audit and investigation tool. Ensure super admin accounts are "
            "dedicated to administrative tasks only. "
            "https://knowledge.workspace.google.com/admin/security/about-the-security-investigation-tool"
        ),
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
        "https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
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
        "https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
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
