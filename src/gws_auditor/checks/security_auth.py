# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 4.1: Authentication checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Authentication and security controls.
"""

from .base import (
    check, make_pass, make_fail, make_warn, make_manual, make_partial,
    get_ou_values,
)
from ..models import CheckResult, Status


@check(
    check_id="CIS-4.1.1.1",
    title="Ensure 2-Step Verification is enforced for all admins",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Set enforcement to 'On' for admin organizational units. "
        "Ensure all admin accounts complete 2SV enrollment. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_2sv_admin_enforcement(data: dict) -> CheckResult:
    """2-Step Verification (2SV) must be enforced for all admin accounts."""
    _ID = "CIS-4.1.1.1"
    _TITLE = "Ensure 2-Step Verification is enforced for all admins"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Set enforcement to 'On' for admin organizational units. "
        "Ensure all admin accounts complete 2SV enrollment. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    users = data.get("users", [])
    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_enforcement")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            # The API may use enforcedFrom (non-empty = enforced) or enableEnforcement
            enforced_from = entry["value"].get("enforcedFrom")
            if enforced_from is not None:
                # enforcedFrom is a timestamp string; non-empty means enforcement is scheduled.
                # Parse it to verify it's a real date, not just a truthy string.
                from datetime import datetime, timezone
                try:
                    dt = datetime.fromisoformat(enforced_from.replace("Z", "+00:00"))
                    enabled = dt <= datetime.now(timezone.utc)
                except (ValueError, AttributeError):
                    enabled = False
            else:
                enabled = entry["value"].get("enableEnforcement", False)
            if enabled is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        # Also check individual admin users
        admins = [u for u in users if u.get("is_admin", False) or u.get("is_super_admin", False)]
        admins_without_2sv = [
            u.get("primary_email", "unknown")
            for u in admins
            if not u.get("is_enrolled_in_2sv", False)
        ]
        if unsafe_ous or admins_without_2sv:
            details_parts = []
            if unsafe_ous:
                ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
                details_parts.append(f"{len(unsafe_ous)} OU(s) lack 2SV enforcement: {ou_list}")
            if admins_without_2sv:
                details_parts.append(
                    f"{len(admins_without_2sv)} admin(s) not enrolled: "
                    f"{', '.join(admins_without_2sv[:10])}"
                )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="; ".join(details_parts),
                actual_value={"unsafe_ous": unsafe_ous, "admins_without_2sv": admins_without_2sv},
                expected_value="2SV enforced for all OUs and all admins enrolled",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) enforce 2SV and all {len(admins)} admin(s) are enrolled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="2SV enforced for all OUs",
        )

    # Fallback: existing mapped value logic
    twosv = security.get("two_step_verification", {})
    admin_enforcement = twosv.get("admin_enforcement", "")

    admins = [u for u in users if u.get("is_admin", False) or u.get("is_super_admin", False)]
    admins_without_2sv = [
        u.get("primary_email", "unknown")
        for u in admins
        if not u.get("is_enrolled_in_2sv", False)
    ]

    if admin_enforcement == "enforced" and not admins_without_2sv:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"2SV is enforced for all {len(admins)} admin account(s).",
            actual_value={"enforcement": admin_enforcement, "admins_without_2sv": []},
            expected_value="enforced for all admins",
        )

    if admins_without_2sv:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(admins_without_2sv)} admin(s) do not have 2SV enrolled: "
                f"{', '.join(admins_without_2sv[:10])}"
                + ("..." if len(admins_without_2sv) > 10 else "")
            ),
            actual_value={"admins_without_2sv": admins_without_2sv},
            expected_value="All admins enrolled in 2SV",
            remediation=_REMED,
        )

    if admin_enforcement != "enforced":
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"2SV enforcement for admins is '{admin_enforcement}' instead of 'enforced'.",
            actual_value=admin_enforcement,
            expected_value="enforced",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="2SV enforcement is configured for admins.",
        actual_value=admin_enforcement,
        expected_value="enforced",
    )


@check(
    check_id="CIS-4.1.1.2",
    title="Ensure hardware security keys are required for admins",
    level="L2",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Set 'Allowed 2-step verification methods' to 'Only security key' "
        "for admin OUs. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_security_keys_admin(data: dict) -> CheckResult:
    """Admins should be required to use hardware security keys for 2SV."""
    _ID = "CIS-4.1.1.2"
    _TITLE = "Ensure hardware security keys are required for admins"
    _L, _S, _SEC = "L2", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Set 'Allowed 2-step verification methods' to 'Only security key' "
        "for admin OUs. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )
    _SAFE = ("ONLY_SECURITY_KEY", "SECURITY_KEY_ONLY", "security_key_only", "security_key")

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_enforcement_factor")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            method = entry["value"].get("allowedSignInFactorSet",
                        entry["value"].get("allowedMethod", ""))
            if method not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": method})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not require security keys: {ou_list}",
                actual_value=unsafe_ous, expected_value="ONLY_SECURITY_KEY for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) require hardware security keys for 2SV.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="ONLY_SECURITY_KEY",
        )

    # Fallback: existing mapped value logic
    twosv = security.get("two_step_verification", {})
    admin_method = twosv.get("admin_allowed_methods", "")

    if admin_method in ("security_key_only", "security_key"):
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Hardware security keys are required for admin 2SV.",
            actual_value=admin_method,
            expected_value="security_key_only",
        )

    if not admin_method:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine admin 2SV method requirement.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Admin 2SV method is '{admin_method}', not restricted to security keys.",
        actual_value=admin_method,
        expected_value="security_key_only",
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.1.3",
    title="Ensure 2-Step Verification is enforced for all users",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > 2-step verification. "
        "Set enforcement to 'On'. Allow a grace period for users to enroll. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    ),
)
def check_2sv_all_users(data: dict) -> CheckResult:
    """2-Step Verification should be enforced for all user accounts."""
    _ID = "CIS-4.1.1.3"
    _TITLE = "Ensure 2-Step Verification is enforced for all users"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > 2-step verification. "
        "Set enforcement to 'On'. Allow a grace period for users to enroll. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
    )

    users = data.get("users", [])
    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_enrollment")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            # The enrollment setting may use allowEnrollment / enableEnrollment
            # or enforcedFrom / enableEnforcement
            enforced_from = entry["value"].get("enforcedFrom")
            if enforced_from is not None:
                from datetime import datetime, timezone
                try:
                    dt = datetime.fromisoformat(enforced_from.replace("Z", "+00:00"))
                    enforced = dt <= datetime.now(timezone.utc)
                except (ValueError, AttributeError):
                    enforced = False
            else:
                enforced = entry["value"].get("allowEnrollment",
                                              entry["value"].get("enableEnrollment",
                                                                 entry["value"].get("enableEnforcement",
                                                                                    entry["value"].get("enforced", False))))
            if enforced is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enforced})
        # Also check individual users
        users_without_2sv = [
            u.get("primary_email", "unknown")
            for u in users
            if not u.get("is_enrolled_in_2sv", False)
        ]
        if unsafe_ous or users_without_2sv:
            details_parts = []
            if unsafe_ous:
                ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
                details_parts.append(f"{len(unsafe_ous)} OU(s) lack 2SV enrollment enforcement: {ou_list}")
            if users_without_2sv:
                details_parts.append(
                    f"{len(users_without_2sv)} user(s) not enrolled: "
                    f"{', '.join(users_without_2sv[:5])}"
                )
            # PARTIAL when policy enforces 2SV at every OU but a small slice
            # of users haven't enrolled yet (new hires in grace period,
            # service accounts, etc.). Pure user-level lag without policy
            # gaps is "compliance in some users" — credit the partial state.
            total_users = max(len(users), 1)
            user_lag_only = (
                not unsafe_ous and users_without_2sv
                and len(users_without_2sv) / total_users < 0.20
            )
            if user_lag_only:
                return make_partial(
                    check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                    details="; ".join(details_parts),
                    actual_value={
                        "unsafe_ous": unsafe_ous,
                        "not_enrolled_count": len(users_without_2sv),
                        "total": total_users,
                    },
                    expected_value="2SV enforced for all OUs and all users enrolled",
                    remediation=_REMED,
                )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="; ".join(details_parts),
                actual_value={"unsafe_ous": unsafe_ous, "not_enrolled_count": len(users_without_2sv)},
                expected_value="2SV enforced for all OUs and all users enrolled",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) enforce 2SV enrollment and all {len(users)} user(s) are enrolled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="2SV enforced for all OUs",
        )

    # Fallback: existing mapped value logic
    twosv = security.get("two_step_verification", {})
    enforcement = twosv.get("enforcement", "")
    users_without_2sv = [
        u.get("primary_email", "unknown")
        for u in users
        if not u.get("is_enrolled_in_2sv", False)
    ]
    total_users = len(users)
    enrolled_count = total_users - len(users_without_2sv)

    if enforcement == "enforced" and not users_without_2sv:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"2SV is enforced and all {total_users} users are enrolled.",
            actual_value={"enforcement": enforcement, "enrolled": enrolled_count, "total": total_users},
            expected_value="enforced for all users",
        )

    if users_without_2sv:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(users_without_2sv)} of {total_users} user(s) not enrolled in 2SV. "
                f"Examples: {', '.join(users_without_2sv[:5])}"
                + ("..." if len(users_without_2sv) > 5 else "")
            ),
            actual_value={
                "enforcement": enforcement,
                "not_enrolled_count": len(users_without_2sv),
                "total": total_users,
            },
            expected_value="All users enrolled in 2SV",
            remediation=_REMED,
        )

    if enforcement != "enforced":
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"2SV enforcement is '{enforcement}' instead of 'enforced'.",
            actual_value=enforcement,
            expected_value="enforced",
            remediation=_REMED,
        )

    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="2SV enforcement is configured for all users.",
        actual_value=enforcement,
        expected_value="enforced",
    )


@check(
    check_id="CIS-4.1.2.1",
    title="Ensure super admin account recovery is disabled",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Account recovery. "
        "Disable 'Allow super admins to recover their account' to prevent "
        "account takeover via recovery mechanisms. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    ),
)
def check_super_admin_recovery(data: dict) -> CheckResult:
    """Super admin self-service account recovery should be disabled."""
    _ID = "CIS-4.1.2.1"
    _TITLE = "Ensure super admin account recovery is disabled"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Account recovery. "
        "Disable 'Allow super admins to recover their account' to prevent "
        "account takeover via recovery mechanisms. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "super_admin_account_recovery")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enabled = entry["value"].get("enableAccountRecovery", entry["value"].get("enabled", None))
            if enabled is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have super admin recovery enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value="Recovery disabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have super admin account recovery disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    recovery = security.get("account_recovery", {})
    super_admin_recovery = recovery.get("super_admin_recovery_enabled", None)

    if super_admin_recovery is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Super admin account recovery is disabled.",
            actual_value=super_admin_recovery,
            expected_value=False,
        )

    if super_admin_recovery is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine super admin recovery setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Super admin account recovery is enabled, which could be exploited.",
        actual_value=super_admin_recovery,
        expected_value=False,
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.2.2",
    title="Ensure user account recovery is enabled",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Account recovery. "
        "Enable account recovery for standard users to allow "
        "self-service password reset. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    ),
)
def check_user_account_recovery(data: dict) -> CheckResult:
    """User account recovery should be enabled for non-admin users."""
    _ID = "CIS-4.1.2.2"
    _TITLE = "Ensure user account recovery is enabled"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Account recovery. "
        "Enable account recovery for standard users to allow "
        "self-service password reset. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "user_account_recovery")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enabled = entry["value"].get("enableAccountRecovery", entry["value"].get("enabled", None))
            if enabled is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have user account recovery disabled: {ou_list}",
                actual_value=unsafe_ous, expected_value="Recovery enabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have user account recovery enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: existing mapped value logic
    recovery = security.get("account_recovery", {})
    user_recovery = recovery.get("user_recovery_enabled", None)

    if user_recovery is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="User account recovery is enabled.",
            actual_value=user_recovery,
            expected_value=True,
        )

    if user_recovery is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine user account recovery setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="User account recovery is disabled, which may cause lockout issues.",
        actual_value=user_recovery,
        expected_value=True,
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.3.1",
    title="Ensure Advanced Protection Program is available",
    level="L2",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enable 'Allow users to enroll in the Advanced Protection Program'. https://knowledge.workspace.google.com/admin/security/enable-user-enrollment-in-the-advanced-protection-program"
    ),
)
def check_advanced_protection(data: dict) -> CheckResult:
    """The Advanced Protection Program should be available for enrollment."""
    _ID = "CIS-4.1.3.1"
    _TITLE = "Ensure Advanced Protection Program is available"
    _L, _S, _SEC = "L2", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enable 'Allow users to enroll in the Advanced Protection Program'. https://knowledge.workspace.google.com/admin/security/enable-user-enrollment-in-the-advanced-protection-program"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "advanced_protection_program")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            available = entry["value"].get("enableAdvancedProtectionSelfEnrollment",
                        entry["value"].get("enableAdvancedProtection",
                        entry["value"].get("enabled", None)))
            if available is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": available})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not have Advanced Protection available: {ou_list}",
                actual_value=unsafe_ous, expected_value="Available for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Advanced Protection Program available.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: existing mapped value logic
    app = security.get("advanced_protection", {})
    available = app.get("enrollment_available", None)

    if available is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Advanced Protection Program enrollment is available.",
            actual_value=available,
            expected_value=True,
        )

    if available is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Advanced Protection Program availability.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Advanced Protection Program enrollment is not available.",
        actual_value=available,
        expected_value=True,
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.4.1",
    title="Ensure login challenges are enforced",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Login challenges. "
        "Enable login challenges for suspicious sign-in attempts. "
        "Do not disable employee ID challenges. https://knowledge.workspace.google.com/admin/security/protect-google-workspace-accounts-with-security-challenges"
    ),
)
def check_login_challenges(data: dict) -> CheckResult:
    """Login challenges should be used to verify suspicious sign-in attempts."""
    _ID = "CIS-4.1.4.1"
    _TITLE = "Ensure login challenges are enforced"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Login challenges. "
        "Enable login challenges for suspicious sign-in attempts. "
        "Do not disable employee ID challenges. https://knowledge.workspace.google.com/admin/security/protect-google-workspace-accounts-with-security-challenges"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "login_challenges")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enabled = entry["value"].get("enableEmployeeIdChallenge",
                        entry["value"].get("enableLoginChallenge",
                        entry["value"].get("enabled", None)))
            if enabled is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not have login challenges enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value="Login challenges enabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have login challenges enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: existing mapped value logic
    login = security.get("login_challenges", {})
    enabled = login.get("enabled", None)

    if enabled is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Login challenges are enabled for suspicious sign-in attempts.",
            actual_value=enabled,
            expected_value=True,
        )

    if enabled is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine login challenge setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Login challenges are not enabled.",
        actual_value=enabled,
        expected_value=True,
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.5.1",
    title="Ensure password policy is enhanced",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Password management. "
        "Set minimum password length to at least 12 characters. "
        "Enable 'Enforce strong password'. Consider disabling password expiration "
        "per NIST guidelines. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    ),
)
def check_password_policy(data: dict) -> CheckResult:
    """Password policy should enforce strong requirements."""
    _ID = "CIS-4.1.5.1"
    _TITLE = "Ensure password policy is enhanced"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Password management. "
        "Set minimum password length to at least 12 characters. "
        "Enable 'Enforce strong password'. Consider disabling password expiration "
        "per NIST guidelines. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "password")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            min_len = entry["value"].get("minimumLength", 0)
            enforce = entry["value"].get("enforceRequirementsAtLogin", None)
            issues = []
            if min_len < 12:
                issues.append(f"min_length={min_len}")
            if enforce is not True:
                issues.append(f"enforce_at_login={enforce}")
            if issues:
                unsafe_ous.append({
                    "org_unit": entry["org_unit"],
                    "value": ", ".join(issues),
                })
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have weak password policy: {ou_list}",
                actual_value=unsafe_ous, expected_value="minimumLength >= 12, enforceRequirementsAtLogin for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have strong password policy.",
            actual_value=f"{len(ou_values)} OU(s) safe",
            expected_value="minimumLength >= 12, enforceRequirementsAtLogin",
        )

    # Fallback: existing mapped value logic
    password = security.get("password_management", {})
    min_length = password.get("minimum_length", 0)
    enforce_strong = password.get("enforce_strong_password", None)
    expiration_days = password.get("expiration_days", 0)

    issues = []
    if min_length < 12:
        issues.append(f"Minimum password length is {min_length} (should be >= 12)")
    if enforce_strong is not True:
        issues.append("Strong password enforcement is not enabled")

    if not issues and (min_length > 0 or enforce_strong is not None):
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Password policy is configured (min length: {min_length}, strong: {enforce_strong}).",
            actual_value={
                "min_length": min_length,
                "enforce_strong": enforce_strong,
                "expiration_days": expiration_days,
            },
            expected_value="Minimum 12 characters, strong password enforced",
        )

    if min_length == 0 and enforce_strong is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine password policy settings.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Password policy issues: {'; '.join(issues)}.",
        actual_value={
            "min_length": min_length,
            "enforce_strong": enforce_strong,
            "expiration_days": expiration_days,
        },
        expected_value="Minimum 12 characters, strong password enforced",
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.2.6.1",
    title="Ensure less secure app access is disabled",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Less secure apps. "
        "Select 'Disable access to less secure apps (Recommended)'. "
        "Users should migrate to OAuth-based authentication. https://knowledge.workspace.google.com/admin/apps/control-access-to-less-secure-apps"
    ),
)
def check_less_secure_apps(data: dict) -> CheckResult:
    """Less secure app access should be disabled for all users."""
    _ID = "CIS-4.2.6.1"
    _TITLE = "Ensure less secure app access is disabled"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Less secure apps. "
        "Select 'Disable access to less secure apps (Recommended)'. "
        "Users should migrate to OAuth-based authentication. https://knowledge.workspace.google.com/admin/apps/control-access-to-less-secure-apps"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "less_secure_apps")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            allowed = entry["value"].get("allowLessSecureApps", None)
            if allowed is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": allowed})
        # Also check individual users
        users = data.get("users", [])
        users_with_lsa = [
            u.get("primary_email", "unknown")
            for u in users
            if u.get("less_secure_apps_enabled", False)
        ]
        if unsafe_ous or users_with_lsa:
            details_parts = []
            if unsafe_ous:
                ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
                details_parts.append(f"{len(unsafe_ous)} OU(s) allow less secure apps: {ou_list}")
            if users_with_lsa:
                details_parts.append(
                    f"{len(users_with_lsa)} user(s) have LSA enabled: "
                    f"{', '.join(users_with_lsa[:10])}"
                )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="; ".join(details_parts),
                actual_value={"unsafe_ous": unsafe_ous, "users_with_lsa_count": len(users_with_lsa)},
                expected_value="Disabled for all OUs and users",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) disable less secure app access.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    lsa = security.get("less_secure_apps", {})
    allowed = lsa.get("allowed", None)

    users = data.get("users", [])
    users_with_lsa = [
        u.get("primary_email", "unknown")
        for u in users
        if u.get("less_secure_apps_enabled", False)
    ]

    if allowed is False and not users_with_lsa:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Less secure app access is disabled for all users.",
            actual_value={"org_policy": False, "users_with_lsa": 0},
            expected_value="Disabled for all users",
        )

    if users_with_lsa:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(users_with_lsa)} user(s) have less secure app access enabled: "
                f"{', '.join(users_with_lsa[:10])}"
                + ("..." if len(users_with_lsa) > 10 else "")
            ),
            actual_value={"users_with_lsa_count": len(users_with_lsa)},
            expected_value="Disabled for all users",
            remediation=_REMED,
        )

    if allowed is True:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Less secure app access is allowed at the organization level.",
            actual_value=allowed,
            expected_value=False,
            remediation=_REMED,
        )

    return make_manual(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Could not determine less secure app access setting.",
        remediation=_REMED,
    )
