# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 4.1: Authentication checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.4.1 - Authentication and security controls.
"""

from datetime import datetime, timezone

from .base import (
    check, make_pass, make_fail, make_warn, make_manual, make_partial, make_review,
    get_ou_values, field_value, ou_verdict, format_ou_values_readable,
)
from ..models import CheckResult, Status


def _enforced_from_active(enforced_from) -> bool:
    """True when a 2SV ``enforcedFrom`` timestamp lies in the past (enforcement in force).

    A value that is not a real timestamp counts as not enforced.
    """
    try:
        dt = datetime.fromisoformat(str(enforced_from).replace("Z", "+00:00"))
        return dt <= datetime.now(timezone.utc)
    except (ValueError, AttributeError):
        return False


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
        def judge(entry):
            # Google documents enforcedFrom as "Unset" = not enforced, so an absent field is a
            # concrete non-compliant value, not an unknown. The timestamp must be a real date in
            # the past; enableEnforcement is a legacy alias.
            enforced_from = field_value(entry, "enforcedFrom")
            if enforced_from is not None:
                return _enforced_from_active(enforced_from)
            return field_value(entry, "enableEnforcement") is True

        policy = ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack 2SV enforcement", pass_text="enforce 2SV",
            expected_value="2SV enforced for all OUs", remediation=_REMED,
        )
        # Also check individual admin users
        admins = [u for u in users if u.get("is_admin", False) or u.get("is_super_admin", False)]
        admins_without_2sv = [
            u.get("primary_email", "unknown")
            for u in admins
            if not u.get("is_enrolled_in_2sv", False) and not u.get("suspended", False)
        ]
        if policy.status == Status.FAIL or admins_without_2sv:
            details_parts = []
            if policy.status != Status.PASS:
                details_parts.append(policy.details)
            if admins_without_2sv:
                details_parts.append(
                    f"{len(admins_without_2sv)} admin(s) not enrolled: "
                    f"{', '.join(admins_without_2sv[:10])}"
                )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="; ".join(details_parts),
                actual_value={"unsafe_ous": policy.actual_value if policy.status == Status.FAIL else "",
                              "admins_without_2sv": admins_without_2sv},
                expected_value="2SV enforced for all OUs and all admins enrolled",
                remediation=_REMED,
            )
        if policy.status != Status.PASS:
            return policy  # enforcement undetermined in some OU: MANUAL
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
        if not u.get("is_enrolled_in_2sv", False) and not u.get("suspended", False)
    ]

    if admin_enforcement in ("enforced", True) and not admins_without_2sv:
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

    if admin_enforcement not in ("enforced", True):
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
    # Policy API enums for "Only security key" (with or without backup security codes)
    _SAFE = ("PASSKEY_ONLY", "PASSKEY_PLUS_SECURITY_CODE", "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE",
             "ONLY_SECURITY_KEY", "SECURITY_KEY_ONLY", "security_key_only", "security_key")

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "two_step_verification_enforcement_factor")
    if ou_values:
        def judge(entry):
            method = field_value(entry, "allowedSignInFactorSet", "allowedMethod")
            if method is None:
                return None  # absent or *_UNSPECIFIED: cannot judge
            return method in _SAFE, method

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not require security keys", pass_text="require hardware security keys for 2SV",
            expected_value="ONLY_SECURITY_KEY for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    twosv = security.get("two_step_verification", {})
    admin_method = twosv.get("admin_allowed_methods", "")

    if admin_method in ("security_key_only", "security_key") or str(admin_method).startswith("passkey"):
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

    # OU-aware path: two_step_verification_enforcement.enforcedFrom decides whether 2SV
    # is enforced (documented default: unset = not enforced). The enrollment setting only
    # says whether users may enrol and is consulted when no enforcement policy exists.
    ou_values = get_ou_values(security, "two_step_verification_enforcement")
    from_enforcement = bool(ou_values)
    if not ou_values:
        ou_values = get_ou_values(security, "two_step_verification_enrollment")
    if ou_values:
        def judge(entry):
            # The enforcement setting carries enforcedFrom (documented: "Unset" = not
            # enforced, so absent is a concrete non-compliant value); the enrollment setting
            # carries allowEnrollment. The remaining names are legacy aliases.
            enforced_from = field_value(entry, "enforcedFrom")
            if enforced_from is not None:
                return _enforced_from_active(enforced_from)
            flag = field_value(entry, "allowEnrollment", "enableEnrollment", "enableEnforcement", "enforced")
            if flag is None:
                return False if from_enforcement else None
            return flag is True

        policy = ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack 2SV enrollment enforcement", pass_text="enforce 2SV enrollment",
            expected_value="2SV enforced for all OUs", remediation=_REMED,
        )
        policy_gap = policy.status == Status.FAIL
        # Also check individual users
        users_without_2sv = [
            u.get("primary_email", "unknown")
            for u in users
            if not u.get("is_enrolled_in_2sv", False) and not u.get("suspended", False)
        ]
        if policy_gap or users_without_2sv:
            details_parts = []
            if policy.status != Status.PASS:
                details_parts.append(policy.details)
            if users_without_2sv:
                details_parts.append(
                    f"{len(users_without_2sv)} user(s) not enrolled: "
                    f"{', '.join(users_without_2sv[:5])}"
                )
            unsafe_ous = policy.actual_value if policy_gap else ""
            # PARTIAL when policy enforces 2SV at every OU but a small slice
            # of users haven't enrolled yet (new hires in grace period,
            # service accounts, etc.). Pure user-level lag without policy
            # gaps is "compliance in some users" — credit the partial state.
            total_users = max(len(users), 1)
            user_lag_only = (
                not policy_gap and users_without_2sv
                and len(users_without_2sv) / total_users < 0.20
            )
            if user_lag_only and policy.status != Status.PASS:
                # Small user lag but the policy itself is undetermined: review, not credit.
                return make_review(
                    check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                    details="; ".join(details_parts),
                    expected_value="2SV enforced for all OUs and all users enrolled",
                    remediation=_REMED,
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
        if policy.status != Status.PASS:
            return policy  # enforcement undetermined in some OU: MANUAL
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
        if not u.get("is_enrolled_in_2sv", False) and not u.get("suspended", False)
    ]
    total_users = len(users)
    enrolled_count = total_users - len(users_without_2sv)

    if enforcement in ("enforced", True) and not users_without_2sv:
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

    if enforcement not in ("enforced", True):
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
    level="L2",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Account recovery. "
        "Disable 'Allow super admins to recover their account' to prevent "
        "account takeover via recovery mechanisms. https://knowledge.workspace.google.com/admin/users/allow-super-administrators-to-recover-their-password"
    ),
)
def check_super_admin_recovery(data: dict) -> CheckResult:
    """Super admin self-service account recovery should be disabled."""
    _ID = "CIS-4.1.2.1"
    _TITLE = "Ensure super admin account recovery is disabled"
    _L, _S, _SEC = "L2", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Account recovery. "
        "Disable 'Allow super admins to recover their account' to prevent "
        "account takeover via recovery mechanisms. https://knowledge.workspace.google.com/admin/users/allow-super-administrators-to-recover-their-password"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "super_admin_account_recovery")
    if ou_values:
        def judge(entry):
            enabled = field_value(entry, "enableAccountRecovery", "enabled")
            return None if enabled is None else enabled is False

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have super admin recovery enabled",
            pass_text="have super admin account recovery disabled",
            expected_value="Recovery disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    recovery = security.get("account_recovery", {})
    super_admin_recovery = recovery.get("super_admin_recovery_enabled", None)

    if super_admin_recovery is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Super admin account recovery is disabled.",
            actual_value=super_admin_recovery,
            expected_value="Disabled for all OUs",
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
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.1.2.2",
    title="Ensure user account recovery is enabled",
    level="L1",
    source="CIS",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Account recovery. "
        "Enable account recovery for standard users to allow "
        "self-service password reset. https://knowledge.workspace.google.com/admin/users/set-up-password-recovery-for-users"
    ),
)
def check_user_account_recovery(data: dict) -> CheckResult:
    """User account recovery should be enabled for non-admin users."""
    _ID = "CIS-4.1.2.2"
    _TITLE = "Ensure user account recovery is enabled"
    _L, _S, _SEC = "L1", "CIS", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Account recovery. "
        "Enable account recovery for standard users to allow "
        "self-service password reset. https://knowledge.workspace.google.com/admin/users/set-up-password-recovery-for-users"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "user_account_recovery")
    if ou_values:
        def judge(entry):
            enabled = field_value(entry, "enableAccountRecovery", "enabled")
            return None if enabled is None else enabled is True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have user account recovery disabled",
            pass_text="have user account recovery enabled",
            expected_value="Recovery enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    recovery = security.get("account_recovery", {})
    user_recovery = recovery.get("user_recovery_enabled", None)

    if user_recovery is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="User account recovery is enabled.",
            actual_value=user_recovery,
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
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
        def judge(entry):
            # No documented default for this field: absent means unknown, not disabled.
            available = field_value(entry, "enableAdvancedProtectionSelfEnrollment",
                                    "enableAdvancedProtection", "enabled")
            return None if available is None else available is True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not have Advanced Protection available",
            pass_text="have Advanced Protection Program available",
            expected_value="Available for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    app = security.get("advanced_protection", {})
    available = app.get("enrollment_available", None)

    if available is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Advanced Protection Program enrollment is available.",
            actual_value=available,
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


_LC_ID = "CIS-4.1.4.1"
_LC_TITLE = "Ensure login challenges are enforced"
_LC_REMED = (
    "Admin console > Security > Authentication > Login challenges. Under Post-SSO verification, "
    "enable 'Ask users for additional verifications from Google if a sign-in or session behavior "
    "looks suspicious, and always apply 2-Step Verification policies (if configured)' for the legacy "
    "SSO profile and for other SSO profiles. Under Login challenges, leave 'Use employee ID to keep "
    "my users more secure' unchecked (CIS 4.1.4.1: employee IDs are susceptible to information-"
    "gathering attacks). https://knowledge.workspace.google.com/admin/security/protect-google-workspace-accounts-with-security-challenges"
)
_LC_EXPECTED = "Employee ID challenge off; post-SSO verification on for every SSO profile"
_LC_POST_SSO = (
    "Post-SSO verification for the legacy and other SSO profiles is not exposed by any Google API: "
    "confirm it in Admin console > Security > Authentication > Login challenges > Post-SSO verification."
)


def _saml_sso_logins(data: dict) -> int:
    """Sign-ins through a third-party identity provider (login audit ``login_type == "saml"``)."""
    count = 0
    for log in data.get("login_logs", []) or []:
        params = log.get("parameters") if isinstance(log, dict) else None
        if isinstance(params, dict) and params.get("login_type") == "saml":
            count += 1
    return count


def _employee_id_off_result(common: dict, data: dict, ou_count: int | None) -> CheckResult:
    """Verdict once the employee ID challenge is known to be off everywhere.

    Post-SSO verification only applies to users who sign in through a third-party IdP. With no
    SAML sign-in in the login log the setting has nothing to act on, so the readable half decides:
    PASS. With SAML sign-ins the setting matters and no API exposes it: MANUAL.
    """
    where = f"All {ou_count} OU(s) leave" if ou_count else "The organisation leaves"
    saml = _saml_sso_logins(data)
    if saml:
        return make_review(
            **common,
            details=(f"{where} the employee ID challenge off (compliant), but {saml} sign-in(s) in the login log "
                     f"came through a third-party SSO identity provider, so post-SSO verification matters. {_LC_POST_SSO}"),
            actual_value={"employee_id_challenge": False, "saml_sso_logins": saml},
            expected_value=_LC_EXPECTED, remediation=_LC_REMED,
        )
    return make_pass(
        **common,
        details=(f"{where} the employee ID challenge off, as CIS 4.1.4.1 requires. No sign-in in the login log "
                 "came through a third-party SSO identity provider, so post-SSO verification has no users to apply "
                 "to; Google applies risk-based login challenges to Google-authenticated users itself."),
        actual_value={"employee_id_challenge": False, "saml_sso_logins": 0},
        expected_value=_LC_EXPECTED,
    )


@check(
    check_id=_LC_ID,
    title=_LC_TITLE,
    level="L2",
    source="CIS",
    section="Security",
    remediation=_LC_REMED,
)
def check_login_challenges(data: dict) -> CheckResult:
    """CIS 4.1.4.1: post-SSO verification on, employee ID challenge off.

    Only the employee ID half is readable (``security.login_challenges.enableEmployeeIdChallenge``).
    On in any OU -> FAIL. Off everywhere -> PASS when the login log shows no third-party SSO
    sign-in (post-SSO verification then has nobody to apply to), else MANUAL because no API
    exposes the post-SSO verification setting.
    """
    _L, _S, _SEC = "L2", "CIS", "Security"
    common = dict(check_id=_LC_ID, title=_LC_TITLE, level=_L, source=_S, section=_SEC)

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "login_challenges")
    if ou_values:
        on, off, unknown = [], [], []
        for entry in ou_values:
            enabled = field_value(entry, "enableEmployeeIdChallenge")
            ou = entry.get("org_unit", "/")
            (unknown if enabled is None else on if enabled else off).append(ou)
        if on:
            return make_fail(
                **common,
                details=(f"{len(on)} OU(s) use the employee ID as a login challenge: {', '.join(on)}. CIS 4.1.4.1 "
                         "requires 'Use employee ID to keep my users more secure' unchecked because a leaked "
                         "list of employee IDs defeats the challenge."
                         + (f" Undetermined in OU(s): {', '.join(unknown)}." if unknown else "")),
                actual_value=format_ou_values_readable([{"org_unit": ou, "value": True} for ou in on]),
                expected_value=_LC_EXPECTED, remediation=_LC_REMED,
            )
        if unknown:
            return make_review(
                **common,
                details=(f"Employee ID challenge could not be determined (value absent or unspecified) for OU(s): "
                         f"{', '.join(unknown)}. {_LC_POST_SSO}"),
                expected_value=_LC_EXPECTED, remediation=_LC_REMED,
            )
        return _employee_id_off_result(common, data, len(ou_values))

    # Fallback: provider-mapped value (enabled = enableEmployeeIdChallenge)
    login = security.get("login_challenges", {})
    enabled = login.get("enabled", None)

    if enabled is None:
        return make_manual(
            **common,
            details="Could not determine the login challenge settings.",
            remediation=_LC_REMED,
        )
    if enabled:
        return make_fail(
            **common,
            details=("The employee ID is used as a login challenge. CIS 4.1.4.1 requires it unchecked because a "
                     "leaked list of employee IDs defeats the challenge."),
            actual_value={"employee_id_challenge": True}, expected_value=_LC_EXPECTED, remediation=_LC_REMED,
        )
    return _employee_id_off_result(common, data, None)


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
        "per NIST guidelines. https://knowledge.workspace.google.com/admin/users/enforce-and-monitor-password-requirements-for-users"
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
        "per NIST guidelines. https://knowledge.workspace.google.com/admin/users/enforce-and-monitor-password-requirements-for-users"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "password")
    if ou_values:
        def judge(entry):
            # Three-field policy. minimumLength and enforceRequirementsAtLogin have documented
            # defaults (8 / false), so an absent value is judged, not unknown; an unspecified
            # allowedStrength cannot confirm compliance on its own.
            raw_len = field_value(entry, "minimumLength")
            try:
                min_len = int(8 if raw_len is None else raw_len)
            except (TypeError, ValueError):
                min_len = 0
            enforce = field_value(entry, "enforceRequirementsAtLogin")
            raw_strength = field_value(entry, "allowedStrength")
            strength = str(raw_strength or "").upper()
            issues = []
            if min_len < 12:
                issues.append(f"min_length={min_len}")
            if strength == "WEAK":
                issues.append("strength=WEAK")
            if enforce is not True:
                issues.append(f"enforce_at_login={enforce}")
            if issues:
                return False, ", ".join(issues)
            return None if raw_strength is None else True

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have weak password policy", pass_text="have strong password policy",
            expected_value="minimumLength >= 12, enforceRequirementsAtLogin for all OUs",
            remediation=_REMED,
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
    check_id="ADD-58",
    title="Ensure less secure app access is disabled",
    level="L1",
    source="OTHER",
    section="Security",
    remediation=(
        "Admin console > Security > Less secure apps. "
        "Select 'Disable access to less secure apps (Recommended)'. "
        "Users should migrate to OAuth-based authentication. https://knowledge.workspace.google.com/admin/apps/control-access-to-less-secure-apps"
    ),
)
def check_less_secure_apps(data: dict) -> CheckResult:
    """Less secure app access should be disabled for all users.

    Carried CIS-4.2.6.1 until 1.6.0; CIS v1.4.1 removed the recommendation, the setting still
    exists in the Admin console, so this stays as an additional check.
    """
    _ID = "ADD-58"
    _TITLE = "Ensure less secure app access is disabled"
    _L, _S, _SEC = "L1", "OTHER", "Security"
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
        def judge(entry):
            allowed = field_value(entry, "allowLessSecureApps")
            return None if allowed is None else allowed is False

        policy = ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow less secure apps", pass_text="disable less secure app access",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )
        # Also check individual users
        users = data.get("users", [])
        users_with_lsa = [
            u.get("primary_email", "unknown")
            for u in users
            if u.get("less_secure_apps_enabled", False)
        ]
        if policy.status == Status.FAIL or users_with_lsa:
            details_parts = []
            if policy.status != Status.PASS:
                details_parts.append(policy.details)
            if users_with_lsa:
                details_parts.append(
                    f"{len(users_with_lsa)} user(s) have LSA enabled: "
                    f"{', '.join(users_with_lsa[:10])}"
                )
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="; ".join(details_parts),
                actual_value={"unsafe_ous": policy.actual_value if policy.status == Status.FAIL else "",
                              "users_with_lsa_count": len(users_with_lsa)},
                expected_value="Disabled for all OUs and users",
                remediation=_REMED,
            )
        if policy.status != Status.PASS:
            return policy  # setting undetermined in some OU: MANUAL
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) disable less secure app access.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Disabled for all OUs",
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
            expected_value="Disabled for all OUs",
            remediation=_REMED,
        )

    return make_manual(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Could not determine less secure app access setting.",
        remediation=_REMED,
    )
