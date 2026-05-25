# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Additional CISA SCuBA Common Controls checks for GWS Security Auditor.

Supplements the main cisa_scuba module with deeper CommonControls coverage.
Only checks NOT already covered by CIS/OTHER/GOOGLE or the main CISA module.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, is_default_policy
from ..models import CheckResult, Status


# ===========================================================================
# Common Controls 2 - Context-Aware Access
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.2.1",
    title="Ensure context-aware access policies are implemented",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Context-aware access. "
        "Configure device policies to enforce endpoint trust "
        "requirements such as screen lock, encryption, and OS version. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
    ),
    requires_license="enterprise_standard",
)
def check_context_aware_access(data: dict) -> CheckResult:
    """Context-aware access device policies should be configured."""
    _ID = "GWS.COMMONCONTROLS.2.1"
    _TITLE = "Ensure context-aware access policies are implemented"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Context-aware access. "
        "Configure device policies to enforce endpoint trust "
        "requirements such as screen lock, encryption, and OS version. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "login_challenges")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            configured_val = entry["value"].get("devicePoliciesConfigured",
                                                entry["value"].get("enabled", None))
            if configured_val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": configured_val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack context-aware access policies: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have context-aware access policies configured.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    caa = security.get("context_aware_access", {})
    configured = caa.get("device_policies_configured", None)

    if configured is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.2.1",
            title="Ensure context-aware access policies are implemented",
            level="L2", source="CISA", section="Security",
            details="Context-aware access device policies are configured.",
            actual_value=configured,
            expected_value=True,
        )

    if configured is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.2.1",
            title="Ensure context-aware access policies are implemented",
            level="L2", source="CISA", section="Security",
            details="Could not determine context-aware access configuration.",
            remediation=(
                "Admin console > Security > Context-aware access. "
                "Create device policies that enforce device trust levels "
                "before granting access to Google Workspace services. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.2.1",
        title="Ensure context-aware access policies are implemented",
        level="L2", source="CISA", section="Security",
        details="Context-aware access device policies are not configured.",
        actual_value=configured,
        expected_value=True,
        remediation=(
            "Admin console > Security > Context-aware access. "
            "Configure device policies to enforce endpoint trust "
            "requirements such as screen lock, encryption, and OS version. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
        ),
    )


# ===========================================================================
# Common Controls 3 - Single Sign-On
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.3.1",
    title="Ensure SSO verification is enabled for organization SSO profile",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > SSO with third-party IdP. "
        "Enable post-SSO verification so that users must re-authenticate with "
        "Google for sensitive operations even after completing SSO. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
    ),
    requires_license="enterprise_plus",
)
def check_sso_verification(data: dict) -> CheckResult:
    """Post-SSO verification should be enabled for the organization SSO profile."""
    _ID = "GWS.COMMONCONTROLS.3.1"
    _TITLE = "Ensure SSO verification is enabled for organization SSO profile"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > SSO with third-party IdP. "
        "Enable post-SSO verification so that users must re-authenticate with "
        "Google for sensitive operations even after completing SSO. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "sso")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("postSsoVerificationEnabled",
                                      entry["value"].get("post_sso_verification_enabled", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack post-SSO verification: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have post-SSO verification enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    sso = security.get("sso", {})
    post_sso = sso.get("post_sso_verification_enabled", None)

    if post_sso is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.3.1",
            title="Ensure SSO verification is enabled for organization SSO profile",
            level="L2", source="CISA", section="Security",
            details="Post-SSO verification is enabled for the organization SSO profile.",
            actual_value=post_sso,
            expected_value=True,
        )

    if post_sso is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.3.1",
            title="Ensure SSO verification is enabled for organization SSO profile",
            level="L2", source="CISA", section="Security",
            details="Could not determine post-SSO verification setting.",
            remediation=(
                "Admin console > Security > Authentication > SSO with third-party IdP. "
                "Enable post-SSO verification to require additional Google authentication "
                "after SSO for sensitive actions. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.3.1",
        title="Ensure SSO verification is enabled for organization SSO profile",
        level="L2", source="CISA", section="Security",
        details="Post-SSO verification is not enabled for the organization SSO profile.",
        actual_value=post_sso,
        expected_value=True,
        remediation=(
            "Admin console > Security > Authentication > SSO with third-party IdP. "
            "Enable post-SSO verification so that users must re-authenticate with "
            "Google for sensitive operations even after completing SSO. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.3.2",
    title="Ensure post-SSO verification is enabled for third-party SSO",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > SSO with third-party IdP. "
        "Enable post-SSO verification for third-party SSO profiles to ensure "
        "users authenticate with Google after IdP login for sensitive actions. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
    ),
    requires_license="enterprise_plus",
)
def check_third_party_sso_verification(data: dict) -> CheckResult:
    """Post-SSO verification should be enabled for third-party SSO profiles."""
    _ID = "GWS.COMMONCONTROLS.3.2"
    _TITLE = "Ensure post-SSO verification is enabled for third-party SSO"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > SSO with third-party IdP. "
        "Enable post-SSO verification for third-party SSO profiles to ensure "
        "users authenticate with Google after IdP login for sensitive actions. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "sso")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("thirdPartySsoVerificationEnabled",
                                      entry["value"].get("third_party_sso_verification_enabled", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack third-party SSO verification: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have third-party SSO verification enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    sso = security.get("sso", {})
    third_party = sso.get("third_party_sso_verification_enabled", None)

    if third_party is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.3.2",
            title="Ensure post-SSO verification is enabled for third-party SSO",
            level="L2", source="CISA", section="Security",
            details="Post-SSO verification is enabled for third-party SSO profiles.",
            actual_value=third_party,
            expected_value=True,
        )

    if third_party is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.3.2",
            title="Ensure post-SSO verification is enabled for third-party SSO",
            level="L2", source="CISA", section="Security",
            details="Could not determine third-party SSO verification setting.",
            remediation=(
                "Admin console > Security > Authentication > SSO with third-party IdP. "
                "Enable post-SSO verification for all third-party SSO profiles to add "
                "a layer of Google authentication. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.3.2",
        title="Ensure post-SSO verification is enabled for third-party SSO",
        level="L2", source="CISA", section="Security",
        details="Post-SSO verification is not enabled for third-party SSO profiles.",
        actual_value=third_party,
        expected_value=True,
        remediation=(
            "Admin console > Security > Authentication > SSO with third-party IdP. "
            "Enable post-SSO verification for third-party SSO profiles to ensure "
            "users authenticate with Google after IdP login for sensitive actions. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
        ),
    )


# ===========================================================================
# Common Controls 4 - Session Management
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.4.1",
    title="Ensure users re-authenticate after 12-hour session expiry",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Google session control. "
        "Reduce session duration to 12 hours or less. Longer sessions "
        "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
    ),
    requires_license="business_plus",
)
def check_session_duration(data: dict) -> CheckResult:
    """Session duration should be 12 hours or less to force re-authentication."""
    _ID = "GWS.COMMONCONTROLS.4.1"
    _TITLE = "Ensure users re-authenticate after 12-hour session expiry"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Google session control. "
        "Reduce session duration to 12 hours or less. Longer sessions "
        "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "session_controls")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            hours = entry["value"].get("sessionDurationHours",
                                       entry["value"].get("duration", None))
            # Also check webSessionDuration (e.g. "1209600s")
            if hours is None:
                web_dur = entry["value"].get("webSessionDuration", "")
                if isinstance(web_dur, str) and web_dur.endswith("s"):
                    try:
                        hours = int(float(web_dur[:-1])) // 3600
                    except (ValueError, TypeError):
                        pass
            if hours is not None:
                try:
                    hours = int(hours)
                except (ValueError, TypeError):
                    hours = None
            # Skip entries where the field is absent (DEFAULT/SYSTEM entries
            # often lack non-default fields)
            if hours is None and is_default_policy(entry):
                continue
            if hours is None or hours > 12:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": hours})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']}h)" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) exceed 12-hour session duration: {ou_list}",
                actual_value=unsafe_ous, expected_value="<= 12 hours",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have session duration <= 12 hours.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="<= 12 hours",
        )

    # Fallback: mapped root-level value
    session_mgmt = security.get("session_management", {})
    duration = session_mgmt.get("session_duration_hours", None)

    if duration is not None and duration <= 12:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.4.1",
            title="Ensure users re-authenticate after 12-hour session expiry",
            level="L1", source="CISA", section="Security",
            details=f"Session duration is set to {duration} hour(s).",
            actual_value=duration,
            expected_value="<= 12 hours",
        )

    if duration is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.4.1",
            title="Ensure users re-authenticate after 12-hour session expiry",
            level="L1", source="CISA", section="Security",
            details="Could not determine session duration setting.",
            remediation=(
                "Admin console > Security > Google session control. "
                "Set session duration to 12 hours or less to ensure "
                "users re-authenticate periodically. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.4.1",
        title="Ensure users re-authenticate after 12-hour session expiry",
        level="L1", source="CISA", section="Security",
        details=f"Session duration is {duration} hours, exceeding the 12-hour maximum.",
        actual_value=duration,
        expected_value="<= 12 hours",
        remediation=(
            "Admin console > Security > Google session control. "
            "Reduce session duration to 12 hours or less. Longer sessions "
            "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
        ),
    )


# ===========================================================================
# Common Controls 6 - Admin Account Configuration
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.6.1",
    title="Ensure admin accounts are cloud-only",
    level="L1",
    source="CISA",
    section="Directory",
    remediation=(
        "Ensure all super admin accounts are cloud-only managed accounts. "
        "Federated admin accounts are vulnerable to on-premises identity "
        "compromise. Create dedicated cloud-only admin accounts and remove "
        "super admin privileges from federated accounts. https://knowledge.workspace.google.com/admin/users/add-accounts"
    ),
)
def check_admin_cloud_only(data: dict) -> CheckResult:
    """Super admin accounts should be cloud-only, not federated."""
    users = data.get("users", [])

    if not users:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.6.1",
            title="Ensure admin accounts are cloud-only",
            level="L1", source="CISA", section="Directory",
            details="No user data available to check admin account federation status.",
            remediation=(
                "Verify that all super admin accounts are cloud-only managed "
                "accounts, not provisioned via directory sync or federation. https://knowledge.workspace.google.com/admin/users/add-accounts"
            ),
        )

    super_admins = [u for u in users if u.get("is_super_admin", False)]
    federated_admins = [
        u.get("primaryEmail", u.get("email", "unknown"))
        for u in super_admins
        if u.get("is_federated", False)
    ]

    if not federated_admins:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.6.1",
            title="Ensure admin accounts are cloud-only",
            level="L1", source="CISA", section="Directory",
            details=f"All {len(super_admins)} super admin account(s) are cloud-only.",
            actual_value={"federated_admins": [], "total_super_admins": len(super_admins)},
            expected_value="No federated super admin accounts",
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.6.1",
        title="Ensure admin accounts are cloud-only",
        level="L1", source="CISA", section="Directory",
        details=(
            f"Found {len(federated_admins)} federated super admin account(s): "
            f"{', '.join(federated_admins)}"
        ),
        actual_value={"federated_admins": federated_admins},
        expected_value="No federated super admin accounts",
        remediation=(
            "Ensure all super admin accounts are cloud-only managed accounts. "
            "Federated admin accounts are vulnerable to on-premises identity "
            "compromise. Create dedicated cloud-only admin accounts and remove "
            "super admin privileges from federated accounts. https://knowledge.workspace.google.com/admin/users/add-accounts"
        ),
    )


# ===========================================================================
# Common Controls 8 - Account Recovery
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.8.3",
    title="Ensure adding recovery information is disabled",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Account recovery. "
        "Disable the option for users to add recovery email or phone. "
        "Personal recovery options can be exploited if the personal "
        "accounts are compromised. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    ),
)
def check_recovery_info_disabled(data: dict) -> CheckResult:
    """Users should not be able to add personal recovery information.

    The recovery email/phone settings are not available via the Cloud
    Identity Policy API.  This check always requires manual verification.
    """
    _ID = "GWS.COMMONCONTROLS.8.3"
    _TITLE = "Ensure adding recovery information is disabled"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Account recovery > Recovery information. "
        "Disable 'Allow admins and users to add recovery email information' "
        "and 'Allow admins and users to add recovery phone information'. https://knowledge.workspace.google.com/admin/security/manage-a-users-security-settings"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Recovery information settings (email/phone) are not available "
            "via the Cloud Identity Policy API. Verify manually in "
            "Admin console > Security > Account recovery > Recovery information."
        ),
        remediation=_REMED,
    )


# ===========================================================================
# Common Controls 9 - Advanced Protection Program
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.9.1",
    title="Ensure privileged accounts are in Advanced Protection Program",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enforce enrollment for all admin accounts. The Advanced Protection "
        "Program provides the strongest account security with hardware "
        "security keys and restricted third-party app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
    ),
)
def check_admin_advanced_protection(data: dict) -> CheckResult:
    """Admin enrollment in the Advanced Protection Program should be enforced."""
    _ID = "GWS.COMMONCONTROLS.9.1"
    _TITLE = "Ensure privileged accounts are in Advanced Protection Program"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enforce enrollment for all admin accounts. The Advanced Protection "
        "Program provides the strongest account security with hardware "
        "security keys and restricted third-party app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "advanced_protection_program")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enforced_val = entry["value"].get("adminEnrollmentEnforced",
                                              entry["value"].get("enabled", None))
            if enforced_val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enforced_val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack Advanced Protection enforcement: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) enforce Advanced Protection for admins.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    ap = security.get("advanced_protection", {})
    enforced = ap.get("admin_enrollment_enforced", None)

    if enforced is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.9.1",
            title="Ensure privileged accounts are in Advanced Protection Program",
            level="L1", source="CISA", section="Security",
            details="Advanced Protection Program enrollment is enforced for admins.",
            actual_value=enforced,
            expected_value=True,
        )

    if enforced is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.9.1",
            title="Ensure privileged accounts are in Advanced Protection Program",
            level="L1", source="CISA", section="Security",
            details="Could not determine Advanced Protection Program enforcement for admins.",
            remediation=(
                "Admin console > Security > Authentication > Advanced Protection Program. "
                "Enable enrollment enforcement for admin accounts to provide the "
                "strongest account protection including phishing-resistant keys. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.9.1",
        title="Ensure privileged accounts are in Advanced Protection Program",
        level="L1", source="CISA", section="Security",
        details="Advanced Protection Program enrollment is not enforced for admins.",
        actual_value=enforced,
        expected_value=True,
        remediation=(
            "Admin console > Security > Authentication > Advanced Protection Program. "
            "Enforce enrollment for all admin accounts. The Advanced Protection "
            "Program provides the strongest account security with hardware "
            "security keys and restricted third-party app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.9.2",
    title="Ensure sensitive users are in Advanced Protection Program",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enable enrollment for sensitive users. These users are high-value targets "
        "and should have the strongest available account protections including "
        "hardware security keys and restricted app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
    ),
)
def check_sensitive_user_advanced_protection(data: dict) -> CheckResult:
    """Sensitive users should be enrolled in the Advanced Protection Program."""
    _ID = "GWS.COMMONCONTROLS.9.2"
    _TITLE = "Ensure sensitive users are in Advanced Protection Program"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Advanced Protection Program. "
        "Enable enrollment for sensitive users. These users are high-value targets "
        "and should have the strongest available account protections including "
        "hardware security keys and restricted app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "advanced_protection_program")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            enrolled = entry["value"].get("sensitiveUserEnrollment",
                                          entry["value"].get("sensitiveUsersEnrolled", None))
            if enrolled is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enrolled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack Advanced Protection for sensitive users: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) enroll sensitive users in Advanced Protection.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    ap = security.get("advanced_protection", {})
    enrollment = ap.get("sensitive_user_enrollment", None)

    if enrollment is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.9.2",
            title="Ensure sensitive users are in Advanced Protection Program",
            level="L2", source="CISA", section="Security",
            details="Advanced Protection Program enrollment is enabled for sensitive users.",
            actual_value=enrollment,
            expected_value=True,
        )

    if enrollment is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.9.2",
            title="Ensure sensitive users are in Advanced Protection Program",
            level="L2", source="CISA", section="Security",
            details="Could not determine Advanced Protection Program enrollment for sensitive users.",
            remediation=(
                "Admin console > Security > Authentication > Advanced Protection Program. "
                "Enable enrollment for sensitive users such as executives, finance, "
                "and IT staff who handle critical data. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.9.2",
        title="Ensure sensitive users are in Advanced Protection Program",
        level="L2", source="CISA", section="Security",
        details="Advanced Protection Program enrollment is not enabled for sensitive users.",
        actual_value=enrollment,
        expected_value=True,
        remediation=(
            "Admin console > Security > Authentication > Advanced Protection Program. "
            "Enable enrollment for sensitive users. These users are high-value targets "
            "and should have the strongest available account protections including "
            "hardware security keys and restricted app access. https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
        ),
    )


# ===========================================================================
# Common Controls 10 - App Access Control
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.10.1",
    title="Ensure app access control policies restrict third-party access",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Restrict third-party API access to only approved applications. "
        "Unrestricted access allows any app to request and obtain "
        "user data through OAuth consent. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_third_party_api_restricted(data: dict) -> CheckResult:
    """Third-party API access should be restricted by app access control policies."""
    _ID = "GWS.COMMONCONTROLS.10.1"
    _TITLE = "Ensure app access control policies restrict third-party access"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Restrict third-party API access to only approved applications. "
        "Unrestricted access allows any app to request and obtain "
        "user data through OAuth consent. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "unconfigured_third_party_apps")
    if not ou_values:
        api_controls = policies.get("api_controls", {})
        ou_values = get_ou_values(api_controls, "unconfigured_third_party_apps")
    if ou_values:
        unsafe_ous = []
        # Safe access levels that restrict third-party apps
        _SAFE_LEVELS = frozenset({
            "BLOCK_ALL_SCOPES", "block_all_scopes",
            "LIMITED_SCOPES", "limited_scopes",
        })
        for entry in ou_values:
            access_level = entry["value"].get("accessLevel",
                                              entry["value"].get("access_level", ""))
            restricted_val = entry["value"].get("thirdPartyApiAccessRestricted",
                                                entry["value"].get("restricted", None))
            # Check accessLevel (API enum) first, then fall back to boolean
            if access_level and access_level in _SAFE_LEVELS:
                continue  # restricted — safe
            if restricted_val is True:
                continue  # legacy boolean — safe
            if not access_level and restricted_val is None:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": access_level or restricted_val})
            elif access_level not in _SAFE_LEVELS:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": access_level})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not restrict third-party API access: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict third-party API access.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    app_access = security.get("app_access", {})
    restricted = app_access.get("third_party_api_access_restricted", None)

    if restricted is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.10.1",
            title="Ensure app access control policies restrict third-party access",
            level="L1", source="CISA", section="Security",
            details="Third-party API access is restricted by app access control policies.",
            actual_value=restricted,
            expected_value=True,
        )

    if restricted is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.10.1",
            title="Ensure app access control policies restrict third-party access",
            level="L1", source="CISA", section="Security",
            details="Could not determine third-party API access restriction setting.",
            remediation=(
                "Admin console > Security > API controls > App access control. "
                "Configure policies to restrict third-party application access "
                "to Google Workspace APIs and user data. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.10.1",
        title="Ensure app access control policies restrict third-party access",
        level="L1", source="CISA", section="Security",
        details="Third-party API access is not restricted.",
        actual_value=restricted,
        expected_value=True,
        remediation=(
            "Admin console > Security > API controls > App access control. "
            "Restrict third-party API access to only approved applications. "
            "Unrestricted access allows any app to request and obtain "
            "user data through OAuth consent. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.2",
    title="Ensure users cannot consent to low-risk app scopes",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Disable the option for users to consent to low-risk scopes. "
        "Even low-risk scopes can leak data if the requesting app "
        "is malicious or compromised. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
    requires_license="enterprise_plus",
)
def check_user_consent_low_risk(data: dict) -> CheckResult:
    """Users should not be able to consent to low-risk OAuth scopes."""
    _ID = "GWS.COMMONCONTROLS.10.2"
    _TITLE = "Ensure users cannot consent to low-risk app scopes"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Disable the option for users to consent to low-risk scopes. "
        "Even low-risk scopes can leak data if the requesting app "
        "is malicious or compromised. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "app_access")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowUserConsentLowRisk",
                                      entry["value"].get("allow_user_consent_low_risk", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow user consent to low-risk scopes: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) prevent user consent to low-risk scopes.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: mapped root-level value
    app_access = security.get("app_access", {})
    consent = app_access.get("allow_user_consent_low_risk", None)

    if consent is False:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.10.2",
            title="Ensure users cannot consent to low-risk app scopes",
            level="L1", source="CISA", section="Security",
            details="User consent to low-risk app scopes is disabled.",
            actual_value=consent,
            expected_value=False,
        )

    if consent is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.10.2",
            title="Ensure users cannot consent to low-risk app scopes",
            level="L1", source="CISA", section="Security",
            details="Could not determine user consent setting for low-risk scopes.",
            remediation=(
                "Admin console > Security > API controls > App access control. "
                "Disable user consent for low-risk OAuth scopes to ensure "
                "all app authorizations go through admin review. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.10.2",
        title="Ensure users cannot consent to low-risk app scopes",
        level="L1", source="CISA", section="Security",
        details="Users can consent to low-risk app scopes without admin approval.",
        actual_value=consent,
        expected_value=False,
        remediation=(
            "Admin console > Security > API controls > App access control. "
            "Disable the option for users to consent to low-risk scopes. "
            "Even low-risk scopes can leak data if the requesting app "
            "is malicious or compromised. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.3",
    title="Ensure unconfigured internal apps are not trusted",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Disable automatic trust for unconfigured internal apps. "
        "Internal apps should be explicitly reviewed and configured "
        "before being granted data access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_unconfigured_internal_apps(data: dict) -> CheckResult:
    """Unconfigured internal apps should not be automatically trusted."""
    _ID = "GWS.COMMONCONTROLS.10.3"
    _TITLE = "Ensure unconfigured internal apps are not trusted"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Disable automatic trust for unconfigured internal apps. "
        "Internal apps should be explicitly reviewed and configured "
        "before being granted data access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path - try security first, then api_controls
    ou_values = get_ou_values(security, "internal_apps")
    if not ou_values:
        api_controls = policies.get("api_controls", {})
        ou_values = get_ou_values(api_controls, "internal_apps")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("trustUnconfiguredInternalApps",
                                      entry["value"].get("trust_unconfigured_internal_apps", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) trust unconfigured internal apps: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) do not trust unconfigured internal apps.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: mapped root-level value
    app_access = security.get("app_access", {})
    trust_internal = app_access.get("trust_unconfigured_internal_apps", None)

    if trust_internal is False:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.10.3",
            title="Ensure unconfigured internal apps are not trusted",
            level="L1", source="CISA", section="Security",
            details="Unconfigured internal apps are not automatically trusted.",
            actual_value=trust_internal,
            expected_value=False,
        )

    if trust_internal is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.10.3",
            title="Ensure unconfigured internal apps are not trusted",
            level="L1", source="CISA", section="Security",
            details="Could not determine unconfigured internal app trust setting.",
            remediation=(
                "Admin console > Security > API controls > App access control. "
                "Do not trust unconfigured internal apps by default. "
                "Each internal app should be explicitly configured and reviewed. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.10.3",
        title="Ensure unconfigured internal apps are not trusted",
        level="L1", source="CISA", section="Security",
        details="Unconfigured internal apps are automatically trusted.",
        actual_value=trust_internal,
        expected_value=False,
        remediation=(
            "Admin console > Security > API controls > App access control. "
            "Disable automatic trust for unconfigured internal apps. "
            "Internal apps should be explicitly reviewed and configured "
            "before being granted data access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.4",
    title="Ensure unconfigured third-party apps are blocked",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > API controls > App access control. "
        "Block unconfigured third-party apps. Allowing unknown apps "
        "creates significant data exfiltration risk as any app can "
        "request OAuth consent from users. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_unconfigured_third_party_apps(data: dict) -> CheckResult:
    """Unconfigured third-party apps should be blocked from accessing data."""
    _ID = "GWS.COMMONCONTROLS.10.4"
    _TITLE = "Ensure unconfigured third-party apps are blocked"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > API controls > App access control. "
        "Block unconfigured third-party apps. Allowing unknown apps "
        "creates significant data exfiltration risk as any app can "
        "request OAuth consent from users. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path - try security first, then api_controls
    ou_values = get_ou_values(security, "unconfigured_third_party_apps")
    if not ou_values:
        api_controls = policies.get("api_controls", {})
        ou_values = get_ou_values(api_controls, "unconfigured_third_party_apps")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowUnconfiguredThirdPartyApps",
                                      entry["value"].get("allow_unconfigured_third_party_apps", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow unconfigured third-party apps: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) block unconfigured third-party apps.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: mapped root-level value
    app_access = security.get("app_access", {})
    allow_unconfigured = app_access.get("allow_unconfigured_third_party_apps", None)

    if allow_unconfigured is False:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.10.4",
            title="Ensure unconfigured third-party apps are blocked",
            level="L1", source="CISA", section="Security",
            details="Unconfigured third-party apps are blocked.",
            actual_value=allow_unconfigured,
            expected_value=False,
        )

    if allow_unconfigured is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.10.4",
            title="Ensure unconfigured third-party apps are blocked",
            level="L1", source="CISA", section="Security",
            details="Could not determine unconfigured third-party app setting.",
            remediation=(
                "Admin console > Security > API controls > App access control. "
                "Block unconfigured third-party apps from accessing Google "
                "Workspace data. Only explicitly approved apps should be allowed. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.10.4",
        title="Ensure unconfigured third-party apps are blocked",
        level="L1", source="CISA", section="Security",
        details="Unconfigured third-party apps are allowed to access data.",
        actual_value=allow_unconfigured,
        expected_value=False,
        remediation=(
            "Admin console > Security > API controls > App access control. "
            "Block unconfigured third-party apps. Allowing unknown apps "
            "creates significant data exfiltration risk as any app can "
            "request OAuth consent from users. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )


# ===========================================================================
# Common Controls 14 - Audit Logging (supplemental)
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.14.2",
    title="Ensure audit log retention meets minimum requirements",
    level="L1",
    source="CISA",
    section="Reporting",
    remediation=(
        "Admin console > Reporting > Audit and investigation. "
        "Verify audit log retention is at least 6 months. Export "
        "logs to BigQuery or a SIEM solution for long-term retention "
        "and forensic analysis capability. https://knowledge.workspace.google.com/admin/reports"
    ),
)
def check_audit_log_retention(data: dict) -> CheckResult:
    """Audit log retention should be at least 6 months.

    Audit log retention and BigQuery export settings are not available
    via the Cloud Identity Policy API.  This check always requires
    manual verification.
    """
    _ID = "GWS.COMMONCONTROLS.14.2"
    _TITLE = "Ensure audit log retention meets minimum requirements"
    _L, _S, _SEC = "L1", "CISA", "Reporting"
    _REMED = (
        "Admin console > Reporting > Audit and investigation. "
        "Verify audit log retention is at least 6 months. Export "
        "logs to BigQuery or a SIEM solution for long-term retention "
        "and forensic analysis capability. https://knowledge.workspace.google.com/admin/reports"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Audit log retention settings are not available via the Cloud "
            "Identity Policy API. Verify manually that logs are retained "
            "for at least 6 months, ideally via BigQuery export or SIEM "
            "integration."
        ),
        remediation=_REMED,
    )


# ===========================================================================
# Common Controls 15 - Data Regions (supplemental)
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.15.2",
    title="Ensure data is processed in the selected storage region",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Account > Account settings > Data regions. "
        "Enable data processing restrictions to ensure data at rest "
        "and in processing remains within the designated geographic region "
        "for compliance with data sovereignty requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    ),
    requires_license="business_standard",
)
def check_data_processing_in_region(data: dict) -> CheckResult:
    """Data processing should be restricted to the configured storage region."""
    _ID = "GWS.COMMONCONTROLS.15.2"
    _TITLE = "Ensure data is processed in the selected storage region"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Account > Account settings > Data regions. "
        "Enable data processing restrictions to ensure data at rest "
        "and in processing remains within the designated geographic region "
        "for compliance with data sovereignty requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "data_regions")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("processingInRegion",
                                      entry["value"].get("processing_in_region", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not restrict data processing to region: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict data processing to selected region.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    data_regions = security.get("data_regions", {})
    processing_in_region = data_regions.get("processing_in_region", None)

    if processing_in_region is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.15.2",
            title="Ensure data is processed in the selected storage region",
            level="L2", source="CISA", section="Security",
            details="Data processing is restricted to the selected storage region.",
            actual_value=processing_in_region,
            expected_value=True,
        )

    if processing_in_region is None:
        return make_review(
            check_id="GWS.COMMONCONTROLS.15.2",
            title="Ensure data is processed in the selected storage region",
            level="L2", source="CISA", section="Security",
            details=(
                "Data processing region is not exposed by the Cloud Identity "
                "Policy API for this tenant — verify in Admin console."
            ),
            remediation=(
                "Admin console > Account > Account settings > Data regions. "
                "Ensure data processing is restricted to the selected "
                "storage region. Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.15.2",
        title="Ensure data is processed in the selected storage region",
        level="L2", source="CISA", section="Security",
        details="Data processing is not restricted to the selected storage region.",
        actual_value=processing_in_region,
        expected_value=True,
        remediation=(
            "Admin console > Account > Account settings > Data regions. "
            "Enable data processing restrictions to ensure data at rest "
            "and in processing remains within the designated geographic region "
            "for compliance with data sovereignty requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
        ),
    )


# ===========================================================================
# Common Controls 16 - Service Status
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.16.1",
    title="Ensure unused Google services are disabled",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Apps > Google Workspace. Disable all services "
        "that are not required for business operations. Each enabled "
        "service expands the attack surface and may introduce "
        "unmonitored data flows. https://knowledge.workspace.google.com/admin/users/advanced/turn-a-service-on-or-off-for-google-workspace-users"
    ),
    requires_license="enterprise_plus",
)
def check_unused_services_disabled(data: dict) -> CheckResult:
    """Unused Google Workspace services should be disabled to reduce attack surface."""
    _ID = "GWS.COMMONCONTROLS.16.1"
    _TITLE = "Ensure unused Google services are disabled"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Apps > Google Workspace. Disable all services "
        "that are not required for business operations. Each enabled "
        "service expands the attack surface and may introduce "
        "unmonitored data flows. https://knowledge.workspace.google.com/admin/users/advanced/turn-a-service-on-or-off-for-google-workspace-users"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "service_status")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("unusedServicesDisabled",
                                      entry["value"].get("unused_services_disabled", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unused services enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have unused services disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: mapped root-level value
    service_status = security.get("service_status", {})
    disabled = service_status.get("unused_services_disabled", None)

    if disabled is True:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.16.1",
            title="Ensure unused Google services are disabled",
            level="L2", source="CISA", section="Security",
            details="Unused Google services are disabled.",
            actual_value=disabled,
            expected_value=True,
        )

    if disabled is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.16.1",
            title="Ensure unused Google services are disabled",
            level="L2", source="CISA", section="Security",
            details="Could not determine unused services status.",
            remediation=(
                "Admin console > Apps > Google Workspace. Review all enabled "
                "services and disable those not actively used by the organization "
                "to minimize the attack surface. https://knowledge.workspace.google.com/admin/users/advanced/turn-a-service-on-or-off-for-google-workspace-users"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.16.1",
        title="Ensure unused Google services are disabled",
        level="L2", source="CISA", section="Security",
        details="Unused Google services are not disabled.",
        actual_value=disabled,
        expected_value=True,
        remediation=(
            "Admin console > Apps > Google Workspace. Disable all services "
            "that are not required for business operations. Each enabled "
            "service expands the attack surface and may introduce "
            "unmonitored data flows. https://knowledge.workspace.google.com/admin/users/advanced/turn-a-service-on-or-off-for-google-workspace-users"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.16.2",
    title="Ensure early access apps are disabled",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Account > Account settings > Release preferences. "
        "Disable early access to pre-release features. These features "
        "have not completed full security review and may introduce "
        "vulnerabilities or unexpected data handling behavior. https://knowledge.workspace.google.com/admin/users/access/turn-early-access-apps-on-or-off-for-users"
    ),
    requires_license="enterprise_plus",
)
def check_early_access_disabled(data: dict) -> CheckResult:
    """Early access (pre-release) apps should be disabled."""
    _ID = "GWS.COMMONCONTROLS.16.2"
    _TITLE = "Ensure early access apps are disabled"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Account > Account settings > Release preferences. "
        "Disable early access to pre-release features. These features "
        "have not completed full security review and may introduce "
        "vulnerabilities or unexpected data handling behavior. https://knowledge.workspace.google.com/admin/users/access/turn-early-access-apps-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "service_status")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("earlyAccessEnabled",
                                      entry["value"].get("early_access_enabled", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have early access enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have early access disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: mapped root-level value
    service_status = security.get("service_status", {})
    early_access = service_status.get("early_access_enabled", None)

    if early_access is False:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.16.2",
            title="Ensure early access apps are disabled",
            level="L2", source="CISA", section="Security",
            details="Early access apps are disabled.",
            actual_value=early_access,
            expected_value=False,
        )

    if early_access is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.16.2",
            title="Ensure early access apps are disabled",
            level="L2", source="CISA", section="Security",
            details="Could not determine early access apps setting.",
            remediation=(
                "Admin console > Account > Account settings > Release preferences. "
                "Disable early access to new features and apps. Pre-release "
                "features may not have undergone full security review. https://knowledge.workspace.google.com/admin/users/access/turn-early-access-apps-on-or-off-for-users"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.16.2",
        title="Ensure early access apps are disabled",
        level="L2", source="CISA", section="Security",
        details="Early access apps are enabled.",
        actual_value=early_access,
        expected_value=False,
        remediation=(
            "Admin console > Account > Account settings > Release preferences. "
            "Disable early access to pre-release features. These features "
            "have not completed full security review and may introduce "
            "vulnerabilities or unexpected data handling behavior. https://knowledge.workspace.google.com/admin/users/access/turn-early-access-apps-on-or-off-for-users"
        ),
    )


# ===========================================================================
# Common Controls 18 - Data Loss Prevention
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.18.2",
    title="Ensure DLP policy is configured for Google Chat",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules for Google Chat to prevent sensitive data "
        "from being shared in chat conversations. Chat is a common "
        "vector for accidental data exposure. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-from-chat-messages-and-attachments"
    ),
    requires_license="enterprise_standard",
)
def check_dlp_chat(data: dict) -> CheckResult:
    """DLP rules should be configured for Google Chat."""
    _ID = "GWS.COMMONCONTROLS.18.2"
    _TITLE = "Ensure DLP policy is configured for Google Chat"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules for Google Chat to prevent sensitive data "
        "from being shared in chat conversations. Chat is a common "
        "vector for accidental data exposure. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-from-chat-messages-and-attachments"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "dlp")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            rules = entry["value"].get("chatDlpRules",
                                        entry["value"].get("chat_dlp_rules", None))
            if not (isinstance(rules, list) and len(rules) > 0):
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": rules})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack DLP rules for Chat: {ou_list}",
                actual_value=unsafe_ous, expected_value="At least one DLP rule for Chat",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have DLP rules configured for Chat.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="At least one DLP rule for Chat",
        )

    # Fallback: mapped root-level value
    dlp = security.get("dlp", {})
    chat_rules = dlp.get("chat_dlp_rules", None)

    if isinstance(chat_rules, list) and len(chat_rules) > 0:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.18.2",
            title="Ensure DLP policy is configured for Google Chat",
            level="L1", source="CISA", section="Security",
            details=f"Found {len(chat_rules)} DLP rule(s) configured for Google Chat.",
            actual_value={"rule_count": len(chat_rules)},
            expected_value="At least one DLP rule for Chat",
        )

    if chat_rules is None:
        return make_review(
            check_id="GWS.COMMONCONTROLS.18.2",
            title="Ensure DLP policy is configured for Google Chat",
            level="L1", source="CISA", section="Security",
            details=(
                "DLP rules are not exposed by the Cloud Identity Policy API — "
                "verify Chat DLP coverage in Admin console."
            ),
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
                "Create DLP rules for Google Chat to detect and prevent "
                "sharing of sensitive data in chat messages and spaces. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-from-chat-messages-and-attachments"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.18.2",
        title="Ensure DLP policy is configured for Google Chat",
        level="L1", source="CISA", section="Security",
        details="No DLP rules are configured for Google Chat.",
        actual_value={"rule_count": 0},
        expected_value="At least one DLP rule for Chat",
        remediation=(
            "Admin console > Security > Data protection > Manage rules. "
            "Create DLP rules for Google Chat to prevent sensitive data "
            "from being shared in chat conversations. Chat is a common "
            "vector for accidental data exposure. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-from-chat-messages-and-attachments"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.18.3",
    title="Ensure DLP policy is configured for Gmail",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules for Gmail to prevent sensitive data from "
        "being emailed externally. Email is the primary channel for "
        "both accidental and intentional data exfiltration. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
    ),
    requires_license="enterprise_plus",
)
def check_dlp_gmail(data: dict) -> CheckResult:
    """DLP rules should be configured for Gmail."""
    _ID = "GWS.COMMONCONTROLS.18.3"
    _TITLE = "Ensure DLP policy is configured for Gmail"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Data protection > Manage rules. "
        "Create DLP rules for Gmail to prevent sensitive data from "
        "being emailed externally. Email is the primary channel for "
        "both accidental and intentional data exfiltration. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "dlp")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            rules = entry["value"].get("gmailDlpRules",
                                        entry["value"].get("gmail_dlp_rules", None))
            if not (isinstance(rules, list) and len(rules) > 0):
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": rules})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) lack DLP rules for Gmail: {ou_list}",
                actual_value=unsafe_ous, expected_value="At least one DLP rule for Gmail",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have DLP rules configured for Gmail.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="At least one DLP rule for Gmail",
        )

    # Fallback: mapped root-level value
    dlp = security.get("dlp", {})
    gmail_rules = dlp.get("gmail_dlp_rules", None)

    if isinstance(gmail_rules, list) and len(gmail_rules) > 0:
        return make_pass(
            check_id="GWS.COMMONCONTROLS.18.3",
            title="Ensure DLP policy is configured for Gmail",
            level="L1", source="CISA", section="Security",
            details=f"Found {len(gmail_rules)} DLP rule(s) configured for Gmail.",
            actual_value={"rule_count": len(gmail_rules)},
            expected_value="At least one DLP rule for Gmail",
        )

    if gmail_rules is None:
        return make_manual(
            check_id="GWS.COMMONCONTROLS.18.3",
            title="Ensure DLP policy is configured for Gmail",
            level="L1", source="CISA", section="Security",
            details="Could not determine DLP configuration for Gmail.",
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
                "Create DLP rules for Gmail to detect and prevent "
                "sensitive data from being sent via email. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.18.3",
        title="Ensure DLP policy is configured for Gmail",
        level="L1", source="CISA", section="Security",
        details="No DLP rules are configured for Gmail.",
        actual_value={"rule_count": 0},
        expected_value="At least one DLP rule for Gmail",
        remediation=(
            "Admin console > Security > Data protection > Manage rules. "
            "Create DLP rules for Gmail to prevent sensitive data from "
            "being emailed externally. Email is the primary channel for "
            "both accidental and intentional data exfiltration. https://knowledge.workspace.google.com/admin/security/prevent-data-leaks-in-email-and-attachments-gmail-dlp"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.18.4",
    title="Ensure DLP policies block external sharing",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Data protection > Manage rules. "
        "Set the DLP default action to 'block' or 'block external sharing'. "
        "Warn-only or audit-only actions do not prevent data loss and "
        "should only be used during initial policy tuning. https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
    ),
    requires_license="enterprise_standard",
)
def check_dlp_block_external(data: dict) -> CheckResult:
    """DLP default action should block or block external sharing of sensitive data."""
    _ID = "GWS.COMMONCONTROLS.18.4"
    _TITLE = "Ensure DLP policies block external sharing"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Data protection > Manage rules. "
        "Set the DLP default action to 'block' or 'block external sharing'. "
        "Warn-only or audit-only actions do not prevent data loss and "
        "should only be used during initial policy tuning. https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "dlp")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("defaultAction",
                                      entry["value"].get("default_action", None))
            if val not in ("block", "block_external", "BLOCK", "BLOCK_EXTERNAL"):
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have DLP action not set to block: {ou_list}",
                actual_value=unsafe_ous, expected_value="block or block_external",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have DLP set to block external sharing.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="block or block_external",
        )

    # Fallback: mapped root-level value
    dlp = security.get("dlp", {})
    default_action = dlp.get("default_action", None)

    if default_action in ("block", "block_external"):
        return make_pass(
            check_id="GWS.COMMONCONTROLS.18.4",
            title="Ensure DLP policies block external sharing",
            level="L1", source="CISA", section="Security",
            details=f"DLP default action is '{default_action}'.",
            actual_value=default_action,
            expected_value="block or block_external",
        )

    if default_action is None:
        return make_review(
            check_id="GWS.COMMONCONTROLS.18.4",
            title="Ensure DLP policies block external sharing",
            level="L1", source="CISA", section="Security",
            details=(
                "DLP rules are not exposed by the Cloud Identity Policy API — "
                "verify the DLP default action in Admin console."
            ),
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
                "Configure DLP rules with a default action of 'block' or "
                "'block external sharing' to prevent sensitive data from "
                "leaving the organization. https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.18.4",
        title="Ensure DLP policies block external sharing",
        level="L1", source="CISA", section="Security",
        details=f"DLP default action is '{default_action}' instead of block or block_external.",
        actual_value=default_action,
        expected_value="block or block_external",
        remediation=(
            "Admin console > Security > Data protection > Manage rules. "
            "Set the DLP default action to 'block' or 'block external sharing'. "
            "Warn-only or audit-only actions do not prevent data loss and "
            "should only be used during initial policy tuning. https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
        ),
    )
