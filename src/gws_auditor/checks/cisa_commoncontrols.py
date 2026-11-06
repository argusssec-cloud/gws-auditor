# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Additional CISA SCuBA Common Controls checks for GWS Security Auditor.

Supplements the main cisa_scuba module with deeper CommonControls coverage.
Only checks NOT already covered by CIS/OTHER/GOOGLE or the main CISA module.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, drop_unspecified,
                   admin_emails, user_usage_by_email, advanced_protection_enrolment, make_not_applicable,
                   format_ou_values_readable, is_default_policy, is_admin_configured, field_value, ou_verdict)
from ..models import CheckResult, Status


def _flag_judge(*names: str, expected: bool):
    """``judge`` for a single boolean field: compliant when it equals *expected*, unknown when absent."""
    def judge(entry: dict):
        value = field_value(entry, *names)
        return None if value is None else value is expected
    return judge


# ===========================================================================
# Common Controls 2 - Context-Aware Access
# ===========================================================================

# api_controls.unconfigured_third_party_apps: the Admin console labels the permissive option
# "(Default) Allow users to access any third-party apps"; the API has no enum member for it and
# returns the zero value ACCESS_LEVEL_UNSPECIFIED on the ADMIN policy (console-verified 2026-11-01).
_DEFAULT_ALLOW_LABEL = "ACCESS_LEVEL_UNSPECIFIED (console default: allow any third-party app)"


def _is_default_allow(entry: dict) -> bool:
    level = str(entry.get("value", {}).get("accessLevel", "")).upper()
    return level == "ACCESS_LEVEL_UNSPECIFIED" and is_admin_configured(entry)


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
    # Context-Aware Access is not a Policy API setting (security.login_challenges only carries
    # enableEmployeeIdChallenge). The latest TOGGLE_CAA_ENABLEMENT admin-log event gives the state.
    # The toggle is necessary, not sufficient: a tenant can be ON with no access level at all
    # (seen live 2026-11-05). PASS needs an access-level assignment in active mode, or a denial
    # event proving enforcement; ON without an assignment event is a review item.
    from .additional import _caa_app_assignment_evidence, _caa_enforcement_events
    assignments = [log for log in data.get("admin_logs", [])
                   if log.get("event_name") == "CHANGE_CAA_APP_ASSIGNMENTS" and isinstance(log.get("parameters"), dict)]
    apps = sorted({str(log["parameters"].get("APPLICATION_NAME", "")).strip() for log in assignments
                   if log["parameters"].get("APPLICATION_NAME")})
    evidence = _caa_app_assignment_evidence(data.get("admin_logs", []), apps)
    # Active-mode evaluations in the context_aware_access log (allowed ACCESS_LEVELS_EVALUATED or
    # ACCESS_DENY_EVENT) with an applied level are direct proof that CAA is enforced, whatever the
    # outcome; they are the strongest evidence and survive an assignment made before the log window.
    enforced = [e for e in _caa_enforcement_events(data.get("caa_events", [])) if e["applied"]]
    denials = sum(1 for e in enforced if e["denied"])
    newest_eval = max((e["time"] for e in enforced), default="")
    state = evidence["toggle"]
    expected = "Context-Aware Access enabled with access levels assigned to apps"
    actual = {"caa_enabled": state, "apps_with_levels": evidence["covered"], "monitor_only": evidence["monitor"],
              "levels_removed": evidence["removed"], "evaluations": len(enforced), "denials": denials}
    if state == "DISABLED" and not (enforced and newest_eval > evidence["toggle_time"]):
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Context-Aware Access was turned off (latest admin-log change).",
            actual_value=actual, expected_value=expected, remediation=_REMED,
        )
    if enforced:
        apps = sorted({e["app"] for e in enforced if e["app"]})
        levels = sorted({t for e in enforced for t in e["applied"]})
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access is enforcing: {len(enforced)} active-mode evaluation(s) "
                     f"({denials} denied) in the CAA log window across {len(apps)} app(s) "
                     f"({', '.join(apps[:8])}) applying access level(s) {', '.join(levels[:5])}."),
            actual_value=actual, expected_value=expected,
        )
    if state == "ENABLED" and evidence["covered"]:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access is enabled and access levels are assigned in active mode to "
                     f"{len(evidence['covered'])} app(s) per the latest admin-log changes: {', '.join(evidence['covered'][:8])}."),
            actual_value=actual, expected_value=expected,
        )
    if state == "ENABLED":
        why = ("access levels were removed from or only monitored for the assigned apps"
               if evidence["removed"] or evidence["monitor"] else
               "no access-level assignment to an app appears in the audit window, so there may be no access level at all")
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access is enabled (latest admin-log change) but {why}. Verify that access levels "
                     "exist and are assigned in Admin console > Security > Access and data control > Context-Aware Access."),
            actual_value=actual, expected_value=expected, remediation=_REMED,
        )

    # Legacy shape only. A bare "enabled" key is NOT accepted: the provider adds it to the real
    # login_challenges value as an alias of enableEmployeeIdChallenge, which is unrelated to CAA.
    ou_values = [e for e in get_ou_values(security, "login_challenges")
                 if "devicePoliciesConfigured" in e["value"] and "enableEmployeeIdChallenge" not in e["value"]]
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("devicePoliciesConfigured", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack context-aware access policies",
            pass_text="have context-aware access policies configured",
            expected_value="Enabled for all OUs", remediation=_REMED,
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
            expected_value="Enabled for all OUs",
        )

    if configured is None:
        # Not an error: Context-Aware Access is not a Policy API setting and there is no
        # TOGGLE_CAA_ENABLEMENT event in the audit-log window, so the state is unknown.
        return make_review(
            check_id="GWS.COMMONCONTROLS.2.1",
            title="Ensure context-aware access policies are implemented",
            level="L2", source="CISA", section="Security",
            details=("Context-Aware Access is not exposed by the Cloud Identity Policy API and no enablement change was found "
                     "in the admin audit log — verify in Admin console > Security > Context-Aware Access."),
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
        expected_value="Enabled for all OUs",
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
    scored=False,  # P3: SSO profiles are not exposed by the Policy API; MANUAL by design
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
    ou_values = []  # P3: "security.sso" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("postSsoVerificationEnabled", "post_sso_verification_enabled", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack post-SSO verification",
            pass_text="have post-SSO verification enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
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
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Authentication > SSO with third-party IdP. "
            "Enable post-SSO verification so that users must re-authenticate with "
            "Google for sensitive operations even after completing SSO. https://knowledge.workspace.google.com/admin/apps/about-the-sso-identity-confirmation-screen"
        ),
    )


@check(
    check_id="GWS.COMMONCONTROLS.3.2",
    scored=False,  # P3: SSO profiles are not exposed by the Policy API; MANUAL by design
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
    ou_values = []  # P3: "security.sso" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("thirdPartySsoVerificationEnabled", "third_party_sso_verification_enabled",
                                   expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack third-party SSO verification",
            pass_text="have third-party SSO verification enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
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
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
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
        def judge(entry: dict):
            hours = None
            # Real field: webSessionDuration as a seconds string, e.g. "1209600s"
            web_dur = field_value(entry, "webSessionDuration")
            if isinstance(web_dur, str) and web_dur.endswith("s"):
                try:
                    hours = float(web_dur[:-1]) / 3600
                except (ValueError, TypeError):
                    hours = None
            if hours is None:
                legacy = field_value(entry, "sessionDurationHours", "duration")
                try:
                    hours = None if legacy is None else float(legacy)
                except (ValueError, TypeError):
                    hours = None
            if hours is None:
                return None  # duration not reported: cannot judge
            shown = int(hours) if hours == int(hours) else round(hours, 2)
            return hours <= 12, shown

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="exceed 12-hour session duration",
            pass_text="have session duration <= 12 hours",
            expected_value="<= 12 hours", remediation=_REMED,
            humanizer=lambda hours: f"{hours}h",
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
    scored=False,  # Admin-console-only control: no API or audit-log signal (plan Decision C)
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

# Policy API: security.advanced_protection_program only says whether users MAY self-enroll
# (enableAdvancedProtectionSelfEnrollment); per-account enrollment is not exposed.
_APP_REMED = (
    "Admin console > Security > Authentication > Advanced Protection Program: allow users to enroll. Then "
    "enroll each account at https://myaccount.google.com/advanced-protection with two security keys or passkeys. "
    "https://knowledge.workspace.google.com/admin/security/protect-users-with-the-advanced-protection-program"
)


def _advanced_protection_verdict(data: dict, population: set[str], who: str, *, check_id: str, title: str,
                                 level: str) -> CheckResult:
    """Three-state Advanced Protection verdict for *population* (lower-case emails).

    * self-enrolment disabled in an OU -> FAIL (nobody there can enrol);
    * an account whose latest user-accounts event is ``titanium_unenroll``, or that has no security
      key and no passkey (so cannot be enrolled) -> FAIL;
    * every account has ``titanium_enroll`` as its latest event -> PASS;
    * otherwise MANUAL: enrolment is not exposed by any API and the audit log only covers 180 days.
    """
    common = dict(check_id=check_id, title=title, level=level, source="CISA", section="Security")
    expected = f"Self-enrollment allowed and every {who} account enrolled"
    security = data.get("policies", {}).get("security", {})
    ou_values = get_ou_values(security, "advanced_protection_program")
    disabled = sorted(str(e.get("org_unit", "/")) for e in ou_values
                      if field_value(e, "enableAdvancedProtectionSelfEnrollment") is False)
    if disabled:
        return make_fail(**common, details=(
            f"{len(disabled)} OU(s) disable Advanced Protection self-enrollment, so {who} accounts there cannot "
            f"enroll: {', '.join(disabled)}"), actual_value={"self_enrollment_disabled_ous": disabled},
            expected_value=expected, remediation=_APP_REMED)

    enrolment = advanced_protection_enrolment(data)
    usage = user_usage_by_email(data)
    failed, enrolled, unknown = [], [], []
    for email in sorted(population):
        state = enrolment.get(email)
        row = usage.get(email) or {}
        keys, passkeys = row.get("accounts:num_security_keys"), row.get("accounts:num_passkeys_enrolled")
        if state and state[0] == "titanium_unenroll":
            failed.append(f"{email} [left Advanced Protection on {state[1][:10]}]")
        elif keys == 0 and passkeys == 0:
            failed.append(f"{email} [no security key or passkey, so cannot be enrolled]")
        elif state and state[0] == "titanium_enroll":
            enrolled.append(email)
        else:
            unknown.append(email)
    actual = {"enrolled": enrolled, "not_enrolled": failed, "unknown": unknown}
    if failed:
        return make_fail(**common, details=(
            f"{len(failed)} of {len(population)} {who} account(s) are not in Advanced Protection: " + "; ".join(failed)),
            actual_value=actual, expected_value=expected, remediation=_APP_REMED)
    if unknown:
        sources = []
        if not data.get("user_account_logs"):
            sources.append("the user_accounts audit log was not collected")
        if not usage:
            sources.append("the per-user usage report was not collected")
        why = ("; " + " and ".join(sources)) if sources else ""
        return make_review(**common, details=(
            f"{len(enrolled)} of {len(population)} {who} account(s) show an Advanced Protection enrollment event; "
            f"{len(unknown)} have no enrollment event in the 180-day user-accounts audit log and the API does not "
            f"expose enrollment state{why}: {', '.join(unknown)}. Verify them in Admin console > Users."),
            actual_value=actual, expected_value=expected, remediation=_APP_REMED)
    return make_pass(**common, details=(
        f"All {len(enrolled)} {who} account(s) are enrolled in Advanced Protection (titanium_enroll is their "
        "latest user-accounts audit event)."), actual_value=actual, expected_value=expected)



@check(
    check_id="GWS.COMMONCONTROLS.9.1",
    title="Ensure privileged accounts are in Advanced Protection Program",
    level="L1",
    source="CISA",
    section="Security",
    remediation=_APP_REMED,
)
def check_admin_advanced_protection(data: dict) -> CheckResult:
    """Super admins and delegated admins should be enrolled in the Advanced Protection Program."""
    admins = admin_emails(data)
    if not admins:
        return make_manual(check_id="GWS.COMMONCONTROLS.9.1",
                           title="Ensure privileged accounts are in Advanced Protection Program",
                           level="L1", source="CISA", section="Security",
                           details="No administrator accounts were collected, so Advanced Protection enrollment "
                                   "cannot be assessed.", remediation=_APP_REMED)
    return _advanced_protection_verdict(
        data, admins, "administrator", check_id="GWS.COMMONCONTROLS.9.1",
        title="Ensure privileged accounts are in Advanced Protection Program", level="L1")



@check(
    check_id="GWS.COMMONCONTROLS.9.2",
    title="Ensure sensitive users are in Advanced Protection Program",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_APP_REMED,
)
def check_sensitive_user_advanced_protection(data: dict) -> CheckResult:
    """Accounts the organisation designates as sensitive (``options.sensitive_users``: emails or
    group addresses) should be enrolled in the Advanced Protection Program."""
    _ID, _TITLE = "GWS.COMMONCONTROLS.9.2", "Ensure sensitive users are in Advanced Protection Program"
    configured = (data.get("_options", {}) or {}).get("sensitive_users", []) or []
    if isinstance(configured, str):
        configured = [configured]
    members = data.get("group_members", {}) or {}
    population: set[str] = set()
    for entry in configured:
        key = str(entry).strip().lower()
        if not key:
            continue
        group = next((members[g] for g in members if str(g).lower() == key), None)
        if group is not None:
            population.update(str(m.get("email", "")).lower() for m in group if isinstance(m, dict) and m.get("email"))
        else:
            population.add(key)
    if not population:
        return make_not_applicable(
            check_id=_ID, title=_TITLE, level="L2", source="CISA", section="Security",
            details=("No sensitive-user population is defined (options.sensitive_users is empty), so there is "
                     "nothing to assess. List the emails or group addresses of sensitive accounts in the config; "
                     "administrators are covered by GWS.COMMONCONTROLS.9.1."),
            actual_value=[])
    return _advanced_protection_verdict(data, population, "sensitive", check_id=_ID, title=_TITLE, level="L2")


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
    default_allow = [e for e in ou_values if _is_default_allow(e)]
    ou_values = drop_unspecified(ou_values, "accessLevel")  # SYSTEM ACCESS_LEVEL_UNSPECIFIED = unknown
    if ou_values or default_allow:
        unsafe_ous = [{"org_unit": e["org_unit"], "value": _DEFAULT_ALLOW_LABEL} for e in default_allow]
        # Safe access levels that restrict third-party apps (BLOCK_ALL is the documented enum,
        # BLOCK_ALL_SCOPES was returned by older API versions)
        _SAFE_LEVELS = frozenset({
            "BLOCK_ALL", "block_all", "BLOCK_ALL_SCOPES", "block_all_scopes",
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
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="Enabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict third-party API access.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Enabled for all OUs",
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
            expected_value="Enabled for all OUs",
        )

    if restricted is None:
        return make_review(
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
        expected_value="Enabled for all OUs",
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
    # Real signal: api_controls.unconfigured_third_party_apps.accessLevel. Users can consent to
    # low-risk (sign-in) scopes of unconfigured apps unless access is blocked entirely.
    ou_values = (get_ou_values(security, "unconfigured_third_party_apps")
                 or get_ou_values(policies.get("api_controls", {}), "unconfigured_third_party_apps"))
    if ou_values:
        def _consent_judge(entry):
            if _is_default_allow(entry):
                return (False, _DEFAULT_ALLOW_LABEL)
            level = field_value(entry, "accessLevel")
            if level is None:
                return None
            lv = str(level).upper()
            if lv in ("BLOCK_ALL", "BLOCK_ALL_SCOPES"):
                return (True, level)
            if "SIGN_IN" in lv or "ALLOW" in lv:
                return (False, level)
            return None
        return ou_verdict(
            ou_values, _consent_judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow user consent to low-risk scopes",
            pass_text="prevent user consent to low-risk scopes",
            expected_value="Disabled for all OUs", remediation=_REMED,
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
            expected_value="Disabled for all OUs",
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
        expected_value="Disabled for all OUs",
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
        # Policy API field is trustInternalApps (api_controls.internal_apps)
        return ou_verdict(
            ou_values, _flag_judge("trustInternalApps", "trustUnconfiguredInternalApps",
                                   "trust_unconfigured_internal_apps", expected=False),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="trust unconfigured internal apps",
            pass_text="do not trust unconfigured internal apps",
            expected_value="Disabled for all OUs", remediation=_REMED,
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
            expected_value="Disabled for all OUs",
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
        expected_value="Disabled for all OUs",
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
    default_allow = [e for e in ou_values if _is_default_allow(e)]
    ou_values = drop_unspecified(ou_values, "accessLevel")  # SYSTEM ACCESS_LEVEL_UNSPECIFIED = unknown
    if ou_values or default_allow:
        unsafe_ous = [{"org_unit": e["org_unit"], "value": _DEFAULT_ALLOW_LABEL} for e in default_allow]
        for entry in ou_values:
            # Policy API field is accessLevel (api_controls.unconfigured_third_party_apps);
            # only BLOCK_ALL (older API: BLOCK_ALL_SCOPES) blocks unconfigured apps
            # (sign-in-only still allows access).
            access_level = entry["value"].get("accessLevel",
                                              entry["value"].get("access_level", None))
            if access_level is not None:
                if str(access_level).upper() not in ("BLOCK_ALL", "BLOCK_ALL_SCOPES"):
                    unsafe_ous.append({"org_unit": entry["org_unit"], "value": access_level})
                continue
            val = entry["value"].get("allowUnconfiguredThirdPartyApps",
                                      entry["value"].get("allow_unconfigured_third_party_apps", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow unconfigured third-party apps: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="Disabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) block unconfigured third-party apps.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Disabled for all OUs",
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
            expected_value="Disabled for all OUs",
        )

    if allow_unconfigured is None:
        return make_review(
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
        expected_value="Disabled for all OUs",
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
    scored=False,  # Admin-console-only control: no API or audit-log signal (plan Decision C)
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
    # Real type: data_regions.data_processing_region.limitToStorageRegion
    ou_values = (get_ou_values(security, "data_processing_region")
                 or get_ou_values(policies.get("data_regions", {}), "data_processing_region"))
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("limitToStorageRegion", "processingInRegion", "processing_in_region", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not restrict data processing to region",
            pass_text="restrict data processing to selected region",
            expected_value="Enabled for all OUs", remediation=_REMED,
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
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
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
    # Policy API: enterprise_service_restrictions.service_status.serviceState. The naming is
    # inverted: restrictions ENABLED means services without an individual control are OFF.
    restrictions = get_ou_values(policies.get("enterprise_service_restrictions", {}), "service_status")
    if restrictions:
        def judge(entry: dict):
            state = field_value(entry, "serviceState")
            return None if state is None else (str(state).upper() == "ENABLED", state)

        return ou_verdict(
            restrictions, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow access to services without an individual control",
            pass_text="restrict services without an individual control",
            expected_value="Restricted for all OUs", remediation=_REMED,
        )

    ou_values = get_ou_values(security, "service_status")
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("unusedServicesDisabled", "unused_services_disabled", expected=True),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unused services enabled",
            pass_text="have unused services disabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
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
            expected_value="Enabled for all OUs",
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
        expected_value="Enabled for all OUs",
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
    # Policy API: early_access_apps.service_status.serviceState
    early = get_ou_values(policies.get("early_access_apps", {}), "service_status")
    if early:
        def judge(entry: dict):
            state = field_value(entry, "serviceState")
            return None if state is None else (str(state).upper() == "DISABLED", state)

        return ou_verdict(
            early, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have early access apps enabled",
            pass_text="have early access apps disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    ou_values = get_ou_values(security, "service_status")
    if ou_values:
        return ou_verdict(
            ou_values, _flag_judge("earlyAccessEnabled", "early_access_enabled", expected=False),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have early access enabled",
            pass_text="have early access disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
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
            expected_value="Disabled for all OUs",
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
        expected_value="Disabled for all OUs",
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

def _rule_list_judge(*names: str):
    """``judge`` for a list-of-rules field: compliant when at least one rule exists, unknown when absent."""
    def judge(entry: dict):
        rules = field_value(entry, *names)
        if rules is None:
            return None
        return (isinstance(rules, list) and len(rules) > 0), rules
    return judge

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
        return ou_verdict(
            ou_values, _rule_list_judge("chatDlpRules", "chat_dlp_rules"),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack DLP rules for Chat",
            pass_text="have DLP rules configured for Chat",
            expected_value="At least one DLP rule for Chat", remediation=_REMED,
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
        return ou_verdict(
            ou_values, _rule_list_judge("gmailDlpRules", "gmail_dlp_rules"),
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="lack DLP rules for Gmail",
            pass_text="have DLP rules configured for Gmail",
            expected_value="At least one DLP rule for Gmail", remediation=_REMED,
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
        def judge(entry: dict):
            action = field_value(entry, "defaultAction", "default_action")
            if action is None:
                return None
            return action in ("block", "block_external", "BLOCK", "BLOCK_EXTERNAL"), action

        return ou_verdict(
            ou_values, judge, check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have DLP action not set to block",
            pass_text="have DLP set to block external sharing",
            expected_value="block or block_external", remediation=_REMED,
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


@check(
    check_id="GWS.COMMONCONTROLS.8.2",
    title="Ensure user account self-recovery is disabled",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Account recovery > User account recovery. "
        "Turn off 'Allow users and non-super admins to recover their account'. "
        "Note: CIS-4.1.2.2 recommends the opposite; choose the framework your organization follows. "
        "https://knowledge.workspace.google.com/admin/security/set-up-password-recovery-for-users"
    ),
)
def check_user_account_recovery_disabled(data: dict) -> CheckResult:
    """SCuBA requires user self-service account recovery to be disabled (conflicts with CIS-4.1.2.2)."""
    _ID = "GWS.COMMONCONTROLS.8.2"
    _TITLE = "Ensure user account self-recovery is disabled"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Authentication > Account recovery > User account recovery. "
        "Turn off 'Allow users and non-super admins to recover their account'. "
        "Note: CIS-4.1.2.2 recommends the opposite; choose the framework your organization follows."
    )

    security = data.get("policies", {}).get("security", {})
    ou_values = get_ou_values(security, "user_account_recovery")
    if not ou_values:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="User account recovery setting was not returned by the Cloud Identity Policy API — verify in Admin console.",
            remediation=_REMED,
        )
    return ou_verdict(
        ou_values, _flag_judge("enableAccountRecovery", expected=False),
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        fail_text="allow user account self-recovery (CIS-4.1.2.2 requires the opposite value)",
        pass_text="have user account self-recovery disabled",
        expected_value="Disabled for all OUs", remediation=_REMED,
        unknown_text="User account recovery setting was not returned by the Cloud Identity Policy API — verify in Admin console.",
    )


# Rules CISA SCuBA GWS.COMMONCONTROLS.13.1 requires (baseline v0.6); other system-defined rules are optional.
SCUBA_REQUIRED_ALERT_RULES = (
    'Government-backed attacks', 'User-reported phishing', "User's Admin privilege revoked",
    'User suspended for spamming through relay', 'User suspended for spamming', 'User suspended due to suspicious activity',
    'User suspended (Google identity alert)', 'User granted Admin privilege', 'Suspicious programmatic login',
    'Suspicious message reported', 'Suspicious login', 'Suspicious device activity',
    'Spike in user-reported spam', 'Rate limited recipient', 'Phishing message detected post-delivery',
    'Phishing in inboxes due to bad whitelist', 'Mobile settings changed', 'Malware message detected post-delivery',
    'Leaked password', 'Google Operations', 'Gmail potential employee spoofing',
    'Email settings changed', 'Drive settings changed', 'Domain data export initiated',
    'Device compromised', 'Calendar settings changed', 'Account suspension warning',
    'Super admin password reset', 'SSO profile added', 'SSO profile updated',
)


@check(
    check_id="GWS.COMMONCONTROLS.13.1",
    title="Ensure system-defined alerting rules are enabled",
    level="L1",
    source="CISA",
    section="Alert Rules",
    remediation=(
        "Admin console > Rules. Filter by 'System defined' and turn on every required alerting rule. "
        "https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_system_defined_alerts_enabled(data: dict) -> CheckResult:
    """System-defined alerting rules should be active (state read from the Policy API)."""
    from .rules import _system_defined_alert_policies

    _ID = "GWS.COMMONCONTROLS.13.1"
    _TITLE = "Ensure system-defined alerting rules are enabled"
    _L, _S, _SEC = "L1", "CISA", "Alert Rules"
    _REMED = "Admin console > Rules. Filter by 'System defined' and turn on every required alerting rule."

    alerts = _system_defined_alert_policies(data)
    norm = lambda name: str(name).lower().replace("\u2019", "'").strip()  # noqa: E731
    states = {norm(a["name"]): a["state"] for a in alerts}
    required = {norm(r): r for r in SCUBA_REQUIRED_ALERT_RULES}
    inactive = sorted(label for key, label in required.items() if states.get(key, "ACTIVE") != "ACTIVE")
    unknown = sorted(label for key, label in required.items() if key not in states)
    optional_off = sorted(a["name"] for a in alerts if a["state"] != "ACTIVE" and norm(a["name"]) not in required)
    note = f" ({len(optional_off)} optional rule(s) are also off: {', '.join(optional_off)})" if optional_off else ""
    if inactive:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"{len(inactive)} of {len(required)} required system-defined alerting rule(s) are turned off: "
                    f"{', '.join(inactive)}.{note}",
            actual_value={"inactive_required_rules": inactive, "inactive_optional_rules": optional_off},
            expected_value="All required system-defined rules ACTIVE", remediation=_REMED,
        )
    if unknown:
        # Some tenants only get back the rules an admin has modified; a rule that was not
        # returned cannot be confirmed either way.
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"{len(required) - len(unknown)} required rule(s) are ACTIVE; {len(unknown)} were not returned by the "
                    f"Policy API and must be verified in Admin console > Rules: {', '.join(unknown)}.{note}",
            remediation=_REMED,
        )
    return make_pass(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"All {len(required)} required system-defined alerting rules are ACTIVE.{note}",
        actual_value={"inactive_required_rules": [], "inactive_optional_rules": optional_off},
        expected_value="All required system-defined rules ACTIVE",
    )
