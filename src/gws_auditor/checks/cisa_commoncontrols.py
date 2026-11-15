# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Additional CISA SCuBA Common Controls checks for GWS Security Auditor.

Supplements the main cisa_scuba module with deeper CommonControls coverage.
Only checks NOT already covered by CIS/OTHER/GOOGLE or the main CISA module.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, drop_unspecified,
                   latest_setting_changes, admin_emails, user_usage_by_email, advanced_protection_enrolment, make_not_applicable,
                   format_ou_values_readable, is_default_policy, is_admin_configured, field_value, ou_verdict)
from ..constants import (
    EDITIONS_CAA, EDITIONS_DATA_PROCESSING_REGION, EDITIONS_DLP, EDITIONS_DLP_DRIVE, EDITIONS_SESSION_CONTROL,
)
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
        "Admin console > Security > Access and data control > Context-Aware Access. "
        "Configure device policies to enforce endpoint trust "
        "requirements such as screen lock, encryption, and OS version. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
    ),
    requires_license=EDITIONS_CAA,
)
def check_context_aware_access(data: dict) -> CheckResult:
    """Context-aware access device policies should be configured."""
    _ID = "GWS.COMMONCONTROLS.2.1"
    _TITLE = "Ensure context-aware access policies are implemented"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Access and data control > Context-Aware Access. "
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
    from .additional import _caa_app_assignment_evidence, _caa_enforcement_events, caa_access_levels
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
    inventory, inventory_source = caa_access_levels(data)
    actual["access_levels"] = sorted(l["title"] for l in inventory.values() if not l["deleted"])
    actual["inventory_source"] = inventory_source
    if inventory_source == "access_context_manager" and not inventory:
        # Authoritative: the organisation's access policy holds no level, so nothing can be assigned.
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=("Access Context Manager lists no access level for the organisation, so Context-Aware "
                     "Access is not implemented" + (" even though it is switched on" if state == "ENABLED" else "") + "."),
            actual_value=actual, expected_value=expected, remediation=_REMED,
        )
    if state == "ENABLED":
        if evidence["removed"] or evidence["monitor"]:
            why = "access levels were removed from or only monitored for the assigned apps"
        elif inventory_source == "access_context_manager":
            why = (f"access level(s) {', '.join(actual['access_levels'][:5])} exist (Access Context Manager) but "
                   "no assignment to an app in active mode appears in the audit window")
        else:
            why = "no access-level assignment to an app appears in the audit window, so there may be no access level at all"
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
                "Admin console > Security > Access and data control > Context-Aware Access. "
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
            "Admin console > Security > Access and data control > Context-Aware Access. "
            "Configure device policies to enforce endpoint trust "
            "requirements such as screen lock, encryption, and OS version. https://knowledge.workspace.google.com/admin/security/deploy-context-aware-access"
        ),
    )


# ===========================================================================
# Common Controls 3 - Single Sign-On
# ===========================================================================

# Admin audit-log setting names for Post-SSO verification (as read by CISA ScubaGoggles 1.1.0;
# Admin console > Security > Authentication > Login challenges > Post-SSO verification).
POST_SSO_LEGACY_SETTING = "SsoPolicyProto challenge_selection_behavior"
POST_SSO_LEGACY_ON = "PERFORM_CHALLENGE_SELECTION"
POST_SSO_PROFILES_SETTING = "SsoPolicyProto sso_profile_challenge_selection_behavior"
POST_SSO_PROFILES_ON = "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION"
_POST_SSO_REMED = (
    "Admin console > Security > Authentication > Login challenges > Post-SSO verification. "
    "Under 'Settings for users signing in using the legacy SSO profile' and 'Settings for users signing in "
    "using other SSO profiles', select 'Ask users for additional verifications from Google if a sign-in or "
    "session behavior looks suspicious, and always apply 2-Step Verification policies (if configured)'. "
    "https://knowledge.workspace.google.com/admin/security/protect-google-workspace-accounts-with-security-challenges"
)


def post_sso_verification_states(data: dict, setting_name: str, on_value: str, default_on: bool) -> dict[str, bool | None]:
    """``{org_unit: True (verification on) | False (bypass) | None (reverted to the console default)}``
    from the latest admin-log change per OU; ``{}`` when the setting was never changed in the window.

    ``DELETE_APPLICATION_SETTING`` means the OU went back to Google's default, which is
    *bypass* for the legacy profile and *apply challenges* for other SSO profiles.
    """
    out: dict[str, bool | None] = {}
    for ou, value in latest_setting_changes(data, setting_name).items():
        v = value.upper()
        if v == "INHERIT_FROM_PARENT":
            continue
        if v == "DELETE_APPLICATION_SETTING":
            out[ou] = default_on
        else:
            out[ou] = v == on_value
    return out


def _post_sso_check(data: dict, *, check_id: str, title: str, level: str, setting_name: str, on_value: str,
                    default_on: bool, profile_text: str) -> CheckResult:
    common = dict(check_id=check_id, title=title, level=level, source="CISA", section="Security")
    states = post_sso_verification_states(data, setting_name, on_value, default_on)
    if not states:
        return make_review(
            **common, remediation=_POST_SSO_REMED,
            details=(f"Post-SSO verification for {profile_text} is not exposed by the Cloud Identity Policy API "
                     f"and no '{setting_name}' change appears in the admin audit log window, so the current value "
                     f"is unknown (Google's console default is {'to apply' if default_on else 'to bypass'} the "
                     "challenges). Saving the setting once in the Admin console makes it visible to future audits."),
        )
    off = sorted(ou for ou, on in states.items() if not on)
    if off:
        return make_fail(
            **common, remediation=_POST_SSO_REMED,
            details=(f"{len(off)} OU(s) let users who sign in through {profile_text} bypass Google's additional "
                     f"verifications (latest admin-log change): {', '.join(off)}."),
            actual_value={"org_units_bypassing": off}, expected_value="Post-SSO verification on",
        )
    return make_pass(
        **common,
        details=(f"Post-SSO verification is on for {profile_text} in {len(states)} OU(s) "
                 "(latest admin-log change)."),
        actual_value={"org_units_on": sorted(states)}, expected_value="Post-SSO verification on",
    )


@check(
    check_id="GWS.COMMONCONTROLS.3.1",
    title="Ensure post-SSO verification is enabled for the organization's SSO profile",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_POST_SSO_REMED,
)
def check_sso_verification(data: dict) -> CheckResult:
    """SCuBA 3.1 (SHOULD): post-SSO verification for users on the legacy (organization) SSO profile.

    Inferred from the admin audit log (``SsoPolicyProto challenge_selection_behavior``,
    compliant value ``PERFORM_CHALLENGE_SELECTION``); Google's default for this profile is
    to bypass the challenges.
    """
    return _post_sso_check(
        data, check_id="GWS.COMMONCONTROLS.3.1",
        title="Ensure post-SSO verification is enabled for the organization's SSO profile", level="L2",
        setting_name=POST_SSO_LEGACY_SETTING, on_value=POST_SSO_LEGACY_ON, default_on=False,
        profile_text="the organization's legacy SSO profile",
    )


@check(
    check_id="GWS.COMMONCONTROLS.3.2",
    title="Ensure post-SSO verification is enabled for third-party SSO profiles",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_POST_SSO_REMED,
)
def check_third_party_sso_verification(data: dict) -> CheckResult:
    """SCuBA 3.2 (SHOULD): post-SSO verification for users on other (third-party) SSO profiles.

    Inferred from the admin audit log (``SsoPolicyProto sso_profile_challenge_selection_behavior``,
    compliant value ``SSO_PROFILES_PERFORM_CHALLENGE_SELECTION``); Google's default for these
    profiles is to apply the challenges.
    """
    return _post_sso_check(
        data, check_id="GWS.COMMONCONTROLS.3.2",
        title="Ensure post-SSO verification is enabled for third-party SSO profiles", level="L2",
        setting_name=POST_SSO_PROFILES_SETTING, on_value=POST_SSO_PROFILES_ON, default_on=True,
        profile_text="other (third-party) SSO profiles",
    )



def web_session_judge(entry: dict):
    """``ou_verdict`` judge for ``security.session_controls``: web session of 12 hours or less.

    Shared by GWS.COMMONCONTROLS.4.1 and CIS-4.2.4.1. Returns ``None`` when the duration is not
    reported, else ``(verdict, hours)``.
    """
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
        "Admin console > Security > Access and data control > Google session control. "
        "Reduce session duration to 12 hours or less. Longer sessions "
        "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
    ),
    requires_license=EDITIONS_SESSION_CONTROL,
)
def check_session_duration(data: dict) -> CheckResult:
    """Session duration should be 12 hours or less to force re-authentication."""
    _ID = "GWS.COMMONCONTROLS.4.1"
    _TITLE = "Ensure users re-authenticate after 12-hour session expiry"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Security > Access and data control > Google session control. "
        "Reduce session duration to 12 hours or less. Longer sessions "
        "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
    )

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "session_controls")
    if ou_values:
        def judge(entry: dict):
            # Real field: webSessionDuration (seconds string); shared judge with CIS-4.2.4.1.
            if field_value(entry, "webSessionDuration", "sessionDurationHours", "duration") is None:
                return None
            return web_session_judge(entry)

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
                "Admin console > Security > Access and data control > Google session control. "
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
            "Admin console > Security > Access and data control > Google session control. "
            "Reduce session duration to 12 hours or less. Longer sessions "
            "increase the risk of session hijacking and unauthorized access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
        ),
    )


# ===========================================================================
# Common Controls 6 - Admin Account Configuration
# ===========================================================================

# Directory privileges that make a role "highly privileged" for SCuBA GWS.COMMONCONTROLS.6
# (ScubaGoggles 1.1.0 HIGHLY_PRIVILEGED_PRIVILEGES): user, group, service, mobile, OU and
# role management, licence management and the legacy User Management alias.
HIGHLY_PRIVILEGED_PRIVILEGES = frozenset({
    "ADMIN_OAUTH_PRIVILEGE_GROUP", "ADMIN_ROLE_MANAGEMENT", "GROUPS_ALL", "MANAGE_USER_LICENSES",
    "MOBILE_ALL", "ORGANIZATION_UNITS_ALL", "SERVICES_ALL", "USERS_ALL", "USERS_CREATE",
    "USERS_SECURITY", "USERS_UPDATE",
})
_GOOGLE_AUTH_MODES = {"SSO_OFF", "SSO_MODE_UNSPECIFIED", ""}
_CC_6_1_REMED = (
    "Admin console > Security > Authentication > SSO with third-party IdP > Manage SSO profile assignments. "
    "Put every super admin and every account holding a privileged admin role (user, group, service, mobile, "
    "OU, role or licence management) in an OU or group whose SSO assignment is 'None' (Google authentication), "
    "or create dedicated cloud-only admin accounts. "
    "https://knowledge.workspace.google.com/admin/security/set-up-sso-via-a-third-party-identity-provider"
)


def privileged_users(data: dict) -> list[dict]:
    """Super admins plus holders of a role carrying a HIGHLY_PRIVILEGED_PRIVILEGES privilege."""
    users = data.get("users", []) or []
    roles = data.get("roles") or {}
    privileged_role_ids = set()
    for role in roles.get("roles", []) or []:
        if role.get("isSuperAdminRole"):
            privileged_role_ids.add(role.get("roleId"))
            continue
        for priv in role.get("rolePrivileges", []) or []:
            if str(priv.get("privilegeName", "")).upper() in HIGHLY_PRIVILEGED_PRIVILEGES:
                privileged_role_ids.add(role.get("roleId"))
                break
    assigned_ids = {str(a.get("assignedTo")) for a in roles.get("assignments", []) or []
                    if str(a.get("assigneeType", "user")).lower() == "user"
                    and a.get("roleId") in privileged_role_ids}
    return [u for u in users if u.get("is_super_admin") or str(u.get("id")) in assigned_ids]


def _sso_mode_for_user(user: dict, assignments: list[dict], ou_paths: dict[str, str],
                       group_emails: dict[str, str], group_members: dict) -> tuple[str, str]:
    """``(mode, where)``: the inbound SSO mode that applies to *user*.

    A group assignment wins over OU assignments; otherwise the deepest OU assignment on the
    user's OU lineage; otherwise ``SSO_OFF`` (no assignment = Google authentication).
    """
    email = str(user.get("primary_email", "")).lower()
    for a in assignments:
        group = str(a.get("targetGroup", ""))
        if not group:
            continue
        gemail = group_emails.get(group.split("/")[-1], "").lower()
        members = group_members.get(gemail, []) if gemail else []
        if any(str(m.get("email", "")).lower() == email for m in members if isinstance(m, dict)):
            return str(a.get("ssoMode", "SSO_MODE_UNSPECIFIED")).upper(), f"group {gemail or group}"
    user_path = user.get("org_unit_path") or user.get("orgUnitPath") or "/"
    best: tuple[int, str, str] | None = None
    for a in assignments:
        target = str(a.get("targetOrgUnit", ""))
        if not target:
            continue
        path = ou_paths.get(target.split("/")[-1])
        if path is None:
            continue
        if path == "/" or user_path == path or user_path.startswith(path.rstrip("/") + "/"):
            depth = 0 if path == "/" else path.count("/")
            if best is None or depth > best[0]:
                best = (depth, str(a.get("ssoMode", "SSO_MODE_UNSPECIFIED")).upper(), f"OU {path}")
    if best:
        return best[1], best[2]
    return "SSO_OFF", "no SSO assignment"


@check(
    check_id="GWS.COMMONCONTROLS.6.1",
    title="Ensure privileged accounts are cloud-only (not signed in through a third-party IdP)",
    level="L1",
    source="CISA",
    section="Directory",
    remediation=_CC_6_1_REMED,
)
def check_admin_cloud_only(data: dict) -> CheckResult:
    """SCuBA 6.1: administrative accounts authenticate with Google, not an external IdP.

    Privileged users (super admins and holders of highly privileged roles) are matched against
    the Cloud Identity inbound SSO assignments: a group assignment, else the nearest OU
    assignment. ``SSO_OFF`` / no assignment is compliant; ``SAML_SSO`` or
    ``DOMAIN_WIDE_SAML_IF_ENABLED`` is not.
    """
    _ID = "GWS.COMMONCONTROLS.6.1"
    _TITLE = "Ensure privileged accounts are cloud-only (not signed in through a third-party IdP)"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Directory")
    sso = data.get("inbound_sso") or {}
    if not sso.get("collected"):
        return make_manual(
            **common, remediation=_CC_6_1_REMED,
            details=("Inbound SSO assignments were not collected"
                     + (f" ({sso.get('reason')})" if sso.get("reason") else "")
                     + ", so it cannot be determined whether privileged accounts sign in through a third-party IdP."),
        )
    privileged = privileged_users(data)
    if not privileged:
        return make_manual(**common, remediation=_CC_6_1_REMED,
                           details="No privileged accounts found to evaluate (users or roles not collected).")
    assignments = sso.get("assignments", []) or []
    if not assignments:
        return make_pass(
            **common,
            details=(f"No inbound SSO assignment exists, so all {len(privileged)} privileged account(s) "
                     "authenticate with Google."),
            actual_value={"privileged_accounts": len(privileged), "sso_assignments": 0},
            expected_value="No privileged account under a SAML SSO assignment",
        )
    ou_paths = {str(ou.get("orgUnitId", "")).replace("id:", ""): ou.get("orgUnitPath", "/")
                for ou in data.get("org_units", []) or []}
    group_emails = {str(g.get("id", "")): str(g.get("email", "")) for g in data.get("groups", []) or []}
    group_members = data.get("group_members", {}) or {}
    federated = []
    for user in privileged:
        mode, where = _sso_mode_for_user(user, assignments, ou_paths, group_emails, group_members)
        if mode not in _GOOGLE_AUTH_MODES:
            federated.append(f"{user.get('primary_email', 'unknown')} ({mode} via {where})")
    if federated:
        return make_fail(
            **common, remediation=_CC_6_1_REMED,
            details=(f"{len(federated)} of {len(privileged)} privileged account(s) sign in through a third-party "
                     f"identity provider: {'; '.join(sorted(federated))}."),
            actual_value={"federated_privileged_accounts": sorted(federated)},
            expected_value="No privileged account under a SAML SSO assignment",
        )
    return make_pass(
        **common,
        details=(f"All {len(privileged)} privileged account(s) fall under SSO_OFF (Google authentication); "
                 f"{len(assignments)} inbound SSO assignment(s) reviewed."),
        actual_value={"privileged_accounts": len(privileged), "sso_assignments": len(assignments)},
        expected_value="No privileged account under a SAML SSO assignment",
    )


@check(
    check_id="GWS.COMMONCONTROLS.8.3",
    scored=False,  # Admin-console-only control: no API or audit-log signal (plan Decision C)
    title="Ensure adding recovery information is disabled",
    level="L2",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Authentication > Account recovery. "
        "Disable the option for users to add recovery email or phone. "
        "Personal recovery options can be exploited if the personal "
        "accounts are compromised. https://knowledge.workspace.google.com/admin/users/allow-users-to-add-password-recovery-details"
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
        "Admin console > Security > Authentication > Account recovery > Recovery information. "
        "Disable 'Allow admins and users to add recovery email information' "
        "and 'Allow admins and users to add recovery phone information'. https://knowledge.workspace.google.com/admin/users/allow-users-to-add-password-recovery-details"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Recovery information settings (email/phone) are not available "
            "via the Cloud Identity Policy API. Verify manually in "
            "Admin console > Security > Authentication > Account recovery > Recovery information."
        ),
        remediation=_REMED,
    )


# ===========================================================================
# Common Controls 9 - Advanced Protection Program
# ===========================================================================

# Policy API: security.advanced_protection_program only says whether users MAY self-enroll
# (enableAdvancedProtectionSelfEnrollment); per-account enrollment is not exposed.
_APP_REMED = (
    "Admin console > Security > Authentication > Advanced Protection Program > Enrollment: allow users to enroll. Then "
    "enroll each account at https://landing.google.com/advancedprotection/ with two security keys or passkeys. "
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

# Google services and the OAuth scope groups the Admin console can restrict for them
# (Security > Access and data control > API controls > Manage Google Services). ``<X>_ALL`` =
# "Restricted" (every scope), ``<X>_HIGH_RISK`` = "Restricted (high risk)" (users may still
# consent to the low-risk scopes). Mapping as in ScubaGoggles 1.1.0.
GOOGLE_SERVICE_SCOPE_GROUPS: dict[str, frozenset[str]] = {
    "Drive": frozenset({"DRIVE_ALL", "DRIVE_HIGH_RISK"}),
    "Gmail": frozenset({"GMAIL_ALL", "GMAIL_HIGH_RISK"}),
    "Calendar": frozenset({"CALENDAR_ALL"}),
    "Contacts": frozenset({"CONTACTS_ALL"}),
    "Google Workspace Admin": frozenset({"GSUITE_ADMIN_ALL"}),
    "Vault": frozenset({"VAULT_ALL"}),
    "Cloud Platform": frozenset({"CLOUD_PLATFORM"}),
    "Cloud Billing": frozenset({"CLOUD_BILLING"}),
    "Cloud Machine Learning": frozenset({"CLOUD_ML"}),
    "Apps Script API": frozenset({"APPS_SCRIPT_API"}),
    "Apps Script Runtime": frozenset({"APPS_SCRIPT_RUNTIME"}),
    "Classroom": frozenset({"CLASSROOM_ALL", "CLASSROOM_HIGH_RISK"}),
    "Tasks": frozenset({"TASKS"}),
    "Groups": frozenset({"GROUPS"}),
    "Chat": frozenset({"CHAT", "CHAT_HIGH_RISK"}),
    "Google Sign-in": frozenset({"SIGN_IN"}),
    "Meet": frozenset({"MEET"}),
    "Cloud Search": frozenset({"CLOUD_SEARCH"}),
}
HIGH_RISK_SCOPE_GROUPS = frozenset({"DRIVE_HIGH_RISK", "GMAIL_HIGH_RISK", "CLASSROOM_HIGH_RISK", "CHAT_HIGH_RISK"})
_API_CONTROLS_REMED = (
    "Admin console > Security > Access and data control > API controls > Manage Google Services. "
    "Set every service to 'Restricted' so that only trusted apps reach Google Workspace data; "
    "'Restricted (high risk)' still lets users consent to low-risk scopes. "
    "https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
)


def _restricted_scope_groups(entry: dict) -> set[str] | None:
    """Scope groups listed under ``api_controls.google_services.services`` for one OU, or None if unknown."""
    services = field_value(entry, "services")
    if services is None or not isinstance(services, list):
        return None
    return {str(svc.get("scopesGroup", "")).upper() for svc in services if isinstance(svc, dict)}


@check(
    check_id="GWS.COMMONCONTROLS.10.1",
    title="Ensure app access control policies restrict third-party access to all Google services",
    level="L1",
    source="CISA",
    section="Security",
    remediation=_API_CONTROLS_REMED,
)
def check_third_party_api_restricted(data: dict) -> CheckResult:
    """SCuBA 10.1: every Google service is restricted ('Restricted' or 'Restricted (high risk)').

    Reads ``api_controls.google_services.services[].scopesGroup`` per OU; a service with
    none of its scope groups listed is unrestricted. Google's default is an empty list, so a
    tenant that never touched App access control fails here.
    """
    _ID = "GWS.COMMONCONTROLS.10.1"
    _TITLE = "Ensure app access control policies restrict third-party access to all Google services"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Security")
    api_controls = data.get("policies", {}).get("api_controls", {})
    ou_values = get_ou_values(api_controls, "google_services")
    if not ou_values:
        return make_review(
            **common, remediation=_API_CONTROLS_REMED,
            details="'api_controls.google_services' was not returned by the Cloud Identity Policy API; verify in the Admin console.",
        )

    def judge(entry):
        groups = _restricted_scope_groups(entry)
        if groups is None:
            return None
        unrestricted = sorted(name for name, scope_groups in GOOGLE_SERVICE_SCOPE_GROUPS.items()
                              if not (scope_groups & groups))
        return (not unrestricted), (", ".join(unrestricted) if unrestricted else "all services restricted")

    return ou_verdict(
        ou_values, judge, **common,
        fail_text="leave Google services unrestricted for third-party apps",
        pass_text="restrict every Google service for third-party apps",
        expected_value="Every Google service Restricted or Restricted (high risk)", remediation=_API_CONTROLS_REMED,
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.2",
    title="Ensure users cannot consent to low-risk app scopes",
    level="L1",
    source="CISA",
    section="Security",
    remediation=_API_CONTROLS_REMED,
)
def check_user_consent_low_risk(data: dict) -> CheckResult:
    """SCuBA 10.2: no service is left in 'Restricted (high risk)', which still lets users consent
    to its low-risk scopes. Reads ``api_controls.google_services.services[].scopesGroup``."""
    _ID = "GWS.COMMONCONTROLS.10.2"
    _TITLE = "Ensure users cannot consent to low-risk app scopes"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Security")
    api_controls = data.get("policies", {}).get("api_controls", {})
    ou_values = get_ou_values(api_controls, "google_services")
    if not ou_values:
        return make_review(
            **common, remediation=_API_CONTROLS_REMED,
            details="'api_controls.google_services' was not returned by the Cloud Identity Policy API; verify in the Admin console.",
        )

    def judge(entry):
        groups = _restricted_scope_groups(entry)
        if groups is None:
            return None
        high_risk_only = sorted(g.split("_")[0].title() for g in groups & HIGH_RISK_SCOPE_GROUPS)
        return (not high_risk_only), (", ".join(high_risk_only) if high_risk_only else "no high-risk-only restriction")

    return ou_verdict(
        ou_values, judge, **common,
        fail_text="restrict services for high-risk scopes only, so users may consent to low-risk scopes",
        pass_text="do not leave any service in 'Restricted (high risk)'",
        expected_value="No service in Restricted (high risk)", remediation=_API_CONTROLS_REMED,
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.3",
    title="Ensure unconfigured internal apps are not trusted",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Security > Access and data control > API controls > App access control. "
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
                "Admin console > Security > Access and data control > API controls > App access control. "
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
            "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Admin console > Security > Access and data control > API controls > App access control. "
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
                "Admin console > Security > Access and data control > API controls > App access control. "
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
            "Admin console > Security > Access and data control > API controls > App access control. "
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
        "Keep audit logs searchable for at least 3 months and retrievable for at least 12 months "
        "(SCuBA 14.2 v1): export them to BigQuery or a SIEM for retention beyond Google's 6-month window. "
        "https://knowledge.workspace.google.com/admin/reports/reports-overview"
    ),
)
def check_audit_log_retention(data: dict) -> CheckResult:
    """Audit logs searchable for 3 months and retrievable for 12 months (SCuBA 14.2 v1).

    Audit log retention and BigQuery export settings are not available
    via the Cloud Identity Policy API.  This check always requires
    manual verification.
    """
    _ID = "GWS.COMMONCONTROLS.14.2"
    _TITLE = "Ensure audit log retention meets minimum requirements"
    _L, _S, _SEC = "L1", "CISA", "Reporting"
    _REMED = (
        "Admin console > Reporting > Audit and investigation. "
        "Keep audit logs searchable for at least 3 months and retrievable for at least 12 months "
        "(SCuBA 14.2 v1): export them to BigQuery or a SIEM for retention beyond Google's 6-month window. "
        "https://knowledge.workspace.google.com/admin/reports/reports-overview"
    )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Audit log retention settings are not available via the Cloud "
            "Identity Policy API. Verify manually that logs are searchable for "
            "at least 3 months and retrievable for at least 12 months (SCuBA 14.2 v1), "
            "typically via BigQuery export or SIEM integration."
        ),
        remediation=_REMED,
    )


# ===========================================================================
# Common Controls 15 - Data Regions (supplemental)
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.15.2",
    title="Ensure data is processed in the selected storage region",
    level="L1",
    source="CISA",
    section="Security",
    remediation=(
        "Admin console > Data > Compliance > Data regions. "
        "Enable data processing restrictions to ensure data at rest "
        "and in processing remains within the designated geographic region "
        "for compliance with data sovereignty requirements. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
    ),
    requires_license=EDITIONS_DATA_PROCESSING_REGION,
)
def check_data_processing_in_region(data: dict) -> CheckResult:
    """Data processing should be restricted to the configured storage region."""
    _ID = "GWS.COMMONCONTROLS.15.2"
    _TITLE = "Ensure data is processed in the selected storage region"
    _L, _S, _SEC = "L1", "CISA", "Security"
    _REMED = (
        "Admin console > Data > Compliance > Data regions. "
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
            level="L1", source="CISA", section="Security",
            details="Data processing is restricted to the selected storage region.",
            actual_value=processing_in_region,
            expected_value="Enabled for all OUs",
        )

    if processing_in_region is None:
        return make_review(
            check_id="GWS.COMMONCONTROLS.15.2",
            title="Ensure data is processed in the selected storage region",
            level="L1", source="CISA", section="Security",
            details=(
                "Data processing region is not exposed by the Cloud Identity "
                "Policy API for this tenant — verify in Admin console."
            ),
            remediation=(
                "Admin console > Data > Compliance > Data regions. "
                "Ensure data processing is restricted to the selected "
                "storage region. Requires Enterprise Plus license. https://knowledge.workspace.google.com/admin/security/about-assured-controls-and-assured-controls-plus"
            ),
        )

    return make_fail(
        check_id="GWS.COMMONCONTROLS.15.2",
        title="Ensure data is processed in the selected storage region",
        level="L1", source="CISA", section="Security",
        details="Data processing is not restricted to the selected storage region.",
        actual_value=processing_in_region,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Data > Compliance > Data regions. "
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
        "Admin console > Apps > Additional Google services > Early Access Apps. "
        "Disable early access to pre-release features. These features "
        "have not completed full security review and may introduce "
        "vulnerabilities or unexpected data handling behavior. https://knowledge.workspace.google.com/admin/users/access/turn-early-access-apps-on-or-off-for-users"
    ),
)
def check_early_access_disabled(data: dict) -> CheckResult:
    """Early access (pre-release) apps should be disabled."""
    _ID = "GWS.COMMONCONTROLS.16.2"
    _TITLE = "Ensure early access apps are disabled"
    _L, _S, _SEC = "L2", "CISA", "Security"
    _REMED = (
        "Admin console > Apps > Additional Google services > Early Access Apps. "
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
                "Admin console > Apps > Additional Google services > Early Access Apps. "
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
            "Admin console > Apps > Additional Google services > Early Access Apps. "
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

# DLP detectors SCuBA 18.1 requires at minimum (Google Cloud DLP infoType names used in
# ``rule.dlp`` content conditions) and the four apps a custom policy must cover.
DLP_REQUIRED_DETECTORS: dict[str, str] = {
    "credit card numbers": "CREDIT_CARD_NUMBER",
    "US ITIN": "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER",
    "US SSN": "US_SOCIAL_SECURITY_NUMBER",
}
DLP_REQUIRED_APPS: dict[str, str] = {"Drive": "drive", "Calendar": "calendar", "Chat": "chat", "Gmail": "gmail"}
_DLP_REMED = (
    "Admin console > Security > Access and data control > Data protection > Manage rules. Create a rule "
    "whose triggers cover Google Drive (file shared), Google Calendar (event saved), Google Chat (message sent, "
    "file uploaded) and Gmail (message sent and received), with conditions for the predefined detectors "
    "Global - Credit card number, United States - Individual Taxpayer Identification Number and United States - "
    "Social Security Number, and the actions of GWS.COMMONCONTROLS.18.2. "
    "https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
)
_DLP_ACTION_REMED = (
    "Admin console > Security > Access and data control > Data protection > Manage rules. In each rule's Actions: "
    "Google Drive 'Block external sharing', Google Chat 'Block message', Google Calendar 'Block event' "
    "(Gmail may stay 'Audit only'). "
    "https://knowledge.workspace.google.com/admin/security/create-data-protection-rules"
)


def active_dlp_rules(data: dict) -> tuple[bool, list[dict]]:
    """``(rules_collected, [rule values with state ACTIVE])`` from the ``rule.dlp`` policies."""
    rules = data.get("policies", {}).get("rules")
    if not isinstance(rules, dict):
        return False, []
    policies = rules.get("_ou_policies", []) or []
    active = []
    for policy in policies:
        setting = policy.get("setting", {}) if isinstance(policy, dict) else {}
        if not str(setting.get("type", "")).endswith("rule.dlp"):
            continue
        value = setting.get("value", {}) or {}
        if str(value.get("state", "")).upper() == "ACTIVE":
            active.append(value)
    return True, active


def _rule_apps(rule: dict) -> set[str]:
    blob = " ".join(str(t.get("app", t.get("application", t))) if isinstance(t, dict) else str(t)
                    for t in (rule.get("triggers") or []))
    action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
    blob += " " + " ".join(action.keys())
    return {app for app, needle in DLP_REQUIRED_APPS.items() if needle in blob.lower()}



def _console_only_review(check_id: str, title: str, level: str, section: str, setting_text: str, remediation: str) -> CheckResult:
    return make_review(
        check_id=check_id, title=title, level=level, source="CISA", section=section,
        details=(f"{setting_text} is not exposed by the Cloud Identity Policy API or by an admin audit-log event "
                 "the auditor knows; verify it in the Admin console."),
        remediation=remediation,
    )


_LOOKER_REMED = (
    "Admin console > Apps > Additional Google services > Looker Studio > Sharing setting. Select OFF so reports "
    "cannot be shared outside the organisation. https://knowledge.workspace.google.com/admin/apps/additional-google-services/looker-studio"
)
_PINPOINT_REMED = (
    "Admin console > Apps > Additional Google services > Pinpoint > Data access settings. Select "
    "'OFF - Users cannot copy files from Drive to Pinpoint'. https://knowledge.workspace.google.com/admin/apps/additional-google-services/pinpoint"
)


@check(
    check_id="GWS.COMMONCONTROLS.16.3",
    scored=False,  # Admin-console-only control: no API or audit-log signal known
    title="Ensure Looker Studio sharing outside the organization is off",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_LOOKER_REMED,
)
def check_looker_studio_sharing(data: dict) -> CheckResult:
    """SCuBA v1 16.3 (SHOULD): no API exposes the Looker Studio sharing setting."""
    return _console_only_review("GWS.COMMONCONTROLS.16.3", "Ensure Looker Studio sharing outside the organization is off",
                                "L2", "Security", "The Looker Studio 'Sharing setting'", _LOOKER_REMED)


@check(
    check_id="GWS.COMMONCONTROLS.16.4",
    scored=False,  # Admin-console-only control: no API or audit-log signal known
    title="Ensure Pinpoint access to Drive is off",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_PINPOINT_REMED,
)
def check_pinpoint_drive_access(data: dict) -> CheckResult:
    """SCuBA v1 16.4 (SHOULD): no API exposes the Pinpoint data-access setting."""
    return _console_only_review("GWS.COMMONCONTROLS.16.4", "Ensure Pinpoint access to Drive is off",
                                "L2", "Security", "The Pinpoint 'Data access settings' toggle", _PINPOINT_REMED)


@check(
    check_id="GWS.COMMONCONTROLS.18.1",
    title="Ensure DLP rules cover Drive, Calendar, Chat and Gmail for credit card, ITIN and SSN data",
    level="L1",
    source="CISA",
    section="Security",
    remediation=_DLP_REMED,
    requires_license=EDITIONS_DLP,
)
def check_dlp_custom_policy(data: dict) -> CheckResult:
    """SCuBA 18.1: an active DLP rule covers each of Drive, Calendar, Chat and Gmail for each of
    the three required detectors (credit card, US ITIN, US SSN), read from the ``rule.dlp`` policies."""
    _ID = "GWS.COMMONCONTROLS.18.1"
    _TITLE = "Ensure DLP rules cover Drive, Calendar, Chat and Gmail for credit card, ITIN and SSN data"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Security")
    collected, rules = active_dlp_rules(data)
    if not collected:
        return make_manual(**common, remediation=_DLP_REMED,
                           details="DLP rules (Policy API category 'rule') were not collected.")
    covered: dict[tuple[str, str], list[str]] = {}
    for rule in rules:
        apps = _rule_apps(rule)
        condition = json_dumps_lower(rule.get("condition"))
        for det_name, infotype in DLP_REQUIRED_DETECTORS.items():
            if infotype.lower() in condition:
                for app in apps:
                    covered.setdefault((app, det_name), []).append(str(rule.get("displayName", "unnamed")))
    missing = [f"{app}: {det}" for app in DLP_REQUIRED_APPS for det in DLP_REQUIRED_DETECTORS if (app, det) not in covered]
    if missing:
        return make_fail(
            **common, remediation=_DLP_REMED,
            details=(f"{len(rules)} active DLP rule(s); {len(missing)} of the 12 required app/detector pairs have no "
                     f"active rule: {', '.join(missing)}."),
            actual_value={"active_rules": len(rules), "missing": missing},
            expected_value="Every app covered for credit card, ITIN and SSN",
        )
    return make_pass(
        **common,
        details=(f"{len(rules)} active DLP rule(s) cover Drive, Calendar, Chat and Gmail for credit card numbers, "
                 "US ITIN and US SSN."),
        actual_value={"active_rules": len(rules), "covered_pairs": len(covered)},
        expected_value="Every app covered for credit card, ITIN and SSN",
    )


def json_dumps_lower(value) -> str:
    import json as _json
    try:
        return _json.dumps(value, default=str).lower()
    except (TypeError, ValueError):
        return str(value).lower()


@check(
    check_id="GWS.COMMONCONTROLS.18.2",
    title="Ensure DLP rule actions block (Drive external sharing, Chat messages, Calendar events)",
    level="L2",
    source="CISA",
    section="Security",
    remediation=_DLP_ACTION_REMED,
    requires_license=EDITIONS_DLP,
)
def check_dlp_actions_block(data: dict) -> CheckResult:
    """SCuBA 18.2 (SHOULD): every active DLP rule blocks for Drive, Chat and Calendar; Gmail rules
    may audit only. A rule action is blocking when its per-app action carries a ``block*`` key
    (e.g. ``driveAction.blockExternalSharing``); ``warnUser`` and audit-only are not."""
    _ID = "GWS.COMMONCONTROLS.18.2"
    _TITLE = "Ensure DLP rule actions block (Drive external sharing, Chat messages, Calendar events)"
    common = dict(check_id=_ID, title=_TITLE, level="L2", source="CISA", section="Security")
    collected, rules = active_dlp_rules(data)
    if not collected:
        return make_manual(**common, remediation=_DLP_ACTION_REMED,
                           details="DLP rules (Policy API category 'rule') were not collected.")
    judged = 0
    non_blocking = []
    for rule in rules:
        action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
        for app_key in ("driveAction", "chatAction", "calendarAction"):
            app_action = action.get(app_key)
            if not isinstance(app_action, dict):
                continue
            judged += 1
            kinds = sorted(app_action.keys())
            if not any("block" in k.lower() for k in kinds):
                non_blocking.append(f"{rule.get('displayName', 'unnamed')} ({app_key}: {', '.join(kinds) or 'no action'})")
    if judged == 0:
        return make_not_applicable(
            **common,
            details=("No active DLP rule acts on Drive, Chat or Calendar, so there is no rule action to judge "
                     "(see GWS.COMMONCONTROLS.18.1)."),
        )
    if non_blocking:
        return make_fail(
            **common, remediation=_DLP_ACTION_REMED,
            details=(f"{len(non_blocking)} of {judged} Drive/Chat/Calendar rule action(s) do not block: "
                     f"{'; '.join(non_blocking[:15])}" + (" ..." if len(non_blocking) > 15 else "") + "."),
            actual_value={"non_blocking_actions": non_blocking}, expected_value="block",
        )
    return make_pass(
        **common,
        details=f"All {judged} Drive/Chat/Calendar DLP rule action(s) block.",
        actual_value={"blocking_actions": judged}, expected_value="block",
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
        "https://knowledge.workspace.google.com/admin/users/set-up-password-recovery-for-users"
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


# Rules CISA SCuBA GWS.COMMONCONTROLS.13.1 requires (policy group 13 description, unchanged from v0.6 to v1); other system-defined rules are optional.
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
