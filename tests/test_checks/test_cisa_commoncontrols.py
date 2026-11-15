"""Tests for CISA SCuBA Common Controls checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_admin_event, make_user_account_event, make_user_usage_row, make_ou_policy


class TestContextAwareAccess:
    """Tests for GWS.COMMONCONTROLS.2.1 context-aware access."""

    def test_context_aware_access_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "context_aware_access": {"device_policies_configured": True},
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS

    def test_context_aware_access_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "context_aware_access": {"device_policies_configured": False},
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.FAIL


class TestPostSsoVerification:
    """GWS.COMMONCONTROLS.3.1 / 3.2: inferred from the SsoPolicyProto admin-log events (ScubaGoggles 1.1.0 names)."""

    LEGACY = "SsoPolicyProto challenge_selection_behavior"
    PROFILES = "SsoPolicyProto sso_profile_challenge_selection_behavior"

    def _ev(self, setting, value, ou="/", time="2026-10-01T10:00:00.000Z"):
        return make_admin_event("CHANGE_APPLICATION_SETTING",
                                {"SETTING_NAME": setting, "NEW_VALUE": value, "ORG_UNIT_NAME": ou}, time=time)

    def test_legacy_profile_on_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification
        full_audit_data["admin_logs"] = [self._ev(self.LEGACY, "PERFORM_CHALLENGE_SELECTION")]
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.PASS and result.scored is True

    def test_legacy_profile_bypass_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification
        full_audit_data["admin_logs"] = [self._ev(self.LEGACY, "BYPASS_CHALLENGE_SELECTION", ou="/Sales")]
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_legacy_profile_reverted_to_default_is_bypass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification
        full_audit_data["admin_logs"] = [self._ev(self.LEGACY, "PERFORM_CHALLENGE_SELECTION", time="2026-09-01T10:00:00.000Z"),
                                         self._ev(self.LEGACY, "DELETE_APPLICATION_SETTING", time="2026-10-01T10:00:00.000Z")]
        assert check_sso_verification(full_audit_data).status == Status.FAIL

    def test_no_event_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification, check_third_party_sso_verification
        full_audit_data["admin_logs"] = []
        for check in (check_sso_verification, check_third_party_sso_verification):
            result = check(full_audit_data)
            assert result.status == Status.MANUAL, check.__name__
            assert "admin audit log" in result.details

    def test_other_profiles_on_passes_and_off_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification
        full_audit_data["admin_logs"] = [self._ev(self.PROFILES, "SSO_PROFILES_PERFORM_CHALLENGE_SELECTION")]
        assert check_third_party_sso_verification(full_audit_data).status == Status.PASS
        full_audit_data["admin_logs"] = [self._ev(self.PROFILES, "SSO_PROFILES_BYPASS_CHALLENGE_SELECTION")]
        assert check_third_party_sso_verification(full_audit_data).status == Status.FAIL

    def test_other_profiles_reverted_to_default_passes(self, full_audit_data):
        """Google's default for other SSO profiles is to apply the challenges."""
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification
        full_audit_data["admin_logs"] = [self._ev(self.PROFILES, "DELETE_APPLICATION_SETTING")]
        assert check_third_party_sso_verification(full_audit_data).status == Status.PASS


class TestSessionManagement:
    """Tests for GWS.COMMONCONTROLS.4.1 session duration."""

    def test_session_duration_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "session_management": {"session_duration_hours": 12},
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.PASS

    def test_session_duration_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "session_management": {"session_duration_hours": 24},
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL


class TestAdminCloudOnly:
    """GWS.COMMONCONTROLS.6.1: privileged accounts versus the Cloud Identity inbound SSO assignments."""

    def _user(self, uid, email, ou, super_admin=False):
        return {"id": uid, "primary_email": email, "primaryEmail": email, "is_super_admin": super_admin,
                "isAdmin": super_admin, "is_delegated_admin": False, "suspended": False, "org_unit_path": ou}

    def _setup(self, data, assignments, collected=True):
        data["inbound_sso"] = {"collected": collected, "assignments": assignments, "reason": "" if collected else "permission denied"}
        data["org_units"] = [{"orgUnitId": "id:root", "orgUnitPath": "/"}, {"orgUnitId": "id:adm", "orgUnitPath": "/Admins"},
                             {"orgUnitId": "id:staff", "orgUnitPath": "/Staff"}]
        data["roles"] = {"roles": [
            {"roleId": "sa", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True, "rolePrivileges": []},
            {"roleId": "um", "roleName": "_USER_MANAGEMENT_ADMIN_ROLE", "rolePrivileges": [{"privilegeName": "USERS_ALL"}]},
            {"roleId": "hd", "roleName": "_HELP_DESK_ADMIN_ROLE", "rolePrivileges": [{"privilegeName": "USERS_RETRIEVE"}]},
        ], "assignments": [{"roleId": "um", "assignedTo": "u3", "assigneeType": "user"},
                           {"roleId": "hd", "assignedTo": "u4", "assigneeType": "user"}]}
        data["users"] = [self._user("u1", "root-admin@example.com", "/Admins", True),
                         self._user("u2", "staff-admin@example.com", "/Staff", True),
                         self._user("u3", "usermgr@example.com", "/Staff"),
                         self._user("u4", "helpdesk@example.com", "/Staff")]
        data["groups"] = [{"id": "g1", "email": "sso-group@example.com", "name": "sso"}]
        data["group_members"] = {"sso-group@example.com": [{"email": "root-admin@example.com", "type": "USER"}]}

    def test_not_collected_is_error(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [], collected=False)
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.ERROR
        assert "not collected" in result.details

    def test_no_assignment_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [])
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["privileged_accounts"] == 3  # u1, u2 super admins + u3 user management

    def test_ou_assignment_fails_privileged_users_in_it(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [{"targetOrgUnit": "orgUnits/staff", "ssoMode": "SAML_SSO", "samlSsoProfile": "p"}])
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.FAIL
        assert "staff-admin@example.com" in result.details and "usermgr@example.com" in result.details
        assert "root-admin" not in result.details and "helpdesk" not in result.details

    def test_nearest_ou_assignment_wins(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [{"targetOrgUnit": "orgUnits/root", "ssoMode": "SAML_SSO"},
                                      {"targetOrgUnit": "orgUnits/adm", "ssoMode": "SSO_OFF"}])
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.FAIL
        assert "root-admin" not in result.details and "staff-admin@example.com" in result.details

    def test_group_assignment_beats_ou(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [{"targetOrgUnit": "orgUnits/adm", "ssoMode": "SSO_OFF"},
                                      {"targetGroup": "groups/g1", "ssoMode": "DOMAIN_WIDE_SAML_IF_ENABLED"}])
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.FAIL
        assert "root-admin@example.com (DOMAIN_WIDE_SAML_IF_ENABLED via group sso-group@example.com)" in result.details

    def test_all_sso_off_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only
        self._setup(full_audit_data, [{"targetOrgUnit": "orgUnits/root", "ssoMode": "SSO_OFF"}])
        assert check_admin_cloud_only(full_audit_data).status == Status.PASS


class TestAccountRecovery:
    """Tests for GWS.COMMONCONTROLS.8.x account recovery checks."""

    def test_recovery_info_always_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_recovery_info_disabled
        result = check_recovery_info_disabled(full_audit_data)
        assert result.status == Status.MANUAL




class TestAppAccessControl:
    """Tests for GWS.COMMONCONTROLS.10.x app access control checks."""

    def test_unconfigured_internal_apps_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"trust_unconfigured_internal_apps": False},
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_unconfigured_internal_apps_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"trust_unconfigured_internal_apps": True},
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL

    def test_unconfigured_third_party_apps_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_unconfigured_third_party_apps": False},
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_unconfigured_third_party_apps_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_unconfigured_third_party_apps": True},
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL


class TestAuditLogRetention:
    """Tests for GWS.COMMONCONTROLS.14.2 audit log retention."""

    def test_audit_log_retention_always_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_audit_log_retention

        result = check_audit_log_retention(full_audit_data)
        assert result.status == Status.MANUAL


class TestDataRegions:
    """Tests for GWS.COMMONCONTROLS.15.2 data processing in region."""

    def test_data_processing_in_region_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "data_regions": {"processing_in_region": True},
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.PASS

    def test_data_processing_in_region_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "data_regions": {"processing_in_region": False},
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL


class TestServiceStatus:
    """Tests for GWS.COMMONCONTROLS.16.x service status checks."""

    def test_unused_services_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"unused_services_disabled": True},
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_unused_services_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"unused_services_disabled": False},
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_early_access_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"early_access_enabled": False},
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_early_access_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"early_access_enabled": True},
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.FAIL


DLP_TRIGGERS = {"drive": "google.workspace.drive.file.v1.share", "gmail": "google.workspace.gmail.email.v1.send",
                "chat": "google.workspace.chat.message.v1.send", "calendar": "google.workspace.calendar.event.v1.save"}
DLP_DETECTORS = ("CREDIT_CARD_NUMBER", "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER", "US_SOCIAL_SECURITY_NUMBER")


def _dlp_rule(name, apps, detectors=DLP_DETECTORS, actions=None, state="ACTIVE"):
    """A ``rule.dlp`` policy in the live shape (triggers, CEL content condition, per-app action)."""
    cond = " || ".join(f"all_content.matches_dlp_detector('{d}', google.privacy.dlp.v2.Likelihood.POSSIBLE, {{}})" for d in detectors)
    action = {f"{a}Action": (actions or {}).get(a, {"warnUser": {}}) for a in apps}
    action["alertCenterAction"] = {"recipients": []}
    return make_ou_policy("rule", "dlp", {"displayName": name, "state": state, "triggers": [DLP_TRIGGERS[a] for a in apps],
                                          "condition": {"contentCondition": cond}, "action": action})


def _dlp_data(full_audit_data, *rules):
    full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
    full_audit_data["policies"]["rules"] = {"_ou_policies": list(rules)}
    return full_audit_data


class TestDlpCustomPolicy:
    """GWS.COMMONCONTROLS.18.1 (SCuBA v1): Drive, Calendar, Chat and Gmail each covered for CC, ITIN and SSN."""

    def test_full_coverage_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_custom_policy
        _dlp_data(full_audit_data, _dlp_rule("PII", ["drive", "gmail", "chat", "calendar"]))
        result = check_dlp_custom_policy(full_audit_data)
        assert result.status == Status.PASS

    def test_coverage_across_rules_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_custom_policy
        _dlp_data(full_audit_data, _dlp_rule("Drive+Gmail", ["drive", "gmail"]), _dlp_rule("Chat", ["chat"]),
                  _dlp_rule("Calendar", ["calendar"]))
        assert check_dlp_custom_policy(full_audit_data).status == Status.PASS

    def test_missing_app_or_detector_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_custom_policy
        _dlp_data(full_audit_data, _dlp_rule("Drive+Gmail", ["drive", "gmail"]),
                  _dlp_rule("Chat", ["chat"], detectors=("CREDIT_CARD_NUMBER",)))
        result = check_dlp_custom_policy(full_audit_data)
        assert result.status == Status.FAIL
        assert "Calendar: credit card numbers" in result.details and "Chat: US SSN" in result.details
        assert "Drive" not in result.details

    def test_inactive_rule_does_not_count(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_custom_policy
        _dlp_data(full_audit_data, _dlp_rule("PII", ["drive", "gmail", "chat", "calendar"], state="INACTIVE"))
        assert check_dlp_custom_policy(full_audit_data).status == Status.FAIL

    def test_rules_not_collected_is_error(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_custom_policy
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"].pop("rules", None)
        assert check_dlp_custom_policy(full_audit_data).status == Status.ERROR


class TestDlpActionsBlock:
    """GWS.COMMONCONTROLS.18.2 (SCuBA v1): Drive, Chat and Calendar actions block; Gmail may audit only."""

    def test_blocking_actions_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_actions_block
        _dlp_data(full_audit_data, _dlp_rule("PII", ["drive", "chat", "calendar", "gmail"], actions={
            "drive": {"blockExternalSharing": {}}, "chat": {"blockMessage": {}}, "calendar": {"blockEvent": {}},
            "gmail": {"auditOnly": {}}}))
        result = check_dlp_actions_block(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value == {"blocking_actions": 3}

    def test_warn_only_drive_action_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_actions_block
        _dlp_data(full_audit_data, _dlp_rule("Warn", ["drive", "chat"], actions={"chat": {"blockMessage": {}}}))
        result = check_dlp_actions_block(full_audit_data)
        assert result.status == Status.FAIL
        assert "Warn (driveAction: warnUser)" in result.details

    def test_gmail_only_rules_are_not_applicable(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_actions_block
        _dlp_data(full_audit_data, _dlp_rule("Mail", ["gmail"]))
        assert check_dlp_actions_block(full_audit_data).status == Status.NOT_APPLICABLE

    def test_rules_not_collected_is_error(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_actions_block
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"].pop("rules", None)
        assert check_dlp_actions_block(full_audit_data).status == Status.ERROR


class TestContextAwareAccessOU:
    """OU-aware tests for GWS.COMMONCONTROLS.2.1 context-aware access."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/Engineering"),
            ],
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": False}, "/Sales"),
            ],
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestSessionDurationOU:
    """OU-aware tests for GWS.COMMONCONTROLS.4.1 session duration.

    Rewritten with the real field (security.session_controls.webSessionDuration, a seconds
    string) instead of the invented sessionDurationHours.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "28800s"}, "/"),
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "43200s"}, "/Engineering"),
            ],
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "43200s"}, "/"),
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "86400s"}, "/Support"),
            ],
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details
        assert "/Support → 24h" in result.actual_value

    def test_fractional_hours_are_compared_exactly(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "session_controls", {"webSessionDuration": "43201s"})]}
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL  # 12.0003 h is over the 12-hour limit
        assert "12.0h" in result.actual_value

    def test_system_only_value_is_judged(self, full_audit_data):
        """A SYSTEM policy is the value in force: Google's 14-day default fails the control."""
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        entry = make_ou_policy("security", "session_controls", {"webSessionDuration": "1209600s"})
        entry["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["security"] = {"_ou_policies": [entry]}
        assert check_session_duration(full_audit_data).status == Status.FAIL

    def test_missing_duration_is_unknown(self, full_audit_data):
        """Was FAIL: an empty value has no documented default, so the check must not judge it."""
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "session_controls", {})]}
        assert check_session_duration(full_audit_data).status == Status.MANUAL








ALL_SERVICE_GROUPS = ("DRIVE_ALL", "GMAIL_ALL", "CALENDAR_ALL", "CONTACTS_ALL", "GSUITE_ADMIN_ALL", "VAULT_ALL",
                      "CLOUD_PLATFORM", "CLOUD_BILLING", "CLOUD_ML", "APPS_SCRIPT_API", "APPS_SCRIPT_RUNTIME",
                      "CLASSROOM_ALL", "TASKS", "GROUPS", "CHAT", "SIGN_IN", "MEET", "CLOUD_SEARCH")


def _services(*groups):
    return {"services": [{"scopesGroup": g, "isEnabled": False} for g in groups]}


class TestAppAccessControlServices:
    """GWS.COMMONCONTROLS.10.1 / 10.2 read api_controls.google_services.services[].scopesGroup (ScubaGoggles 1.1.0):
    <X>_ALL = Restricted, <X>_HIGH_RISK = Restricted (high risk), nothing = Unrestricted."""

    def _set(self, data, *entries):
        data["policies"]["api_controls"] = {"_ou_policies": list(entries)}

    def test_all_services_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted, check_user_consent_low_risk
        self._set(full_audit_data, make_ou_policy("api_controls", "google_services", _services(*ALL_SERVICE_GROUPS)))
        assert check_third_party_api_restricted(full_audit_data).status == Status.PASS
        assert check_user_consent_low_risk(full_audit_data).status == Status.PASS

    def test_unrestricted_service_fails_10_1(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted, check_user_consent_low_risk
        groups = tuple(g for g in ALL_SERVICE_GROUPS if g not in ("DRIVE_ALL", "MEET"))
        self._set(full_audit_data, make_ou_policy("api_controls", "google_services", _services(*groups)))
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.FAIL
        assert "Drive" in str(result.actual_value) and "Meet" in str(result.actual_value)
        assert check_user_consent_low_risk(full_audit_data).status == Status.PASS

    def test_high_risk_only_fails_10_2_but_satisfies_10_1(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted, check_user_consent_low_risk
        groups = tuple("DRIVE_HIGH_RISK" if g == "DRIVE_ALL" else g for g in ALL_SERVICE_GROUPS)
        self._set(full_audit_data, make_ou_policy("api_controls", "google_services", _services(*groups)))
        assert check_third_party_api_restricted(full_audit_data).status == Status.PASS
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL
        assert "Drive" in str(result.actual_value)

    def test_google_default_empty_list_fails_10_1(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted
        self._set(full_audit_data, make_ou_policy("api_controls", "google_services", {"services": []}))
        assert check_third_party_api_restricted(full_audit_data).status == Status.FAIL

    def test_child_ou_named(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk
        self._set(full_audit_data,
                  make_ou_policy("api_controls", "google_services", _services(*ALL_SERVICE_GROUPS), "/"),
                  make_ou_policy("api_controls", "google_services",
                                 _services(*("GMAIL_HIGH_RISK" if g == "GMAIL_ALL" else g for g in ALL_SERVICE_GROUPS)), "/Sales"))
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL and "/Sales" in result.details

    def test_setting_not_returned_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted, check_user_consent_low_risk
        full_audit_data["policies"]["api_controls"] = {}
        full_audit_data["policies"]["security"] = {}
        for check in (check_third_party_api_restricted, check_user_consent_low_risk):
            assert check(full_audit_data).status == Status.MANUAL


class TestUnconfiguredInternalAppsOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.3 unconfigured internal apps.

    Rewritten with the real field api_controls.internal_apps.trustInternalApps.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": False}, "/Ops"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": True}, "/DevOps"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/DevOps" in result.details

    def test_fallback_to_api_controls(self, full_audit_data):
        """When security has no matching _ou_policies, fall back to api_controls."""
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["api_controls"] = {
            "_ou_policies": [
                make_ou_policy("api_controls", "internal_apps",
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("api_controls", "internal_apps",
                                {"trustInternalApps": True}, "/Sandbox"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details


class TestUnconfiguredThirdPartyAppsOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.4 unconfigured third-party apps."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/Security"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": True}, "/Testing"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Testing" in result.details

    def test_fallback_to_api_controls(self, full_audit_data):
        """When security has no matching _ou_policies, fall back to api_controls."""
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["api_controls"] = {
            "_ou_policies": [
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": True}, "/External"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/External" in result.details


class TestDataProcessingInRegionOU:
    """GWS.COMMONCONTROLS.15.2 on the real data_regions.data_processing_region.limitToStorageRegion."""

    def _set(self, data, *flags):
        data["subscription_type"] = "Google Workspace Enterprise Plus"
        data["policies"]["security"] = {}
        data["policies"]["data_regions"] = {"_ou_policies": [
            make_ou_policy("data_regions", "data_processing_region", {"limitToStorageRegion": v}, ou)
            for ou, v in flags]}

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", True), ("/Finance", True))
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", True), ("/Remote", False))
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Remote" in result.details

    def test_live_system_default_fails(self, full_audit_data):
        """The live SYSTEM policy says limitToStorageRegion=false: the value in force fails."""
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", False))
        for e in full_audit_data["policies"]["data_regions"]["_ou_policies"]:
            e["_raw"] = {"type": "SYSTEM"}
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL and "Google default" in result.details

class TestUnusedServicesDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.1 unused services.

    Rewritten with the real setting enterprise_service_restrictions.service_status.serviceState
    (ENABLED = services without an individual control are restricted).
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {
            "_ou_policies": [
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/"),
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/IT"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {
            "_ou_policies": [
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/"),
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "DISABLED"}, "/Sandbox"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details

    def test_unspecified_state_is_unknown(self, full_audit_data):
        """Was FAIL: SERVICE_STATE_UNSPECIFIED carries no state."""
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {"_ou_policies": [
            make_ou_policy("enterprise_service_restrictions", "service_status",
                           {"serviceState": "SERVICE_STATE_UNSPECIFIED"})]}
        assert check_unused_services_disabled(full_audit_data).status == Status.MANUAL


class TestEarlyAccessDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.2 early access apps.

    Rewritten with the real setting early_access_apps.service_status.serviceState.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {
            "_ou_policies": [
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/"),
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/Security"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {
            "_ou_policies": [
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/"),
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "ENABLED"}, "/Beta"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Beta" in result.details

    def test_unspecified_state_is_unknown(self, full_audit_data):
        """Was FAIL: SERVICE_STATE_UNSPECIFIED carries no state."""
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {"_ou_policies": [
            make_ou_policy("early_access_apps", "service_status",
                           {"serviceState": "SERVICE_STATE_UNSPECIFIED"})]}
        assert check_early_access_disabled(full_audit_data).status == Status.MANUAL


class TestUnknownValuesAreManual:
    """Plan Decision A: an absent field without a documented default, or an *_UNSPECIFIED enum,
    is unknown. No OU may PASS or FAIL because of it; a real non-compliant OU still wins."""

    @pytest.mark.parametrize("setting_key, check_name", [
        ("internal_apps", "check_unconfigured_internal_apps"),
        ("data_processing_region", "check_data_processing_in_region"),
    ])
    def test_empty_value_is_manual(self, full_audit_data, setting_key, check_name):
        """Was FAIL for every one of these: an empty ADMIN value has no documented default."""
        from gws_auditor.checks import cisa_commoncontrols

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", setting_key, {})]}
        result = getattr(cisa_commoncontrols, check_name)(full_audit_data)
        assert result.status == Status.MANUAL, check_name
        assert "could not be determined" in result.details

    def test_account_recovery_uses_documented_default(self, full_audit_data):
        """enableAccountRecovery has a documented default (false), so an empty value is judged."""
        from gws_auditor.checks.cisa_commoncontrols import check_user_account_recovery_disabled

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "user_account_recovery", {})]}
        assert check_user_account_recovery_disabled(full_audit_data).status == Status.PASS


class TestAdvancedProtection:
    """GWS.COMMONCONTROLS.9.1 / 9.2: three-state verdict from the Policy API self-enrollment flag,
    titanium_enroll / titanium_unenroll events in the user_accounts audit log and the security-key
    and passkey counts of the user usage report."""

    def _allow(self, data, allowed=True, ou="/"):
        data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program",
                           {"enableAdvancedProtectionSelfEnrollment": allowed}, ou)]}

    def test_self_enrollment_disabled_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_admin_advanced_protection, check_sensitive_user_advanced_protection)
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program", {"enableAdvancedProtectionSelfEnrollment": True}, "/"),
            make_ou_policy("security", "advanced_protection_program", {"enableAdvancedProtectionSelfEnrollment": False}, "/Remote")]}
        full_audit_data["_options"] = {"sensitive_users": ["user1@example.com"]}
        for check in (check_admin_advanced_protection, check_sensitive_user_advanced_protection):
            result = check(full_audit_data)
            assert result.status == Status.FAIL, check.__name__
            assert "/Remote" in result.details

    def test_all_admins_enrolled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [
            make_user_account_event("admin1@example.com", "titanium_enroll", "2026-09-01T10:00:00.000Z"),
            make_user_account_event("admin2@example.com", "titanium_enroll", "2026-09-02T10:00:00.000Z")]
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com", num_security_keys=2),
                                         make_user_usage_row("admin2@example.com", num_passkeys_enrolled=2, num_security_keys=0)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["enrolled"] == ["admin1@example.com", "admin2@example.com"]

    def test_unenroll_is_latest_event_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [
            make_user_account_event("admin1@example.com", "titanium_enroll", "2026-09-01T10:00:00.000Z"),
            make_user_account_event("admin1@example.com", "titanium_unenroll", "2026-10-01T10:00:00.000Z"),
            make_user_account_event("admin2@example.com", "titanium_enroll", "2026-09-02T10:00:00.000Z")]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "admin1@example.com [left Advanced Protection on 2026-10-01]" in result.details

    def test_admin_without_key_or_passkey_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com", num_security_keys=0, num_passkeys_enrolled=0),
                                         make_user_usage_row("admin2@example.com", num_security_keys=1)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "admin1@example.com [no security key or passkey" in result.details
        assert "admin2" not in result.details

    def test_no_evidence_is_review(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.MANUAL
        assert "no enrollment event" in result.details and "user_accounts audit log was not collected" in result.details
        assert set(result.actual_value["unknown"]) == {"admin1@example.com", "admin2@example.com"}

    def test_partial_evidence_is_review_not_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [make_user_account_event("admin1@example.com", "titanium_enroll")]
        full_audit_data["user_usage"] = [make_user_usage_row("admin2@example.com", num_security_keys=1)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.MANUAL
        assert "1 of 2 administrator" in result.details and "admin2@example.com" in result.details

    def test_empty_policy_value_still_assesses_accounts(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program", {})]}
        full_audit_data["user_account_logs"] = [make_user_account_event(e, "titanium_enroll")
                                                for e in ("admin1@example.com", "admin2@example.com")]
        assert check_admin_advanced_protection(full_audit_data).status == Status.PASS

    def test_no_admins_collected_is_error(self, full_audit_data):
        """No users means the directory was not collected: ERROR (make_manual), never a verdict."""
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        full_audit_data["users"] = []
        assert check_admin_advanced_protection(full_audit_data).status == Status.ERROR

    def test_sensitive_users_unconfigured_not_applicable(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection
        self._allow(full_audit_data)
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE
        assert "options.sensitive_users" in result.details

    def test_sensitive_users_from_emails_and_group(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["_options"] = {"sensitive_users": ["User1@example.com", "execs@example.com"]}
        full_audit_data["group_members"] = {"execs@example.com": [{"email": "ceo@example.com"}, {"email": "cfo@example.com"}]}
        full_audit_data["user_account_logs"] = [make_user_account_event(e, "titanium_enroll")
                                                for e in ("user1@example.com", "ceo@example.com", "cfo@example.com")]
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["enrolled"] == ["ceo@example.com", "cfo@example.com", "user1@example.com"]
        full_audit_data["user_usage"] = [make_user_usage_row("cfo@example.com", num_security_keys=0, num_passkeys_enrolled=0)]
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL and "cfo@example.com" in result.details
