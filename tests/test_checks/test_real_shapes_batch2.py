"""Regression tests for checks corrected against real Policy API / admin-log shapes (batch 2).

Setting types, field names and enums follow tests/fixtures/policy_api_shapes.json; admin-log
setting names follow the ones CISA ScubaGoggles uses.
"""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


def _set(data, category, setting_key, value, org_unit="/"):
    data["policies"][category] = {"_ou_policies": [make_ou_policy(category, setting_key, value, org_unit)]}


def _setting_change(name, new_value, ou="/", time="2026-04-01T00:00:00Z"):
    return {"event_name": "CHANGE_APPLICATION_SETTING", "time": time,
            "parameters": {"SETTING_NAME": name, "NEW_VALUE": new_value, "ORG_UNIT_NAME": ou}}


def _alert(name, state):
    return make_ou_policy("rule", "system_defined_alerts", {"displayName": name, "state": state})


class TestAlertRules:
    def test_inactive_policy_state_beats_default_and_logs(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        full_audit_data["admin_logs"] = []
        full_audit_data["policies"]["rules"] = {"_ou_policies": [_alert("User granted Admin privilege", "INACTIVE")]}
        assert check_alert_admin_privilege(full_audit_data).status == Status.FAIL

    def test_active_policy_state_passes(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["admin_logs"] = []
        full_audit_data["policies"]["rules"] = {"_ou_policies": [_alert("User's password changed", "ACTIVE")]}
        assert check_alert_password_change(full_audit_data).status == Status.PASS

    def test_13_1_fails_only_on_required_rules(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_system_defined_alerts_enabled

        # "User's password changed" is optional in SCuBA; "Leaked password" is required
        full_audit_data["policies"]["rules"] = {"_ou_policies": [
            _alert("Leaked password", "ACTIVE"), _alert("User's password changed", "INACTIVE")]}
        assert check_system_defined_alerts_enabled(full_audit_data).status != Status.FAIL
        full_audit_data["policies"]["rules"] = {"_ou_policies": [
            _alert("Leaked password", "INACTIVE"), _alert("User's password changed", "ACTIVE")]}
        result = check_system_defined_alerts_enabled(full_audit_data)
        assert result.status == Status.FAIL and "Leaked password" in result.details

    def test_13_1_pass_needs_every_required_rule(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            SCUBA_REQUIRED_ALERT_RULES, check_system_defined_alerts_enabled)

        full_audit_data["policies"]["rules"] = {"_ou_policies": [_alert("Leaked password", "ACTIVE")]}
        assert check_system_defined_alerts_enabled(full_audit_data).status == Status.MANUAL  # rest not returned
        full_audit_data["policies"]["rules"] = {"_ou_policies": [
            _alert(name, "ACTIVE") for name in SCUBA_REQUIRED_ALERT_RULES] + [_alert("Apps outage alert", "INACTIVE")]}
        result = check_system_defined_alerts_enabled(full_audit_data)
        assert result.status == Status.PASS and "Apps outage alert" in result.details


class TestAccountRecoveryFrameworkConflict:
    @pytest.mark.parametrize("enabled, scuba, cis", [(True, Status.FAIL, Status.PASS), (False, Status.PASS, Status.FAIL)])
    def test_scuba_8_2_and_cis_4_1_2_2_disagree_by_design(self, full_audit_data, enabled, scuba, cis):
        from gws_auditor.checks.cisa_commoncontrols import check_user_account_recovery_disabled
        from gws_auditor.checks.security_auth import check_user_account_recovery

        _set(full_audit_data, "security", "user_account_recovery", {"enableAccountRecovery": enabled})
        assert check_user_account_recovery_disabled(full_audit_data).status == scuba
        assert check_user_account_recovery(full_audit_data).status == cis


class TestDriveModeAware:
    _ALLOWLIST = {"externalSharingMode": "ALLOWLISTED_DOMAINS", "warnForExternalSharing": False,
                  "warnForSharingOutsideAllowlistedDomains": True, "allowNonGoogleInvites": True,
                  "allowNonGoogleInvitesInAllowlistedDomains": False}

    def test_allowlist_mode_uses_allowlist_fields(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing
        from gws_auditor.checks.cisa_services import check_drive_external_sharing_warning

        _set(full_audit_data, "drive", "external_sharing", dict(self._ALLOWLIST))
        assert check_drive_external_sharing_warning(full_audit_data).status == Status.PASS
        assert check_drive_non_google_sharing(full_audit_data).status == Status.PASS

    def test_allowlist_mode_fails_on_allowlist_fields(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing

        _set(full_audit_data, "drive", "external_sharing",
             {**self._ALLOWLIST, "allowNonGoogleInvites": False, "allowNonGoogleInvitesInAllowlistedDomains": True})
        assert check_drive_non_google_sharing(full_audit_data).status == Status.FAIL

    def test_security_update_users_can_remove_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_security_updates

        _set(full_audit_data, "drive", "file_security_update",
             {"securityUpdate": "APPLY_TO_IMPACTED_FILES", "allowUsersToManageUpdate": True})
        assert check_drive_security_updates(full_audit_data).status == Status.FAIL
        _set(full_audit_data, "drive", "file_security_update",
             {"securityUpdate": "APPLY_TO_IMPACTED_FILES", "allowUsersToManageUpdate": False})
        assert check_drive_security_updates(full_audit_data).status == Status.PASS

    def test_add_ons_ignore_drive_sdk_and_use_admin_logs(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled

        _set(full_audit_data, "drive", "drive_sdk", {"enableDriveSdkApiAccess": True})
        full_audit_data["admin_logs"] = []
        assert check_drive_add_ons_disabled(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"] = [_setting_change("ENABLE_DOCS_ADD_ONS", "true", time="2026-01-01T00:00:00Z"),
                                         _setting_change("ENABLE_DOCS_ADD_ONS", "false", time="2026-02-01T00:00:00Z")]
        assert check_drive_add_ons_disabled(full_audit_data).status == Status.PASS
        full_audit_data["admin_logs"].append(_setting_change("ENABLE_DOCS_ADD_ONS", "true", time="2026-03-01T00:00:00Z"))
        assert check_drive_add_ons_disabled(full_audit_data).status == Status.FAIL


class TestAdminLogInference:
    def test_gemini_alpha(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gemini_alpha_features

        full_audit_data["policies"].pop("gemini", None)
        # Live name and values (flip test 2026-11-06, APPLICATION_NAME "Gemini in Workspace").
        live = "Beta Gemini Features Beta Features enabled"
        full_audit_data["admin_logs"] = [_setting_change(live, "true")]
        assert check_gemini_alpha_features(full_audit_data).status == Status.FAIL
        full_audit_data["admin_logs"] = [_setting_change(live, "false")]
        assert check_gemini_alpha_features(full_audit_data).status == Status.PASS
        # ScubaGoggles' name is still honoured as a fallback.
        full_audit_data["admin_logs"] = [_setting_change("GenAiAlphaSettingsProto alpha_enabled", "true")]
        assert check_gemini_alpha_features(full_audit_data).status == Status.FAIL

    def test_gemini_beta_live_sequence(self, full_audit_data):
        """Exact 2026-11-06 flip: the first save is CREATE_APPLICATION_SETTING (no OLD_VALUE), the
        revert CHANGE_APPLICATION_SETTING; a sibling UXR setting with the same prefix must not match."""
        from gws_auditor.checks.cisa_scuba import check_gemini_alpha_features

        full_audit_data["policies"].pop("gemini", None)
        create_on = {"event_name": "CREATE_APPLICATION_SETTING", "time": "2026-11-06T17:40:57.787Z",
                     "parameters": {"APPLICATION_NAME": "Gemini in Workspace", "ORG_UNIT_NAME": "argussec.io",
                                    "SETTING_NAME": "Beta Gemini Features Beta Features enabled",
                                    "NEW_VALUE": "true", "APPLICATION_EDITION": "duet_main_enterprise_standard_2024"}}
        uxr = {"event_name": "CREATE_APPLICATION_SETTING", "time": "2026-11-06T17:40:57.787Z",
               "parameters": {"APPLICATION_NAME": "Gemini in Workspace", "ORG_UNIT_NAME": "argussec.io",
                              "SETTING_NAME": "Beta Gemini Features Beta UXR outreach enabled",
                              "NEW_VALUE": "false", "APPLICATION_EDITION": "duet_main_enterprise_standard_2024"}}
        change_off = {"event_name": "CHANGE_APPLICATION_SETTING", "time": "2026-11-06T17:41:13.591Z",
                      "parameters": {"APPLICATION_NAME": "Gemini in Workspace", "ORG_UNIT_NAME": "argussec.io",
                                     "SETTING_NAME": "Beta Gemini Features Beta Features enabled",
                                     "OLD_VALUE": "true", "NEW_VALUE": "false",
                                     "APPLICATION_EDITION": "duet_main_enterprise_standard_2024"}}
        full_audit_data["admin_logs"] = []
        assert check_gemini_alpha_features(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"] = [create_on, uxr]
        result = check_gemini_alpha_features(full_audit_data)
        assert result.status == Status.FAIL
        assert "argussec.io" in result.details
        full_audit_data["admin_logs"] = [create_on, uxr, change_off]
        assert check_gemini_alpha_features(full_audit_data).status == Status.PASS
        full_audit_data["admin_logs"] = [uxr]  # only the sibling setting: unknown -> MANUAL
        assert check_gemini_alpha_features(full_audit_data).status == Status.MANUAL

    def test_context_aware_access_allowed_evaluations_prove_enforcement(self, full_audit_data):
        """Exact live events 2026-11-06: ACCESS_LEVELS_EVALUATED with Geo restriction applied and satisfied."""
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access
        from tests.test_checks.test_additional import _caa_event

        full_audit_data["admin_logs"] = []
        full_audit_data["caa_events"] = [
            {"event_name": "ACCESS_LEVELS_EVALUATED", "event_type": "CONTEXT_AWARE_ACCESS_USER_EVENT",
             "time": "2026-11-06T18:33:34.387Z", "actor_email": "admin@example.com", "ip_address": "203.0.113.5",
             "parameters": {"CAA_ACCESS_LEVEL_APPLIED": ["Geo restriction"], "CAA_ACCESS_LEVEL_SATISFIED": ["Geo restriction"],
                            "CAA_APPLICATION": "GMAIL", "CAA_DEVICE_ID": "UNKNOWN",
                            "CAA_DEVICE_STATE": "No Device Signals", "PROTECTED_API_ACCESS": ["GMAIL"]}}]
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS
        assert "1 active-mode evaluation(s) (0 denied)" in result.details
        assert "GMAIL" in result.details and "Geo restriction" in result.details
        # Monitor-mode names and evaluations without an applied level are not enforcement.
        full_audit_data["caa_events"] = [_caa_event("MONITOR_MODE_ACCESS_EVALUATED_EVENT", "GMAIL"),
                                         _caa_event("ACCESS_LEVELS_EVALUATED", "DRIVE", applied=())]
        assert check_context_aware_access(full_audit_data).status == Status.MANUAL
        # An evaluation newer than a DISABLED toggle beats the toggle; an older one does not.
        full_audit_data["admin_logs"] = [{"event_name": "TOGGLE_CAA_ENABLEMENT", "time": "2026-11-01T00:00:00Z",
                                          "parameters": {"NEW_VALUE": "DISABLED"}}]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL", time="2026-11-06T18:33:34.387Z")]
        assert check_context_aware_access(full_audit_data).status == Status.PASS
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL", time="2026-10-01T00:00:00Z")]
        assert check_context_aware_access(full_audit_data).status == Status.FAIL

    def test_context_aware_access_with_access_context_manager_inventory(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access
        from tests.test_checks.test_security_access import TestGeoBlocking as G

        on = [{"event_name": "TOGGLE_CAA_ENABLEMENT", "time": "2026-04-01T00:00:00Z", "parameters": {"NEW_VALUE": "ENABLED"}}]
        full_audit_data["caa_events"] = []
        # ON but the organisation has no access level at all -> FAIL (authoritative inventory)
        full_audit_data["admin_logs"] = on
        full_audit_data["access_context"] = G._acm()
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "no access level" in result.details and "switched on" in result.details
        # No toggle event either: still FAIL, nothing can be assigned
        full_audit_data["admin_logs"] = []
        assert check_context_aware_access(full_audit_data).status == Status.FAIL
        # ON, levels exist, no assignment in the window -> MANUAL naming the levels
        full_audit_data["admin_logs"] = on
        full_audit_data["access_context"] = G._acm(G._GEO, G._DEVICE)
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Geo restriction" in result.details and "Access Context Manager" in result.details
        assert result.actual_value["access_levels"] == ["Corp devices", "Geo restriction"]
        # Active assignment in the window -> PASS as before
        full_audit_data["admin_logs"] = on + [{"event_name": "CHANGE_CAA_APP_ASSIGNMENTS", "time": "2026-05-01T00:00:00Z",
                                               "parameters": {"APPLICATION_NAME": "GMAIL", "MODE": "BLOCK",
                                                              "CAA_ACCESS_ASSIGNMENTS_NEW": ["Geo restriction"]}}]
        assert check_context_aware_access(full_audit_data).status == Status.PASS

    def test_context_aware_access_event(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        def toggle(v):
            return [{"event_name": "TOGGLE_CAA_ENABLEMENT", "time": "2026-04-01T00:00:00Z", "parameters": {"NEW_VALUE": v}}]
        full_audit_data["admin_logs"] = toggle("ENABLED")
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.MANUAL  # ON with no access level assigned is not "implemented" (seen live)
        assert "no access-level assignment" in result.details
        # Real CHANGE_CAA_APP_ASSIGNMENTS shape (flip test 2026-11-06): per app and mode, list-valued.
        full_audit_data["admin_logs"] = toggle("ENABLED") + [{"event_name": "CHANGE_CAA_APP_ASSIGNMENTS", "time": "2026-04-02T00:00:00Z",
            "parameters": {"APPLICATION_NAME": "GMAIL", "CAA_ACCESS_ASSIGNMENTS_NEW": ["Corp devices"], "MODE": "BLOCK",
                           "TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "example.com"}}]
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS and "GMAIL" in result.details
        full_audit_data["admin_logs"][-1]["parameters"]["MODE"] = "MONITOR"
        assert check_context_aware_access(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"][-1]["parameters"]["MODE"] = "BLOCK"
        full_audit_data["admin_logs"].append({"event_name": "CHANGE_CAA_APP_ASSIGNMENTS", "time": "2026-04-03T00:00:00Z",
            "parameters": {"APPLICATION_NAME": "GMAIL", "CAA_ACCESS_ASSIGNMENTS_OLD": ["Corp devices"], "MODE": "BLOCK",
                           "TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "example.com"}})
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.MANUAL and "removed" in result.details
        full_audit_data["admin_logs"] = toggle("DISABLED")
        assert check_context_aware_access(full_audit_data).status == Status.FAIL

    def test_dwd_scopes_classified_and_revocation_honoured(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation

        def ev(name, client, scopes, time):
            return {"event_name": name, "time": time, "parameters": {"API_CLIENT_NAME": client, "API_SCOPES": scopes}}
        base = "https://www.googleapis.com/auth/"
        full_audit_data["policies"].setdefault("security", {}).pop("api_access", None)
        full_audit_data["admin_logs"] = [ev("AUTHORIZE_API_CLIENT_ACCESS", "111", base + "admin.directory.user.readonly", "2026-01-01")]
        assert check_domain_wide_delegation(full_audit_data).status == Status.MANUAL  # read-only scope: nothing to flag, inventory unproven
        full_audit_data["admin_logs"].append(ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{base}gmail.modify,{base}drive", "2026-01-02"))
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.WARN and "222" in result.details and "111:" not in result.details
        full_audit_data["admin_logs"].append(ev("REMOVE_API_CLIENT_ACCESS", "222", "", "2026-01-03"))
        assert check_domain_wide_delegation(full_audit_data).status == Status.MANUAL  # the risky grant was revoked


class TestNoGuessing:
    def test_advanced_protection_enrollment_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection

        _set(full_audit_data, "security", "advanced_protection_program",
             {"enableAdvancedProtectionSelfEnrollment": True, "securityCodeOption": "ALLOWED_WITHOUT_REMOTE_ACCESS"})
        assert check_admin_advanced_protection(full_audit_data).status == Status.MANUAL
        _set(full_audit_data, "security", "advanced_protection_program", {"enableAdvancedProtectionSelfEnrollment": False})
        assert check_admin_advanced_protection(full_audit_data).status == Status.FAIL

    def test_inbound_gateway_unknown_spf_is_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf

        full_audit_data["policies"]["gmail"] = {"inbound_gateway": {"configured": True}}
        assert check_inbound_gateway_spf(full_audit_data).status == Status.MANUAL

    def test_shared_drives_enumeration_error_is_not_a_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions

        full_audit_data["shared_drives"] = []
        full_audit_data["api_errors"] = [{"operation": "get_shared_drives", "error": "403", "type": "HttpError"}]
        assert check_shared_drive_restrictions(full_audit_data).status == Status.ERROR


class TestMisc:
    def test_external_groups_uses_collaboration_capability(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        _set(full_audit_data, "groups", "groups_sharing", {"collaborationCapability": "ANYONE_CAN_ACCESS"})
        assert check_external_groups_disabled(full_audit_data).status == Status.FAIL
        _set(full_audit_data, "groups", "groups_sharing", {"collaborationCapability": "DOMAIN_USERS_ONLY"})
        assert check_external_groups_disabled(full_audit_data).status == Status.PASS

    def test_spf_plus_all_fails_and_neutral_warns(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_spf

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        def spf(record):
            full_audit_data["dns_records"] = {"example.com": {"spf": {"record_found": True, "record": record}}}
            return check_gmail_spf(full_audit_data).status
        assert spf("v=spf1 include:_spf.google.com +all") == Status.FAIL
        assert spf("v=spf1 include:_spf.google.com ?all") == Status.WARN
        assert spf("v=spf1 include:_spf.google.com ~all") == Status.PASS

    def test_suspended_users_are_not_a_2sv_gap(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users

        _set(full_audit_data, "security", "two_step_verification_enforcement", {"enforcedFrom": "2026-01-01T00:00:00Z"})
        full_audit_data["users"] = [
            {"primary_email": "a@example.com", "is_enrolled_in_2sv": True, "suspended": False},
            {"primary_email": "gone@example.com", "is_enrolled_in_2sv": False, "suspended": True},
        ]
        result = check_2sv_all_users(full_audit_data)
        assert "gone@example.com" not in str(result.details) + str(result.actual_value)

    def test_takeout_per_service_status(self, full_audit_data):
        from gws_auditor.checks.additional import check_takeout_restriction

        full_audit_data["policies"]["takeout"] = {"_ou_policies": [
            make_ou_policy("maps", "user_takeout", {"takeoutStatus": "DISABLED"}),
            make_ou_policy("youtube", "user_takeout", {"takeoutStatus": "ENABLED"})]}
        result = check_takeout_restriction(full_audit_data)
        assert result.status == Status.FAIL and "youtube" in result.details and "maps" not in result.details
        full_audit_data["policies"]["takeout"] = {"_ou_policies": [
            make_ou_policy("maps", "user_takeout", {"takeoutStatus": "DISABLED"})]}
        assert check_takeout_restriction(full_audit_data).status == Status.PASS

    def test_dlp_rules_mapped_per_app(self):
        from gws_auditor.provider import _map_rules

        policies = {"rules": {"_ou_policies": [
            make_ou_policy("rule", "dlp", {"displayName": "PII", "state": "ACTIVE", "action": {"driveAction": {}}}),
            make_ou_policy("rule", "dlp", {"displayName": "Off", "state": "INACTIVE", "action": {"gmailAction": {}}})]}}
        _map_rules(policies)
        dlp = policies["security"]["dlp"]
        assert dlp["drive_dlp_enabled"] is True and dlp["drive_rule_count"] == 1
        assert dlp["gmail_dlp_enabled"] is False and dlp["chat_dlp_enabled"] is False


class TestAdminRolesOnGroups:
    def _data(self, data, who_can_join):
        data["api_errors"] = []
        data["groups"] = [{"id": "g1", "email": "helpdesk@example.com", "settings": {"whoCanJoin": who_can_join}}]
        data["roles"] = {"roles": [{"roleId": "r1", "roleName": "_USER_MANAGEMENT_ADMIN_ROLE"}],
                         "assignments": [{"roleId": "r1", "assignedTo": "g1", "assigneeType": "group"}]}
        return data

    def test_open_group_with_admin_role_fails(self, full_audit_data):
        from gws_auditor.checks.additional import check_admin_roles_assigned_to_groups

        result = check_admin_roles_assigned_to_groups(self._data(full_audit_data, "ALL_IN_DOMAIN_CAN_JOIN"))
        assert result.status == Status.FAIL and "helpdesk@example.com" in result.details

    def test_restricted_group_warns_and_no_group_passes(self, full_audit_data):
        from gws_auditor.checks.additional import check_admin_roles_assigned_to_groups

        data = self._data(full_audit_data, "INVITED_CAN_JOIN")
        assert check_admin_roles_assigned_to_groups(data).status == Status.WARN
        data["roles"]["assignments"][0]["assigneeType"] = "user"
        assert check_admin_roles_assigned_to_groups(data).status == Status.PASS

    def test_not_collected_is_not_a_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_admin_roles_assigned_to_groups

        full_audit_data.pop("roles", None)
        assert check_admin_roles_assigned_to_groups(full_audit_data).status == Status.ERROR
