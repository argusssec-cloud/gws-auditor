"""Regressions found by running against a live Enterprise Standard tenant (2026-09-20).

Shapes below are the ones the Cloud Identity Policy API returned (field names and enums only).
"""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


def _set(data, category, setting_key, value):
    data["policies"][category] = {"_ou_policies": [make_ou_policy(category, setting_key, value)]}


class TestDataRegions:
    @pytest.mark.parametrize("region, status", [("ANY_REGION", Status.FAIL), ("US", Status.PASS), ("EUROPE", Status.PASS)])
    def test_any_region_is_not_a_pinned_region(self, full_audit_data, region, status):
        from gws_auditor.checks.cisa_scuba import check_data_regions

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("data_regions", "data_at_rest_region", {"region": region})]}
        assert check_data_regions(full_audit_data).status == status

    def test_mapper(self):
        from gws_auditor.provider import _is_specific_data_region

        assert not _is_specific_data_region("ANY_REGION")
        assert _is_specific_data_region("EUROPE")


class TestMeetAutomaticRecording:
    def test_recording_allowed_is_not_automatic_recording(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording, check_meet_auto_transcription

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "video_recording", {"enableRecording": True}),
            make_ou_policy("meet", "automatic_recording", {"enabled": False}),
            make_ou_policy("meet", "automatic_transcription", {"enabled": False})]}
        assert check_meet_auto_recording(full_audit_data).status == Status.PASS
        assert check_meet_auto_transcription(full_audit_data).status == Status.PASS

    def test_automatic_recording_on_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording, check_meet_auto_transcription

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "automatic_recording", {"enabled": True}),
            make_ou_policy("meet", "automatic_transcription", {"enabled": True})]}
        assert check_meet_auto_recording(full_audit_data).status == Status.FAIL
        assert check_meet_auto_transcription(full_audit_data).status == Status.FAIL

    def test_mapper_does_not_turn_allowed_into_automatic(self):
        from gws_auditor.provider import _map_meet

        policies = {"meet": {"video_recording": {"enableRecording": True}}}
        _map_meet(policies)
        assert "auto_recording_enabled" not in policies["meet"].get("recording", {})
        policies = {"meet": {"video_recording": {"enableRecording": True}, "automatic_recording": {"enabled": False}}}
        _map_meet(policies)
        assert policies["meet"]["recording"]["auto_recording_enabled"] is False


class TestMultiPartyApproval:
    @pytest.mark.parametrize("state, status", [("ENABLED", Status.PASS), ("DISABLED", Status.FAIL)])
    def test_real_state_field(self, full_audit_data, state, status):
        from gws_auditor.checks.cisa_scuba import check_multi_party_approval

        full_audit_data["admin_logs"] = []
        _set(full_audit_data, "multi_party_approval", "require_approvals", {"multiPartyApprovalState": state})
        assert check_multi_party_approval(full_audit_data).status == status

    def test_mapper(self):
        from gws_auditor.provider import _map_multi_party_approval

        policies = {"multi_party_approval": {"require_approvals": {"multiPartyApprovalState": "ENABLED"}}}
        _map_multi_party_approval(policies)
        assert policies["security"]["multi_party_approval"]["enabled"] is True


class TestUnspecifiedAccessLevelIsUnknown:
    def _unspecified(self, data):
        data["admin_logs"] = []
        data["policies"]["security"] = {}
        data["policies"]["access_control"] = {}
        _set(data, "api_controls", "unconfigured_third_party_apps",
             {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED", "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"})

    def test_not_a_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_third_party_api_restricted, check_unconfigured_third_party_apps)
        from gws_auditor.checks.security_access import check_third_party_app_access, check_third_party_app_review

        self._unspecified(full_audit_data)
        full_audit_data["token_logs"] = [{"app_name": "Some App", "client_id": "1"}]
        for check in (check_third_party_api_restricted, check_unconfigured_third_party_apps,
                      check_third_party_app_access, check_third_party_app_review):
            assert check(full_audit_data).status in (Status.MANUAL, Status.ERROR), check.__name__

    def test_a_reported_level_is_still_judged(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        self._unspecified(full_audit_data)
        _set(full_audit_data, "api_controls", "unconfigured_third_party_apps", {"accessLevel": "ALLOW_ALL"})
        assert check_unconfigured_third_party_apps(full_audit_data).status == Status.FAIL


class TestDlpActionKinds:
    def _rule(self, **actions):
        return make_ou_policy("rule", "dlp", {"displayName": "r", "state": "ACTIVE", "action": actions})

    def test_warn_only_rules_are_not_blocking(self):
        from gws_auditor.provider import _map_rules

        policies = {"rules": {"_ou_policies": [self._rule(driveAction={"warnUser": {}}, gmailAction={"warnUser": {}})]}}
        _map_rules(policies)
        dlp = policies["security"]["dlp"]
        assert dlp["default_action"] == "warn" and dlp["gmail_dlp_enabled"] is True and dlp["chat_dlp_enabled"] is False

    def test_blocking_rule(self):
        from gws_auditor.provider import _map_rules

        policies = {"rules": {"_ou_policies": [self._rule(driveAction={"blockAccess": {}})]}}
        _map_rules(policies)
        assert policies["security"]["dlp"]["default_action"] == "block"

    def test_unrecognised_action_kind_is_left_undetermined(self):
        from gws_auditor.provider import _map_rules

        policies = {"rules": {"_ou_policies": [self._rule(driveAction={"somethingNew": {}})]}}
        _map_rules(policies)
        assert "default_action" not in policies["security"]["dlp"]


def test_context_aware_access_unknown_is_manual_not_error(full_audit_data):
    from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

    full_audit_data["admin_logs"] = []
    full_audit_data["policies"]["security"] = {}
    assert check_context_aware_access(full_audit_data).status == Status.MANUAL


def test_context_aware_access_ignores_employee_id_challenge_alias(full_audit_data):
    """The provider adds an "enabled" alias to login_challenges; it must not be read as CAA state."""
    from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

    full_audit_data["admin_logs"] = []
    full_audit_data["policies"]["security"] = {"_ou_policies": [
        make_ou_policy("security", "login_challenges", {"enableEmployeeIdChallenge": False, "enabled": False})]}
    assert check_context_aware_access(full_audit_data).status == Status.MANUAL


def test_admin_policy_wins_over_system_default_in_root_merge():
    """A SYSTEM default listed after the ADMIN policy must not replace the admin's value."""
    from gws_auditor.provider import _normalize_policies

    def policy(kind, trust):
        return {"category": "api_controls", "name": f"policies/{kind}", "orgUnit": "/",
                "setting": {"type": "settings/api_controls.internal_apps", "value": {"trustInternalApps": trust}},
                "_raw": {"type": kind, "policyQuery": {"orgUnit": "orgUnits/root"}}}

    merged = _normalize_policies({"api_controls": [policy("SYSTEM", True), policy("ADMIN", False), policy("SYSTEM", True)]}, [])
    assert merged["api_controls"]["internal_apps"]["trustInternalApps"] is False
