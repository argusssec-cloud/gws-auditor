"""Plan phase P4: round trips from raw Policy API resources (as PolicyClient returns them)
through normalize_data() into the checks, using the real-shape samples in
tests/fixtures/policy_api_samples.json.

What this layer catches that unit tests cannot: dead provider-mapped keys, OU-id resolution,
ADMIN-over-SYSTEM precedence, rule.dlp / rule.system_defined_alerts handling, admin-log
inference from nested events, and any check that raises on a real payload.
"""

import copy
import json
from pathlib import Path

import pytest

from gws_auditor.models import Status

SAMPLES = json.loads((Path(__file__).parent.parent / "fixtures" / "policy_api_samples.json").read_text())["settings"]
VERDICTS = {Status.PASS, Status.FAIL, Status.WARN, Status.PARTIAL}


def _category_of(setting_type: str) -> str | None:
    from gws_auditor.api.policy import POLICY_CATEGORIES
    if setting_type.endswith(".user_takeout") or setting_type.startswith("takeout."):
        return "takeout"
    return {v: k for k, v in POLICY_CATEGORIES.items()}.get(setting_type.split(".", 1)[0])


def raw_policy(setting_type, value, kind="ADMIN", org_unit="/", sort_order=None):
    """One policy in the shape PolicyClient._normalise_policies returns."""
    if sort_order is None:
        sort_order = 201.0 if kind == "ADMIN" else 101.0
    setting = {"type": f"settings/{setting_type}", "value": copy.deepcopy(value)}
    return {"category": _category_of(setting_type) or "x", "name": f"policies/sample/{setting_type}",
            "setting": setting, "orgUnit": org_unit,
            "_raw": {"type": kind, "policyQuery": {"orgUnit": org_unit, "sortOrder": sort_order}, "setting": setting}}


def raw_tenant(policies_by_category=None, **overrides):
    base = {"users": [], "domains": [{"domainName": "example.com", "isPrimary": True}],
            "org_units": [{"orgUnitPath": "/", "orgUnitId": "id:root"}], "groups": [], "group_members": {},
            "policies": policies_by_category or {}, "chrome_policies": {}, "admin_logs": [], "login_logs": [],
            "token_logs": [], "caa_events": [], "usage_reports": {}, "dns_records": {}, "alert_center_rules": [],
            "calendar_acls": {}, "chat_spaces": [], "mobile_devices": [], "chromeos_devices": [],
            "endpoint_devices": [], "app_passwords": [], "user_tokens": [], "shared_drives": [],
            "subscription_info": {}, "subscription_type": "Google Workspace Enterprise Plus", "_options": {},
            "api_errors": [], "roles": {}}
    base.update(overrides)
    return base


def sample_tenant(kind):
    policies = {}
    for setting_type, kinds in SAMPLES.items():
        cat = _category_of(setting_type)
        if kind in kinds and cat:
            policies.setdefault(cat, []).append(raw_policy(setting_type, kinds[kind], kind))
    return raw_tenant(policies)


def normalized(raw):
    from gws_auditor.provider import normalize_data
    return normalize_data(copy.deepcopy(raw))


def run_all(data):
    from gws_auditor.checks.registry import CheckRegistry
    return {m.check_id: m.func(copy.deepcopy(data)) for m in CheckRegistry().get_all_checks()}


class TestRealShapesNeverRaise:
    @pytest.mark.parametrize("kind", ["ADMIN", "SYSTEM"])
    def test_every_check_runs_on_a_real_shape_tenant(self, kind):
        results = run_all(normalized(sample_tenant(kind)))
        crashed = [cid for cid, r in results.items() if "Check execution error" in (r.details or "")]
        assert crashed == []


class TestOuBranchAndLegacyBranchAgree:
    """The OU branch is the production path; the legacy branch serves old caches. When both reach a
    verdict on the same real input they must agree. The legacy branch is allowed to say it cannot
    determine the setting (MANUAL / ERROR), never to contradict the OU branch."""

    @pytest.mark.parametrize("kind", ["ADMIN", "SYSTEM"])
    def test_no_contradicting_verdicts(self, kind):
        data = normalized(sample_tenant(kind))
        legacy = copy.deepcopy(data)
        for cat in legacy["policies"].values():
            if isinstance(cat, dict):
                cat.pop("_ou_policies", None)
        ou_results, legacy_results = run_all(data), run_all(legacy)
        conflicts = [f"{cid}: ou={ou_results[cid].status.value} legacy={legacy_results[cid].status.value}"
                     for cid in ou_results
                     if ou_results[cid].status in VERDICTS and legacy_results[cid].status in VERDICTS
                     and ou_results[cid].status != legacy_results[cid].status]
        assert conflicts == []


class TestOrgUnitResolution:
    def test_org_unit_ids_resolve_to_paths(self):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        raw = raw_tenant({"gmail": [
            raw_policy("gmail.mail_delegation", {"enableMailDelegation": False}, org_unit="orgUnits/rootid"),
            raw_policy("gmail.mail_delegation", {"enableMailDelegation": True}, org_unit="orgUnits/salesid")]},
            org_units=[{"orgUnitPath": "/", "orgUnitId": "id:rootid"}, {"orgUnitPath": "/Sales", "orgUnitId": "id:salesid"}])
        result = check_gmail_mail_delegation(normalized(raw))
        assert result.status == Status.FAIL
        assert "/Sales" in result.details and "orgUnits/" not in result.details


class TestPolicyPrecedence:
    def _delegation(self, *entries):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        return check_gmail_mail_delegation(normalized(raw_tenant({"gmail": list(entries)})))

    def test_admin_overrides_system_for_the_same_ou(self):
        result = self._delegation(raw_policy("gmail.mail_delegation", {"enableMailDelegation": True}, "SYSTEM"),
                                  raw_policy("gmail.mail_delegation", {"enableMailDelegation": False}, "ADMIN"))
        assert result.status == Status.PASS and "Google default" not in result.details

    def test_admin_override_wins_regardless_of_list_order(self):
        result = self._delegation(raw_policy("gmail.mail_delegation", {"enableMailDelegation": False}, "ADMIN"),
                                  raw_policy("gmail.mail_delegation", {"enableMailDelegation": True}, "SYSTEM"))
        assert result.status == Status.PASS

    def test_system_only_is_judged_with_provenance(self):
        result = self._delegation(raw_policy("gmail.mail_delegation", {"enableMailDelegation": True}, "SYSTEM"))
        assert result.status == Status.FAIL and "Google default" in result.details

    def test_absent_setting_in_queried_family_takes_documented_default(self):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        raw = raw_tenant({"gmail": [raw_policy("gmail.pop_access", {"enablePopAccess": True})]})
        result = check_gmail_auto_forwarding(normalized(raw))
        assert result.status == Status.FAIL and "Google default" in result.details  # default: forwarding on


class TestDlpRulesRoundTrip:
    def _rules(self, *rules):
        return raw_tenant({"rules": [raw_policy("rule.dlp", r) for r in rules]})

    def _rule(self, app, action, state="ACTIVE"):
        return {"displayName": f"{app} rule", "state": state, "triggers": [{"app": app.upper()}],
                "condition": "c", "action": {f"{app}Action": {action: {}}}}

    def test_active_block_rules_pass(self):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external, check_dlp_chat, check_dlp_gmail
        data = normalized(self._rules(self._rule("gmail", "blockAccess"), self._rule("chat", "blockAccess")))
        assert check_dlp_gmail(data).status == Status.PASS
        assert check_dlp_chat(data).status == Status.PASS
        assert check_dlp_block_external(data).status == Status.PASS

    def test_inactive_rule_does_not_count(self):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_gmail
        data = normalized(self._rules(self._rule("gmail", "blockAccess", state="INACTIVE")))
        assert check_dlp_gmail(data).status == Status.FAIL

    def test_warn_only_rules_do_not_block(self):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external
        data = normalized(self._rules(self._rule("gmail", "warnUser")))
        assert check_dlp_block_external(data).status == Status.FAIL


class TestSystemDefinedAlertRulesRoundTrip:
    @pytest.mark.parametrize("state, status", [("ACTIVE", Status.PASS), ("INACTIVE", Status.FAIL)])
    def test_admin_privilege_rule_state(self, state, status):
        from gws_auditor.checks.rules import check_alert_admin_privilege
        raw = raw_tenant({"rules": [raw_policy("rule.system_defined_alerts",
                                               {"displayName": "User granted Admin privilege", "state": state})]})
        assert check_alert_admin_privilege(normalized(raw)).status == status


class TestAuditLogInferenceRoundTrip:
    """Nested Reports API events flatten into SETTING_NAME / NEW_VALUE parameters; the newest event
    per OU wins, INHERIT_FROM_PARENT is ignored, no event means MANUAL."""

    def _event(self, setting_name, new_value, time, ou="/"):
        return {"id": {"time": time}, "actor": {"email": "admin@example.com"}, "events": [{
            "type": "APPLICATION_SETTINGS", "name": "CHANGE_APPLICATION_SETTING", "parameters": [
                {"name": "SETTING_NAME", "value": setting_name}, {"name": "NEW_VALUE", "value": new_value},
                {"name": "ORG_UNIT_NAME", "value": ou}]}]}

    GEMINI = "BardNonDuetEnablementProto enable_bard_non_duet_access"

    @pytest.mark.parametrize("value, status", [("true", Status.FAIL), ("false", Status.PASS)])
    def test_gemini_unlicensed_access_from_log(self, value, status):
        from gws_auditor.checks.cisa_scuba import check_gemini_unlicensed_access
        data = normalized(raw_tenant(admin_logs=[self._event(self.GEMINI, value, "2026-09-01T00:00:00Z")]))
        assert check_gemini_unlicensed_access(data).status == status

    def test_newest_event_wins(self):
        from gws_auditor.checks.cisa_scuba import check_gemini_unlicensed_access
        data = normalized(raw_tenant(admin_logs=[self._event(self.GEMINI, "true", "2026-09-01T00:00:00Z"),
                                                 self._event(self.GEMINI, "false", "2026-09-02T00:00:00Z")]))
        assert check_gemini_unlicensed_access(data).status == Status.PASS

    def test_inherit_from_parent_and_no_event_are_manual(self):
        from gws_auditor.checks.cisa_scuba import check_gemini_unlicensed_access
        assert check_gemini_unlicensed_access(normalized(raw_tenant())).status == Status.MANUAL
        data = normalized(raw_tenant(admin_logs=[self._event(self.GEMINI, "INHERIT_FROM_PARENT", "2026-09-01T00:00:00Z")]))
        assert check_gemini_unlicensed_access(data).status == Status.MANUAL

    @pytest.mark.parametrize("value, status", [("true", Status.FAIL), ("false", Status.PASS)])
    def test_drive_add_ons_from_log(self, value, status):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled
        data = normalized(raw_tenant(admin_logs=[self._event("ENABLE_DOCS_ADD_ONS", value, "2026-09-01T00:00:00Z")]))
        assert check_drive_add_ons_disabled(data).status == status


class TestUnspecifiedRoundTrip:
    def test_admin_unspecified_third_party_access_is_the_console_default(self):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps
        value = {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED", "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"}
        raw = raw_tenant({"api_controls": [raw_policy("api_controls.unconfigured_third_party_apps", value, "SYSTEM"),
                                           raw_policy("api_controls.unconfigured_third_party_apps", value, "ADMIN")]})
        assert check_unconfigured_third_party_apps(normalized(raw)).status == Status.FAIL

    def test_system_only_unspecified_is_unknown(self):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps
        value = {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED", "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"}
        raw = raw_tenant({"api_controls": [raw_policy("api_controls.unconfigured_third_party_apps", value, "SYSTEM")]})
        assert check_unconfigured_third_party_apps(normalized(raw)).status == Status.MANUAL
