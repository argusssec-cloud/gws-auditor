"""Plan phase P3: checks moved from non-existent setting types to real ones, and checks declared
MANUAL-by-design (unscored) because no API exposes their control."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy

ENTERPRISE_PLUS = "Google Workspace Enterprise Plus"


class TestGmailOfflineRealType:
    """CIS-3.1.3.1.2 now reads gmail.web_offline.enabled."""

    @pytest.mark.parametrize("enabled, status", [(False, Status.PASS), (True, Status.FAIL)])
    def test_web_offline(self, full_audit_data, enabled, status):
        from gws_auditor.checks.apps_gmail import check_gmail_offline
        full_audit_data["subscription_type"] = ENTERPRISE_PLUS
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "web_offline", {"enabled": enabled, "signoutDataDeletionEnforced": False})]}
        assert check_gmail_offline(full_audit_data).status == status

    def test_live_system_default_passes(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_offline
        full_audit_data["subscription_type"] = ENTERPRISE_PLUS
        entry = make_ou_policy("gmail", "web_offline", {"enabled": False, "signoutDataDeletionEnforced": False})
        entry["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [entry]}
        result = check_gmail_offline(full_audit_data)
        assert result.status == Status.PASS and "Google default" in result.details


class TestComprehensiveMailStorageRealType:
    """CIS-3.1.3.7.1: the setting carries only a ruleId; gmail.rule_states says whether it is on."""

    def _data(self, full_audit_data, enabled):
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "comprehensive_mail_storage", {"ruleId": "abc:123"}),
            make_ou_policy("gmail", "rule_states", {"ruleStates": [{"ruleId": "abc:123", "enabled": enabled}]})]}
        return full_audit_data

    @pytest.mark.parametrize("enabled, status", [(True, Status.PASS), (False, Status.FAIL)])
    def test_rule_state_decides(self, full_audit_data, enabled, status):
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage
        assert check_gmail_comprehensive_storage(self._data(full_audit_data, enabled)).status == status

    def test_rule_id_without_rule_states_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "comprehensive_mail_storage", {"ruleId": "abc:123"})]}
        assert check_gmail_comprehensive_storage(full_audit_data).status == Status.MANUAL


class TestDriveDlpFromRealRules:
    """CIS-4.2.3.1 is fed by rule.dlp policies through the provider; FAIL was believed unreachable."""

    def _run(self, full_audit_data, action_key):
        from gws_auditor.checks.security_access import check_drive_dlp
        from gws_auditor.provider import normalize_data
        raw = dict(full_audit_data)
        raw["subscription_type"] = "Google Workspace Enterprise Standard"
        raw["org_units"] = []
        raw["policies"] = {"rules": [{
            "setting": {"type": "settings/rule.dlp", "value": {
                "displayName": "Block SSNs", "state": "ACTIVE",
                "triggers": [{"app": "DRIVE" if action_key == "driveAction" else "GMAIL"}],
                "condition": "x", "action": {action_key: {"blockAccess": {}}}}},
            "orgUnit": "/", "_raw": {"type": "ADMIN"}}]}
        return check_drive_dlp(normalize_data(raw))

    def test_active_drive_rule_passes(self, full_audit_data):
        assert self._run(full_audit_data, "driveAction").status in (Status.PASS, Status.WARN)

    def test_only_gmail_rules_fails(self, full_audit_data):
        assert self._run(full_audit_data, "gmailAction").status == Status.FAIL


class TestCalendarDlpFromRealRules:
    """ADD-23 reads real rule.dlp policies; unknown is MANUAL, a fetched category without a
    Calendar rule is FAIL, a Calendar-triggered rule is PASS."""

    def _run(self, full_audit_data, trigger_app):
        from gws_auditor.checks.additional import check_calendar_dlp
        from gws_auditor.provider import normalize_data
        raw = dict(full_audit_data)
        raw["subscription_type"] = "Google Workspace Enterprise Standard"
        raw["org_units"] = []
        raw["policies"] = {"rules": [{
            "setting": {"type": "settings/rule.dlp", "value": {
                "displayName": "r", "state": "ACTIVE", "triggers": [{"app": trigger_app}],
                "condition": "x", "action": {"driveAction": {"warnUser": {}}}}},
            "orgUnit": "/", "_raw": {"type": "ADMIN"}}]}
        return check_calendar_dlp(normalize_data(raw))

    def test_calendar_rule_passes(self, full_audit_data):
        assert self._run(full_audit_data, "CALENDAR").status == Status.PASS

    def test_rules_fetched_without_calendar_rule_fails(self, full_audit_data):
        assert self._run(full_audit_data, "DRIVE").status == Status.FAIL


class TestManualByDesignAreUnscored:
    """Controls with no API or audit-log signal only ask for review and do not score."""

    IDS = ["CIS-3.1.2.2.1", "CIS-3.1.3.7.2", "CIS-4.2.2.1", "CIS-4.2.5.1", "GWS.CHAT.5.2",
           "GWS.CALENDAR.3.2", "GWS.COMMONCONTROLS.16.3", "GWS.COMMONCONTROLS.16.4", "GWS.DRIVEDOCS.5.2",
           "ADD-07", "ADD-11", "ADD-13", "ADD-21", "ADD-22", "ADD-24", "ADD-26"]
    # GWS.COMMONCONTROLS.3.1 / 3.2 left the list on 2026-11-14 (admin-log SsoPolicyProto events, ScubaGoggles 1.1.0
    # names) and 7.1 is scored from the Policy API; 16.3, 16.4 and DRIVEDOCS.5.2 arrived with SCuBA v1; MEET.6.3 left on
    # 2026-11-15 (flip: MeetGenAiVisualContentSettingsProto policy).
    # ADD-02, ADD-15, ADD-18 and CIS-3.1.1.2.2 left this list on 2026-11-07/08: live flips confirmed their
    # admin-log names (security sandbox setting, Workspace Studio service toggle, Skip password enrollment
    # state, SHARING_INSIDE_DOMAIN_FOR_SECONDARY_CALENDAR) and they are scored. ADD-07 and ADD-13 also read the log but stay unscored: a TLS rule can be proven present,
    # never absent, and Gemini feature switches are only seen for services an admin touched.
    # GWS.COMMONCONTROLS.7.1 reads the Policy API type when a tenant returns it and stays unscored.

    def test_flagged_unscored(self):
        from gws_auditor.checks.registry import CheckRegistry
        scored = {m.check_id: m.scored for m in CheckRegistry().get_all_checks()}
        assert [cid for cid in self.IDS if scored[cid]] == []

    def test_no_dead_setting_type_is_looked_up(self):
        import ast, json
        from pathlib import Path
        shapes = json.loads(Path("tests/fixtures/policy_api_shapes.json").read_text())["settings"]
        known = {t.split(".", 1)[1] for t in shapes}
        dead = []
        for path in Path("src/gws_auditor/checks").glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "get_ou_values"
                        and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                        and node.args[1].value not in known):
                    dead.append(f"{path.name}:{node.lineno}:{node.args[1].value}")
        assert dead == []


class TestSitesServiceOff:
    """P6 console reading: Sites OFF for everyone while the SYSTEM creation flag stays true."""

    def test_service_off_passes_despite_system_creation_flag(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled
        sysp = make_ou_policy("sites", "sites_creation_and_modification", {"allowSitesCreation": True, "allowSitesModification": True})
        sysp["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["sites"] = {"_ou_policies": [
            sysp, make_ou_policy("sites", "service_status", {"serviceState": "DISABLED"})]}
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.PASS and "service OFF" in result.details

    def test_service_on_fails_even_with_creation_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled
        full_audit_data["policies"]["sites"] = {"_ou_policies": [
            make_ou_policy("sites", "sites_creation_and_modification", {"allowSitesCreation": False}),
            make_ou_policy("sites", "service_status", {"serviceState": "ENABLED"})]}
        assert check_sites_creation_disabled(full_audit_data).status == Status.FAIL
