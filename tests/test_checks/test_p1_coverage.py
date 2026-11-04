"""Plan phase P1: PASS and FAIL tests for checks the coverage gate found one-sided."""

import pytest

from gws_auditor.models import Status


class TestInternalSpamFilterBypass:
    """CIS-3.1.3.6.2 had no tests at all."""

    def _data(self, full_audit_data, bypass):
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["gmail"] = {"spam_settings": {"bypass_spam_for_internal_senders": bypass}}
        return full_audit_data

    def test_not_bypassed_passes(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        assert check_gmail_internal_spam_filter(self._data(full_audit_data, False)).status == Status.PASS

    def test_bypassed_fails(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        assert check_gmail_internal_spam_filter(self._data(full_audit_data, True)).status == Status.FAIL

    def test_unknown_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["gmail"] = {}
        assert check_gmail_internal_spam_filter(full_audit_data).status == Status.MANUAL

    @pytest.mark.parametrize("bypass, status", [(True, Status.FAIL), (False, Status.PASS)])
    def test_end_to_end_from_real_spam_override_rule(self, full_audit_data, bypass, status):
        """The provider derives the mapped key from gmail.spam_override_lists.spamOverride[]."""
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        from gws_auditor.provider import normalize_data
        raw = dict(full_audit_data)
        raw["subscription_type"] = "Google Workspace Enterprise Plus"
        raw["org_units"] = []
        raw["policies"] = {"gmail": [{
            "setting": {"type": "settings/gmail.spam_override_lists",
                        "value": {"spamOverride": [{"ruleId": "r1", "bypassInternalSenders": bypass,
                                                    "bypassSelectedSenders": False, "addToQuarantine": False}]}},
            "orgUnit": "/", "_raw": {"type": "ADMIN"}}]}
        assert check_gmail_internal_spam_filter(normalize_data(raw)).status == status

    def test_below_enterprise_plus_is_not_applicable(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        d = self._data(full_audit_data, True)
        d["subscription_type"] = "Business Starter"
        assert check_gmail_internal_spam_filter(d).status == Status.NOT_APPLICABLE


class TestTlsEnforcement:
    """CIS-3.1.3.7.2 only had a PASS test. The key is test-only: no Policy API setting feeds it,
    so production is MANUAL (phase P3 decides whether the check becomes MANUAL-by-design)."""

    def _data(self, full_audit_data, tls):
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["gmail"] = {"compliance": {"tls_required": tls}}
        return full_audit_data

    def test_not_required_fails(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_tls_enforcement
        assert check_gmail_tls_enforcement(self._data(full_audit_data, False)).status == Status.FAIL

    def test_required_passes(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_tls_enforcement
        assert check_gmail_tls_enforcement(self._data(full_audit_data, True)).status == Status.PASS

    def test_unknown_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_tls_enforcement
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["gmail"] = {}
        assert check_gmail_tls_enforcement(full_audit_data).status == Status.MANUAL


class TestPasswordAlert:
    """ADD-08 only had PASS and MANUAL tests."""

    def test_not_deployed_fails(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        full_audit_data["policies"]["security"] = {"password_alert": {"deployed": False, "trigger": 0}}
        assert check_password_alert(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("trigger, status", [(0, Status.FAIL), (1, Status.PASS), (2, Status.PASS)])
    def test_end_to_end_from_chrome_policy(self, full_audit_data, trigger, status):
        """The provider maps chrome_policies.password_protection_warning_trigger to the alert state."""
        from gws_auditor.checks.additional import check_password_alert
        from gws_auditor.provider import normalize_data
        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {"security": []}
        raw["chrome_policies"] = {"password_protection_warning_trigger": trigger}
        assert check_password_alert(normalize_data(raw)).status == status

    def test_chrome_policy_unavailable_is_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        from gws_auditor.provider import normalize_data
        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {"security": []}
        raw["chrome_policies"] = {}
        assert check_password_alert(normalize_data(raw)).status == Status.MANUAL
