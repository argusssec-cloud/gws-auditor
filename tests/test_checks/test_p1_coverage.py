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

    def test_business_starter_is_evaluated(self, full_audit_data):
        # Gmail spam settings exist in every edition (Google's quarantine and spam articles carry no
        # edition restriction), so the former Enterprise Plus gate was wrong and is gone (2026-11-10).
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        d = self._data(full_audit_data, True)
        d["subscription_type"] = "Business Starter"
        assert check_gmail_internal_spam_filter(d).status == Status.FAIL


class TestInternalSpamFilterBypassPerOU:
    """CIS-3.1.3.6.2 judges gmail.spam_override_lists on every OU that sets it (2026-11-16): custom spam
    filters are set per OU, and the flat mapped value only ever held the root OU's rules."""

    @staticmethod
    def _rule(**flags):
        return {"ruleId": "r1", "description": "Internal bypass", "bypassInternalSenders": False,
                "bypassSelectedSenders": False, "hideWarningBannerFromSelectedSenders": False, **flags}

    def _policies(self, full_audit_data, *entries):
        from tests.factories import make_ou_policy
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [make_ou_policy("gmail", "spam_override_lists", value, ou) for value, ou in entries],
            # the flat mapping (root OU) says "no bypass": the per-OU path must win
            "spam_settings": {"bypass_spam_for_internal_senders": False},
        }
        return full_audit_data

    def test_child_ou_override_fails_and_is_named(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        d = self._policies(full_audit_data,
                           ({"spamOverride": []}, "/"),
                           ({"spamOverride": [self._rule(bypassInternalSenders=True)]}, "/Engineering"))
        result = check_gmail_internal_spam_filter(d)
        assert result.status == Status.FAIL
        assert "1 OU(s)" in result.details and "/Engineering" in result.details and "/," not in result.details
        assert "Internal bypass" in str(result.actual_value)

    def test_root_bypass_child_override_clean_names_root_only(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        d = self._policies(full_audit_data,
                           ({"spamOverride": [self._rule(bypassInternalSenders=True)]}, "/"),
                           ({"spamOverride": [self._rule(ruleId="r2")]}, "/Guests"))
        result = check_gmail_internal_spam_filter(d)
        assert result.status == Status.FAIL
        assert "/Guests" not in result.details and result.details.endswith(": /")

    def test_all_ous_clean_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        d = self._policies(full_audit_data,
                           ({"spamOverride": [self._rule(bypassSelectedSenders=True)]}, "/"),
                           ({"spamOverride": []}, "/Engineering"))
        result = check_gmail_internal_spam_filter(d)
        assert result.status == Status.PASS and "All 2 OU(s)" in result.details

    def test_rule_switched_off_in_rule_states_is_ignored(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal
        from tests.factories import make_ou_policy
        d = self._policies(full_audit_data,
                           ({"spamOverride": [self._rule(bypassInternalSenders=True)]}, "/"))
        d["policies"]["gmail"]["_ou_policies"].append(
            make_ou_policy("gmail", "rule_states", {"ruleStates": [{"ruleId": "r1", "enabled": False}]}))
        assert check_gmail_internal_spam_filter(d).status == Status.PASS
        assert check_spam_bypass_internal(d).status == Status.PASS

    def test_rule_enabled_in_rule_states_still_fails(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal
        from tests.factories import make_ou_policy
        d = self._policies(full_audit_data,
                           ({"spamOverride": [self._rule(bypassInternalSenders=True)]}, "/"))
        d["policies"]["gmail"]["_ou_policies"].append(
            make_ou_policy("gmail", "rule_states", {"ruleStates": [{"ruleId": "r1", "enabled": True}]}))
        assert check_gmail_internal_spam_filter(d).status == Status.FAIL
        assert check_spam_bypass_internal(d).status == Status.FAIL

    def test_legacy_cache_without_ou_policies_still_reads_the_root_value(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_internal_spam_filter
        full_audit_data["policies"]["gmail"] = {"spam_settings": {"bypass_spam_for_internal_senders": True}}
        assert check_gmail_internal_spam_filter(full_audit_data).status == Status.FAIL

    def test_18_3_fallback_reads_the_providers_key(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal
        full_audit_data["policies"]["gmail"] = {"spam_settings": {"bypass_spam_for_internal_senders": True}}
        assert check_spam_bypass_internal(full_audit_data).status == Status.FAIL
        full_audit_data["policies"]["gmail"] = {"spam_settings": {"bypass_spam_for_internal_senders": False}}
        assert check_spam_bypass_internal(full_audit_data).status == Status.PASS


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
        full_audit_data["policies"]["security"] = {"password_alert": {"deployed": False, "trigger": "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_NO_WARNING"}}
        assert check_password_alert(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("trigger, status", [
        ("PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_NO_WARNING", Status.FAIL),
        ("PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PASSWORD_REUSE", Status.PASS),
        ("PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PHISHING_REUSE", Status.WARN),
    ])
    def test_end_to_end_from_chrome_policy(self, full_audit_data, trigger, status):
        """The provider maps chrome_policies.password_protection_warning_trigger (chrome.users.PasswordAlert enum) to the alert state."""
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
        raw["api_errors"] = [{"operation": "resolve_policy(chrome.users.PasswordAlert)", "error": "403"}]
        assert check_password_alert(normalize_data(raw)).status == Status.MANUAL
