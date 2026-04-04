"""Tests for Google Chat security checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestChatExternalRestriction:
    """Tests for CIS-3.1.4.2.1: external chat restriction."""

    def test_pass_when_allowlisted_domains(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {
                "restriction_mode": "allowlisted_domains",
                "allowed_domains": ["partner.com"],
            },
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {"restriction_mode": "disabled"},
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_unrestricted(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {"restriction_mode": "unrestricted"},
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_when_open(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {"restriction_mode": "open"},
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_empty(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {"restriction_mode": ""},
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.ERROR

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {}
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.ERROR


class TestChatAppInstallation:
    """Tests for CIS-3.1.4.4.1: Chat app installation."""

    def test_pass_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "apps": {"chat_apps_enabled": False},
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "apps": {"chat_apps_enabled": True},
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "apps": {"chat_apps_enabled": None},
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.MANUAL


class TestChatWebhooks:
    """Tests for CIS-3.1.4.4.2: incoming webhooks."""

    def test_pass_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "apps": {"incoming_webhooks_enabled": False},
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "apps": {"incoming_webhooks_enabled": True},
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "apps": {"incoming_webhooks_enabled": None},
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.MANUAL

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {}
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------


class TestChatExternalRestrictionOU:
    """OU-aware tests for CIS-3.1.4.2.1: external chat restriction."""

    def test_all_ous_allowlisted(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "external_chat_restriction",
                                {"externalChatRestriction": "TRUSTED_DOMAINS", "allowExternalChat": True}, "/"),
                make_ou_policy("chat", "external_chat_restriction",
                                {"externalChatRestriction": "TRUSTED_DOMAINS", "allowExternalChat": True}, "/Engineering"),
            ],
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_safe_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "external_chat_restriction",
                                {"allowExternalChat": False}, "/"),
            ],
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "external_chat_restriction",
                                {"externalChatRestriction": "TRUSTED_DOMAINS", "allowExternalChat": True}, "/"),
                make_ou_policy("chat", "external_chat_restriction",
                                {"externalChatRestriction": "NO_RESTRICTION", "allowExternalChat": True}, "/Sales"),
            ],
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_external_restriction

        full_audit_data["policies"]["chat"] = {
            "external_chat": {
                "restriction_mode": "allowlisted_domains",
                "allowed_domains": ["partner.com"],
            },
        }
        result = check_chat_external_restriction(full_audit_data)
        assert result.status == Status.PASS


class TestChatAppInstallationOU:
    """OU-aware tests for CIS-3.1.4.4.1: Chat app installation."""

    def test_all_ous_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_apps_access",
                                {"enableApps": False}, "/"),
                make_ou_policy("chat", "chat_apps_access",
                                {"enableApps": False}, "/Finance"),
            ],
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_apps_access",
                                {"enableApps": False}, "/"),
                make_ou_policy("chat", "chat_apps_access",
                                {"enableApps": True}, "/DevOps"),
            ],
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.FAIL
        assert "/DevOps" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_app_installation

        full_audit_data["policies"]["chat"] = {
            "apps": {"chat_apps_enabled": False},
        }
        result = check_chat_app_installation(full_audit_data)
        assert result.status == Status.PASS


class TestChatWebhooksOU:
    """OU-aware tests for CIS-3.1.4.4.2: incoming webhooks."""

    def test_all_ous_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_apps_access",
                                {"enableWebhooks": False}, "/"),
                make_ou_policy("chat", "chat_apps_access",
                                {"enableWebhooks": False}, "/Legal"),
            ],
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_apps_access",
                                {"enableWebhooks": False}, "/"),
                make_ou_policy("chat", "chat_apps_access",
                                {"enableWebhooks": True}, "/Support"),
            ],
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_chat import check_chat_webhooks

        full_audit_data["policies"]["chat"] = {
            "apps": {"incoming_webhooks_enabled": False},
        }
        result = check_chat_webhooks(full_audit_data)
        assert result.status == Status.PASS
