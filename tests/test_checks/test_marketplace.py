"""Tests for apps_marketplace checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestExternalGroupsDisabled:
    """Tests for CIS-3.1.8.1: Ensure external Google Groups is disabled."""

    def test_pass_external_groups_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"]["external_groups_access_enabled"] = False
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-3.1.8.1"
        assert result.actual_value is False

    def test_fail_external_groups_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"]["external_groups_access_enabled"] = True
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value is True
        assert result.expected_value is False
        assert result.remediation

    def test_manual_external_groups_none(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"]["external_groups_access_enabled"] = None
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.ERROR
        assert "Could not determine" in result.details


class TestMarketplaceRestriction:
    """Tests for CIS-3.1.9.1.1: Ensure Marketplace apps are restricted."""

    def test_pass_with_approved_only_policy(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "approved_only",
            "restrict_to_approved_apps": None,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-3.1.9.1.1"

    def test_pass_with_restricted_policy(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "restricted",
            "restrict_to_approved_apps": None,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_with_restrict_to_approved_apps_true(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "",
            "restrict_to_approved_apps": True,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_unrestricted_policy(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "unrestricted",
            "restrict_to_approved_apps": False,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "unrestricted" in result.details
        assert result.remediation

    def test_manual_when_both_empty_none(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "",
            "restrict_to_approved_apps": None,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.ERROR
        assert "Could not determine" in result.details


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------


class TestExternalGroupsDisabledOU:
    """OU-aware tests for CIS-3.1.8.1."""

    def test_all_ous_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"externalGroupsAccessEnabled": False}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"externalGroupsAccessEnabled": False}, "/Engineering"),
            ],
        }
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"externalGroupsAccessEnabled": False}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"externalGroupsAccessEnabled": True}, "/Sales"),
            ],
        }
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_external_groups_disabled

        full_audit_data["policies"]["groups"] = {
            "external_groups_access_enabled": False,
        }
        result = check_external_groups_disabled(full_audit_data)
        assert result.status == Status.PASS


class TestMarketplaceRestrictionOU:
    """OU-aware tests for CIS-3.1.9.1.1."""

    def test_all_ous_restricted(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"appInstallPolicy": "ALLOWLIST_ONLY"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"appInstallPolicy": "APPROVED_ONLY"}, "/Engineering"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unrestricted(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"appInstallPolicy": "ALLOWLIST_ONLY"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"appInstallPolicy": "UNRESTRICTED"}, "/Dev"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Dev" in result.details

    def test_child_ou_empty_policy(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"appInstallPolicy": "ALLOWLIST_ONLY"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {}, "/HR"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "approved_only",
            "restrict_to_approved_apps": None,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS
