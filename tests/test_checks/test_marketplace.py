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
        assert result.expected_value == "Disabled for all OUs"
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
                                {"collaborationCapability": "DOMAIN_USERS_ONLY"}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"collaborationCapability": "DOMAIN_USERS_ONLY"}, "/Engineering"),
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
                                {"collaborationCapability": "DOMAIN_USERS_ONLY"}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"collaborationCapability": "ANYONE_CAN_ACCESS"}, "/Sales"),
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
                                {"accessLevel": "ALLOW_LISTED_APPS"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"accessLevel": "ALLOW_NONE"}, "/Engineering"),
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
                                {"accessLevel": "ALLOW_LISTED_APPS"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"accessLevel": "ALLOW_ALL"}, "/Dev"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Dev" in result.details

    def test_child_ou_empty_policy(self, full_audit_data):
        # An absent accessLevel is unknown (its default is edition-dependent and not injected),
        # so the OU is undetermined -> MANUAL rather than the old FAIL.
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"accessLevel": "ALLOW_LISTED_APPS"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {}, "/HR"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.MANUAL
        assert "/HR" in result.details

    def test_unspecified_access_level_is_unknown(self, full_audit_data):
        # ACCESS_LEVEL_UNSPECIFIED is "not set", never a PASS or FAIL verdict.
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED"}, "/"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.MANUAL

    def test_unsafe_ou_wins_over_unknown_ou(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "_ou_policies": [
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {"accessLevel": "ALLOW_ALL"}, "/"),
                make_ou_policy("workspace_marketplace", "apps_access_options",
                                {}, "/HR"),
            ],
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details  # unknown OUs are listed alongside the failure

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        full_audit_data["policies"]["marketplace"] = {
            "app_install_policy": "approved_only",
            "restrict_to_approved_apps": None,
        }
        result = check_marketplace_restriction(full_audit_data)
        assert result.status == Status.PASS
