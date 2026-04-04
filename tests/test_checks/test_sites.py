"""Tests for apps_sites checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestSitesCreationDisabled:
    """Tests for CIS-3.1.7.1: Ensure Google Sites creation is disabled."""

    def test_pass_sites_creation_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"]["sites_creation_enabled"] = False
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-3.1.7.1"
        assert result.actual_value is False

    def test_fail_sites_creation_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"]["sites_creation_enabled"] = True
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value is True
        assert result.expected_value is False
        assert result.remediation

    def test_manual_sites_creation_none(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"]["sites_creation_enabled"] = None
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Could not determine" in result.details


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------


class TestSitesCreationDisabledOU:
    """OU-aware tests for CIS-3.1.7.1."""

    def test_all_ous_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = {
            "_ou_policies": [
                make_ou_policy("sites", "sites_creation_and_modification",
                                {"allowSitesCreation": False}, "/"),
                make_ou_policy("sites", "sites_creation_and_modification",
                                {"allowSitesCreation": False}, "/Engineering"),
            ],
        }
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = {
            "_ou_policies": [
                make_ou_policy("sites", "sites_creation_and_modification",
                                {"allowSitesCreation": False}, "/"),
                make_ou_policy("sites", "sites_creation_and_modification",
                                {"allowSitesCreation": True}, "/Marketing"),
            ],
        }
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = {
            "sites_creation_enabled": False,
        }
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.PASS
