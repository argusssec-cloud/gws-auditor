"""Tests for apps_sites checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


def _sites(*entries):
    return {"_ou_policies": list(entries)}


class TestSitesServiceOff:
    """CIS-3.1.7.1 (v1.4.1): 'Ensure service status for Google Sites is set to off' judges
    sites.service_status.serviceState; new-site creation alone does not satisfy it."""

    def test_service_off_everywhere_passes(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = _sites(
            make_ou_policy("sites", "service_status", {"serviceState": "DISABLED"}, "/"),
            make_ou_policy("sites", "service_status", {"serviceState": "DISABLED"}, "/Engineering"),
        )
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-3.1.7.1"
        assert "2 OU(s)" in result.details

    def test_service_on_in_child_ou_fails(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = _sites(
            make_ou_policy("sites", "service_status", {"serviceState": "DISABLED"}, "/"),
            make_ou_policy("sites", "service_status", {"serviceState": "ENABLED"}, "/Marketing"),
        )
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details
        assert result.remediation

    def test_creation_disabled_but_service_on_fails_and_says_why(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = _sites(
            make_ou_policy("sites", "service_status", {"serviceState": "ENABLED"}, "/"),
            make_ou_policy("sites", "sites_creation_and_modification",
                           {"allowSitesCreation": False, "allowSitesModification": True}, "/"),
        )
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "New-site creation is disabled" in result.details
        assert "service itself to be OFF" in result.details

    def test_service_off_with_system_creation_flag_true_passes(self, full_audit_data):
        # Console reading 2026-11-04: Sites OFF for everyone while the SYSTEM creation flag stays true.
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        sysp = make_ou_policy("sites", "sites_creation_and_modification",
                              {"allowSitesCreation": True, "allowSitesModification": True})
        sysp["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["sites"] = _sites(
            sysp, make_ou_policy("sites", "service_status", {"serviceState": "DISABLED"}))
        assert check_sites_creation_disabled(full_audit_data).status == Status.PASS

    def test_unspecified_state_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = _sites(
            make_ou_policy("sites", "service_status", {"serviceState": "SERVICE_STATE_UNSPECIFIED"}, "/"))
        assert check_sites_creation_disabled(full_audit_data).status == Status.MANUAL


class TestSitesServiceFallback:
    """Without Policy API entries the mapped root value decides; creation flags alone are not enough."""

    def test_mapped_disabled_passes(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = {"service_status": "disabled"}
        assert check_sites_creation_disabled(full_audit_data).status == Status.PASS

    def test_mapped_enabled_fails(self, full_audit_data):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = {"service_status": "enabled"}
        assert check_sites_creation_disabled(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("sites", [
        {},
        {"sites_creation_enabled": False},
        {"_ou_policies": [make_ou_policy("sites", "sites_creation_and_modification", {"allowSitesCreation": False}, "/")]},
    ])
    def test_unknown_service_state_is_manual(self, full_audit_data, sites):
        from gws_auditor.checks.apps_sites import check_sites_creation_disabled

        full_audit_data["policies"]["sites"] = sites
        result = check_sites_creation_disabled(full_audit_data)
        assert result.status == Status.MANUAL
        assert "service_status" in result.details
