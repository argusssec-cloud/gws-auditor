"""Tests for security access control checks (OU-aware + fallback)."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy



# -----------------------------------------------------------------------
# CIS-4.2.1.1: Third-party app access
# -----------------------------------------------------------------------

class TestThirdPartyAppAccess:
    """Tests for CIS-4.2.1.1 (fallback path)."""

    def test_pass_restricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": True,
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_trust_policy_restricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": None,
            "trust_policy": "restricted",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_unrestricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": False,
            "trust_policy": "open",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": None,
            "trust_policy": "",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.MANUAL


class TestThirdPartyAppAccessOU:
    """OU-aware tests for CIS-4.2.1.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "RESTRICTED"}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "BLOCKED"}, "/Engineering"),
            ],
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "RESTRICTED"}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "UNRESTRICTED"}, "/Sales"),
            ],
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": True,
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.2.1.2: Third-party app review (non-policy, unchanged)
# -----------------------------------------------------------------------

class TestThirdPartyAppReview:
    """Tests for CIS-4.2.1.2 (uses token_logs, not policy)."""

    def test_no_token_logs_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = []
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.ERROR

    def test_with_token_logs_no_policy_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = [
            {"app_name": "SomeApp", "client_id": "abc123"},
            {"app_name": "AnotherApp", "client_id": "def456"},
        ]
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.FAIL

    def test_with_token_logs_and_policy_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = [
            {"app_name": "SomeApp", "client_id": "abc123"},
            {"app_name": "AnotherApp", "client_id": "def456"},
        ]
        full_audit_data["policies"]["access_control"] = {
            "app_access_policy": "restricted",
        }
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# CIS-4.2.1.3: Internal API access (no OU mapping given, unchanged)
# -----------------------------------------------------------------------

class TestInternalApiAccess:
    """Tests for CIS-4.2.1.3."""

    def test_controlled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": True,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.PASS

    def test_not_controlled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": False,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# CIS-4.2.1.4: Domain-wide delegation (no OU mapping, unchanged)
# -----------------------------------------------------------------------

class TestDomainWideDelegation:
    """Tests for CIS-4.2.1.4."""

    def test_manual_when_no_data(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "domain_wide_delegation_clients": [],
        }
        full_audit_data["admin_logs"] = []
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL

    def test_delegation_exists_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "domain_wide_delegation_clients": [
                {"client_id": "sa-123", "scopes": ["https://www.googleapis.com/auth/admin.directory.user"]},
            ],
        }
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# CIS-4.2.2.1: Geo-blocking (no OU mapping, unchanged)
# -----------------------------------------------------------------------

class TestGeoBlocking:
    """Tests for CIS-4.2.2.1."""

    def test_with_regions_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": True,
            "blocked_regions": ["CN", "RU", "KP"],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS

    def test_no_regions_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": False,
            "blocked_regions": [],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# CIS-4.2.4.1: Device Bound Session Credentials (DBSC)
# -----------------------------------------------------------------------

class TestSessionControl:
    """Tests for CIS-4.2.4.1: DBSC."""

    def test_dbsc_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {"dbsc_enabled": True}
        result = check_session_control(full_audit_data)
        assert result.status == Status.PASS

    def test_dbsc_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {"dbsc_enabled": False}
        result = check_session_control(full_audit_data)
        assert result.status == Status.FAIL

    def test_dbsc_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {}
        result = check_session_control(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# CIS-4.2.5.1: Cloud session control (no OU mapping, unchanged)
# -----------------------------------------------------------------------

class TestCloudSessionControl:
    """Tests for CIS-4.2.5.1."""

    def test_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": True,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.PASS

    def test_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": False,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# _parse_session_duration_hours unit tests
# -----------------------------------------------------------------------

class TestParseSessionDuration:
    """Unit tests for the session duration parser."""

    def test_seconds_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("28800s") == 8.0

    def test_hours_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("12h") == 12.0

    def test_int_seconds(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours(43200) == 12.0

    def test_none_returns_none(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours(None) is None

    def test_invalid_string_returns_none(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("bogus") is None

    def test_plain_numeric_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("3600") == 1.0
