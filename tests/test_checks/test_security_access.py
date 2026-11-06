"""Tests for security access control checks (OU-aware + fallback)."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_admin_event
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
    """CIS-4.2.1.4: grants come from AUTHORIZE_API_CLIENT_ACCESS / REMOVE_API_CLIENT_ACCESS admin events
    (API_CLIENT_NAME may list several client IDs); no API lists the clients."""

    _BASE = "https://www.googleapis.com/auth/"

    def _ev(self, name, clients, scopes, time):
        return make_admin_event(name, {"API_CLIENT_NAME": clients, "API_SCOPES": scopes}, time)

    def test_no_event_in_window_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [make_admin_event("CHANGE_APPLICATION_SETTING", {}, "2026-08-01T00:00:00Z")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL
        assert "since 2026-08-01" in result.details

    def test_low_risk_grants_are_review_with_window(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [self._ev(
            "AUTHORIZE_API_CLIENT_ACCESS", "111.apps.googleusercontent.com,222.apps.googleusercontent.com,333.apps.googleusercontent.com",
            f"{self._BASE}drive.file,\n{self._BASE}spreadsheets.currentonly,\n{self._BASE}userinfo.email,\nopenid", "2026-10-19T21:06:23.587Z")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL  # inventory never known complete: review, never PASS
        assert result.actual_value["delegation_count"] == 3  # comma-separated client IDs are split
        assert "since 2026-10-19" in result.details and "not visible" in result.details

    def test_org_wide_write_scopes_warn(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "111", f"{self._BASE}admin.directory.user.readonly", "2026-01-01"),
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify,{self._BASE}drive", "2026-01-02")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.WARN
        assert "222: drive, gmail.modify" in result.details and "111:" not in result.details
        assert result.actual_value == {"delegation_count": 2, "high_risk_clients": 1, "allowlisted_clients": 0, "window_start": "2026-01-01"}

    def test_allowlisted_risky_client_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify", "2026-01-02")]
        full_audit_data["_options"] = {"dwd_allowlist": ["222"]}
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL
        assert "1 client(s) with such scopes are vetted" in result.details
        assert result.actual_value["allowlisted_clients"] == 1

    def test_revocation_after_grant_clears_it(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify", "2026-01-02"),
            self._ev("REMOVE_API_CLIENT_ACCESS", "222", "", "2026-01-03")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL and result.actual_value["delegation_count"] == 0


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
