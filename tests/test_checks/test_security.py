"""Tests for security authentication and access checks."""

import pytest

from gws_auditor.models import Status


def _make_security_data(full_audit_data, **overrides):
    """Helper to set nested security policy values for tests."""
    security = full_audit_data["policies"].setdefault("security", {})
    for key, value in overrides.items():
        if "." in key:
            parts = key.split(".")
            d = security
            for part in parts[:-1]:
                d = d.setdefault(part, {})
            d[parts[-1]] = value
        else:
            security[key] = value
    return full_audit_data


class TestTwoStepVerification:
    """Tests for CIS-4.1.1.x 2SV checks."""

    def test_2sv_enforced_admins_pass(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_enforcement": "enforced"})
        # Mark admin users as enrolled
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = True
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.PASS

    def test_2sv_enforced_admins_fail(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_enforcement": "not_enforced"})
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = False
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.FAIL

    def test_2sv_enforced_all_pass(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        _make_security_data(full_audit_data,
            **{"two_step_verification.enforcement": "enforced"})
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.PASS


class TestPasswordPolicy:
    """Tests for CIS-4.1.5.1 password policy."""

    def test_password_policy_enhanced_pass(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        _make_security_data(full_audit_data,
            **{
                "password_management.minimum_length": 14,
                "password_management.enforce_strong_password": True,
            })
        result = check_password_policy(full_audit_data)
        assert result.status == Status.PASS

    def test_password_policy_not_enhanced_fail(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        _make_security_data(full_audit_data,
            **{
                "password_management.minimum_length": 6,
                "password_management.enforce_strong_password": False,
            })
        result = check_password_policy(full_audit_data)
        assert result.status == Status.FAIL


class TestLessSecureApps:
    """Tests for CIS-4.2.6.1 less secure apps."""

    def test_less_secure_apps_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        _make_security_data(full_audit_data,
            **{"less_secure_apps.allowed": False})
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_less_secure_apps_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        _make_security_data(full_audit_data,
            **{"less_secure_apps.allowed": True})
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.FAIL


class TestAccessControl:
    """Tests for CIS-4.2.x access control checks."""

    def test_third_party_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": True,
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS

    def test_dlp_configured_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_drive_dlp
        full_audit_data["policies"].setdefault("security", {})["dlp"] = {
            "drive_dlp_enabled": True,
            "drive_rule_count": 3,
        }
        result = check_drive_dlp(full_audit_data)
        assert result.status == Status.PASS


class TestThirdPartyAppReview:
    """Tests for CIS-4.2.1.2 third-party app review check."""

    def test_no_token_logs_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = []
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.ERROR

    def test_with_token_logs_no_policy_fail(self, full_audit_data):
        """Token logs with OAuth apps but no access policy → FAIL."""
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = [
            {"app_name": "SomeApp", "client_id": "abc123"},
            {"app_name": "AnotherApp", "client_id": "def456"},
        ]
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.FAIL

    def test_with_token_logs_and_policy_manual(self, full_audit_data):
        """Token logs with OAuth apps and access policy → MANUAL (needs review)."""
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


class TestInternalApiAccess:
    """Tests for CIS-4.2.1.3 internal app API access check."""

    def test_internal_api_controlled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": True,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.PASS

    def test_internal_api_not_controlled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": False,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.FAIL


class TestDomainWideDelegation:
    """Tests for CIS-4.2.1.4 domain-wide delegation review check."""

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


class TestGeoBlocking:
    """Tests for CIS-4.2.2.1 geo-blocking configuration check."""

    def test_geo_blocking_with_regions_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": True,
            "blocked_regions": ["CN", "RU", "KP"],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS

    def test_geo_blocking_no_regions_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": False,
            "blocked_regions": [],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.FAIL


class TestSessionControl:
    """Tests for CIS-4.2.4.1 DBSC check."""

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


class TestCloudSessionControl:
    """Tests for CIS-4.2.5.1 cloud session control check."""

    def test_cloud_session_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": True,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.PASS

    def test_cloud_session_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": False,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.FAIL
