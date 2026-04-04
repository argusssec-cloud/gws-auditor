"""Tests for CISA SCuBA Common Controls checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestContextAwareAccess:
    """Tests for GWS.COMMONCONTROLS.2.1 context-aware access."""

    def test_context_aware_access_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "context_aware_access": {"device_policies_configured": True},
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS

    def test_context_aware_access_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "context_aware_access": {"device_policies_configured": False},
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.FAIL


class TestSSOVerification:
    """Tests for GWS.COMMONCONTROLS.3.x SSO verification checks."""

    def test_sso_verification_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification

        full_audit_data["policies"]["security"] = {
            "sso": {"post_sso_verification_enabled": True},
        }
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.PASS

    def test_sso_verification_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification

        full_audit_data["policies"]["security"] = {
            "sso": {"post_sso_verification_enabled": False},
        }
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.FAIL

    def test_third_party_sso_verification_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification

        full_audit_data["policies"]["security"] = {
            "sso": {"third_party_sso_verification_enabled": True},
        }
        result = check_third_party_sso_verification(full_audit_data)
        assert result.status == Status.PASS

    def test_third_party_sso_verification_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification

        full_audit_data["policies"]["security"] = {
            "sso": {"third_party_sso_verification_enabled": False},
        }
        result = check_third_party_sso_verification(full_audit_data)
        assert result.status == Status.FAIL


class TestSessionManagement:
    """Tests for GWS.COMMONCONTROLS.4.1 session duration."""

    def test_session_duration_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "session_management": {"session_duration_hours": 12},
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.PASS

    def test_session_duration_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "session_management": {"session_duration_hours": 24},
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL


class TestAdminCloudOnly:
    """Tests for GWS.COMMONCONTROLS.6.1 admin cloud-only accounts."""

    def test_admin_cloud_only_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only

        full_audit_data["users"] = [
            {
                "primaryEmail": "admin@example.com",
                "is_super_admin": True,
                "is_federated": False,
            },
        ]
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.PASS

    def test_admin_cloud_only_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_cloud_only

        full_audit_data["users"] = [
            {
                "primaryEmail": "admin@example.com",
                "is_super_admin": True,
                "is_federated": True,
            },
        ]
        result = check_admin_cloud_only(full_audit_data)
        assert result.status == Status.FAIL


class TestAccountRecovery:
    """Tests for GWS.COMMONCONTROLS.8.x account recovery checks."""

    def test_recovery_info_always_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_recovery_info_disabled
        result = check_recovery_info_disabled(full_audit_data)
        assert result.status == Status.MANUAL


class TestAdvancedProtection:
    """Tests for GWS.COMMONCONTROLS.9.x Advanced Protection Program checks."""

    def test_admin_advanced_protection_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection

        full_audit_data["policies"]["security"] = {
            "advanced_protection": {"admin_enrollment_enforced": True},
        }
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.PASS

    def test_admin_advanced_protection_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection

        full_audit_data["policies"]["security"] = {
            "advanced_protection": {"admin_enrollment_enforced": False},
        }
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL

    def test_sensitive_user_advanced_protection_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection

        full_audit_data["policies"]["security"] = {
            "advanced_protection": {"sensitive_user_enrollment": True},
        }
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.PASS

    def test_sensitive_user_advanced_protection_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection

        full_audit_data["policies"]["security"] = {
            "advanced_protection": {"sensitive_user_enrollment": False},
        }
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL


class TestAppAccessControl:
    """Tests for GWS.COMMONCONTROLS.10.x app access control checks."""

    def test_third_party_api_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted

        full_audit_data["policies"]["security"] = {
            "app_access": {"third_party_api_access_restricted": True},
        }
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.PASS

    def test_third_party_api_restricted_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted

        full_audit_data["policies"]["security"] = {
            "app_access": {"third_party_api_access_restricted": False},
        }
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.FAIL

    def test_user_consent_low_risk_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_user_consent_low_risk": False},
        }
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.PASS

    def test_user_consent_low_risk_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_user_consent_low_risk": True},
        }
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL

    def test_unconfigured_internal_apps_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"trust_unconfigured_internal_apps": False},
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_unconfigured_internal_apps_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"trust_unconfigured_internal_apps": True},
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL

    def test_unconfigured_third_party_apps_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_unconfigured_third_party_apps": False},
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_unconfigured_third_party_apps_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "app_access": {"allow_unconfigured_third_party_apps": True},
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL


class TestAuditLogRetention:
    """Tests for GWS.COMMONCONTROLS.14.2 audit log retention."""

    def test_audit_log_retention_always_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_audit_log_retention

        result = check_audit_log_retention(full_audit_data)
        assert result.status == Status.MANUAL


class TestDataRegions:
    """Tests for GWS.COMMONCONTROLS.15.2 data processing in region."""

    def test_data_processing_in_region_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "data_regions": {"processing_in_region": True},
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.PASS

    def test_data_processing_in_region_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "data_regions": {"processing_in_region": False},
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL


class TestServiceStatus:
    """Tests for GWS.COMMONCONTROLS.16.x service status checks."""

    def test_unused_services_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"unused_services_disabled": True},
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_unused_services_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"unused_services_disabled": False},
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_early_access_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"early_access_enabled": False},
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_early_access_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "service_status": {"early_access_enabled": True},
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.FAIL


class TestDLP:
    """Tests for GWS.COMMONCONTROLS.18.x DLP checks."""

    def test_dlp_chat_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_chat

        full_audit_data["policies"]["security"] = {
            "dlp": {"chat_dlp_rules": ["rule1"]},
        }
        result = check_dlp_chat(full_audit_data)
        assert result.status == Status.PASS

    def test_dlp_chat_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_chat

        full_audit_data["policies"]["security"] = {
            "dlp": {"chat_dlp_rules": []},
        }
        result = check_dlp_chat(full_audit_data)
        assert result.status == Status.FAIL

    def test_dlp_gmail_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_gmail

        full_audit_data["policies"]["security"] = {
            "dlp": {"gmail_dlp_rules": ["rule1", "rule2", "rule3"]},
        }
        result = check_dlp_gmail(full_audit_data)
        assert result.status == Status.PASS

    def test_dlp_gmail_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_gmail

        full_audit_data["policies"]["security"] = {
            "dlp": {"gmail_dlp_rules": []},
        }
        result = check_dlp_gmail(full_audit_data)
        assert result.status == Status.FAIL

    def test_dlp_block_external_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external

        full_audit_data["policies"]["security"] = {
            "dlp": {"default_action": "block_external"},
        }
        result = check_dlp_block_external(full_audit_data)
        assert result.status == Status.PASS

    def test_dlp_block_external_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external

        full_audit_data["policies"]["security"] = {
            "dlp": {"default_action": "warn"},
        }
        result = check_dlp_block_external(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------

class TestContextAwareAccessOU:
    """OU-aware tests for GWS.COMMONCONTROLS.2.1 context-aware access."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/Engineering"),
            ],
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_context_aware_access

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"devicePoliciesConfigured": False}, "/Sales"),
            ],
        }
        result = check_context_aware_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestSSOVerificationOU:
    """OU-aware tests for GWS.COMMONCONTROLS.3.1 SSO verification."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "sso",
                                {"postSsoVerificationEnabled": True}, "/"),
                make_ou_policy("security", "sso",
                                {"postSsoVerificationEnabled": True}, "/Engineering"),
            ],
        }
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sso_verification

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "sso",
                                {"postSsoVerificationEnabled": True}, "/"),
                make_ou_policy("security", "sso",
                                {"postSsoVerificationEnabled": False}, "/Marketing"),
            ],
        }
        result = check_sso_verification(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestThirdPartySSOVerificationOU:
    """OU-aware tests for GWS.COMMONCONTROLS.3.2 third-party SSO verification."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "sso",
                                {"thirdPartySsoVerificationEnabled": True}, "/"),
                make_ou_policy("security", "sso",
                                {"thirdPartySsoVerificationEnabled": True}, "/Finance"),
            ],
        }
        result = check_third_party_sso_verification(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_sso_verification

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "sso",
                                {"thirdPartySsoVerificationEnabled": True}, "/"),
                make_ou_policy("security", "sso",
                                {"thirdPartySsoVerificationEnabled": False}, "/Contractors"),
            ],
        }
        result = check_third_party_sso_verification(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details


class TestSessionDurationOU:
    """OU-aware tests for GWS.COMMONCONTROLS.4.1 session duration."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "session_controls",
                                {"sessionDurationHours": 8}, "/"),
                make_ou_policy("security", "session_controls",
                                {"sessionDurationHours": 12}, "/Engineering"),
            ],
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "session_controls",
                                {"sessionDurationHours": 12}, "/"),
                make_ou_policy("security", "session_controls",
                                {"sessionDurationHours": 24}, "/Support"),
            ],
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details


class TestAdminAdvancedProtectionOU:
    """OU-aware tests for GWS.COMMONCONTROLS.9.1 admin Advanced Protection."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"adminEnrollmentEnforced": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"adminEnrollmentEnforced": True}, "/IT"),
            ],
        }
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"adminEnrollmentEnforced": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"adminEnrollmentEnforced": False}, "/Remote"),
            ],
        }
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Remote" in result.details


class TestSensitiveUserAdvancedProtectionOU:
    """OU-aware tests for GWS.COMMONCONTROLS.9.2 sensitive user Advanced Protection."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"sensitiveUserEnrollment": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"sensitiveUserEnrollment": True}, "/Executives"),
            ],
        }
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"sensitiveUserEnrollment": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"sensitiveUserEnrollment": False}, "/Vendors"),
            ],
        }
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Vendors" in result.details


class TestThirdPartyApiRestrictedOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.1 third-party API restriction."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": True}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": True}, "/Engineering"),
            ],
        }
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": True}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": False}, "/Labs"),
            ],
        }
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Labs" in result.details

    def test_fallback_to_api_controls(self, full_audit_data):
        """When security has no matching _ou_policies, fall back to api_controls."""
        from gws_auditor.checks.cisa_commoncontrols import check_third_party_api_restricted

        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["api_controls"] = {
            "_ou_policies": [
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": True}, "/"),
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"thirdPartyApiAccessRestricted": False}, "/Research"),
            ],
        }
        result = check_third_party_api_restricted(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Research" in result.details


class TestUserConsentLowRiskOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.2 user consent low-risk scopes."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "app_access",
                                {"allowUserConsentLowRisk": False}, "/"),
                make_ou_policy("security", "app_access",
                                {"allowUserConsentLowRisk": False}, "/Legal"),
            ],
        }
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "app_access",
                                {"allowUserConsentLowRisk": False}, "/"),
                make_ou_policy("security", "app_access",
                                {"allowUserConsentLowRisk": True}, "/Marketing"),
            ],
        }
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestUnconfiguredInternalAppsOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.3 unconfigured internal apps."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "internal_apps",
                                {"trustUnconfiguredInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustUnconfiguredInternalApps": False}, "/Ops"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "internal_apps",
                                {"trustUnconfiguredInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustUnconfiguredInternalApps": True}, "/DevOps"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/DevOps" in result.details

    def test_fallback_to_api_controls(self, full_audit_data):
        """When security has no matching _ou_policies, fall back to api_controls."""
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["api_controls"] = {
            "_ou_policies": [
                make_ou_policy("api_controls", "internal_apps",
                                {"trustUnconfiguredInternalApps": False}, "/"),
                make_ou_policy("api_controls", "internal_apps",
                                {"trustUnconfiguredInternalApps": True}, "/Sandbox"),
            ],
        }
        result = check_unconfigured_internal_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details


class TestUnconfiguredThirdPartyAppsOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.4 unconfigured third-party apps."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/Security"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": True}, "/Testing"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Testing" in result.details

    def test_fallback_to_api_controls(self, full_audit_data):
        """When security has no matching _ou_policies, fall back to api_controls."""
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["api_controls"] = {
            "_ou_policies": [
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": False}, "/"),
                make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                {"allowUnconfiguredThirdPartyApps": True}, "/External"),
            ],
        }
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/External" in result.details


class TestDataProcessingInRegionOU:
    """OU-aware tests for GWS.COMMONCONTROLS.15.2 data processing in region."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "data_regions",
                                {"processingInRegion": True}, "/"),
                make_ou_policy("security", "data_regions",
                                {"processingInRegion": True}, "/Finance"),
            ],
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "data_regions",
                                {"processingInRegion": True}, "/"),
                make_ou_policy("security", "data_regions",
                                {"processingInRegion": False}, "/Remote"),
            ],
        }
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Remote" in result.details


class TestUnusedServicesDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.1 unused services."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "service_status",
                                {"unusedServicesDisabled": True}, "/"),
                make_ou_policy("security", "service_status",
                                {"unusedServicesDisabled": True}, "/IT"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "service_status",
                                {"unusedServicesDisabled": True}, "/"),
                make_ou_policy("security", "service_status",
                                {"unusedServicesDisabled": False}, "/Sandbox"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details


class TestEarlyAccessDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.2 early access apps."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "service_status",
                                {"earlyAccessEnabled": False}, "/"),
                make_ou_policy("security", "service_status",
                                {"earlyAccessEnabled": False}, "/Security"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "service_status",
                                {"earlyAccessEnabled": False}, "/"),
                make_ou_policy("security", "service_status",
                                {"earlyAccessEnabled": True}, "/Beta"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Beta" in result.details


class TestDlpChatOU:
    """OU-aware tests for GWS.COMMONCONTROLS.18.2 DLP for Chat."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_chat

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"chatDlpRules": ["rule1"]}, "/"),
                make_ou_policy("security", "dlp",
                                {"chatDlpRules": ["rule2"]}, "/Legal"),
            ],
        }
        result = check_dlp_chat(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_chat

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"chatDlpRules": ["rule1"]}, "/"),
                make_ou_policy("security", "dlp",
                                {"chatDlpRules": []}, "/Interns"),
            ],
        }
        result = check_dlp_chat(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details


class TestDlpGmailOU:
    """OU-aware tests for GWS.COMMONCONTROLS.18.3 DLP for Gmail."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_gmail

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"gmailDlpRules": ["rule1"]}, "/"),
                make_ou_policy("security", "dlp",
                                {"gmailDlpRules": ["rule2"]}, "/HR"),
            ],
        }
        result = check_dlp_gmail(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_gmail

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"gmailDlpRules": ["rule1"]}, "/"),
                make_ou_policy("security", "dlp",
                                {"gmailDlpRules": []}, "/Contractors"),
            ],
        }
        result = check_dlp_gmail(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details


class TestDlpBlockExternalOU:
    """OU-aware tests for GWS.COMMONCONTROLS.18.4 DLP block external."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"defaultAction": "block"}, "/"),
                make_ou_policy("security", "dlp",
                                {"defaultAction": "block_external"}, "/Engineering"),
            ],
        }
        result = check_dlp_block_external(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "dlp",
                                {"defaultAction": "block"}, "/"),
                make_ou_policy("security", "dlp",
                                {"defaultAction": "warn"}, "/Sales"),
            ],
        }
        result = check_dlp_block_external(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details
