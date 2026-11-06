"""Tests for CISA SCuBA Common Controls checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_user_account_event, make_user_usage_row, make_ou_policy


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


class TestSsoVerificationIsManualByDesign:
    """P3: SSO profiles are not a Policy API setting type, so GWS.COMMONCONTROLS.3.1 / 3.2 can
    only ask for review and are unscored."""

    def test_any_sso_shaped_input_is_review(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_sso_verification, check_third_party_sso_verification)
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "sso", {"postSsoVerificationEnabled": True}, "/")]}
        for check in (check_sso_verification, check_third_party_sso_verification):
            result = check(full_audit_data)
            assert result.status in (Status.MANUAL, Status.ERROR), check.__name__
            assert result.scored is False

class TestSessionDurationOU:
    """OU-aware tests for GWS.COMMONCONTROLS.4.1 session duration.

    Rewritten with the real field (security.session_controls.webSessionDuration, a seconds
    string) instead of the invented sessionDurationHours.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "28800s"}, "/"),
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "43200s"}, "/Engineering"),
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
                                {"webSessionDuration": "43200s"}, "/"),
                make_ou_policy("security", "session_controls",
                                {"webSessionDuration": "86400s"}, "/Support"),
            ],
        }
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details
        assert "/Support → 24h" in result.actual_value

    def test_fractional_hours_are_compared_exactly(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "session_controls", {"webSessionDuration": "43201s"})]}
        result = check_session_duration(full_audit_data)
        assert result.status == Status.FAIL  # 12.0003 h is over the 12-hour limit
        assert "12.0h" in result.actual_value

    def test_system_only_value_is_judged(self, full_audit_data):
        """A SYSTEM policy is the value in force: Google's 14-day default fails the control."""
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        entry = make_ou_policy("security", "session_controls", {"webSessionDuration": "1209600s"})
        entry["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["security"] = {"_ou_policies": [entry]}
        assert check_session_duration(full_audit_data).status == Status.FAIL

    def test_missing_duration_is_unknown(self, full_audit_data):
        """Was FAIL: an empty value has no documented default, so the check must not judge it."""
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "session_controls", {})]}
        assert check_session_duration(full_audit_data).status == Status.MANUAL








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
    """GWS.COMMONCONTROLS.10.2 on the real api_controls.unconfigured_third_party_apps.accessLevel."""

    def _set(self, data, *levels):
        data["subscription_type"] = "Google Workspace Enterprise Plus"
        data["policies"]["security"] = {}
        data["policies"]["api_controls"] = {"_ou_policies": [
            make_ou_policy("api_controls", "unconfigured_third_party_apps", {"accessLevel": lv}, ou)
            for ou, lv in levels]}

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk
        self._set(full_audit_data, ("/", "BLOCK_ALL"), ("/Legal", "BLOCK_ALL_SCOPES"))
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk
        self._set(full_audit_data, ("/", "BLOCK_ALL"), ("/Marketing", "ALLOW_SIGN_IN_ONLY"))
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_console_default_allow_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk
        self._set(full_audit_data, ("/", "ACCESS_LEVEL_UNSPECIFIED"))
        assert check_user_consent_low_risk(full_audit_data).status == Status.FAIL

class TestUnconfiguredInternalAppsOU:
    """OU-aware tests for GWS.COMMONCONTROLS.10.3 unconfigured internal apps.

    Rewritten with the real field api_controls.internal_apps.trustInternalApps.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": False}, "/Ops"),
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
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("security", "internal_apps",
                                {"trustInternalApps": True}, "/DevOps"),
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
                                {"trustInternalApps": False}, "/"),
                make_ou_policy("api_controls", "internal_apps",
                                {"trustInternalApps": True}, "/Sandbox"),
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
    """GWS.COMMONCONTROLS.15.2 on the real data_regions.data_processing_region.limitToStorageRegion."""

    def _set(self, data, *flags):
        data["subscription_type"] = "Google Workspace Enterprise Plus"
        data["policies"]["security"] = {}
        data["policies"]["data_regions"] = {"_ou_policies": [
            make_ou_policy("data_regions", "data_processing_region", {"limitToStorageRegion": v}, ou)
            for ou, v in flags]}

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", True), ("/Finance", True))
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", True), ("/Remote", False))
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Remote" in result.details

    def test_live_system_default_fails(self, full_audit_data):
        """The live SYSTEM policy says limitToStorageRegion=false: the value in force fails."""
        from gws_auditor.checks.cisa_commoncontrols import check_data_processing_in_region
        self._set(full_audit_data, ("/", False))
        for e in full_audit_data["policies"]["data_regions"]["_ou_policies"]:
            e["_raw"] = {"type": "SYSTEM"}
        result = check_data_processing_in_region(full_audit_data)
        assert result.status == Status.FAIL and "Google default" in result.details

class TestUnusedServicesDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.1 unused services.

    Rewritten with the real setting enterprise_service_restrictions.service_status.serviceState
    (ENABLED = services without an individual control are restricted).
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {
            "_ou_policies": [
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/"),
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/IT"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {
            "_ou_policies": [
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "ENABLED"}, "/"),
                make_ou_policy("enterprise_service_restrictions", "service_status",
                                {"serviceState": "DISABLED"}, "/Sandbox"),
            ],
        }
        result = check_unused_services_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details

    def test_unspecified_state_is_unknown(self, full_audit_data):
        """Was FAIL: SERVICE_STATE_UNSPECIFIED carries no state."""
        from gws_auditor.checks.cisa_commoncontrols import check_unused_services_disabled

        full_audit_data["policies"]["enterprise_service_restrictions"] = {"_ou_policies": [
            make_ou_policy("enterprise_service_restrictions", "service_status",
                           {"serviceState": "SERVICE_STATE_UNSPECIFIED"})]}
        assert check_unused_services_disabled(full_audit_data).status == Status.MANUAL


class TestEarlyAccessDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.16.2 early access apps.

    Rewritten with the real setting early_access_apps.service_status.serviceState.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {
            "_ou_policies": [
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/"),
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/Security"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {
            "_ou_policies": [
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "DISABLED"}, "/"),
                make_ou_policy("early_access_apps", "service_status",
                                {"serviceState": "ENABLED"}, "/Beta"),
            ],
        }
        result = check_early_access_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Beta" in result.details

    def test_unspecified_state_is_unknown(self, full_audit_data):
        """Was FAIL: SERVICE_STATE_UNSPECIFIED carries no state."""
        from gws_auditor.checks.cisa_commoncontrols import check_early_access_disabled

        full_audit_data["policies"]["early_access_apps"] = {"_ou_policies": [
            make_ou_policy("early_access_apps", "service_status",
                           {"serviceState": "SERVICE_STATE_UNSPECIFIED"})]}
        assert check_early_access_disabled(full_audit_data).status == Status.MANUAL


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


class TestUnknownValuesAreManual:
    """Plan Decision A: an absent field without a documented default, or an *_UNSPECIFIED enum,
    is unknown. No OU may PASS or FAIL because of it; a real non-compliant OU still wins."""

    @pytest.mark.parametrize("setting_key, check_name", [
        ("unconfigured_third_party_apps", "check_user_consent_low_risk"),
        ("internal_apps", "check_unconfigured_internal_apps"),
        ("data_processing_region", "check_data_processing_in_region"),
        ("dlp", "check_dlp_chat"),
        ("dlp", "check_dlp_gmail"),
        ("dlp", "check_dlp_block_external"),
    ])
    def test_empty_value_is_manual(self, full_audit_data, setting_key, check_name):
        """Was FAIL for every one of these: an empty ADMIN value has no documented default."""
        from gws_auditor.checks import cisa_commoncontrols

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", setting_key, {})]}
        result = getattr(cisa_commoncontrols, check_name)(full_audit_data)
        assert result.status == Status.MANUAL, check_name
        assert "could not be determined" in result.details

    def test_non_compliant_ou_beats_unknown_ou(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_user_consent_low_risk

        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("api_controls", "unconfigured_third_party_apps", {}, "/"),
            make_ou_policy("api_controls", "unconfigured_third_party_apps", {"accessLevel": "ALLOW_SIGN_IN_ONLY"}, "/Marketing"),
        ]}
        result = check_user_consent_low_risk(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details
        assert "Undetermined" in result.details and "/" in result.details

    def test_unspecified_dlp_action_is_unknown(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_dlp_block_external

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "dlp", {"defaultAction": "ACTION_UNSPECIFIED"})]}
        assert check_dlp_block_external(full_audit_data).status == Status.MANUAL

    def test_account_recovery_uses_documented_default(self, full_audit_data):
        """enableAccountRecovery has a documented default (false), so an empty value is judged."""
        from gws_auditor.checks.cisa_commoncontrols import check_user_account_recovery_disabled

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "user_account_recovery", {})]}
        assert check_user_account_recovery_disabled(full_audit_data).status == Status.PASS


class TestAdvancedProtection:
    """GWS.COMMONCONTROLS.9.1 / 9.2: three-state verdict from the Policy API self-enrollment flag,
    titanium_enroll / titanium_unenroll events in the user_accounts audit log and the security-key
    and passkey counts of the user usage report."""

    def _allow(self, data, allowed=True, ou="/"):
        data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program",
                           {"enableAdvancedProtectionSelfEnrollment": allowed}, ou)]}

    def test_self_enrollment_disabled_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_admin_advanced_protection, check_sensitive_user_advanced_protection)
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program", {"enableAdvancedProtectionSelfEnrollment": True}, "/"),
            make_ou_policy("security", "advanced_protection_program", {"enableAdvancedProtectionSelfEnrollment": False}, "/Remote")]}
        full_audit_data["_options"] = {"sensitive_users": ["user1@example.com"]}
        for check in (check_admin_advanced_protection, check_sensitive_user_advanced_protection):
            result = check(full_audit_data)
            assert result.status == Status.FAIL, check.__name__
            assert "/Remote" in result.details

    def test_all_admins_enrolled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [
            make_user_account_event("admin1@example.com", "titanium_enroll", "2026-09-01T10:00:00.000Z"),
            make_user_account_event("admin2@example.com", "titanium_enroll", "2026-09-02T10:00:00.000Z")]
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com", num_security_keys=2),
                                         make_user_usage_row("admin2@example.com", num_passkeys_enrolled=2, num_security_keys=0)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["enrolled"] == ["admin1@example.com", "admin2@example.com"]

    def test_unenroll_is_latest_event_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [
            make_user_account_event("admin1@example.com", "titanium_enroll", "2026-09-01T10:00:00.000Z"),
            make_user_account_event("admin1@example.com", "titanium_unenroll", "2026-10-01T10:00:00.000Z"),
            make_user_account_event("admin2@example.com", "titanium_enroll", "2026-09-02T10:00:00.000Z")]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "admin1@example.com [left Advanced Protection on 2026-10-01]" in result.details

    def test_admin_without_key_or_passkey_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com", num_security_keys=0, num_passkeys_enrolled=0),
                                         make_user_usage_row("admin2@example.com", num_security_keys=1)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "admin1@example.com [no security key or passkey" in result.details
        assert "admin2" not in result.details

    def test_no_evidence_is_review(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.MANUAL
        assert "no enrollment event" in result.details and "user_accounts audit log was not collected" in result.details
        assert set(result.actual_value["unknown"]) == {"admin1@example.com", "admin2@example.com"}

    def test_partial_evidence_is_review_not_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["user_account_logs"] = [make_user_account_event("admin1@example.com", "titanium_enroll")]
        full_audit_data["user_usage"] = [make_user_usage_row("admin2@example.com", num_security_keys=1)]
        result = check_admin_advanced_protection(full_audit_data)
        assert result.status == Status.MANUAL
        assert "1 of 2 administrator" in result.details and "admin2@example.com" in result.details

    def test_empty_policy_value_still_assesses_accounts(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "advanced_protection_program", {})]}
        full_audit_data["user_account_logs"] = [make_user_account_event(e, "titanium_enroll")
                                                for e in ("admin1@example.com", "admin2@example.com")]
        assert check_admin_advanced_protection(full_audit_data).status == Status.PASS

    def test_no_admins_collected_is_error(self, full_audit_data):
        """No users means the directory was not collected: ERROR (make_manual), never a verdict."""
        from gws_auditor.checks.cisa_commoncontrols import check_admin_advanced_protection
        full_audit_data["users"] = []
        assert check_admin_advanced_protection(full_audit_data).status == Status.ERROR

    def test_sensitive_users_unconfigured_not_applicable(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection
        self._allow(full_audit_data)
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE
        assert "options.sensitive_users" in result.details

    def test_sensitive_users_from_emails_and_group(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_sensitive_user_advanced_protection
        self._allow(full_audit_data)
        full_audit_data["_options"] = {"sensitive_users": ["User1@example.com", "execs@example.com"]}
        full_audit_data["group_members"] = {"execs@example.com": [{"email": "ceo@example.com"}, {"email": "cfo@example.com"}]}
        full_audit_data["user_account_logs"] = [make_user_account_event(e, "titanium_enroll")
                                                for e in ("user1@example.com", "ceo@example.com", "cfo@example.com")]
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["enrolled"] == ["ceo@example.com", "cfo@example.com", "user1@example.com"]
        full_audit_data["user_usage"] = [make_user_usage_row("cfo@example.com", num_security_keys=0, num_passkeys_enrolled=0)]
        result = check_sensitive_user_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL and "cfo@example.com" in result.details
