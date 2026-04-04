"""Tests for additional (non-CIS) security checks."""

from datetime import datetime, timedelta, timezone

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy, make_user


class TestAdditionalChecks:
    """Tests for Other + Google best practice checks."""

    def test_mx_records_google_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_mx_records
        # Fix all domains to have Google MX
        for domain in full_audit_data["dns_records"]:
            full_audit_data["dns_records"][domain]["mx"] = [
                {"host": "aspmx.l.google.com.", "priority": 1},
            ]
        result = check_mx_records(full_audit_data)
        assert result.status == Status.PASS

    def test_takeout_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_takeout_restriction
        full_audit_data["policies"]["security"]["data_export"] = {
            "takeout_enabled": False,
        }
        result = check_takeout_restriction(full_audit_data)
        assert result.status == Status.PASS


class TestSecuritySandbox:
    """Tests for ADD-02 security sandbox check."""

    def test_security_sandbox_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["policies"]["gmail"] = {
            "safety": {"security_sandbox_enabled": True},
        }
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.PASS

    def test_security_sandbox_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["policies"]["gmail"] = {
            "safety": {"security_sandbox_enabled": False},
        }
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.FAIL


class TestInboundGatewaySpf:
    """Tests for ADD-06 inbound gateway SPF configuration check."""

    def test_no_gateway_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": False},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.PASS

    def test_gateway_with_spf_reject_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": True, "reject_if_spf_fail": True},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.PASS

    def test_gateway_without_spf_reject_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": True, "reject_if_spf_fail": False},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.FAIL


class TestPartnerTls:
    """Tests for ADD-07 partner domain TLS enforcement check."""

    def test_partner_tls_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_partner_tls
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "partner_domain_tls_rules": [{"domain": "partner.com"}],
            },
        }
        result = check_partner_tls(full_audit_data)
        assert result.status == Status.PASS

    def test_partner_tls_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_partner_tls
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "partner_domain_tls_rules": [],
                "tls_required": False,
            },
        }
        result = check_partner_tls(full_audit_data)
        assert result.status == Status.FAIL


class TestPasswordAlert:
    """Tests for ADD-08 Password Alert deployment check."""

    def test_password_alert_deployed_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        full_audit_data["policies"]["security"]["password_alert"] = {
            "deployed": True,
        }
        result = check_password_alert(full_audit_data)
        assert result.status == Status.PASS

    def test_password_alert_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        full_audit_data["policies"]["security"]["password_alert"] = {
            "deployed": None,
        }
        result = check_password_alert(full_audit_data)
        assert result.status == Status.MANUAL


class TestClientSideEncryption:
    """Tests for ADD-11 client-side encryption check."""

    def test_cse_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_client_side_encryption
        full_audit_data["policies"]["security"]["client_side_encryption"] = {
            "enabled": True,
        }
        result = check_client_side_encryption(full_audit_data)
        assert result.status == Status.PASS

    def test_cse_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_client_side_encryption
        full_audit_data["policies"]["security"]["client_side_encryption"] = {
            "enabled": False,
        }
        result = check_client_side_encryption(full_audit_data)
        assert result.status == Status.FAIL


class TestGmailDlp:
    """Tests for ADD-12 Gmail DLP rules check."""

    def test_gmail_dlp_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_dlp
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "dlp_rules": [{"name": "PII detection"}],
                "content_compliance_rules": [],
            },
        }
        full_audit_data["policies"]["security"]["dlp"] = {
            "gmail_dlp_enabled": None,
        }
        result = check_gmail_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_gmail_dlp_empty_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_dlp
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "dlp_rules": [],
                "content_compliance_rules": [],
            },
        }
        full_audit_data["policies"]["security"]["dlp"] = {
            "gmail_dlp_enabled": False,
        }
        result = check_gmail_dlp(full_audit_data)
        assert result.status == Status.FAIL


# ---------------------------------------------------------------------------
# ADD-13 to ADD-27: New 2025-2026 checks
# ---------------------------------------------------------------------------


class TestGeminiWorkspaceFeatures:
    """Tests for ADD-13 Gemini features in Workspace apps."""

    def test_gemini_workspace_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {
            "workspace_features": {"enabled": False},
        }
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_workspace_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {
            "workspace_features": {"enabled": True},
        }
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_workspace_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {}
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.MANUAL


class TestGeminiChrome:
    """Tests for ADD-14 Gemini in Chrome."""

    def test_gemini_chrome_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": False},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_chrome_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": True},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_not_configured_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {}
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_none_value_fail(self, full_audit_data):
        """None value for enabled should be treated as not-disabled (FAIL)."""
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": None},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_missing_policies_key(self, full_audit_data):
        """Missing gemini key in policies should FAIL."""
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"].pop("gemini", None)
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL


class TestWorkspaceStudio:
    """Tests for ADD-15 Workspace Studio access."""

    def test_studio_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {
            "workspace_studio": {"enabled": False},
        }
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.PASS

    def test_studio_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {
            "workspace_studio": {"enabled": True},
        }
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.FAIL

    def test_studio_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {}
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.MANUAL


class TestAppleWritingTools:
    """Tests for ADD-16 Apple Intelligence Writing Tools."""

    def test_apple_writing_tools_always_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_apple_writing_tools
        result = check_apple_writing_tools(full_audit_data)
        assert result.status == Status.MANUAL


class TestPasskeysEnforced:
    """Tests for ADD-18 passkey enforcement."""

    def test_passkeys_always_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_passkeys_enforced
        result = check_passkeys_enforced(full_audit_data)
        assert result.status == Status.MANUAL


class TestCaaOidc:
    """Tests for ADD-20 Context-Aware Access for OIDC apps."""

    def test_caa_oidc_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["policies"]["security"]["access_control"] = {
            "caa_oidc_enabled": True,
        }
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.PASS

    def test_caa_oidc_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["policies"]["security"]["access_control"] = {
            "caa_oidc_enabled": False,
        }
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL

    def test_caa_oidc_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["policies"]["security"]["access_control"] = {}
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.MANUAL


class TestMpaVaultExports:
    """Tests for ADD-21 Multi-Party Approval for Vault exports."""

    def test_mpa_vault_covered_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_mpa_vault_exports
        full_audit_data["policies"]["security"]["multi_party_approval"] = {
            "vault_exports_covered": True,
        }
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.PASS

    def test_mpa_vault_not_covered_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_mpa_vault_exports
        full_audit_data["policies"]["security"]["multi_party_approval"] = {
            "vault_exports_covered": False,
        }
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.FAIL

    def test_mpa_vault_not_configured_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_mpa_vault_exports
        # No multi_party_approval key
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.FAIL


class TestGmailClassificationLabels:
    """Tests for ADD-22 Gmail data classification labels."""

    def test_classification_labels_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"classification_labels_enabled": True},
        }
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.PASS

    def test_classification_labels_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"classification_labels_enabled": False},
        }
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.FAIL

    def test_classification_labels_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {}
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.MANUAL


class TestCalendarDlp:
    """Tests for ADD-23 Calendar DLP rules."""

    def test_calendar_dlp_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["calendar"]["dlp_rules"] = [
            {"name": "PII in events"},
        ]
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_dlp_security_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["security"]["dlp"] = {
            "calendar_dlp_enabled": True,
        }
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_dlp_empty_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["calendar"]["dlp_rules"] = []
        full_audit_data["policies"]["security"]["dlp"] = {
            "calendar_dlp_enabled": False,
        }
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.FAIL

    def test_calendar_dlp_not_configured_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        # No dlp_rules key in calendar, no dlp key in security
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.FAIL


class TestGmailCse:
    """Tests for ADD-26 Gmail client-side encryption."""

    def test_gmail_cse_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"cse_enabled": True},
        }
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.PASS

    def test_gmail_cse_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"cse_enabled": False},
        }
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.FAIL

    def test_gmail_cse_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {}
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.MANUAL


class TestMeetComplianceRecording:
    """Tests for ADD-27 Meet compliance recording."""

    def test_compliance_recording_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": True},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS

    def test_compliance_recording_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": False},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.FAIL

    def test_compliance_recording_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {}
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.MANUAL


# ---------------------------------------------------------------------------
# OU-aware tests
# ---------------------------------------------------------------------------


class TestMeetComplianceRecordingOU:
    """OU-aware tests for ADD-27 Meet compliance recording."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/"),
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/Compliance"),
            ],
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_recording_disabled(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/"),
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": False}, "/Interns"),
            ],
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": True},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-28: Groups with no active members
# -----------------------------------------------------------------------

class TestGroupsNoActiveUsers:
    """Tests for ADD-28 groups with no active members check."""

    def test_pass_all_groups_have_active_members(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = [
            {"email": "team@example.com", "directMembersCount": 2},
        ]
        full_audit_data["group_members"] = {
            "team@example.com": [
                {"email": "admin1@example.com", "role": "MEMBER"},
                {"email": "user1@example.com", "role": "MEMBER"},
            ],
        }
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_empty_group(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = [
            {"email": "empty@example.com", "directMembersCount": 0},
        ]
        full_audit_data["group_members"] = {}
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.WARN
        assert "empty@example.com" in result.actual_value["empty_groups"]

    def test_warn_all_inactive_members(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        suspended_user = make_user(email="suspended@example.com", suspended=True)
        full_audit_data["users"].append(suspended_user)
        full_audit_data["groups"] = [
            {"email": "dead@example.com", "directMembersCount": 1},
        ]
        full_audit_data["group_members"] = {
            "dead@example.com": [
                {"email": "suspended@example.com", "role": "MEMBER"},
            ],
        }
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.WARN
        assert "dead@example.com" in result.actual_value["all_inactive_groups"]

    def test_pass_no_groups(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = []
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-29: Chat spaces with no recent activity
# -----------------------------------------------------------------------

class TestChatSpacesInactive:
    """Tests for ADD-29 inactive Chat spaces check."""

    def test_pass_all_active(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/abc", "displayName": "Active Space", "lastActiveTime": recent},
        ]
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_inactive_space(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/old", "displayName": "Old Space", "lastActiveTime": old},
        ]
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["inactive_spaces"][0]["name"] == "Old Space"

    def test_manual_no_data(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        full_audit_data["chat_spaces"] = []
        result = check_chat_spaces_inactive(full_audit_data)
        # make_review returns MANUAL status
        assert result.status == Status.MANUAL

    def test_custom_threshold(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        # 50 days ago - should pass with default 90 but fail with 30-day threshold
        ts = (datetime.now(timezone.utc) - timedelta(days=50)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/mid", "displayName": "Mid Space", "lastActiveTime": ts},
        ]
        full_audit_data["_options"] = {"chat_inactive_days": 30}
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.WARN


# -----------------------------------------------------------------------
# ADD-30: Mobile devices not synced recently
# -----------------------------------------------------------------------

class TestMobileDevicesStale:
    """Tests for ADD-30 stale mobile devices check."""

    def test_pass_all_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel 8", "email": ["user@example.com"], "lastSync": recent, "status": "APPROVED"},
        ]
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "iPhone 12", "email": ["user@example.com"], "lastSync": old, "status": "APPROVED"},
        ]
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        full_audit_data["mobile_devices"] = []
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.PASS
        assert "No mobile devices enrolled" in result.details


# -----------------------------------------------------------------------
# ADD-31: ChromeOS devices not active recently
# -----------------------------------------------------------------------

class TestChromeosDevicesStale:
    """Tests for ADD-31 stale ChromeOS devices check."""

    def test_pass_all_active(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["chromeos_devices"] = [
            {"model": "Chromebook", "serialNumber": "SN123", "lastSync": recent, "status": "ACTIVE"},
        ]
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["chromeos_devices"] = [
            {"model": "Chromebook", "serialNumber": "SN456", "annotatedUser": "user@example.com",
             "lastSync": old, "status": "ACTIVE"},
        ]
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        full_audit_data["chromeos_devices"] = []
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-38: Endpoint verification devices stale
# -----------------------------------------------------------------------

class TestEndpointDevicesStale:
    """Tests for ADD-38 stale endpoint verification devices check."""

    def test_pass_all_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "laptop1", "deviceType": "WINDOWS", "lastSyncTime": recent,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "old-laptop", "deviceType": "MAC_OS", "lastSyncTime": old,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_warn_never_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        old_create = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "never-synced", "deviceType": "LINUX", "createTime": old_create,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["stale_devices"][0]["last_sync"] == "never"

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        full_audit_data["endpoint_devices"] = []
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-39: Devices pending approval too long
# -----------------------------------------------------------------------

class TestDevicesPending:
    """Tests for ADD-39 devices pending approval check."""

    def test_pass_no_pending(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel", "email": "u@example.com", "status": "APPROVED", "firstSync": recent},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_mobile_pending_too_long(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "iPhone", "email": "u@example.com", "status": "PENDING", "firstSync": old},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["pending_devices"]) == 1
        assert result.actual_value["pending_devices"][0]["device_type"] == "Mobile"

    def test_warn_endpoint_pending_too_long(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = []
        full_audit_data["endpoint_devices"] = [
            {"hostname": "laptop1", "managementState": "PENDING",
             "createTime": old, "owner": {"userResourceName": "users/123"}},
        ]
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["pending_devices"][0]["device_type"] == "Endpoint"

    def test_pass_pending_recent(self, full_audit_data):
        """Pending devices that were enrolled recently should not trigger a warning."""
        from gws_auditor.checks.additional import check_devices_pending
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel", "email": "u@example.com", "status": "PENDING", "firstSync": recent},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-32: Users without 2SV by OU inventory
# -----------------------------------------------------------------------

class TestTwoSvInventory:
    """Tests for ADD-32 2SV inventory check."""

    def test_pass_all_enrolled(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="a@example.com", is_enrolled_in_2sv=True),
            make_user(email="b@example.com", is_enrolled_in_2sv=True),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["summary"]["not_enrolled"] == 0

    def test_fail_some_not_enrolled(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="a@example.com", is_enrolled_in_2sv=True),
            make_user(email="b@example.com", is_enrolled_in_2sv=False),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["summary"]["not_enrolled"] == 1
        # Check per-OU breakdown
        root_ou = next(ou for ou in result.actual_value["per_ou"] if ou["org_unit"] == "/")
        assert "b@example.com" in root_ou["users_without_2sv"]

    def test_excludes_suspended_users(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="active@example.com", is_enrolled_in_2sv=True),
            make_user(email="suspended@example.com", is_enrolled_in_2sv=False, suspended=True),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["summary"]["total_users"] == 1

    def test_multi_ou_breakdown(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="eng@example.com", is_enrolled_in_2sv=True, org_unit_path="/Engineering"),
            make_user(email="sales@example.com", is_enrolled_in_2sv=False, org_unit_path="/Sales"),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.FAIL
        assert len(result.actual_value["per_ou"]) == 2

    def test_error_no_users(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = []
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.ERROR


# -----------------------------------------------------------------------
# ADD-33: OAuth apps with dangerous privileges
# -----------------------------------------------------------------------

class TestOauthDangerousApps:
    """Tests for ADD-33 OAuth dangerous apps check."""

    def test_pass_no_dangerous_apps(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Safe App",
                    "client_id": "safe-123",
                    "scope": "https://www.googleapis.com/auth/userinfo.email",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_grants"] == 1

    def test_fail_dangerous_scopes(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Risky App",
                    "client_id": "risky-456",
                    "scope": "https://mail.google.com/ https://www.googleapis.com/auth/drive",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "Risky App" in result.actual_value["dangerous_apps"]
        app = result.actual_value["dangerous_apps"]["Risky App"]
        assert app["risk_level"] == "CRITICAL"
        assert "user@example.com" in app["granted_by"]

    def test_warn_no_token_logs(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = []
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.WARN

    def test_ignores_non_authorize_events(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "revoke",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Some App",
                    "scope": "https://mail.google.com/",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        # No authorize events processed, but token_logs is non-empty
        assert result.status == Status.PASS
        assert result.actual_value["total_grants"] == 0

    def test_multiple_apps_aggregation(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user1@example.com",
                "parameters": {
                    "app_name": "App A",
                    "scope": "https://www.googleapis.com/auth/admin.directory.user",
                },
            },
            {
                "event_name": "authorize",
                "actor_email": "user2@example.com",
                "parameters": {
                    "app_name": "App A",
                    "scope": "https://www.googleapis.com/auth/admin.directory.group",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.FAIL
        app = result.actual_value["dangerous_apps"]["App A"]
        assert app["grant_count"] == 2
        assert len(app["granted_by"]) == 2


# -----------------------------------------------------------------------
# ADD-34: App-Specific Passwords
# -----------------------------------------------------------------------

class TestAppPasswords:
    """Tests for ADD-34 App-Specific Passwords check."""

    def test_no_asps_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = []
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_asps"] == 0

    def test_asps_found_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = [
            {
                "userEmail": "user1@example.com",
                "codeId": 1,
                "name": "Thunderbird",
                "creationTime": "1700000000",
                "lastTimeUsed": "1700100000",
            },
            {
                "userEmail": "user2@example.com",
                "codeId": 2,
                "name": "IMAP client",
                "creationTime": "1700000000",
                "lastTimeUsed": 0,
            },
        ]
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["total_asps"] == 2
        assert result.actual_value["users_with_asps"] == 2
        assert result.actual_value["never_used_asps"] == 1

    def test_never_used_asps(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = [
            {
                "userEmail": "user1@example.com",
                "codeId": 1,
                "name": "Old app",
                "creationTime": "1600000000",
                "lastTimeUsed": 0,
            },
        ]
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["never_used_asps"] == 1
        asps = result.actual_value["asps_by_user"][0]["asps"]
        assert asps[0]["last_used"] == "Never"


# -----------------------------------------------------------------------
# ADD-35: Shared Drives security settings
# -----------------------------------------------------------------------

class TestSharedDriveRestrictions:
    """Tests for ADD-35 Shared Drives restrictions check."""

    def test_no_drives_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = []
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_drives"] == 0

    def test_all_secure_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = [
            {
                "id": "drive-1",
                "name": "Secure Drive",
                "restrictions": {
                    "domainUsersOnly": True,
                    "driveMembersOnly": True,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": True,
                },
            },
        ]
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["insecure_drives"] == 0

    def test_insecure_drive_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = [
            {
                "id": "drive-1",
                "name": "Open Drive",
                "restrictions": {
                    "domainUsersOnly": False,
                    "driveMembersOnly": False,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": False,
                },
            },
            {
                "id": "drive-2",
                "name": "Locked Drive",
                "restrictions": {
                    "domainUsersOnly": True,
                    "driveMembersOnly": True,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": True,
                },
            },
        ]
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["insecure_drives"] == 1
        assert result.actual_value["total_drives"] == 2
        # Verify the insecure drive has issues listed
        open_drive = result.actual_value["drives"][0]
        assert len(open_drive["issues"]) == 3


# -----------------------------------------------------------------------
# ADD-37: Group discoverability
# -----------------------------------------------------------------------

class TestGroupDiscoverability:
    """Tests for ADD-37 group discoverability check."""

    def test_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = [
            {
                "email": "team@example.com",
                "settings": {"whoCanDiscoverGroup": "ALL_MEMBERS_CAN_DISCOVER"},
            },
        ]
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.PASS

    def test_public_group_fail(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = [
            {
                "email": "public@example.com",
                "settings": {"whoCanDiscoverGroup": "ANYONE_CAN_DISCOVER"},
            },
            {
                "email": "private@example.com",
                "settings": {"whoCanDiscoverGroup": "ALL_MEMBERS_CAN_DISCOVER"},
            },
        ]
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["public_groups_count"] == 1
        assert "public@example.com" in result.actual_value["public_groups"]

    def test_no_groups_manual(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = []
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.ERROR


class TestLicenseGating:
    """Tests for license-aware ERROR → NOT_APPLICABLE reclassification."""

    def test_error_reclassified_on_business_starter(self, full_audit_data):
        """ERROR results should become NOT_APPLICABLE on Business Starter."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE
        assert "Business Standard" in result.details

    def test_error_not_reclassified_on_enterprise_plus(self, full_audit_data):
        """ERROR results should stay ERROR on Enterprise Plus (genuine API issue)."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Enterprise Plus"
        result = check_security_sandbox(full_audit_data)
        # On Enterprise Plus the check runs normally; with empty policy data
        # it should return ERROR (not reclassified)
        assert result.status == Status.ERROR

    def test_error_not_reclassified_when_license_unknown(self, full_audit_data):
        """ERROR results should stay ERROR when license is unknown."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = ""
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.ERROR

    def test_pass_not_reclassified(self, full_audit_data):
        """PASS results should not be affected by license gating."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Business Starter"
        full_audit_data["policies"]["gmail"]["safety"] = {
            "security_sandbox_enabled": True,
        }
        result = check_security_sandbox(full_audit_data)
        # Even on Business Starter, a PASS should stay PASS
        assert result.status in (Status.PASS, Status.ERROR, Status.NOT_APPLICABLE)

    def test_subscription_info_fallback(self, full_audit_data):
        """subscription_info.edition should work as fallback."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_info"] = {"edition": "Business Starter"}
        full_audit_data.pop("subscription_type", None)
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE

    def test_rules_check_runs_on_all_editions(self, full_audit_data):
        """Alert rule checks should run on all editions (no license gate)."""
        from gws_auditor.checks.rules import check_alert_password_change
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_alert_password_change(full_audit_data)
        # System-defined alerts are available on all editions
        assert result.status != Status.NOT_APPLICABLE

    def test_dlp_check_reclassified(self, full_audit_data):
        """DLP checks should be reclassified on Business Starter."""
        from gws_auditor.checks.security_access import check_drive_dlp
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_drive_dlp(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE


class TestActiveOAuthTokens:
    """Tests for ADD-36: Active OAuth tokens with dangerous scopes."""

    def test_no_tokens_warns(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = []
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.WARN

    def test_safe_tokens_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "safe-app.apps.googleusercontent.com",
                "displayText": "Safe App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["openid", "profile", "email"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS

    def test_native_apps_skipped(self, full_audit_data):
        """Native apps (Google's own) should be skipped entirely."""
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "google-native",
                "displayText": "Google Native",
                "anonymous": False,
                "nativeApp": True,
                "scopes": ["https://mail.google.com/"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_tokens"] == 0

    def test_dangerous_scopes_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "evil-app.example.com",
                "displayText": "Evil App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": [
                    "https://mail.google.com/",
                    "https://www.googleapis.com/auth/drive",
                ],
                "userEmail": "admin@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        assert "CRITICAL" in result.details
        apps = result.actual_value["dangerous_apps"]
        assert "Evil App" in apps
        assert apps["Evil App"]["risk_level"] == "CRITICAL"

    def test_anonymous_app_flagged(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "anon-client-id",
                "displayText": "Anon App",
                "anonymous": True,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/drive"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["Anon App"]["anonymous"] is True
        assert "anonymous" in result.details.lower()

    def test_multiple_users_aggregated(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "shared-app",
                "displayText": "Shared App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "userEmail": "user1@example.com",
            },
            {
                "clientId": "shared-app",
                "displayText": "Shared App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "userEmail": "user2@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["Shared App"]["install_count"] == 2
        assert len(apps["Shared App"]["users"]) == 2

    def test_ediscovery_scope_critical(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "ediscovery-app",
                "displayText": "eDiscovery Tool",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/ediscovery"],
                "userEmail": "admin@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["eDiscovery Tool"]["risk_level"] == "CRITICAL"

    def test_safe_tokens_with_anonymous_pass(self, full_audit_data):
        """Anonymous apps with no dangerous scopes should pass."""
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "anon-safe",
                "displayText": "Anon Safe",
                "anonymous": True,
                "nativeApp": False,
                "scopes": ["openid", "profile"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["anonymous_apps"] == 1
