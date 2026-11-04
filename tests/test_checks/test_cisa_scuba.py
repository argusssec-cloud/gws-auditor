"""Tests for CISA SCuBA security checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestCisaGmail:
    """Tests for CISA SCuBA Gmail checks."""

    def test_dmarc_strict_alignment_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_strict_alignment
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {
                    "record_found": True,
                    "record": "v=DMARC1; p=reject; aspf=s; adkim=s; rua=mailto:d@example.com",
                    "policy": "reject",
                },
            },
        }
        full_audit_data["domains"] = [{"domainName": "example.com"}]
        result = check_dmarc_strict_alignment(full_audit_data)
        assert result.status == Status.PASS

    def test_dmarc_strict_alignment_warn_on_relaxed(self, full_audit_data):
        """Relaxed alignment is RFC 7489 default → WARN (not FAIL)."""
        from gws_auditor.checks.cisa_scuba import check_dmarc_strict_alignment
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {
                    "record_found": True,
                    "record": "v=DMARC1; p=reject; aspf=r; adkim=r",
                    "policy": "reject",
                },
            },
        }
        full_audit_data["domains"] = [{"domainName": "example.com"}]
        result = check_dmarc_strict_alignment(full_audit_data)
        assert result.status == Status.WARN

    def test_dmarc_reporting_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_reporting
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {
                    "record_found": True,
                    "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
                    "policy": "reject",
                },
            },
        }
        full_audit_data["domains"] = [{"domainName": "example.com"}]
        result = check_dmarc_reporting(full_audit_data)
        assert result.status == Status.PASS

    def test_dmarc_reporting_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_reporting
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {
                    "record_found": True,
                    "record": "v=DMARC1; p=reject",
                    "policy": "reject",
                },
            },
        }
        full_audit_data["domains"] = [{"domainName": "example.com"}]
        result = check_dmarc_reporting(full_audit_data)
        assert result.status == Status.FAIL

    def test_email_uploads_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_uploads
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"email_uploads_enabled": False},
        }
        result = check_gmail_email_uploads(full_audit_data)
        assert result.status == Status.PASS

    def test_workspace_sync_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_workspace_sync
        full_audit_data["policies"]["gmail"] = {
            "end_user_access": {"workspace_sync_enabled": False},
        }
        result = check_gmail_workspace_sync(full_audit_data)
        assert result.status == Status.PASS

    def test_email_allowlist_empty_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_allowlist
        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"email_allowlist": [], "email_allowlist_enabled": False},
        }
        result = check_gmail_email_allowlist(full_audit_data)
        assert result.status == Status.PASS

    def test_email_allowlist_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_allowlist
        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {
                "email_allowlist": ["spammer@bad.com"],
                "email_allowlist_enabled": True,
            },
        }
        result = check_gmail_email_allowlist(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaCalendar:
    """Tests for CISA SCuBA Calendar checks."""

    def test_calendar_interop_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_interop_disabled
        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": False},
        }
        result = check_calendar_interop_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_interop_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_interop_disabled
        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True},
        }
        result = check_calendar_interop_disabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_paid_appointments_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_paid_appointments
        full_audit_data["policies"]["calendar"] = {
            "appointments": {"paid_appointments_enabled": False},
        }
        result = check_calendar_paid_appointments(full_audit_data)
        assert result.status == Status.PASS


class TestCisaChat:
    """Tests for CISA SCuBA Chat checks."""

    def test_chat_history_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled
        full_audit_data["policies"]["chat"] = {
            "history": {"history_enabled": True},
        }
        result = check_chat_history_enabled(full_audit_data)
        assert result.status == Status.PASS

    def test_chat_history_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled
        full_audit_data["policies"]["chat"] = {
            "history": {"history_enabled": False},
        }
        result = check_chat_history_enabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_chat_history_user_control_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_user_control
        full_audit_data["policies"]["chat"] = {
            "history": {"allow_user_modification": False},
        }
        result = check_chat_history_user_control(full_audit_data)
        assert result.status == Status.PASS

    def test_chat_content_reporting_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_content_reporting
        full_audit_data["policies"]["chat"] = {
            "content_reporting": {"enabled": True},
        }
        result = check_chat_content_reporting(full_audit_data)
        assert result.status == Status.PASS


class TestCisaDrive:
    """Tests for CISA SCuBA Drive and Docs checks."""

    def test_receive_non_allowlisted_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted
        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"receive_files_from_non_allowlisted": False},
        }
        result = check_drive_receive_non_allowlisted(full_audit_data)
        assert result.status == Status.PASS

    def test_non_google_sharing_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing
        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"allow_non_google_account_sharing": False},
        }
        result = check_drive_non_google_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_anyone_with_link_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link
        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"anyone_with_link_enabled": False},
        }
        result = check_drive_anyone_with_link(full_audit_data)
        assert result.status == Status.PASS

    def test_anyone_with_link_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link
        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"anyone_with_link_enabled": True},
        }
        result = check_drive_anyone_with_link(full_audit_data)
        assert result.status == Status.FAIL

    def test_default_access_private_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_default_access
        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"default_link_sharing_access": "private_to_owner"},
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.PASS

    def test_security_updates_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_security_updates
        full_audit_data["policies"]["drive"] = {
            "features": {"security_update_for_files": True},
        }
        result = check_drive_security_updates(full_audit_data)
        assert result.status == Status.PASS


class TestCisaMeet:
    """Tests for CISA SCuBA Meet checks."""

    def test_external_join_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join
        full_audit_data["policies"]["meet"] = {
            "safety": {"external_users_must_ask_to_join": True},
        }
        result = check_meet_external_join(full_audit_data)
        assert result.status == Status.PASS

    def test_non_gws_access_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access
        full_audit_data["policies"]["meet"] = {
            "safety": {"non_workspace_meetings_allowed": False},
        }
        result = check_meet_non_gws_access(full_audit_data)
        assert result.status == Status.PASS

    def test_host_management_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_host_management
        full_audit_data["policies"]["meet"] = {
            "safety": {"host_management_enabled": True},
        }
        result = check_meet_host_management(full_audit_data)
        assert result.status == Status.PASS

    def test_external_warning_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_warning
        full_audit_data["policies"]["meet"] = {
            "safety": {"warn_for_external_participants": True},
        }
        result = check_meet_external_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_incoming_calls_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls
        full_audit_data["policies"]["meet"] = {
            "calling": {"incoming_calls_restricted": True},
        }
        result = check_meet_incoming_calls(full_audit_data)
        assert result.status == Status.PASS

    def test_auto_recording_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording
        full_audit_data["policies"]["meet"] = {
            "recording": {"auto_recording_enabled": False},
        }
        result = check_meet_auto_recording(full_audit_data)
        assert result.status == Status.PASS

    def test_auto_transcription_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_transcription
        full_audit_data["policies"]["meet"] = {
            "recording": {"auto_transcription_enabled": False},
        }
        result = check_meet_auto_transcription(full_audit_data)
        assert result.status == Status.PASS


class TestCisaGroups:
    """Tests for CISA SCuBA Groups checks."""

    def test_external_posting_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_external_posting
        full_audit_data["policies"]["groups"] = {
            "allow_external_posting": False,
        }
        result = check_groups_external_posting(full_audit_data)
        assert result.status == Status.PASS

    def test_directory_hiding_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_directory_hiding
        full_audit_data["policies"]["groups"] = {
            "allow_hiding_from_directory": False,
        }
        result = check_groups_directory_hiding(full_audit_data)
        assert result.status == Status.PASS


class TestCisaCommonControls:
    """Tests for CISA SCuBA Common Controls checks."""

    def test_sms_mfa_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled
        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "allowed_methods": "security_key_only",
        }
        result = check_sms_voice_mfa_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_mfa_enrollment_period_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period
        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "new_user_enrollment_period_days": 3,
        }
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.PASS

    def test_mfa_enrollment_period_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period
        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "new_user_enrollment_period_days": 30,
        }
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.FAIL

    def test_trust_device_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_trust_device_disabled
        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "allow_trust_device": False,
        }
        result = check_trust_device_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_audit_logging_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_audit_logging_enabled
        # full_audit_data already has admin_logs from fixture
        result = check_audit_logging_enabled(full_audit_data)
        assert result.status == Status.PASS

    def test_audit_logging_no_logs_manual(self, full_audit_data):
        """Empty admin_logs + login_logs → MANUAL (needs manual verification)."""
        from gws_auditor.checks.cisa_scuba import check_audit_logging_enabled
        full_audit_data["admin_logs"] = []
        full_audit_data["login_logs"] = []
        result = check_audit_logging_enabled(full_audit_data)
        assert result.status == Status.MANUAL
        assert "No audit log events" in result.details

    def test_multi_party_approval_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_multi_party_approval
        full_audit_data["policies"]["security"]["multi_party_approval"] = {
            "enabled": True,
        }
        result = check_multi_party_approval(full_audit_data)
        assert result.status == Status.PASS


class TestCisaClassroom:
    """Tests for CISA SCuBA Classroom checks."""

    def test_class_membership_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_class_membership_restricted
        full_audit_data["policies"]["classroom"] = {
            "sharing": {"class_membership": "domain_only"},
        }
        result = check_class_membership_restricted(full_audit_data)
        assert result.status == Status.PASS

    def test_class_membership_restricted_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_class_membership_restricted
        full_audit_data["policies"]["classroom"] = {
            "sharing": {"class_membership": "anyone"},
        }
        result = check_class_membership_restricted(full_audit_data)
        assert result.status == Status.FAIL

    def test_classes_to_join_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_classes_to_join_restricted
        full_audit_data["policies"]["classroom"] = {
            "sharing": {"classes_to_join": "domain_only"},
        }
        result = check_classes_to_join_restricted(full_audit_data)
        assert result.status == Status.PASS

    def test_classes_to_join_restricted_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_classes_to_join_restricted
        full_audit_data["policies"]["classroom"] = {
            "sharing": {"classes_to_join": "anyone"},
        }
        result = check_classes_to_join_restricted(full_audit_data)
        assert result.status == Status.FAIL

    def test_classroom_api_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_classroom_api_disabled
        full_audit_data["policies"]["classroom"] = {
            "api_access": {"enabled": False},
        }
        result = check_classroom_api_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_classroom_api_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_classroom_api_disabled
        full_audit_data["policies"]["classroom"] = {
            "api_access": {"enabled": True},
        }
        result = check_classroom_api_disabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_clever_roster_import_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_clever_roster_import_disabled
        full_audit_data["policies"]["classroom"] = {
            "roster_import": {"clever_enabled": False},
        }
        result = check_clever_roster_import_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_clever_roster_import_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_clever_roster_import_disabled
        full_audit_data["policies"]["classroom"] = {
            "roster_import": {"clever_enabled": True},
        }
        result = check_clever_roster_import_disabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_teachers_only_unenroll_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_teachers_only_unenroll
        full_audit_data["policies"]["classroom"] = {
            "class_settings": {"who_can_unenroll_students": "teachers_only"},
        }
        result = check_teachers_only_unenroll(full_audit_data)
        assert result.status == Status.PASS

    def test_teachers_only_unenroll_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_teachers_only_unenroll
        full_audit_data["policies"]["classroom"] = {
            "class_settings": {"who_can_unenroll_students": "anyone"},
        }
        result = check_teachers_only_unenroll(full_audit_data)
        assert result.status == Status.FAIL

    def test_class_creation_verified_teachers_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_class_creation_verified_teachers
        full_audit_data["policies"]["classroom"] = {
            "class_settings": {"who_can_create_classes": "verified_teachers"},
        }
        result = check_class_creation_verified_teachers(full_audit_data)
        assert result.status == Status.PASS

    def test_class_creation_verified_teachers_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_class_creation_verified_teachers
        full_audit_data["policies"]["classroom"] = {
            "class_settings": {"who_can_create_classes": "anyone"},
        }
        result = check_class_creation_verified_teachers(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaGemini:
    """Tests for CISA SCuBA Gemini checks."""

    def test_gemini_unlicensed_access_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gemini_unlicensed_access
        full_audit_data["policies"]["gemini"] = {
            "access": {"unlicensed_access_enabled": False},
        }
        result = check_gemini_unlicensed_access(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_unlicensed_access_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gemini_unlicensed_access
        full_audit_data["policies"]["gemini"] = {
            "access": {"unlicensed_access_enabled": True},
        }
        result = check_gemini_unlicensed_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_alpha_features_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gemini_alpha_features
        full_audit_data["policies"]["gemini"] = {
            "features": {"alpha_features_enabled": False},
        }
        result = check_gemini_alpha_features(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_alpha_features_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gemini_alpha_features
        full_audit_data["policies"]["gemini"] = {
            "features": {"alpha_features_enabled": True},
        }
        result = check_gemini_alpha_features(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaAssuredControls:
    """Tests for CISA SCuBA Assured Controls checks."""

    def test_access_approvals_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_access_approvals_enabled
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "access_approvals_enabled": True,
        }
        result = check_access_approvals_enabled(full_audit_data)
        assert result.status == Status.PASS

    def test_access_approvals_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_access_approvals_enabled
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "access_approvals_enabled": False,
        }
        result = check_access_approvals_enabled(full_audit_data)
        assert result.status == Status.FAIL

    def test_support_access_region_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_support_access_region
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "support_access_region": "us",
        }
        result = check_support_access_region(full_audit_data)
        assert result.status == Status.PASS

    def test_support_access_region_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_support_access_region
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "support_access_region": "global",
        }
        result = check_support_access_region(full_audit_data)
        assert result.status == Status.FAIL

    def test_multi_region_processing_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_multi_region_processing_disabled
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "multi_region_processing_enabled": False,
        }
        result = check_multi_region_processing_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_multi_region_processing_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_multi_region_processing_disabled
        full_audit_data["policies"]["security"]["assured_controls"] = {
            "multi_region_processing_enabled": True,
        }
        result = check_multi_region_processing_disabled(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaSites:
    """Tests for CISA SCuBA Sites checks."""

    def test_sites_service_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sites_service_disabled
        full_audit_data["policies"]["sites"] = {
            "service_status": "disabled",
        }
        result = check_sites_service_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_sites_service_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sites_service_disabled
        full_audit_data["policies"]["sites"] = {
            "service_status": "enabled",
        }
        result = check_sites_service_disabled(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------

# --- Gmail OU tests ---


class TestGmailEmailUploadsOU:
    """OU-aware tests for GWS.GMAIL.8.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_uploads

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "user_email_uploads",
                                {"enableMailAndContactsImport": False}, "/"),
                make_ou_policy("gmail", "user_email_uploads",
                                {"enableMailAndContactsImport": False}, "/Engineering"),
            ],
        }
        result = check_gmail_email_uploads(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_uploads

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "user_email_uploads",
                                {"enableMailAndContactsImport": False}, "/"),
                make_ou_policy("gmail", "user_email_uploads",
                                {"enableMailAndContactsImport": True}, "/Sales"),
            ],
        }
        result = check_gmail_email_uploads(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_uploads

        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"email_uploads_enabled": False},
        }
        result = check_gmail_email_uploads(full_audit_data)
        assert result.status == Status.PASS


class TestGmailWorkspaceSyncOU:
    """OU-aware tests for GWS.GMAIL.10.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_workspace_sync

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "workspace_sync_for_outlook",
                                {"enableGoogleWorkspaceSyncForMicrosoftOutlook": False}, "/"),
                make_ou_policy("gmail", "workspace_sync_for_outlook",
                                {"enableGoogleWorkspaceSyncForMicrosoftOutlook": False}, "/Engineering"),
            ],
        }
        result = check_gmail_workspace_sync(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_workspace_sync

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "workspace_sync_for_outlook",
                                {"enableGoogleWorkspaceSyncForMicrosoftOutlook": False}, "/"),
                make_ou_policy("gmail", "workspace_sync_for_outlook",
                                {"enableGoogleWorkspaceSyncForMicrosoftOutlook": True}, "/Finance"),
            ],
        }
        result = check_gmail_workspace_sync(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Finance" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_workspace_sync

        full_audit_data["policies"]["gmail"] = {
            "end_user_access": {"workspace_sync_enabled": False},
        }
        result = check_gmail_workspace_sync(full_audit_data)
        assert result.status == Status.PASS


class TestGmailEmailAllowlistOU:
    """OU-aware tests for GWS.GMAIL.14.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_allowlist

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_spam_filter_ip_allowlist",
                                {"allowedIpAddresses": []}, "/"),
                make_ou_policy("gmail", "email_spam_filter_ip_allowlist",
                                {"allowedIpAddresses": []}, "/Engineering"),
            ],
        }
        result = check_gmail_email_allowlist(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_allowlist

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_spam_filter_ip_allowlist",
                                {"allowedIpAddresses": []}, "/"),
                make_ou_policy("gmail", "email_spam_filter_ip_allowlist",
                                {"allowedIpAddresses": ["1.2.3.4"]}, "/Marketing"),
            ],
        }
        result = check_gmail_email_allowlist(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_gmail_email_allowlist

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"email_allowlist": [], "email_allowlist_enabled": False},
        }
        result = check_gmail_email_allowlist(full_audit_data)
        assert result.status == Status.PASS


# --- Calendar OU tests ---


class TestCalendarInteropGlobal:
    """Global-level tests for GWS.CALENDAR.3.1 (not per-OU)."""

    def test_manual_when_missing(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_interop_disabled

        full_audit_data["policies"]["calendar"] = {}
        result = check_calendar_interop_disabled(full_audit_data)
        assert result.status == Status.ERROR


class TestCalendarPaidAppointmentsOU:
    """OU-aware tests for GWS.CALENDAR.4.1."""  # real field: enablePayments

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_paid_appointments

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "appointment_schedules",
                                {"enablePayments": False}, "/"),
                make_ou_policy("calendar", "appointment_schedules",
                                {"enablePayments": False}, "/Support"),
            ],
        }
        result = check_calendar_paid_appointments(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_paid_appointments

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "appointment_schedules",
                                {"enablePayments": False}, "/"),
                make_ou_policy("calendar", "appointment_schedules",
                                {"enablePayments": True}, "/Sales"),
            ],
        }
        result = check_calendar_paid_appointments(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_paid_appointments

        full_audit_data["policies"]["calendar"] = {
            "appointments": {"paid_appointments_enabled": False},
        }
        result = check_calendar_paid_appointments(full_audit_data)
        assert result.status == Status.PASS


# --- Chat OU tests ---


class TestChatHistoryEnabledOU:
    """OU-aware tests for GWS.CHAT.1.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_history",
                                {"historyOnByDefault": True}, "/"),
                make_ou_policy("chat", "chat_history",
                                {"historyOnByDefault": True}, "/Engineering"),
            ],
        }
        result = check_chat_history_enabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_history",
                                {"historyOnByDefault": True}, "/"),
                make_ou_policy("chat", "chat_history",
                                {"historyOnByDefault": False}, "/Contractors"),
            ],
        }
        result = check_chat_history_enabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled

        full_audit_data["policies"]["chat"] = {
            "history": {"history_enabled": True},
        }
        result = check_chat_history_enabled(full_audit_data)
        assert result.status == Status.PASS


class TestChatHistoryUserControlOU:
    """OU-aware tests for GWS.CHAT.1.2."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_user_control

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_history",
                                {"allowUserModification": False}, "/"),
                make_ou_policy("chat", "chat_history",
                                {"allowUserModification": False}, "/Engineering"),
            ],
        }
        result = check_chat_history_user_control(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_user_control

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_history",
                                {"allowUserModification": False}, "/"),
                make_ou_policy("chat", "chat_history",
                                {"allowUserModification": True}, "/Marketing"),
            ],
        }
        result = check_chat_history_user_control(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_user_control

        full_audit_data["policies"]["chat"] = {
            "history": {"allow_user_modification": False},
        }
        result = check_chat_history_user_control(full_audit_data)
        assert result.status == Status.PASS


class TestChatContentReportingOU:
    """OU-aware tests for GWS.CHAT.5.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_content_reporting

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_reporting",
                                {"contentReportingEnabled": True}, "/"),
                make_ou_policy("chat", "chat_reporting",
                                {"contentReportingEnabled": True}, "/Engineering"),
            ],
        }
        result = check_chat_content_reporting(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_content_reporting

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_reporting",
                                {"contentReportingEnabled": True}, "/"),
                make_ou_policy("chat", "chat_reporting",
                                {"contentReportingEnabled": False}, "/Contractors"),
            ],
        }
        result = check_chat_content_reporting(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_content_reporting

        full_audit_data["policies"]["chat"] = {
            "content_reporting": {"enabled": True},
        }
        result = check_chat_content_reporting(full_audit_data)
        assert result.status == Status.PASS


# --- Drive and Docs OU tests ---


class TestDriveReceiveNonAllowlistedOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.2."""  # real fields; invented receiveFilesFromNonAllowlisted dropped

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowReceivingExternalFiles": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowReceivingExternalFiles": False}, "/Engineering"),
            ],
        }
        result = check_drive_receive_non_allowlisted(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowReceivingExternalFiles": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowReceivingExternalFiles": True}, "/Partners"),
            ],
        }
        result = check_drive_receive_non_allowlisted(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Partners" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"receive_files_from_non_allowlisted": False},
        }
        result = check_drive_receive_non_allowlisted(full_audit_data)
        assert result.status == Status.PASS


class TestDriveNonGoogleSharingOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.4."""  # real field: allowNonGoogleInvites

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowNonGoogleInvites": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowNonGoogleInvites": False}, "/Engineering"),
            ],
        }
        result = check_drive_non_google_sharing(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowNonGoogleInvites": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalSharingMode": "ALLOWED", "allowNonGoogleInvites": True}, "/Sales"),
            ],
        }
        result = check_drive_non_google_sharing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_non_google_sharing

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"allow_non_google_account_sharing": False},
        }
        result = check_drive_non_google_sharing(full_audit_data)
        assert result.status == Status.PASS


class TestDriveAnyoneWithLinkOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.5."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowPublishingFiles": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowPublishingFiles": False}, "/Engineering"),
            ],
        }
        result = check_drive_anyone_with_link(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowPublishingFiles": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowPublishingFiles": True}, "/Marketing"),
            ],
        }
        result = check_drive_anyone_with_link(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"anyone_with_link_enabled": False},
        }
        result = check_drive_anyone_with_link(full_audit_data)
        assert result.status == Status.PASS


class TestDriveDefaultAccessOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.8."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "PRIVATE_TO_OWNER"}, "/"),
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "LINK_SHARING_PRIVATE"}, "/Engineering"),
            ],
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_pass_with_link_sharing_private_ou(self, full_audit_data):
        """LINK_SHARING_PRIVATE is the real API enum and should pass."""
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "LINK_SHARING_PRIVATE"}, "/"),
            ],
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_link_sharing_anyone_ou(self, full_audit_data):
        """LINK_SHARING_ANYONE is too permissive and should fail."""
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "LINK_SHARING_ANYONE"}, "/"),
            ],
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "PRIVATE_TO_OWNER"}, "/"),
                make_ou_policy("drive", "general_access_default",
                                {"defaultFileAccess": "PRIMARY_AUDIENCE_WITH_LINK"}, "/HR"),
            ],
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details

    def test_fallback_link_sharing_private(self, full_audit_data):
        """Fallback path should also accept link_sharing_private."""
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"default_link_sharing_access": "link_sharing_private"},
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_default_access

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"default_link_sharing_access": "private_to_owner"},
        }
        result = check_drive_default_access(full_audit_data)
        assert result.status == Status.PASS


class TestDriveSecurityUpdatesOU:
    """OU-aware tests for GWS.DRIVEDOCS.3.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_security_updates

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive_and_docs", "file_security_update",
                                {"securityUpdate": "APPLY_TO_IMPACTED_FILES", "allowUsersToManageUpdate": False}, "/"),
                make_ou_policy("drive_and_docs", "file_security_update",
                                {"securityUpdate": "APPLY_TO_IMPACTED_FILES", "allowUsersToManageUpdate": False}, "/Engineering"),
            ],
        }
        result = check_drive_security_updates(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_security_updates

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive_and_docs", "file_security_update",
                                {"securityUpdate": "APPLY_TO_IMPACTED_FILES"}, "/"),
                make_ou_policy("drive_and_docs", "file_security_update",
                                {"securityUpdate": "REMOVE_FROM_IMPACTED_FILES"}, "/Legacy"),
            ],
        }
        result = check_drive_security_updates(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_security_updates

        full_audit_data["policies"]["drive"] = {
            "features": {"security_update_for_files": True},
        }
        result = check_drive_security_updates(full_audit_data)
        assert result.status == Status.PASS


# --- Meet OU tests ---


class TestMeetExternalJoinOU:
    """OU-aware tests for GWS.MEET.1.1."""  # real enum: meet_joining.allowedAudience

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "meet_joining",
                                {"allowedAudience": "TRUSTED"}, "/"),
                make_ou_policy("meet", "meet_joining",
                                {"allowedAudience": "TRUSTED"}, "/Engineering"),
            ],
        }
        result = check_meet_external_join(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "meet_joining",
                                {"allowedAudience": "TRUSTED"}, "/"),
                make_ou_policy("meet", "meet_joining",
                                {"allowedAudience": "OPEN"}, "/Sales"),
            ],
        }
        result = check_meet_external_join(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join

        full_audit_data["policies"]["meet"] = {
            "safety": {"external_users_must_ask_to_join": True},
        }
        result = check_meet_external_join(full_audit_data)
        assert result.status == Status.PASS


class TestMeetNonGwsAccessOU:
    """OU-aware tests for GWS.MEET.2.1."""  # real enum: safety_access.meetingsAllowedToJoin

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_access",
                                {"meetingsAllowedToJoin": "ANY_WORKSPACE_ORGANIZATION"}, "/"),
                make_ou_policy("meet", "safety_access",
                                {"meetingsAllowedToJoin": "ANY_WORKSPACE_ORGANIZATION"}, "/Engineering"),
            ],
        }
        result = check_meet_non_gws_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_access",
                                {"meetingsAllowedToJoin": "ANY_WORKSPACE_ORGANIZATION"}, "/"),
                make_ou_policy("meet", "safety_access",
                                {"meetingsAllowedToJoin": "ALL"}, "/Contractors"),
            ],
        }
        result = check_meet_non_gws_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access

        full_audit_data["policies"]["meet"] = {
            "safety": {"non_workspace_meetings_allowed": False},
        }
        result = check_meet_non_gws_access(full_audit_data)
        assert result.status == Status.PASS


class TestMeetHostManagementOU:
    """OU-aware tests for GWS.MEET.3.1."""  # real field: enableHostManagement

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_host_management

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_host_management",
                                {"enableHostManagement": True}, "/"),
                make_ou_policy("meet", "safety_host_management",
                                {"enableHostManagement": True}, "/Engineering"),
            ],
        }
        result = check_meet_host_management(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_host_management

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_host_management",
                                {"enableHostManagement": True}, "/"),
                make_ou_policy("meet", "safety_host_management",
                                {"enableHostManagement": False}, "/Interns"),
            ],
        }
        result = check_meet_host_management(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_host_management

        full_audit_data["policies"]["meet"] = {
            "safety": {"host_management_enabled": True},
        }
        result = check_meet_host_management(full_audit_data)
        assert result.status == Status.PASS


class TestMeetExternalWarningOU:
    """OU-aware tests for GWS.MEET.4.1."""  # real field: enableExternalLabel

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_warning

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_external_participants",
                                {"enableExternalLabel": True}, "/"),
                make_ou_policy("meet", "safety_external_participants",
                                {"enableExternalLabel": True}, "/Engineering"),
            ],
        }
        result = check_meet_external_warning(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_warning

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "safety_external_participants",
                                {"enableExternalLabel": True}, "/"),
                make_ou_policy("meet", "safety_external_participants",
                                {"enableExternalLabel": False}, "/Sales"),
            ],
        }
        result = check_meet_external_warning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_warning

        full_audit_data["policies"]["meet"] = {
            "safety": {"warn_for_external_participants": True},
        }
        result = check_meet_external_warning(full_audit_data)
        assert result.status == Status.PASS


class TestMeetIncomingCallsOU:
    """OU-aware tests for GWS.MEET.5.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "meet_incoming_call_restrictions",
                                {"allowedCallers": "CONTACTS_AND_ORGANIZATION_ONLY"}, "/"),
                make_ou_policy("meet", "meet_incoming_call_restrictions",
                                {"allowedCallers": "CONTACTS_AND_ORGANIZATION_ONLY"}, "/Engineering"),
            ],
        }
        result = check_meet_incoming_calls(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "meet_incoming_call_restrictions",
                                {"allowedCallers": "CONTACTS_AND_ORGANIZATION_ONLY"}, "/"),
                make_ou_policy("meet", "meet_incoming_call_restrictions",
                                {"allowedCallers": "EVERYONE"}, "/Support"),
            ],
        }
        result = check_meet_incoming_calls(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls

        full_audit_data["policies"]["meet"] = {
            "calling": {"incoming_calls_restricted": True},
        }
        result = check_meet_incoming_calls(full_audit_data)
        assert result.status == Status.PASS


class TestMeetAutoRecordingOU:
    """OU-aware tests for GWS.MEET.6.1."""  # real setting: automatic_recording.enabled

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "automatic_recording",
                                {"enabled": False}, "/"),
                make_ou_policy("meet", "automatic_recording",
                                {"enabled": False}, "/Engineering"),
            ],
        }
        result = check_meet_auto_recording(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "automatic_recording",
                                {"enabled": False}, "/"),
                make_ou_policy("meet", "automatic_recording",
                                {"enabled": True}, "/Legal"),
            ],
        }
        result = check_meet_auto_recording(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legal" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording

        full_audit_data["policies"]["meet"] = {
            "recording": {"auto_recording_enabled": False},
        }
        result = check_meet_auto_recording(full_audit_data)
        assert result.status == Status.PASS


class TestMeetAutoTranscriptionOU:
    """OU-aware tests for GWS.MEET.6.2."""  # real setting: automatic_transcription.enabled

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_transcription

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "automatic_transcription",
                                {"enabled": False}, "/"),
                make_ou_policy("meet", "automatic_transcription",
                                {"enabled": False}, "/Engineering"),
            ],
        }
        result = check_meet_auto_transcription(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_transcription

        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "automatic_transcription",
                                {"enabled": False}, "/"),
                make_ou_policy("meet", "automatic_transcription",
                                {"enabled": True}, "/Exec"),
            ],
        }
        result = check_meet_auto_transcription(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Exec" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_transcription

        full_audit_data["policies"]["meet"] = {
            "recording": {"auto_transcription_enabled": False},
        }
        result = check_meet_auto_transcription(full_audit_data)
        assert result.status == Status.PASS


# --- Groups OU tests ---


class TestGroupsExternalPostingOU:
    """OU-aware tests for GWS.GROUPS.1.3."""  # real field: ownersCanAllowIncomingMailFromPublic

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_external_posting

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowIncomingMailFromPublic": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowIncomingMailFromPublic": False}, "/Engineering"),
            ],
        }
        result = check_groups_external_posting(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_external_posting

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowIncomingMailFromPublic": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowIncomingMailFromPublic": True}, "/Marketing"),
            ],
        }
        result = check_groups_external_posting(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_external_posting

        full_audit_data["policies"]["groups"] = {
            "allow_external_posting": False,
        }
        result = check_groups_external_posting(full_audit_data)
        assert result.status == Status.PASS


class TestGroupsDirectoryHidingOU:
    """OU-aware tests for GWS.GROUPS.4.1."""  # real fields: ownersCanHideGroups / newGroupsAreHidden

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_directory_hiding

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanHideGroups": False, "newGroupsAreHidden": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanHideGroups": False, "newGroupsAreHidden": False}, "/Engineering"),
            ],
        }
        result = check_groups_directory_hiding(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_directory_hiding

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanHideGroups": False, "newGroupsAreHidden": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanHideGroups": True, "newGroupsAreHidden": False}, "/Contractors"),
            ],
        }
        result = check_groups_directory_hiding(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_directory_hiding

        full_audit_data["policies"]["groups"] = {
            "allow_hiding_from_directory": False,
        }
        result = check_groups_directory_hiding(full_audit_data)
        assert result.status == Status.PASS


# --- Common Controls OU tests ---


class TestSmsMfaDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.1.3."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "/Engineering"),
            ],
        }
        result = check_sms_voice_mfa_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedSignInFactorSet": "PASSKEY_ONLY"}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedSignInFactorSet": "ALL"}, "/Sales"),
            ],
        }
        result = check_sms_voice_mfa_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled

        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "allowed_methods": "security_key_only",
        }
        result = check_sms_voice_mfa_disabled(full_audit_data)
        assert result.status == Status.PASS


class TestMfaEnrollmentPeriodOU:
    """OU-aware tests for GWS.COMMONCONTROLS.1.4."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_grace_period",
                                {"enrollmentGracePeriod": "259200s"}, "/"),
                make_ou_policy("security", "two_step_verification_grace_period",
                                {"enrollmentGracePeriod": "604800s"}, "/Engineering"),
            ],
        }
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_grace_period",
                                {"enrollmentGracePeriod": "259200s"}, "/"),
                make_ou_policy("security", "two_step_verification_grace_period",
                                {"enrollmentGracePeriod": "2592000s"}, "/Contractors"),
            ],
        }
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period

        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "new_user_enrollment_period_days": 3,
        }
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.PASS


class TestTrustDeviceDisabledOU:
    """OU-aware tests for GWS.COMMONCONTROLS.1.5."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_trust_device_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_device_trust",
                                {"allowTrustingDevice": False}, "/"),
                make_ou_policy("security", "two_step_verification_device_trust",
                                {"allowTrustingDevice": False}, "/Engineering"),
            ],
        }
        result = check_trust_device_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_trust_device_disabled

        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_device_trust",
                                {"allowTrustingDevice": False}, "/"),
                make_ou_policy("security", "two_step_verification_device_trust",
                                {"allowTrustingDevice": True}, "/Exec"),
            ],
        }
        result = check_trust_device_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Exec" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_trust_device_disabled

        full_audit_data["policies"]["security"]["two_step_verification"] = {
            "allow_trust_device": False,
        }
        result = check_trust_device_disabled(full_audit_data)
        assert result.status == Status.PASS


# --- Unknown-value handling (field absent without a documented default, or *_UNSPECIFIED) ---


class TestUnknownValuesAreManual:
    """Unknown per-OU values are MANUAL, never PASS or FAIL; a real non-compliant OU still wins."""

    def test_meet_joining_unspecified_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "meet_joining", {"allowedAudience": "ALLOWED_AUDIENCE_UNSPECIFIED"}, "/")]}
        result = check_meet_external_join(full_audit_data)
        assert result.status == Status.MANUAL
        assert "/" in result.details

    def test_incoming_calls_unspecified_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "meet_incoming_call_restrictions",
                           {"allowedCallers": "ALLOWED_CALLERS_UNSPECIFIED"}, "/")]}
        assert check_meet_incoming_calls(full_audit_data).status == Status.MANUAL

    def test_empty_value_without_documented_default_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_calendar_paid_appointments

        # calendar.appointment_schedules has no documented default -> cannot judge
        full_audit_data["policies"]["calendar"] = {"_ou_policies": [
            make_ou_policy("calendar", "appointment_schedules", {}, "/")]}
        assert check_calendar_paid_appointments(full_audit_data).status == Status.MANUAL

    def test_empty_value_with_documented_default_is_judged(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_groups_directory_hiding, check_groups_external_posting

        # groups_sharing documented defaults: ownersCanHideGroups/newGroupsAreHidden False (PASS),
        # ownersCanAllowIncomingMailFromPublic True (FAIL)
        full_audit_data["policies"]["groups"] = {"_ou_policies": [
            make_ou_policy("groups", "groups_sharing", {}, "/")]}
        assert check_groups_directory_hiding(full_audit_data).status == Status.PASS
        assert check_groups_external_posting(full_audit_data).status == Status.FAIL

    def test_unknown_sharing_mode_is_manual_unless_publishing_off(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "external_sharing",
                           {"externalSharingMode": "EXTERNAL_SHARING_MODE_UNSPECIFIED",
                            "allowPublishingFiles": True}, "/")]}
        assert check_drive_anyone_with_link(full_audit_data).status == Status.MANUAL
        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "external_sharing",
                           {"externalSharingMode": "EXTERNAL_SHARING_MODE_UNSPECIFIED",
                            "allowPublishingFiles": False}, "/")]}
        assert check_drive_anyone_with_link(full_audit_data).status == Status.PASS

    def test_non_compliant_ou_wins_over_unknown_ou(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "safety_access", {"meetingsAllowedToJoin": "ALL"}, "/"),
            make_ou_policy("meet", "safety_access", {}, "/Sales")]}
        result = check_meet_non_gws_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details and "Undetermined" in result.details

    def test_data_region_unspecified_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_data_regions

        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("data_regions", "data_at_rest_region", {"region": "REGION_UNSPECIFIED"}, "/")]}
        assert check_data_regions(full_audit_data).status == Status.MANUAL

    def test_grace_period_documented_default_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_mfa_enrollment_period

        # documented default enrollmentGracePeriod "0s" is outside 1-7 days
        full_audit_data["policies"]["security"] = {"_ou_policies": [
            make_ou_policy("security", "two_step_verification_grace_period", {}, "/")]}
        result = check_mfa_enrollment_period(full_audit_data)
        assert result.status == Status.FAIL
        assert "0d" in str(result.actual_value)

    def test_automatic_recording_unknown_but_recording_disabled_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_auto_recording

        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "automatic_recording", {}, "/"),
            make_ou_policy("meet", "video_recording", {"enableRecording": False}, "/")]}
        assert check_meet_auto_recording(full_audit_data).status == Status.PASS
        full_audit_data["policies"]["meet"] = {"_ou_policies": [
            make_ou_policy("meet", "automatic_recording", {}, "/"),
            make_ou_policy("meet", "video_recording", {"enableRecording": True}, "/")]}
        assert check_meet_auto_recording(full_audit_data).status == Status.MANUAL
