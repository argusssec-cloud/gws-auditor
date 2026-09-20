"""Regression tests using field names/enums as actually returned by the Cloud Identity Policy API.

Each case reproduces a false FAIL where a securely configured tenant failed because
the check read a field the API does not return.
"""

from gws_auditor.models import Status
from tests.factories import make_ou_policy

# drive_and_docs.external_sharing as returned for an allowlist-restricted tenant
_DRIVE_SHARING = {
    "externalSharingMode": "ALLOWLISTED_DOMAINS",
    "allowReceivingExternalFiles": True,
    "allowPublishingFiles": False,
    "allowedPartiesForDistributingContent": "NONE",
}


def _set(data, category, setting_key, value, org_unit="/"):
    data["policies"][category] = {
        "_ou_policies": [make_ou_policy(category, setting_key, value, org_unit)],
    }


class TestApiControls:
    def test_internal_apps_not_trusted_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        _set(full_audit_data, "api_controls", "internal_apps", {"trustInternalApps": False})
        assert check_unconfigured_internal_apps(full_audit_data).status == Status.PASS

    def test_internal_apps_trusted_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_internal_apps

        _set(full_audit_data, "api_controls", "internal_apps", {"trustInternalApps": True})
        assert check_unconfigured_internal_apps(full_audit_data).status == Status.FAIL

    def test_unconfigured_apps_blocked_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        _set(full_audit_data, "api_controls", "unconfigured_third_party_apps",
             {"accessLevel": "BLOCK_ALL_SCOPES"})
        assert check_unconfigured_third_party_apps(full_audit_data).status == Status.PASS

    def test_unconfigured_apps_sign_in_only_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps

        _set(full_audit_data, "api_controls", "unconfigured_third_party_apps",
             {"accessLevel": "ALLOW_SIGN_IN_SCOPES_ONLY"})
        result = check_unconfigured_third_party_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "ALLOW_SIGN_IN_SCOPES_ONLY" in str(result.actual_value)

    def test_app_review_sees_access_level(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review

        full_audit_data["token_logs"] = [{"app_name": "Some App", "client_id": "123"}]
        full_audit_data["policies"]["access_control"] = {}
        _set(full_audit_data, "api_controls", "unconfigured_third_party_apps",
             {"accessLevel": "BLOCK_ALL_SCOPES"})
        assert check_third_party_app_review(full_audit_data).status == Status.MANUAL


class TestChatHistory:
    def test_history_on_by_default_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_enabled

        _set(full_audit_data, "chat", "chat_history",
             {"historyOnByDefault": True, "allowUserModification": False})
        assert check_chat_history_enabled(full_audit_data).status == Status.PASS

    def test_user_modification_disabled_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_chat_history_user_control

        _set(full_audit_data, "chat", "chat_history",
             {"historyOnByDefault": True, "allowUserModification": False})
        assert check_chat_history_user_control(full_audit_data).status == Status.PASS

    def test_space_history_always_on_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        _set(full_audit_data, "chat", "space_history", {"historyState": "HISTORY_ALWAYS_ON"})
        assert check_chat_space_history(full_audit_data).status == Status.PASS

    def test_space_history_always_off_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        _set(full_audit_data, "chat", "space_history", {"historyState": "HISTORY_ALWAYS_OFF"})
        assert check_chat_space_history(full_audit_data).status == Status.FAIL


class TestDriveExternalSharing:
    def test_publishing_disabled_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        _set(full_audit_data, "drive", "external_sharing", dict(_DRIVE_SHARING))
        assert check_drive_anyone_with_link(full_audit_data).status == Status.PASS

    def test_publishing_enabled_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link

        _set(full_audit_data, "drive", "external_sharing",
             {**_DRIVE_SHARING, "allowPublishingFiles": True})
        assert check_drive_anyone_with_link(full_audit_data).status == Status.FAIL

    def test_distribution_none_passes_despite_receiving_enabled(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        _set(full_audit_data, "drive", "external_sharing", dict(_DRIVE_SHARING))
        assert check_drive_external_upload(full_audit_data).status == Status.PASS

    def test_distribution_internal_users_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        _set(full_audit_data, "drive", "external_sharing",
             {**_DRIVE_SHARING, "allowedPartiesForDistributingContent": "ELIGIBLE_INTERNAL_USERS"})
        result = check_drive_external_upload(full_audit_data)
        assert result.status == Status.FAIL
        assert "ELIGIBLE_INTERNAL_USERS" in str(result.actual_value)

    def test_sharing_disallowed_passes_both(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_anyone_with_link
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        _set(full_audit_data, "drive", "external_sharing", {"externalSharingMode": "DISALLOWED"})
        assert check_drive_anyone_with_link(full_audit_data).status == Status.PASS
        assert check_drive_external_upload(full_audit_data).status == Status.PASS

    def test_allowlist_mode_passes(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_domain_allowlist

        _set(full_audit_data, "drive", "external_sharing", dict(_DRIVE_SHARING))
        assert check_drive_domain_allowlist(full_audit_data).status == Status.PASS

    def test_allowed_mode_fails(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_domain_allowlist

        _set(full_audit_data, "drive", "external_sharing",
             {**_DRIVE_SHARING, "externalSharingMode": "ALLOWED"})
        assert check_drive_domain_allowlist(full_audit_data).status == Status.FAIL


class TestGmail:
    def test_mail_storage_rule_id_only_is_manual_not_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage

        _set(full_audit_data, "gmail", "comprehensive_mail_storage", {"ruleId": "abc:123"})
        assert check_gmail_comprehensive_storage(full_audit_data).status == Status.MANUAL

    def test_partner_tls_not_collected_is_manual_not_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_partner_tls

        full_audit_data["policies"]["gmail"] = {}
        assert check_partner_tls(full_audit_data).status == Status.MANUAL


class TestGmailSpamAndAttachments:
    _SAFETY = {
        "anomalousAttachmentProtectionConsequence": "QUARANTINE",
        "encryptedAttachmentProtectionConsequence": "SPAM_FOLDER",
        "attachmentWithScriptsProtectionConsequence": "QUARANTINE",
    }

    def test_attachments_removed_from_inbox_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        _set(full_audit_data, "gmail", "email_attachment_safety", dict(self._SAFETY))
        assert check_flagged_email_action(full_audit_data).status == Status.PASS

    def test_attachment_warning_only_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        _set(full_audit_data, "gmail", "email_attachment_safety",
             {**self._SAFETY, "encryptedAttachmentProtectionConsequence": "WARNING"})
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.FAIL
        assert "encryptedAttachmentProtectionConsequence=WARNING" in str(result.actual_value)

    def _override(self, **rule):
        base = {"bypassInternalSenders": False, "bypassSelectedSenders": False,
                "hideWarningBannerFromSelectedSenders": False}
        return {"spamOverride": [{**base, **rule}]}

    def test_selected_sender_bypass_fails_18_1_only(self, full_audit_data):
        from gws_auditor.checks.cisa_services import (
            check_spam_approved_senders_domains,
            check_spam_bypass_internal,
            check_spam_domains_bypass_hide_warnings,
        )

        _set(full_audit_data, "gmail", "spam_override_lists", self._override(bypassSelectedSenders=True))
        assert check_spam_approved_senders_domains(full_audit_data).status == Status.FAIL
        assert check_spam_domains_bypass_hide_warnings(full_audit_data).status == Status.PASS
        assert check_spam_bypass_internal(full_audit_data).status == Status.PASS

    def test_bypass_and_hide_warnings_fails_18_2(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        _set(full_audit_data, "gmail", "spam_override_lists",
             self._override(bypassSelectedSenders=True, hideWarningBannerFromSelectedSenders=True))
        assert check_spam_domains_bypass_hide_warnings(full_audit_data).status == Status.FAIL

    def test_internal_bypass_fails_18_3(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        _set(full_audit_data, "gmail", "spam_override_lists", self._override(bypassInternalSenders=True))
        assert check_spam_bypass_internal(full_audit_data).status == Status.FAIL

    def test_no_bypass_rules_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        _set(full_audit_data, "gmail", "spam_override_lists", self._override())
        assert check_spam_approved_senders_domains(full_audit_data).status == Status.PASS


class TestSignInFactors:
    def _factor(self, data, value):
        _set(data, "security", "two_step_verification_enforcement_factor",
             {"allowedSignInFactorSet": value})

    def test_passkey_only_passes_both(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled
        from gws_auditor.checks.security_auth import check_security_keys_admin

        self._factor(full_audit_data, "PASSKEY_ONLY")
        assert check_sms_voice_mfa_disabled(full_audit_data).status == Status.PASS
        assert check_security_keys_admin(full_audit_data).status == Status.PASS

    def test_all_methods_fails_both(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_sms_voice_mfa_disabled
        from gws_auditor.checks.security_auth import check_security_keys_admin

        self._factor(full_audit_data, "ALL")
        assert check_sms_voice_mfa_disabled(full_audit_data).status == Status.FAIL
        assert check_security_keys_admin(full_audit_data).status == Status.FAIL


class TestClassroom:
    def test_secure_uppercase_enums_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import (
            check_class_creation_verified_teachers,
            check_class_membership_restricted,
            check_clever_roster_import_disabled,
            check_teachers_only_unenroll,
        )

        full_audit_data["policies"]["classroom"] = {"_ou_policies": [
            make_ou_policy("classroom", "class_membership",
                           {"whoCanJoinClasses": "ANYONE_IN_ALLOWLISTED_DOMAINS",
                            "whichClassesCanUsersJoin": "CLASSES_IN_ALLOWLISTED_DOMAINS"}),
            make_ou_policy("classroom", "student_unenrollment", {"whoCanUnenrollStudents": "TEACHERS_ONLY"}),
            make_ou_policy("classroom", "teacher_permissions", {"whoCanCreateClasses": "VERIFIED_TEACHERS_ONLY"}),
            make_ou_policy("classroom", "roster_import", {"rosterImportOption": "OFF"}),
        ]}
        assert check_class_membership_restricted(full_audit_data).status == Status.PASS
        assert check_teachers_only_unenroll(full_audit_data).status == Status.PASS
        assert check_class_creation_verified_teachers(full_audit_data).status == Status.PASS
        assert check_clever_roster_import_disabled(full_audit_data).status == Status.PASS

    def test_insecure_enums_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import (
            check_class_creation_verified_teachers,
            check_clever_roster_import_disabled,
            check_teachers_only_unenroll,
        )

        full_audit_data["policies"]["classroom"] = {"_ou_policies": [
            make_ou_policy("classroom", "student_unenrollment", {"whoCanUnenrollStudents": "STUDENTS_AND_TEACHERS"}),
            make_ou_policy("classroom", "teacher_permissions",
                           {"whoCanCreateClasses": "ALL_PENDING_AND_VERIFIED_TEACHERS"}),
            make_ou_policy("classroom", "roster_import", {"rosterImportOption": "ON_CLEVER"}),
        ]}
        assert check_teachers_only_unenroll(full_audit_data).status == Status.FAIL
        assert check_class_creation_verified_teachers(full_audit_data).status == Status.FAIL
        assert check_clever_roster_import_disabled(full_audit_data).status == Status.FAIL


class TestMiscRealEnums:
    def test_marketplace_allow_none_passes(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        _set(full_audit_data, "marketplace", "apps_access_options", {"accessLevel": "ALLOW_NONE"})
        assert check_marketplace_restriction(full_audit_data).status == Status.PASS

    def test_marketplace_allow_all_fails(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction

        _set(full_audit_data, "marketplace", "apps_access_options", {"accessLevel": "ALLOW_ALL"})
        assert check_marketplace_restriction(full_audit_data).status == Status.FAIL

    def test_meet_reads_safety_access(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_meet_non_gws_access

        _set(full_audit_data, "meet", "safety_access", {"meetingsAllowedToJoin": "ALL"})
        assert check_meet_non_gws_access(full_audit_data).status == Status.FAIL
        _set(full_audit_data, "meet", "safety_access", {"meetingsAllowedToJoin": "ANY_WORKSPACE_ORGANIZATION"})
        assert check_meet_non_gws_access(full_audit_data).status == Status.PASS

    def test_groups_owners_can_allow_external_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_members

        _set(full_audit_data, "groups", "groups_sharing",
             {"collaborationCapability": "DOMAIN_USERS_ONLY", "ownersCanAllowExternalMembers": True})
        assert check_groups_external_members(full_audit_data).status == Status.FAIL
        _set(full_audit_data, "groups", "groups_sharing",
             {"collaborationCapability": "DOMAIN_USERS_ONLY", "ownersCanAllowExternalMembers": False})
        assert check_groups_external_members(full_audit_data).status == Status.PASS

    def test_drive_distribution_none_passes(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_distribution

        _set(full_audit_data, "drive", "external_sharing", dict(_DRIVE_SHARING))
        assert check_drive_external_distribution(full_audit_data).status == Status.PASS

    def test_third_party_access_block_all_passes(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access

        _set(full_audit_data, "api_controls", "unconfigured_third_party_apps", {"accessLevel": "BLOCK_ALL_SCOPES"})
        full_audit_data["policies"]["security"].pop("_ou_policies", None)
        assert check_third_party_app_access(full_audit_data).status == Status.PASS

    def test_scope_risk_longest_pattern_wins(self):
        from gws_auditor.checks.additional import _classify_scope_risk

        base = "https://www.googleapis.com/auth/"
        assert _classify_scope_risk(base + "drive.admin") == "CRITICAL"
        assert _classify_scope_risk(base + "drive.file") == "MEDIUM"
        assert _classify_scope_risk(base + "drive") == "HIGH"

    def test_public_group_detected_from_nested_settings(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["groups"] = [
            {"email": "open@example.com", "settings": {"whoCanViewGroup": "ANYONE_CAN_VIEW"}},
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status != Status.PASS
        assert "open@example.com" in str(result.details) + str(result.actual_value)

    def test_suspended_super_admin_gives_no_redundancy(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_min

        full_audit_data["users"] = [
            {"primary_email": "a@example.com", "is_super_admin": True, "suspended": False},
            {"primary_email": "b@example.com", "is_super_admin": True, "suspended": True},
        ]
        assert check_super_admin_count_min(full_audit_data).status == Status.FAIL
