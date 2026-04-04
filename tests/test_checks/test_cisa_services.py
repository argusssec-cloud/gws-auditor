"""Tests for CISA SCuBA service-specific checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestCisaServicesGmail:
    """Tests for CISA SCuBA Gmail service-specific checks."""

    # -- GWS.GMAIL.4.1: check_dmarc_published --

    def test_dmarc_published_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_dmarc_published

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {"record_found": True, "policy": "reject"},
            },
        }
        result = check_dmarc_published(full_audit_data)
        assert result.status == Status.PASS

    def test_dmarc_published_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_dmarc_published

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {"record_found": False, "policy": "none"},
            },
        }
        result = check_dmarc_published(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GMAIL.4.2: check_dmarc_reject --

    def test_dmarc_reject_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_dmarc_reject

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {"record_found": True, "policy": "reject"},
            },
        }
        result = check_dmarc_reject(full_audit_data)
        assert result.status == Status.PASS

    def test_dmarc_reject_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_dmarc_reject

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["dns_records"] = {
            "example.com": {
                "dmarc": {"record_found": True, "policy": "quarantine"},
            },
        }
        result = check_dmarc_reject(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GMAIL.5.5: check_flagged_email_action --

    def test_flagged_email_action_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "safety": {"flagged_email_action": "quarantine"},
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.PASS

    def test_flagged_email_action_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "safety": {"flagged_email_action": "inbox"},
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GMAIL.18.1: check_spam_approved_senders_domains --

    def test_spam_approved_senders_domains_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"approved_senders_domains": []},
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.PASS

    def test_spam_approved_senders_domains_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"approved_senders_domains": ["spammer.com"]},
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GMAIL.18.2: check_spam_domains_bypass_hide_warnings --

    def test_spam_domains_bypass_hide_warnings_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"domains_bypass_and_hide_warnings": []},
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.PASS

    def test_spam_domains_bypass_hide_warnings_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"domains_bypass_and_hide_warnings": ["bad.com"]},
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GMAIL.18.3: check_spam_bypass_internal --

    def test_spam_bypass_internal_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"bypass_spam_filters_for_internal": False},
        }
        result = check_spam_bypass_internal(full_audit_data)
        assert result.status == Status.PASS

    def test_spam_bypass_internal_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "spam_settings": {"bypass_spam_filters_for_internal": True},
        }
        result = check_spam_bypass_internal(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaServicesDrive:
    """Tests for CISA SCuBA Drive and Docs service-specific checks."""

    # -- GWS.DRIVEDOCS.1.3: check_drive_external_sharing_warning --

    def test_drive_external_sharing_warning_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"warn_for_external_sharing": True},
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_external_sharing_warning_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"warn_for_external_sharing": False},
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.1.6: check_drive_access_checker --

    def test_drive_access_checker_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"access_checker_suggestions": "recipients_only"},
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_access_checker_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"access_checker_suggestions": "anyone_in_domain"},
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.1.7: check_drive_external_upload --

    def test_drive_external_upload_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"allow_upload_to_external_drives": False},
        }
        result = check_drive_external_upload(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_external_upload_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"allow_upload_to_external_drives": True},
        }
        result = check_drive_external_upload(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.1.9: check_drive_ood_warning --

    def test_drive_ood_warning_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_ood_warning

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"out_of_domain_warning_enabled": True},
        }
        result = check_drive_ood_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_ood_warning_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_ood_warning

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"out_of_domain_warning_enabled": False},
        }
        result = check_drive_ood_warning(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.2.1: check_drive_manager_override --

    def test_drive_manager_override_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"allow_manager_override": False},
        }
        result = check_drive_manager_override(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_manager_override_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"allow_manager_override": True},
        }
        result = check_drive_manager_override(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.2.2: check_drive_non_member_access --

    def test_drive_non_member_access_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_non_member_access

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"allow_non_member_access": True},
        }
        result = check_drive_non_member_access(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_non_member_access_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_non_member_access

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"allow_non_member_access": False},
        }
        result = check_drive_non_member_access(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.5.1: check_drive_add_ons_disabled --

    def test_drive_add_ons_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled

        full_audit_data["policies"]["drive"] = {
            "features": {"add_ons_enabled": False},
        }
        result = check_drive_add_ons_disabled(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_add_ons_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled

        full_audit_data["policies"]["drive"] = {
            "features": {"add_ons_enabled": True},
        }
        result = check_drive_add_ons_disabled(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.DRIVEDOCS.6.1: check_drive_desktop_restricted --

    def test_drive_desktop_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {
            "features": {"desktop_authorized_only": True, "desktop_allowed": True},
        }
        result = check_drive_desktop_restricted(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_desktop_restricted_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {
            "features": {"desktop_authorized_only": False, "desktop_allowed": True},
        }
        result = check_drive_desktop_restricted(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaServicesChat:
    """Tests for CISA SCuBA Google Chat service-specific checks."""

    # -- GWS.CHAT.3.1: check_chat_space_history --

    def test_chat_space_history_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {
            "history": {"space_history_enabled": True},
        }
        result = check_chat_space_history(full_audit_data)
        assert result.status == Status.PASS

    def test_chat_space_history_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {
            "history": {"space_history_enabled": False},
        }
        result = check_chat_space_history(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.CHAT.5.2: check_chat_reporting_categories --

    def test_chat_reporting_categories_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_reporting_categories

        full_audit_data["policies"]["chat"] = {
            "content_reporting": {"all_categories_selected": True},
        }
        result = check_chat_reporting_categories(full_audit_data)
        assert result.status == Status.PASS

    def test_chat_reporting_categories_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_reporting_categories

        full_audit_data["policies"]["chat"] = {
            "content_reporting": {"all_categories_selected": False},
        }
        result = check_chat_reporting_categories(full_audit_data)
        assert result.status == Status.FAIL


class TestCisaServicesCalendar:
    """Tests for CISA SCuBA Calendar service-specific checks."""

    # -- GWS.CALENDAR.3.2: check_calendar_interop_auth_method --

    def test_calendar_interop_auth_method_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True, "auth_method": "graph_api"},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_interop_auth_method_fail_ews(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True, "auth_method": "ews"},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.FAIL

    def test_calendar_interop_auth_method_fail_basic(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True, "auth_method": "basic_auth"},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.FAIL

    def test_calendar_interop_na_when_disabled(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": False},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE


class TestCisaServicesGroups:
    """Tests for CISA SCuBA Groups service-specific checks."""

    # -- GWS.GROUPS.1.1: check_groups_external_access_default --

    def test_groups_external_access_default_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_access_default

        full_audit_data["policies"]["groups"] = {
            "sharing": {"external_access_default": "disabled"},
        }
        result = check_groups_external_access_default(full_audit_data)
        assert result.status == Status.PASS

    def test_groups_external_access_default_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_access_default

        full_audit_data["policies"]["groups"] = {
            "sharing": {"external_access_default": "enabled"},
        }
        result = check_groups_external_access_default(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GROUPS.1.2: check_groups_external_members --

    def test_groups_external_members_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_members

        full_audit_data["policies"]["groups"] = {
            "sharing": {"allow_external_members": False},
        }
        result = check_groups_external_members(full_audit_data)
        assert result.status == Status.PASS

    def test_groups_external_members_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_members

        full_audit_data["policies"]["groups"] = {
            "sharing": {"allow_external_members": True},
        }
        result = check_groups_external_members(full_audit_data)
        assert result.status == Status.FAIL

    # -- GWS.GROUPS.3.1: check_groups_conversation_visibility --

    def test_groups_conversation_visibility_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "visibility": {"default_conversation_visibility": "members_only"},
        }
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.PASS

    def test_groups_conversation_visibility_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "visibility": {"default_conversation_visibility": "anyone_can_view"},
        }
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------

# -- Gmail OU-aware tests --


class TestFlaggedEmailActionOU:
    """OU-aware tests for GWS.GMAIL.5.5: check_flagged_email_action."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"flaggedEmailAction": "quarantine"}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"flaggedEmailAction": "spam"}, "/Engineering"),
            ],
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"flaggedEmailAction": "quarantine"}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"flaggedEmailAction": "inbox"}, "/Sales"),
            ],
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestSpamApprovedSendersDomainsOU:
    """OU-aware tests for GWS.GMAIL.18.1: check_spam_approved_senders_domains."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"approvedSendersDomains": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"approvedSendersDomains": []}, "/Engineering"),
            ],
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"approvedSendersDomains": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"approvedSendersDomains": ["spammer.com"]}, "/Marketing"),
            ],
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestSpamDomainsBypassHideWarningsOU:
    """OU-aware tests for GWS.GMAIL.18.2: check_spam_domains_bypass_hide_warnings."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"domainsBypassAndHideWarnings": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"domainsBypassAndHideWarnings": []}, "/Engineering"),
            ],
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"domainsBypassAndHideWarnings": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"domainsBypassAndHideWarnings": ["bad.com"]}, "/Support"),
            ],
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details


class TestSpamBypassInternalOU:
    """OU-aware tests for GWS.GMAIL.18.3: check_spam_bypass_internal."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"bypassSpamFiltersForInternal": False}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"bypassSpamFiltersForInternal": False}, "/Engineering"),
            ],
        }
        result = check_spam_bypass_internal(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists",
                                {"bypassSpamFiltersForInternal": False}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                {"bypassSpamFiltersForInternal": True}, "/Finance"),
            ],
        }
        result = check_spam_bypass_internal(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Finance" in result.details


# -- Drive OU-aware tests --


class TestDriveExternalSharingWarningOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.3: check_drive_external_sharing_warning."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"warnForExternalSharing": True}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"warnForExternalSharing": True}, "/Engineering"),
            ],
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"warnForExternalSharing": True}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"warnForExternalSharing": False}, "/Sales"),
            ],
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestDriveAccessCheckerOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.6: check_drive_access_checker."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "recipients_only"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "target_audience_only"}, "/Engineering"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_pass_with_uppercase_api_enum(self, full_audit_data):
        """The real API returns uppercase enums like RECIPIENTS_ONLY."""
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "RECIPIENTS_ONLY"}, "/"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_uppercase_api_enum(self, full_audit_data):
        """TARGET_AUDIENCE_WITH_LINK is too permissive and should fail."""
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "TARGET_AUDIENCE_WITH_LINK"}, "/"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.FAIL

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "recipients_only"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestions": "anyone_in_domain"}, "/Marketing"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestDriveExternalUploadOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.7: check_drive_external_upload."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowUploadToExternalDrives": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowUploadToExternalDrives": False}, "/Engineering"),
            ],
        }
        result = check_drive_external_upload(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_external_upload

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowUploadToExternalDrives": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowUploadToExternalDrives": True}, "/Contractors"),
            ],
        }
        result = check_drive_external_upload(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details


class TestDriveOodWarningOU:
    """OU-aware tests for GWS.DRIVEDOCS.1.9: check_drive_ood_warning."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_ood_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_file_warning",
                                {"highlightingEnabled": True}, "/"),
                make_ou_policy("drive", "external_file_warning",
                                {"highlightingEnabled": True}, "/Engineering"),
            ],
        }
        result = check_drive_ood_warning(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_ood_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_file_warning",
                                {"highlightingEnabled": True}, "/"),
                make_ou_policy("drive", "external_file_warning",
                                {"highlightingEnabled": False}, "/HR"),
            ],
        }
        result = check_drive_ood_warning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details


class TestDriveManagerOverrideOU:
    """OU-aware tests for GWS.DRIVEDOCS.2.1: check_drive_manager_override."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagerOverride": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagerOverride": False}, "/Engineering"),
            ],
        }
        result = check_drive_manager_override(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagerOverride": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagerOverride": True}, "/Sales"),
            ],
        }
        result = check_drive_manager_override(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestDriveNonMemberAccessOU:
    """OU-aware tests for GWS.DRIVEDOCS.2.2: check_drive_non_member_access."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_non_member_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": True}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": True}, "/Engineering"),
            ],
        }
        result = check_drive_non_member_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_non_member_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": True}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": False}, "/Finance"),
            ],
        }
        result = check_drive_non_member_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Finance" in result.details


class TestDriveAddOnsDisabledOU:
    """OU-aware tests for GWS.DRIVEDOCS.5.1: check_drive_add_ons_disabled."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_sdk",
                                {"addOnsEnabled": False}, "/"),
                make_ou_policy("drive", "drive_sdk",
                                {"addOnsEnabled": False}, "/Engineering"),
            ],
        }
        result = check_drive_add_ons_disabled(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_add_ons_disabled

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_sdk",
                                {"addOnsEnabled": False}, "/"),
                make_ou_policy("drive", "drive_sdk",
                                {"addOnsEnabled": True}, "/Marketing"),
            ],
        }
        result = check_drive_add_ons_disabled(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestDriveDesktopRestrictedOU:
    """OU-aware tests for GWS.DRIVEDOCS.6.1: check_drive_desktop_restricted."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_for_desktop",
                                {"desktopAuthorizedOnly": True, "desktopAllowed": True}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"desktopAllowed": False, "desktopAuthorizedOnly": False}, "/Engineering"),
            ],
        }
        result = check_drive_desktop_restricted(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_for_desktop",
                                {"desktopAuthorizedOnly": True, "desktopAllowed": True}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"desktopAuthorizedOnly": False, "desktopAllowed": True}, "/Contractors"),
            ],
        }
        result = check_drive_desktop_restricted(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details


# -- Chat OU-aware tests --


class TestChatSpaceHistoryOU:
    """OU-aware tests for GWS.CHAT.3.1: check_chat_space_history."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "space_history",
                                {"spaceHistoryEnabled": True}, "/"),
                make_ou_policy("chat", "space_history",
                                {"spaceHistoryEnabled": True}, "/Engineering"),
            ],
        }
        result = check_chat_space_history(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "space_history",
                                {"spaceHistoryEnabled": True}, "/"),
                make_ou_policy("chat", "space_history",
                                {"spaceHistoryEnabled": False}, "/Support"),
            ],
        }
        result = check_chat_space_history(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details


class TestChatReportingCategoriesOU:
    """OU-aware tests for GWS.CHAT.5.2: check_chat_reporting_categories."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_reporting_categories

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_reporting",
                                {"allCategoriesSelected": True}, "/"),
                make_ou_policy("chat", "chat_reporting",
                                {"allCategoriesSelected": True}, "/Engineering"),
            ],
        }
        result = check_chat_reporting_categories(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_reporting_categories

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "chat_reporting",
                                {"allCategoriesSelected": True}, "/"),
                make_ou_policy("chat", "chat_reporting",
                                {"allCategoriesSelected": False}, "/Contractors"),
            ],
        }
        result = check_chat_reporting_categories(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details


# -- Calendar OU-aware tests --


class TestCalendarInteropAuthMethodGlobal:
    """Global-level tests for GWS.CALENDAR.3.2 (not per-OU)."""

    def test_pass_ms365(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True, "auth_method": "ms365"},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_legacy(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True, "auth_method": "legacy"},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_enabled_no_method(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_calendar_interop_auth_method

        full_audit_data["policies"]["calendar"] = {
            "interop": {"exchange_interop_enabled": True},
        }
        result = check_calendar_interop_auth_method(full_audit_data)
        assert result.status == Status.ERROR


# -- Groups OU-aware tests --


class TestGroupsExternalAccessDefaultOU:
    """OU-aware tests for GWS.GROUPS.1.1: check_groups_external_access_default."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_access_default

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"externalAccessDefault": "disabled"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"externalAccessDefault": "disabled"}, "/Engineering"),
            ],
        }
        result = check_groups_external_access_default(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_access_default

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"externalAccessDefault": "disabled"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"externalAccessDefault": "enabled"}, "/Marketing"),
            ],
        }
        result = check_groups_external_access_default(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestGroupsExternalMembersOU:
    """OU-aware tests for GWS.GROUPS.1.2: check_groups_external_members."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_members

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"allowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"allowExternalMembers": False}, "/Engineering"),
            ],
        }
        result = check_groups_external_members(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_external_members

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"allowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"allowExternalMembers": True}, "/Sales"),
            ],
        }
        result = check_groups_external_members(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details


class TestGroupsConversationVisibilityOU:
    """OU-aware tests for GWS.GROUPS.3.1: check_groups_conversation_visibility."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"defaultConversationVisibility": "members_only"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"defaultConversationVisibility": "MEMBERS_ONLY"}, "/Engineering"),
            ],
        }
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups", "groups_sharing",
                                {"defaultConversationVisibility": "members_only"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"defaultConversationVisibility": "anyone_can_view"}, "/Support"),
            ],
        }
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details
