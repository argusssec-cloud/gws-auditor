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

    def _lists(self, data, *entries, addresses=("alice@partner.example", "bob@partner.example")):
        data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "email_address_lists", {"emailAddressList": [
                {"id": "L1", "name": "Partners", "addressList": {"address": [{"address": a} for a in addresses]}}]}),
            make_ou_policy("gmail", "rule_states", {"ruleStates": [{"ruleId": "r1", "enabled": True}, {"ruleId": "L1", "enabled": True}]}),
            *entries]}

    def test_spam_approved_senders_addresses_only_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains
        self._lists(full_audit_data, make_ou_policy("gmail", "spam_override_lists",
                    _override(ruleId="r1", bypassSelectedSenders=True, bypassSenderAllowlist=["L1"])))
        assert check_spam_approved_senders_domains(full_audit_data).status == Status.PASS

    def test_spam_approved_senders_domain_entry_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains
        self._lists(full_audit_data, make_ou_policy("gmail", "spam_override_lists",
                    _override(ruleId="r1", bypassSelectedSenders=True, bypassSenderAllowlist=["L1"])),
                    addresses=("alice@partner.example", "spammer.example"))
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.FAIL
        assert "Partners (spammer.example)" in result.details

    # -- GWS.GMAIL.18.2: check_spam_domains_bypass_hide_warnings --

    def test_spam_domains_bypass_hide_warnings_pass(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings
        self._lists(full_audit_data, make_ou_policy("gmail", "spam_override_lists",
                    _override(ruleId="r1", hideWarningBannerFromSelectedSenders=True, hideWarningBannerSenderAllowlist=["L1"])))
        assert check_spam_domains_bypass_hide_warnings(full_audit_data).status == Status.PASS

    def test_spam_domains_bypass_hide_warnings_fail(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings
        self._lists(full_audit_data, make_ou_policy("gmail", "spam_override_lists",
                    _override(ruleId="r1", hideWarningBannerFromSelectedSenders=True, hideWarningBannerSenderAllowlist=["L1"])),
                    addresses=("bad.example",))
        assert check_spam_domains_bypass_hide_warnings(full_audit_data).status == Status.FAIL

    def test_disabled_list_is_ignored(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "email_address_lists", {"emailAddressList": [
                {"id": "L1", "name": "Old", "addressList": {"address": [{"address": "spammer.example"}]}}]}),
            make_ou_policy("gmail", "rule_states", {"ruleStates": [{"ruleId": "r1", "enabled": True}, {"ruleId": "L1", "enabled": False}]}),
            make_ou_policy("gmail", "spam_override_lists", _override(ruleId="r1", bypassSelectedSenders=True, bypassSenderAllowlist=["L1"]))]}
        assert check_spam_approved_senders_domains(full_audit_data).status == Status.PASS

    def test_unresolvable_lists_are_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "spam_override_lists", _override(bypassSelectedSenders=True))]}
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.MANUAL
        assert "could not be read" in result.details

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


_ATTACHMENT_SAFE = {
    "anomalousAttachmentProtectionConsequence": "SPAM_FOLDER",
    "encryptedAttachmentProtectionConsequence": "SPAM_FOLDER",
    "attachmentWithScriptsProtectionConsequence": "QUARANTINE",
}


class TestFlaggedEmailActionOU:
    """OU-aware tests for GWS.GMAIL.5.5: check_flagged_email_action.

    Rewritten with the real shape (gmail.email_attachment_safety *Consequence enums) instead of
    the invented flaggedEmailAction field.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_attachment_safety", dict(_ATTACHMENT_SAFE), "/"),
                make_ou_policy("gmail", "email_attachment_safety", dict(_ATTACHMENT_SAFE), "/Engineering"),
            ],
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_attachment_safety", dict(_ATTACHMENT_SAFE), "/"),
                make_ou_policy("gmail", "email_attachment_safety",
                                {**_ATTACHMENT_SAFE, "anomalousAttachmentProtectionConsequence": "WARNING"},
                                "/Sales"),
            ],
        }
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details
        assert "anomalousAttachmentProtectionConsequence=WARNING" in result.actual_value

    def test_entry_without_consequences_is_unknown(self, full_audit_data):
        """Was ERROR: an entry that says nothing about this control is unknown, not a failure."""
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "email_attachment_safety", {"enableAnomalousAttachmentProtection": True})]}
        assert check_flagged_email_action(full_audit_data).status == Status.MANUAL

    def test_unspecified_consequence_is_unknown(self, full_audit_data):
        """Was FAIL: *_UNSPECIFIED carries no state; the other two safe consequences cannot PASS the OU."""
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "email_attachment_safety",
                           {**_ATTACHMENT_SAFE, "encryptedAttachmentProtectionConsequence": "CONSEQUENCE_UNSPECIFIED"})]}
        assert check_flagged_email_action(full_audit_data).status == Status.MANUAL


def _override(**rule):
    """A gmail.spam_override_lists value with one spamOverride[] rule (real shape)."""
    base = {"bypassInternalSenders": False, "bypassSelectedSenders": False,
            "hideWarningBannerFromSelectedSenders": False}
    return {"spamOverride": [{**base, **rule}]}


class TestSpamApprovedSendersDomainsOU:
    """OU-aware tests for GWS.GMAIL.18.1: check_spam_approved_senders_domains.

    Rewritten with the real spamOverride[] rules instead of the invented approvedSendersDomains.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists", _override(), "/Engineering"),
            ],
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_approved_senders_domains
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_address_lists", {"emailAddressList": [
                    {"id": "L1", "name": "Vendors", "addressList": {"address": [{"address": "vendor.example"}]}}]}),
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                _override(bypassSelectedSenders=True, bypassSenderAllowlist=["L1"]), "/Marketing"),
            ],
        }
        result = check_spam_approved_senders_domains(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details and "vendor.example" in result.details

    def test_absent_rule_list_is_the_documented_default(self, full_audit_data):
        """spamOverride[] absent means the documented default [] (no override rules): PASS, not unknown."""
        from gws_auditor.checks.cisa_services import (
            check_spam_approved_senders_domains, check_spam_bypass_internal,
            check_spam_domains_bypass_hide_warnings)

        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "spam_override_lists", {})]}
        for check in (check_spam_approved_senders_domains, check_spam_domains_bypass_hide_warnings,
                      check_spam_bypass_internal):
            assert check(full_audit_data).status == Status.PASS, check.__name__


class TestSpamDomainsBypassHideWarningsOU:
    """OU-aware tests for GWS.GMAIL.18.2: check_spam_domains_bypass_hide_warnings.

    Rewritten with the real spamOverride[] rules instead of the invented domainsBypassAndHideWarnings.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                _override(bypassSelectedSenders=True), "/Engineering"),
            ],
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_domains_bypass_hide_warnings
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_address_lists", {"emailAddressList": [
                    {"id": "L1", "name": "Vendors", "addressList": {"address": [{"address": "vendor.example"}]}}]}),
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                _override(hideWarningBannerFromSelectedSenders=True, hideWarningBannerSenderAllowlist=["L1"]), "/Marketing"),
            ],
        }
        result = check_spam_domains_bypass_hide_warnings(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details and "vendor.example" in result.details

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                _override(bypassSelectedSenders=True), "/Engineering"),
            ],
        }
        result = check_spam_bypass_internal(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_spam_bypass_internal

        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}, "/"),
                make_ou_policy("gmail", "spam_override_lists",
                                _override(bypassInternalSenders=True), "/Finance"),
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
                                {"allowedPartiesForDistributingContent": "NONE"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowedPartiesForDistributingContent": "NONE"}, "/Engineering"),
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
                                {"allowedPartiesForDistributingContent": "NONE"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowedPartiesForDistributingContent": "ALL_ELIGIBLE_USERS"}, "/Contractors"),
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
    """OU-aware tests for GWS.DRIVEDOCS.2.1: check_drive_manager_override.

    Rewritten with the real field shared_drive_creation.allowManagersToOverrideSettings.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": False}, "/Engineering"),
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
                                {"allowManagersToOverrideSettings": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": True}, "/Sales"),
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
    """OU-aware tests for GWS.DRIVEDOCS.6.1: check_drive_desktop_restricted.

    Rewritten with the real fields drive_for_desktop.restrictToAuthorizedDevices /
    allowDriveForDesktop instead of the invented desktopAuthorizedOnly / desktopAllowed.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_for_desktop",
                                {"restrictToAuthorizedDevices": True, "allowDriveForDesktop": True}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"allowDriveForDesktop": False, "restrictToAuthorizedDevices": False}, "/Engineering"),
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
                                {"restrictToAuthorizedDevices": True, "allowDriveForDesktop": True}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"restrictToAuthorizedDevices": False, "allowDriveForDesktop": True}, "/Contractors"),
            ],
        }
        result = check_drive_desktop_restricted(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_missing_restriction_flag_is_unknown(self, full_audit_data):
        """Was FAIL: with only allowDriveForDesktop=true the OU may still restrict to authorized devices."""
        from gws_auditor.checks.cisa_services import check_drive_desktop_restricted

        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "drive_for_desktop", {"allowDriveForDesktop": True})]}
        assert check_drive_desktop_restricted(full_audit_data).status == Status.MANUAL


# -- Chat OU-aware tests --


class TestChatSpaceHistoryOU:
    """OU-aware tests for GWS.CHAT.3.1: check_chat_space_history.

    Rewritten with the real field chat.space_history.historyState.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {
            "_ou_policies": [
                make_ou_policy("chat", "space_history",
                                {"historyState": "DEFAULT_HISTORY_ON"}, "/"),
                make_ou_policy("chat", "space_history",
                                {"historyState": "DEFAULT_HISTORY_ON"}, "/Engineering"),
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
                                {"historyState": "DEFAULT_HISTORY_ON"}, "/"),
                make_ou_policy("chat", "space_history",
                                {"historyState": "HISTORY_ALWAYS_OFF"}, "/Support"),
            ],
        }
        result = check_chat_space_history(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details


class TestChatReportingCategoriesIsManualByDesign:
    """P3: the Policy API exposes no reporting-category list, so GWS.CHAT.5.2 is review-only and unscored."""

    def test_real_content_reporting_entry_is_review(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_reporting_categories
        full_audit_data["subscription_type"] = "Google Workspace Enterprise Plus"
        full_audit_data["policies"]["chat"] = {"_ou_policies": [
            make_ou_policy("chat", "content_reporting", {"spacesReporting": "CONTENT_REPORTING_STATE_ENABLED"}, "/")]}
        result = check_chat_reporting_categories(full_audit_data)
        assert result.status in (Status.MANUAL, Status.ERROR)
        assert result.scored is False

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
                                {"collaborationCapability": "DOMAIN_USERS_ONLY", "ownersCanAllowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"collaborationCapability": "DOMAIN_USERS_ONLY", "ownersCanAllowExternalMembers": False}, "/Engineering"),
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
                                {"collaborationCapability": "DOMAIN_USERS_ONLY", "ownersCanAllowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"collaborationCapability": "ANYONE_CAN_ACCESS"}, "/Marketing"),
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
                                {"ownersCanAllowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowExternalMembers": False}, "/Engineering"),
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
                                {"ownersCanAllowExternalMembers": False}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"ownersCanAllowExternalMembers": True}, "/Sales"),
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
                                {"viewTopicsDefaultAccessLevel": "GROUP_MEMBERS"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"viewTopicsDefaultAccessLevel": "GROUP_MEMBERS"}, "/Engineering"),
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
                                {"viewTopicsDefaultAccessLevel": "GROUP_MEMBERS"}, "/"),
                make_ou_policy("groups", "groups_sharing",
                                {"viewTopicsDefaultAccessLevel": "ANYONE_CAN_VIEW_TOPICS"}, "/Support"),
            ],
        }
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Support" in result.details


class TestUnknownValuesAreManual:
    """Plan Decision A: an absent field without a documented default, or an *_UNSPECIFIED enum,
    is unknown; a documented default is judged; a real non-compliant OU still wins."""

    def test_unspecified_sharing_mode_is_unknown(self, full_audit_data):
        """Was PASS (1.3) / FAIL (1.7): the mode decides which fields apply, so it cannot be guessed."""
        from gws_auditor.checks.cisa_services import (
            check_drive_external_sharing_warning, check_drive_external_upload)

        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "external_sharing",
                           {"externalSharingMode": "EXTERNAL_SHARING_MODE_UNSPECIFIED",
                            "allowedPartiesForDistributingContent": "ALL_ELIGIBLE_USERS"})]}
        assert check_drive_external_sharing_warning(full_audit_data).status == Status.MANUAL
        assert check_drive_external_upload(full_audit_data).status == Status.MANUAL

    def test_documented_drive_defaults_are_judged(self, full_audit_data):
        """An empty value takes Google's documented defaults: warnings on (PASS), access checker
        RECIPIENTS_OR_AUDIENCE_OR_PUBLIC (FAIL), distribution ALL_ELIGIBLE_USERS (FAIL)."""
        from gws_auditor.checks.cisa_services import (
            check_drive_access_checker, check_drive_external_sharing_warning, check_drive_external_upload)

        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "external_sharing", {})]}
        assert check_drive_external_sharing_warning(full_audit_data).status == Status.PASS
        assert check_drive_access_checker(full_audit_data).status == Status.FAIL
        assert check_drive_external_upload(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("category, setting_key, check_name", [
        ("drive", "external_file_warning", "check_drive_ood_warning"),
        ("drive", "shared_drive_creation", "check_drive_manager_override"),
        ("drive", "shared_drive_creation", "check_drive_non_member_access"),
        ("drive", "drive_for_desktop", "check_drive_desktop_restricted"),
        ("chat", "space_history", "check_chat_space_history"),
    ])
    def test_empty_value_without_documented_default_is_manual(self, full_audit_data, category, setting_key, check_name):
        """Was FAIL for every one of these."""
        from gws_auditor.checks import cisa_services

        full_audit_data["policies"][category] = {"_ou_policies": [
            make_ou_policy(category, setting_key, {})]}
        result = getattr(cisa_services, check_name)(full_audit_data)
        assert result.status == Status.MANUAL, check_name
        assert "could not be determined" in result.details

    def test_unspecified_history_state_is_unknown(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_chat_space_history

        full_audit_data["policies"]["chat"] = {"_ou_policies": [
            make_ou_policy("chat", "space_history", {"historyState": "HISTORY_STATE_UNSPECIFIED"})]}
        assert check_chat_space_history(full_audit_data).status == Status.MANUAL

    def test_non_compliant_ou_beats_unknown_ou(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_drive_non_member_access

        full_audit_data["policies"]["drive"] = {"_ou_policies": [
            make_ou_policy("drive", "shared_drive_creation", {}, "/"),
            make_ou_policy("drive", "shared_drive_creation", {"allowNonMemberAccess": False}, "/Finance"),
        ]}
        result = check_drive_non_member_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Finance" in result.details and "Undetermined" in result.details

    def test_system_only_shared_drive_value_is_judged(self, full_audit_data):
        """A SYSTEM policy is the value in force, not "unconfigured"."""
        from gws_auditor.checks.cisa_services import check_drive_manager_override

        entry = make_ou_policy("drive", "shared_drive_creation", {"allowManagersToOverrideSettings": True})
        entry["_raw"] = {"type": "SYSTEM"}
        full_audit_data["policies"]["drive"] = {"_ou_policies": [entry]}
        assert check_drive_manager_override(full_audit_data).status == Status.FAIL

    def test_unspecified_collaboration_capability_is_unknown(self, full_audit_data):
        """Was FAIL: GROUPS.1.1 is decided by collaborationCapability, which carries no state here."""
        from gws_auditor.checks.cisa_services import check_groups_external_access_default

        full_audit_data["policies"]["groups"] = {"_ou_policies": [
            make_ou_policy("groups", "groups_sharing",
                           {"collaborationCapability": "COLLABORATION_CAPABILITY_UNSPECIFIED"})]}
        assert check_groups_external_access_default(full_audit_data).status == Status.MANUAL

    def test_groups_documented_defaults_are_judged(self, full_audit_data):
        """Empty groups_sharing takes the documented defaults: DOMAIN_USERS_ONLY /
        ownersCanAllowExternalMembers=false (PASS) and viewTopicsDefaultAccessLevel=DOMAIN_USERS (FAIL)."""
        from gws_auditor.checks.cisa_services import (
            check_groups_conversation_visibility, check_groups_external_access_default,
            check_groups_external_members)

        full_audit_data["policies"]["groups"] = {"_ou_policies": [
            make_ou_policy("groups", "groups_sharing", {})]}
        assert check_groups_external_access_default(full_audit_data).status == Status.PASS
        assert check_groups_external_members(full_audit_data).status == Status.PASS
        assert check_groups_conversation_visibility(full_audit_data).status == Status.FAIL

    def test_unspecified_visibility_is_unknown(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {"_ou_policies": [
            make_ou_policy("groups", "groups_sharing",
                           {"viewTopicsDefaultAccessLevel": "VIEW_TOPICS_DEFAULT_ACCESS_LEVEL_UNSPECIFIED"})]}
        assert check_groups_conversation_visibility(full_audit_data).status == Status.MANUAL
