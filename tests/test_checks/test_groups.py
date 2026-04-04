"""Tests for Groups security checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestGroupsExternalAccess:
    """Tests for CIS-3.1.6.1: external Groups access is private."""

    def test_pass_with_private_policy_no_external(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": False,
            "default_group_visibility": "private",
        }
        full_audit_data["groups"] = [
            {
                "email": "team@example.com",
                "whoCanViewGroup": "ALL_MANAGERS_CAN_VIEW",
                "whoCanViewMembership": "ALL_MANAGERS_CAN_VIEW",
            },
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_with_members_only_visibility(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": False,
            "default_group_visibility": "members_only",
        }
        full_audit_data["groups"] = []
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_public_group_view(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": True,
            "default_group_visibility": "public",
        }
        full_audit_data["groups"] = [
            {
                "email": "public-group@example.com",
                "whoCanViewGroup": "ANYONE_CAN_VIEW",
                "whoCanViewMembership": "ALL_MANAGERS_CAN_VIEW",
            },
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_with_public_membership_view(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": True,
            "default_group_visibility": "public",
        }
        full_audit_data["groups"] = [
            {
                "email": "open-members@example.com",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewMembership": "ANYONE_CAN_VIEW",
            },
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_with_domain_wide_view(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": True,
            "default_group_visibility": "public",
        }
        full_audit_data["groups"] = [
            {
                "email": "domain-visible@example.com",
                "whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW",
                "whoCanViewMembership": "ALL_MANAGERS_CAN_VIEW",
            },
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_no_data(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": None,
        }
        full_audit_data["groups"] = []
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.ERROR

    def test_pass_with_restricted_groups_but_external_allowed(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_external_access

        # Policy allows external but no group has public visibility => pass
        full_audit_data["policies"]["groups"] = {
            "external_members_allowed": True,
            "default_group_visibility": "public",
        }
        full_audit_data["groups"] = [
            {
                "email": "private@example.com",
                "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
            },
        ]
        result = check_groups_external_access(full_audit_data)
        assert result.status == Status.PASS


class TestGroupsCreationRestriction:
    """Tests for CIS-3.1.6.2: group creation restricted to admins."""

    def test_pass_admins_only(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "admins_only",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_admin(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "admin",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_case_insensitive(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "ADMINS_ONLY",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_anyone(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "anyone",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_when_all_users(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "all_users_in_domain",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_empty(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.ERROR

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {}
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.ERROR


class TestGroupsConversationVisibility:
    """Tests for CIS-3.1.6.3: group conversation viewing is restricted."""

    def test_pass_with_members_only_policy(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "default_message_visibility": "members_only",
        }
        full_audit_data["groups"] = [
            {
                "email": "team@example.com",
                "settings": {"whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW"},
            },
        ]
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_with_private_policy(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "default_message_visibility": "private",
        }
        full_audit_data["groups"] = []
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_anyone_can_view(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "default_message_visibility": "members_only",
        }
        full_audit_data["groups"] = [
            {
                "email": "exposed@example.com",
                "settings": {"whoCanViewGroup": "ANYONE_CAN_VIEW"},
            },
        ]
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_with_domain_can_view(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {
            "default_message_visibility": "members_only",
        }
        full_audit_data["groups"] = [
            {
                "email": "domain-exposed@example.com",
                "settings": {"whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW"},
            },
        ]
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_with_multiple_exposed_groups(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {}
        full_audit_data["groups"] = [
            {
                "email": "group1@example.com",
                "settings": {"whoCanViewGroup": "ANYONE_CAN_VIEW"},
            },
            {
                "email": "group2@example.com",
                "settings": {"whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW"},
            },
            {
                "email": "group3@example.com",
                "settings": {"whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW"},
            },
        ]
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.FAIL
        # Only group1 and group2 are exposed, group3 is fine
        assert "2" in result.details

    def test_manual_when_no_groups_no_policy(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {}
        full_audit_data["groups"] = []
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.MANUAL

    def test_pass_when_groups_exist_but_all_restricted(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_conversation_visibility

        full_audit_data["policies"]["groups"] = {}
        full_audit_data["groups"] = [
            {
                "email": "secure1@example.com",
                "settings": {"whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW"},
            },
            {
                "email": "secure2@example.com",
                "settings": {"whoCanViewGroup": "ALL_MANAGERS_CAN_VIEW"},
            },
        ]
        result = check_groups_conversation_visibility(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------


class TestGroupsCreationRestrictionOU:
    """OU-aware tests for CIS-3.1.6.2."""

    def test_all_ous_admins_only(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"whoCanCreateGroups": "ADMINS_ONLY"}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"whoCanCreateGroups": "ADMINS_ONLY"}, "/Engineering"),
            ],
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_allows_anyone(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"whoCanCreateGroups": "ADMINS_ONLY"}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"whoCanCreateGroups": "ALL_USERS_IN_DOMAIN"}, "/Sales"),
            ],
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_child_ou_empty_creator(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "_ou_policies": [
                make_ou_policy("groups_for_business", "groups_sharing",
                                {"whoCanCreateGroups": "ADMINS_ONLY"}, "/"),
                make_ou_policy("groups_for_business", "groups_sharing",
                                {}, "/HR"),
            ],
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_creation_restriction

        full_audit_data["policies"]["groups"] = {
            "who_can_create_groups": "admins_only",
        }
        result = check_groups_creation_restriction(full_audit_data)
        assert result.status == Status.PASS
