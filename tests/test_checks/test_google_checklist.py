"""ADD-63..66: Google security checklist items on groups and administrator accounts (additional_identity.py)."""

from gws_auditor.checks.additional_identity import (check_group_spam_moderation, check_super_admin_spare_key,
                                                    check_super_admin_recovery_info, check_group_admin_role_conditions)
from gws_auditor.models import Status

SECURITY_CONDITION = ("api.getAttribute('cloudidentity.googleapis.com/groups.labels', []).hasAny(['groups.security']) "
                      "&& resource.type == 'cloudidentity.googleapis.com/Group'")


def _usage_row(email, keys):
    return {"entity": {"userEmail": email}, "parameters": [{"name": "accounts:num_security_keys", "intValue": str(keys)}]}


class TestGroupSpamModeration:
    def test_moderate_pass(self, full_audit_data):
        full_audit_data["groups"][0]["settings"]["spamModerationLevel"] = "MODERATE"
        r = check_group_spam_moderation(full_audit_data)
        assert r.status == Status.PASS and r.actual_value["levels"] == {"MODERATE": 1}

    def test_allow_fails(self, full_audit_data):
        full_audit_data["groups"][0]["settings"]["spamModerationLevel"] = "ALLOW"
        full_audit_data["groups"].append({"email": "ok@example.com", "settings": {"spamModerationLevel": "REJECT"}})
        r = check_group_spam_moderation(full_audit_data)
        assert r.status == Status.FAIL and "team@example.com" in r.details and "ok@example.com" not in r.details

    def test_no_settings_is_error(self, full_audit_data):
        full_audit_data["groups"] = [{"email": "x@example.com", "settings": {}}]
        assert check_group_spam_moderation(full_audit_data).status == Status.ERROR
        full_audit_data["groups"] = []
        assert check_group_spam_moderation(full_audit_data).status == Status.ERROR

    def test_settings_without_level_is_error(self, full_audit_data):
        full_audit_data["groups"][0]["settings"].pop("spamModerationLevel", None)
        assert check_group_spam_moderation(full_audit_data).status == Status.ERROR

    def test_mixed_missing_level_noted_in_pass(self, full_audit_data):
        full_audit_data["groups"][0]["settings"]["spamModerationLevel"] = "SILENTLY_MODERATE"
        full_audit_data["groups"].append({"email": "nolevel@example.com", "settings": {"whoCanJoin": "INVITED_CAN_JOIN"}})
        r = check_group_spam_moderation(full_audit_data)
        assert r.status == Status.PASS and "1 group(s) returned no spamModerationLevel" in r.details


class TestSuperAdminSpareKey:
    def test_two_keys_each_pass(self, full_audit_data):
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 2), _usage_row("admin2@example.com", 3)]
        assert check_super_admin_spare_key(full_audit_data).status == Status.PASS

    def test_single_key_fails(self, full_audit_data):
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 1), _usage_row("admin2@example.com", 2)]
        r = check_super_admin_spare_key(full_audit_data)
        assert r.status == Status.FAIL and "admin1@example.com (1 key)" in r.details

    def test_zero_keys_fails(self, full_audit_data):
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 0), _usage_row("admin2@example.com", 0)]
        r = check_super_admin_spare_key(full_audit_data)
        assert r.status == Status.FAIL and "2 of 2" in r.details

    def test_missing_row_is_review(self, full_audit_data):
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 2)]
        r = check_super_admin_spare_key(full_audit_data)
        assert r.status == Status.MANUAL and "admin2@example.com" in r.details

    def test_usage_not_collected_is_error(self, full_audit_data):
        full_audit_data["user_usage"] = []
        assert check_super_admin_spare_key(full_audit_data).status == Status.ERROR

    def test_no_super_admin_is_error(self, full_audit_data):
        for u in full_audit_data["users"]:
            u["is_super_admin"] = False
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 2)]
        assert check_super_admin_spare_key(full_audit_data).status == Status.ERROR

    def test_non_admin_rows_are_ignored(self, full_audit_data):
        full_audit_data["user_usage"] = [_usage_row("admin1@example.com", 2), _usage_row("admin2@example.com", 2),
                                         _usage_row("user1@example.com", 0)]
        assert check_super_admin_spare_key(full_audit_data).status == Status.PASS


class TestSuperAdminRecoveryInfo:
    def _set(self, data, email, phone):
        for u in data["users"]:
            if u.get("is_super_admin"):
                u["recovery_email"] = email
                u["recovery_phone"] = phone

    def test_both_set_pass(self, full_audit_data):
        self._set(full_audit_data, "me@personal.example", "+15555550100")
        r = check_super_admin_recovery_info(full_audit_data)
        assert r.status == Status.PASS and "GWS.COMMONCONTROLS.8.3" in r.details

    def test_missing_phone_fails(self, full_audit_data):
        self._set(full_audit_data, "me@personal.example", "")
        r = check_super_admin_recovery_info(full_audit_data)
        assert r.status == Status.FAIL and "no recovery phone" in r.details

    def test_missing_both_fails(self, full_audit_data):
        self._set(full_audit_data, "", None)
        r = check_super_admin_recovery_info(full_audit_data)
        assert r.status == Status.FAIL and "no recovery email or phone" in r.details

    def test_only_super_admins_judged(self, full_audit_data):
        self._set(full_audit_data, "me@personal.example", "+15555550100")
        for u in full_audit_data["users"]:
            if not u.get("is_super_admin"):
                u["recovery_email"] = ""
        assert check_super_admin_recovery_info(full_audit_data).status == Status.PASS

    def test_no_super_admin_is_error(self, full_audit_data):
        for u in full_audit_data["users"]:
            u["is_super_admin"] = False
        assert check_super_admin_recovery_info(full_audit_data).status == Status.ERROR


class TestGroupAdminRoleConditions:
    def _roles(self, data, assignments, condition_key="condition"):
        data["roles"] = {
            "roles": [
                {"roleId": "1", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True, "rolePrivileges": [{"privilegeName": "GROUPS_ALL"}]},
                {"roleId": "2", "roleName": "_GROUPS_EDITOR_ROLE", "rolePrivileges": [{"privilegeName": "GROUPS_UPDATE"}, {"privilegeName": "GROUPS_RETRIEVE"}]},
                {"roleId": "3", "roleName": "_HELP_DESK_ROLE", "rolePrivileges": [{"privilegeName": "USERS_RESET_PASSWORD"}]},
            ],
            "assignments": assignments,
        }
        data["subscription_info"] = {"tier_keys_present": ["enterprise_standard"]}
        data["api_errors"] = []
        return data

    def test_conditioned_pass(self, full_audit_data):
        data = self._roles(full_audit_data, [
            {"roleId": "2", "assignedTo": "u1", "assigneeType": "user", "condition": SECURITY_CONDITION},
            {"roleId": "2", "assignedTo": "u2", "assigneeType": "user", "condition": "!" + SECURITY_CONDITION},
            {"roleId": "1", "assignedTo": "u3", "assigneeType": "user"},
            {"roleId": "3", "assignedTo": "u4", "assigneeType": "user"},
        ])
        r = check_group_admin_role_conditions(data)
        assert r.status == Status.PASS and "1 to security groups, 1 to non-security groups" in r.details

    def test_unconditioned_fails_and_names_the_assignee(self, full_audit_data):
        full_audit_data["users"][0]["id"] = "u1"
        data = self._roles(full_audit_data, [{"roleId": "2", "assignedTo": "u1", "assigneeType": "user"}])
        r = check_group_admin_role_conditions(data)
        assert r.status == Status.FAIL and "admin1@example.com (_GROUPS_EDITOR_ROLE)" in r.details

    def test_no_group_role_assigned_pass(self, full_audit_data):
        data = self._roles(full_audit_data, [{"roleId": "3", "assignedTo": "u4", "assigneeType": "user"},
                                             {"roleId": "1", "assignedTo": "u3", "assigneeType": "user"}])
        r = check_group_admin_role_conditions(data)
        assert r.status == Status.PASS and "only super admins" in r.details

    def test_roles_not_collected_is_error(self, full_audit_data):
        full_audit_data["roles"] = {}
        full_audit_data["subscription_info"] = {"tier_keys_present": ["enterprise_standard"]}
        assert check_group_admin_role_conditions(full_audit_data).status == Status.ERROR
        data = self._roles(full_audit_data, [])
        data["api_errors"] = [{"operation": "list_role_assignments", "error": "403"}]
        assert check_group_admin_role_conditions(data).status == Status.ERROR

    def test_edition_without_conditions_is_not_applicable(self, full_audit_data):
        data = self._roles(full_audit_data, [{"roleId": "2", "assignedTo": "u1", "assigneeType": "user"}])
        data["subscription_info"] = {"tier_keys_present": ["business_starter"]}
        assert check_group_admin_role_conditions(data).status == Status.NOT_APPLICABLE
