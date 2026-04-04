"""Tests for security authentication checks (OU-aware + fallback)."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


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


# -----------------------------------------------------------------------
# CIS-4.1.1.1: 2SV admin enforcement
# -----------------------------------------------------------------------

class TestTwoSvAdminEnforcement:
    """Tests for CIS-4.1.1.1 (fallback path)."""

    def test_pass_when_enforced_and_enrolled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_enforcement": "enforced"})
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = True
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_not_enforced(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_enforcement": "not_enforced"})
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = False
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.FAIL


class TestTwoSvAdminEnforcementOU:
    """OU-aware tests for CIS-4.1.1.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement",
                                {"enableEnforcement": True}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement",
                                {"enableEnforcement": True}, "/Engineering"),
            ],
        }
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement",
                                {"enableEnforcement": True}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement",
                                {"enableEnforcement": False}, "/Sales"),
            ],
        }
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_enforcement": "enforced"})
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = True
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.PASS

    def test_empty_ou_policies_list(self, full_audit_data):
        """Empty _ou_policies should fall through to fallback path."""
        from gws_auditor.checks.security_auth import check_2sv_admin_enforcement
        for u in full_audit_data["users"]:
            if u.get("is_super_admin"):
                u["is_admin"] = True
                u["is_enrolled_in_2sv"] = True
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [],
            "two_step_verification": {"admin_enforcement": "enforced"},
        }
        result = check_2sv_admin_enforcement(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.1.2: Security keys for admins
# -----------------------------------------------------------------------

class TestSecurityKeysAdmin:
    """Tests for CIS-4.1.1.2 (fallback path)."""

    def test_pass_security_key_only(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_allowed_methods": "security_key_only"})
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_any_method(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_allowed_methods": "any"})
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_empty(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_allowed_methods": ""})
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.ERROR


class TestSecurityKeysAdminOU:
    """OU-aware tests for CIS-4.1.1.2."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "ONLY_SECURITY_KEY"}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "SECURITY_KEY_ONLY"}, "/Admins"),
            ],
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "ONLY_SECURITY_KEY"}, "/"),
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "ANY_METHOD"}, "/Contractors"),
            ],
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_security_keys_admin
        _make_security_data(full_audit_data,
            **{"two_step_verification.admin_allowed_methods": "security_key_only"})
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS

    def test_empty_ou_policies_list(self, full_audit_data):
        """Empty _ou_policies should fall through to fallback path."""
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [],
            "two_step_verification": {"admin_allowed_methods": "security_key_only"},
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS

    def test_ou_policies_with_non_dict_entry(self, full_audit_data):
        """Non-dict entries in _ou_policies should be skipped gracefully."""
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                None,
                "junk",
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "ONLY_SECURITY_KEY"}, "/"),
            ],
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS

    def test_ou_policies_missing_setting_key(self, full_audit_data):
        """Entry with empty setting dict (no type field) should be skipped."""
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                {"setting": {}, "orgUnit": "/Orphan"},
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "SECURITY_KEY_ONLY"}, "/"),
            ],
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.PASS

    def test_unrecognized_method_fails(self, full_audit_data):
        """An unrecognized method like PHONE_VERIFICATION should FAIL."""
        from gws_auditor.checks.security_auth import check_security_keys_admin
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor",
                                {"allowedMethod": "PHONE_VERIFICATION"}, "/"),
            ],
        }
        result = check_security_keys_admin(full_audit_data)
        assert result.status == Status.FAIL
        assert "PHONE_VERIFICATION" in result.details


# -----------------------------------------------------------------------
# CIS-4.1.1.3: 2SV all users
# -----------------------------------------------------------------------

class TestTwoSvAllUsers:
    """Tests for CIS-4.1.1.3 (fallback path)."""

    def test_pass_enforced_all_enrolled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        _make_security_data(full_audit_data,
            **{"two_step_verification.enforcement": "enforced"})
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_users_not_enrolled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        _make_security_data(full_audit_data,
            **{"two_step_verification.enforcement": "enforced"})
        # user2 already has is_enrolled_in_2sv=False in fixture
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.FAIL


class TestTwoSvAllUsersOU:
    """OU-aware tests for CIS-4.1.1.3."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enrollment",
                                {"enableEnforcement": True}, "/"),
                make_ou_policy("security", "two_step_verification_enrollment",
                                {"enableEnforcement": True}, "/Engineering"),
            ],
        }
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "two_step_verification_enrollment",
                                {"enableEnforcement": True}, "/"),
                make_ou_policy("security", "two_step_verification_enrollment",
                                {"enableEnforcement": False}, "/Interns"),
            ],
        }
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_2sv_all_users
        _make_security_data(full_audit_data,
            **{"two_step_verification.enforcement": "enforced"})
        for u in full_audit_data["users"]:
            u["is_enrolled_in_2sv"] = True
        result = check_2sv_all_users(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.2.1: Super admin recovery disabled
# -----------------------------------------------------------------------

class TestSuperAdminRecovery:
    """Tests for CIS-4.1.2.1 (fallback path)."""

    def test_pass_recovery_disabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.super_admin_recovery_enabled": False})
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_recovery_enabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.super_admin_recovery_enabled": True})
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.super_admin_recovery_enabled": None})
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.ERROR


class TestSuperAdminRecoveryOU:
    """OU-aware tests for CIS-4.1.2.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "super_admin_account_recovery",
                                {"enableAccountRecovery": False}, "/"),
                make_ou_policy("security", "super_admin_account_recovery",
                                {"enableAccountRecovery": False}, "/Admins"),
            ],
        }
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "super_admin_account_recovery",
                                {"enableAccountRecovery": False}, "/"),
                make_ou_policy("security", "super_admin_account_recovery",
                                {"enableAccountRecovery": True}, "/Legacy"),
            ],
        }
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_super_admin_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.super_admin_recovery_enabled": False})
        result = check_super_admin_recovery(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.2.2: User account recovery enabled
# -----------------------------------------------------------------------

class TestUserAccountRecovery:
    """Tests for CIS-4.1.2.2 (fallback path)."""

    def test_pass_recovery_enabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.user_recovery_enabled": True})
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_recovery_disabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.user_recovery_enabled": False})
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.user_recovery_enabled": None})
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.ERROR


class TestUserAccountRecoveryOU:
    """OU-aware tests for CIS-4.1.2.2."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "user_account_recovery",
                                {"enableAccountRecovery": True}, "/"),
                make_ou_policy("security", "user_account_recovery",
                                {"enableAccountRecovery": True}, "/Engineering"),
            ],
        }
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "user_account_recovery",
                                {"enableAccountRecovery": True}, "/"),
                make_ou_policy("security", "user_account_recovery",
                                {"enableAccountRecovery": False}, "/Contractors"),
            ],
        }
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_user_account_recovery
        _make_security_data(full_audit_data,
            **{"account_recovery.user_recovery_enabled": True})
        result = check_user_account_recovery(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.3.1: Advanced Protection Program
# -----------------------------------------------------------------------

class TestAdvancedProtection:
    """Tests for CIS-4.1.3.1 (fallback path)."""

    def test_pass_available(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        _make_security_data(full_audit_data,
            **{"advanced_protection.enrollment_available": True})
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_not_available(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        _make_security_data(full_audit_data,
            **{"advanced_protection.enrollment_available": False})
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        _make_security_data(full_audit_data,
            **{"advanced_protection.enrollment_available": None})
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.ERROR


class TestAdvancedProtectionOU:
    """OU-aware tests for CIS-4.1.3.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"enableAdvancedProtection": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"enableAdvancedProtection": True}, "/Executives"),
            ],
        }
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "advanced_protection_program",
                                {"enableAdvancedProtection": True}, "/"),
                make_ou_policy("security", "advanced_protection_program",
                                {"enableAdvancedProtection": False}, "/Temps"),
            ],
        }
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Temps" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_advanced_protection
        _make_security_data(full_audit_data,
            **{"advanced_protection.enrollment_available": True})
        result = check_advanced_protection(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.4.1: Login challenges
# -----------------------------------------------------------------------

class TestLoginChallenges:
    """Tests for CIS-4.1.4.1 (fallback path)."""

    def test_pass_enabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        _make_security_data(full_audit_data,
            **{"login_challenges.enabled": True})
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_disabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        _make_security_data(full_audit_data,
            **{"login_challenges.enabled": False})
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        _make_security_data(full_audit_data,
            **{"login_challenges.enabled": None})
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.ERROR


class TestLoginChallengesOU:
    """OU-aware tests for CIS-4.1.4.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"enableLoginChallenge": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"enableLoginChallenge": True}, "/Engineering"),
            ],
        }
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "login_challenges",
                                {"enableLoginChallenge": True}, "/"),
                make_ou_policy("security", "login_challenges",
                                {"enableLoginChallenge": False}, "/Marketing"),
            ],
        }
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_login_challenges
        _make_security_data(full_audit_data,
            **{"login_challenges.enabled": True})
        result = check_login_challenges(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.1.5.1: Password policy
# -----------------------------------------------------------------------

class TestPasswordPolicy:
    """Tests for CIS-4.1.5.1 (fallback path)."""

    def test_pass_enhanced(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        _make_security_data(full_audit_data,
            **{
                "password_management.minimum_length": 14,
                "password_management.enforce_strong_password": True,
            })
        result = check_password_policy(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_weak(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        _make_security_data(full_audit_data,
            **{
                "password_management.minimum_length": 6,
                "password_management.enforce_strong_password": False,
            })
        result = check_password_policy(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_missing(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        full_audit_data["policies"]["security"] = {}
        result = check_password_policy(full_audit_data)
        assert result.status == Status.ERROR


class TestPasswordPolicyOU:
    """OU-aware tests for CIS-4.1.5.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "password",
                                {"minimumLength": 14, "enforceRequirementsAtLogin": True}, "/"),
                make_ou_policy("security", "password",
                                {"minimumLength": 12, "enforceRequirementsAtLogin": True}, "/Engineering"),
            ],
        }
        result = check_password_policy(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_weak_length(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "password",
                                {"minimumLength": 14, "enforceRequirementsAtLogin": True}, "/"),
                make_ou_policy("security", "password",
                                {"minimumLength": 8, "enforceRequirementsAtLogin": True}, "/Interns"),
            ],
        }
        result = check_password_policy(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details

    def test_child_ou_no_enforcement(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "password",
                                {"minimumLength": 14, "enforceRequirementsAtLogin": True}, "/"),
                make_ou_policy("security", "password",
                                {"minimumLength": 14, "enforceRequirementsAtLogin": False}, "/Legacy"),
            ],
        }
        result = check_password_policy(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy
        _make_security_data(full_audit_data,
            **{
                "password_management.minimum_length": 14,
                "password_management.enforce_strong_password": True,
            })
        result = check_password_policy(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.2.6.1: Less secure apps
# -----------------------------------------------------------------------

class TestLessSecureApps:
    """Tests for CIS-4.2.6.1 (fallback path)."""

    def test_pass_disabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        _make_security_data(full_audit_data,
            **{"less_secure_apps.allowed": False})
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_enabled(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        _make_security_data(full_audit_data,
            **{"less_secure_apps.allowed": True})
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.FAIL


class TestLessSecureAppsOU:
    """OU-aware tests for CIS-4.2.6.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "less_secure_apps",
                                {"allowLessSecureApps": False}, "/"),
                make_ou_policy("security", "less_secure_apps",
                                {"allowLessSecureApps": False}, "/Engineering"),
            ],
        }
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "less_secure_apps",
                                {"allowLessSecureApps": False}, "/"),
                make_ou_policy("security", "less_secure_apps",
                                {"allowLessSecureApps": True}, "/Legacy"),
            ],
        }
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_less_secure_apps
        _make_security_data(full_audit_data,
            **{"less_secure_apps.allowed": False})
        result = check_less_secure_apps(full_audit_data)
        assert result.status == Status.PASS
