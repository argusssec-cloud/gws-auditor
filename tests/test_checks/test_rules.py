"""Tests for rules (alert rules) checks."""

import pytest

from gws_auditor.models import Status


def _get_check_func(func_name):
    """Import and return a check function from the rules module by name."""
    import gws_auditor.checks.rules as rules_mod
    return getattr(rules_mod, func_name)


def _make_rule_event(rule_name: str, status_to: str, time: str = "2026-03-15T00:00:00Z") -> dict:
    """Create a normalized SYSTEM_DEFINED_RULE_UPDATED admin log entry."""
    status_from = "OFF" if status_to == "ON" else "ON"
    return {
        "event_name": "SYSTEM_DEFINED_RULE_UPDATED",
        "event_type": "SYSTEM_DEFINED_RULES",
        "time": time,
        "parameters": {
            "SYSTEM_DEFINED_RULE_NAME": rule_name,
            "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE": f"Status changed from {status_from} to {status_to}.",
        },
    }


class TestAlertPasswordChange:
    """Tests for CIS-6.1: Ensure alert for user password change is configured."""

    def test_pass_with_alert_rule_in_policies(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "password_change_alert", "type": "custom"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.1"

    def test_pass_via_system_rule_event(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("User's password changed", "ON"),
        ]
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_via_system_rule_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("User's password changed", "ON", "2026-03-10T00:00:00Z"),
            _make_rule_event("User's password changed", "OFF", "2026-03-15T00:00:00Z"),
        ]
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_with_no_data(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.MANUAL


class TestAlertGovernmentAttacks:
    """Tests for CIS-6.2: Ensure alert for government-backed attacks is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_government_attacks

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "government_backed_attack_warning", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_government_attacks(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.2"

    def test_pass_system_default_active(self, full_audit_data):
        """Government-backed attacks is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_government_attacks

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_government_attacks(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_government_attacks

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Government-backed attacks", "OFF"),
        ]
        result = check_alert_government_attacks(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertSuspiciousActivity:
    """Tests for CIS-6.3: Ensure alert for suspicious activity is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_activity

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "suspicious_activity_detection", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_activity(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.3"

    def test_pass_system_default_active(self, full_audit_data):
        """Suspicious activity is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_suspicious_activity

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_activity(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_activity

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Suspicious activity", "OFF"),
        ]
        result = check_alert_suspicious_activity(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertAdminPrivilege:
    """Tests for CIS-6.4: Ensure alert for admin privilege grant is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "admin_privilege_grant_alert", "type": "custom"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_admin_privilege(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.4"

    def test_pass_via_system_rule_event(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("User granted Admin privilege", "ON"),
        ]
        result = check_alert_admin_privilege(full_audit_data)
        assert result.status == Status.PASS

    def test_manual_no_data(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_admin_privilege(full_audit_data)
        assert result.status == Status.MANUAL


class TestAlertSuspiciousProgrammaticLogin:
    """Tests for CIS-6.5: Ensure alert for suspicious programmatic login is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_programmatic_login

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "suspicious_programmatic_login_alert", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_programmatic_login(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.5"

    def test_pass_system_default_active(self, full_audit_data):
        """Suspicious programmatic login is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_suspicious_programmatic_login

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_programmatic_login(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_programmatic_login

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Suspicious programmatic login", "OFF"),
        ]
        result = check_alert_suspicious_programmatic_login(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertSuspiciousLogin:
    """Tests for CIS-6.6: Ensure alert for suspicious login is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_login

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "suspicious_login_detector", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_login(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.6"

    def test_pass_system_default_active(self, full_audit_data):
        """Suspicious login is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_suspicious_login

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_login(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_login

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Suspicious login", "OFF"),
        ]
        result = check_alert_suspicious_login(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertLeakedPassword:
    """Tests for CIS-6.7: Ensure alert for leaked password is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_leaked_password

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "leaked_password_notification", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_leaked_password(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.7"

    def test_pass_system_default_active(self, full_audit_data):
        """Leaked password is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_leaked_password

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_leaked_password(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_leaked_password

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Password has been leaked", "OFF"),
        ]
        result = check_alert_leaked_password(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertEmployeeSpoofing:
    """Tests for CIS-6.8: Ensure alert for employee spoofing is configured."""

    def test_pass_with_alert_rule(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_employee_spoofing

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "employee_spoofing_alert", "type": "custom"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_employee_spoofing(full_audit_data)
        assert result.status == Status.PASS
        assert result.check_id == "CIS-6.8"

    def test_pass_system_default_active(self, full_audit_data):
        """Employee spoofing is a system-defined alert active by default."""
        from gws_auditor.checks.rules import check_alert_employee_spoofing

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = []
        result = check_alert_employee_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_explicitly_disabled(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_employee_spoofing

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["alert_center_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("Potential employee spoofing", "OFF"),
        ]
        result = check_alert_employee_spoofing(full_audit_data)
        assert result.status == Status.FAIL


class TestAlertRuleDetectionViaSystemEvents:
    """Test that _check_alert_rule properly handles SYSTEM_DEFINED_RULE_UPDATED events."""

    def test_latest_event_wins(self, full_audit_data):
        """When multiple events exist, the latest timestamp determines status."""
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("User's password changed", "ON", "2026-03-10T00:00:00Z"),
            _make_rule_event("User's password changed", "OFF", "2026-03-15T00:00:00Z"),
        ]
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.FAIL

    def test_re_enabled_after_disable(self, full_audit_data):
        """Rule disabled then re-enabled should show as PASS."""
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            _make_rule_event("User's password changed", "ON", "2026-03-10T00:00:00Z"),
            _make_rule_event("User's password changed", "OFF", "2026-03-12T00:00:00Z"),
            _make_rule_event("User's password changed", "ON", "2026-03-15T00:00:00Z"),
        ]
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.PASS

    def test_unrelated_log_system_default(self, full_audit_data):
        """Leaked password is default-active, so unrelated logs don't change that."""
        from gws_auditor.checks.rules import check_alert_leaked_password

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            {
                "event_name": "user_login",
                "parameters": {"ip_address": "10.0.0.1"},
            },
        ]
        result = check_alert_leaked_password(full_audit_data)
        assert result.status == Status.PASS

    def test_manual_non_default_no_data(self, full_audit_data):
        """Password change is NOT default-active, no data -> MANUAL."""
        from gws_auditor.checks.rules import check_alert_password_change

        full_audit_data["policies"]["security"]["alert_rules"] = []
        full_audit_data["admin_logs"] = [
            {
                "event_name": "user_login",
                "parameters": {"ip_address": "10.0.0.1"},
            },
        ]
        result = check_alert_password_change(full_audit_data)
        assert result.status == Status.MANUAL


class TestAlertRuleDetectionViaRuleType:
    """Test that _check_alert_rule matches on the 'type' field of alert rules."""

    def test_pass_match_on_rule_type(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_suspicious_activity

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "general_alert", "type": "suspicious_activity_detection"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_suspicious_activity(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_case_insensitive_match(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_leaked_password

        full_audit_data["policies"]["security"]["alert_rules"] = [
            {"name": "Leaked_Password_Alert", "type": "system"},
        ]
        full_audit_data["admin_logs"] = []
        result = check_alert_leaked_password(full_audit_data)
        assert result.status == Status.PASS
