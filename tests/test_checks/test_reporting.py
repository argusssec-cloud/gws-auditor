"""Tests for reporting checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_user_usage_row


class TestUsageReportReviewed:
    """Tests for CIS-5.1.1.1: Ensure App Usage Activity Report is reviewed."""

    def test_manual_with_usage_reports_available(self, full_audit_data):
        from gws_auditor.checks.reporting import check_usage_report_reviewed

        full_audit_data["usage_reports"] = [
            {"date": "2024-01-15", "parameters": [{"name": "accounts:num_users", "intValue": "100"}]},
            {"date": "2024-01-14", "parameters": [{"name": "accounts:num_users", "intValue": "99"}]},
        ]
        result = check_usage_report_reviewed(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.check_id == "CIS-5.1.1.1"
        assert "available" in result.details.lower()
        assert "2 report entries" in result.details

    def test_not_applicable_with_empty_usage_reports(self, full_audit_data):
        from gws_auditor.checks.reporting import check_usage_report_reviewed

        full_audit_data["usage_reports"] = []
        result = check_usage_report_reviewed(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE
        assert "not available" in result.details.lower()


class TestSecurityReportReviewed:
    """CIS-5.1.1.2: the Security report columns (accounts:* user usage parameters) reviewed
    for administrator accounts, as the benchmark's minimum."""

    def test_usage_report_not_collected_is_review(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_report_reviewed
        full_audit_data["user_usage"] = []
        result = check_security_report_reviewed(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.check_id == "CIS-5.1.1.2" and result.scored is True
        assert "not collected" in result.details

    def test_clean_admin_rows_pass(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_report_reviewed
        full_audit_data["user_usage"] = [
            make_user_usage_row("admin1@example.com", num_authorized_apps=3),
            make_user_usage_row("admin2@example.com", num_security_keys=0, num_passkeys_enrolled=0),
            make_user_usage_row("user2@example.com", is_2sv_enrolled=False, password_strength="WEAK")]
        result = check_security_report_reviewed(full_audit_data)
        assert result.status == Status.PASS  # non-admin anomalies are outside the minimum review
        assert result.actual_value["admins"]["admin1@example.com"]["authorized_apps"] == 3
        assert result.actual_value["admins"]["admin2@example.com"]["security_keys"] == 0  # reported, not judged

    @pytest.mark.parametrize("field,value,text", [
        ("is_2sv_enrolled", False, "2SV not enrolled"),
        ("password_strength", "WEAK", "password strength WEAK"),
        ("password_length_compliance", "NON_COMPLIANT", "password length NON_COMPLIANT"),
        ("is_less_secure_apps_access_allowed", True, "less secure apps allowed"),
    ])
    def test_admin_anomaly_fails(self, full_audit_data, field, value, text):
        from gws_auditor.checks.reporting import check_security_report_reviewed
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com"),
                                         make_user_usage_row("admin2@example.com", **{field: value})]
        result = check_security_report_reviewed(full_audit_data)
        assert result.status == Status.FAIL
        assert f"admin2@example.com [{text}]" in result.details

    def test_missing_admin_row_is_review(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_report_reviewed
        full_audit_data["user_usage"] = [make_user_usage_row("admin1@example.com")]
        result = check_security_report_reviewed(full_audit_data)
        assert result.status == Status.MANUAL
        assert "admin2@example.com" in result.details and result.actual_value["no_row_yet"] == ["admin2@example.com"]

    def test_no_admins_is_error(self, full_audit_data):
        """No users means the directory was not collected: ERROR (make_manual), never a verdict."""
        from gws_auditor.checks.reporting import check_security_report_reviewed
        full_audit_data["users"] = []
        full_audit_data["user_usage"] = [make_user_usage_row("x@example.com")]
        assert check_security_report_reviewed(full_audit_data).status == Status.ERROR
