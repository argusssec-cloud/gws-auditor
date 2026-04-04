"""Tests for reporting checks."""

import pytest

from gws_auditor.models import Status


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


class TestSecurityInvestigationTool:
    """Tests for CIS-5.1.1.2: Ensure Security Investigation Tool is used."""

    def test_manual_with_investigation_events(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_investigation_tool

        full_audit_data["admin_logs"] = [
            {"event_name": "security_investigation", "parameters": {}},
            {"event_name": "investigation_query", "parameters": {}},
        ]
        result = check_security_investigation_tool(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.check_id == "CIS-5.1.1.2"
        assert "2" in result.details
        assert "investigation" in result.details.lower()

    def test_manual_with_investigation_substring_match(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_investigation_tool

        full_audit_data["admin_logs"] = [
            {"event_name": "run_investigation_report", "parameters": {}},
        ]
        result = check_security_investigation_tool(full_audit_data)
        assert result.status == Status.MANUAL
        assert "1" in result.details

    def test_fail_no_investigation_events(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_investigation_tool

        full_audit_data["admin_logs"] = [
            {"event_name": "user_login", "parameters": {}},
            {"event_name": "password_change", "parameters": {}},
        ]
        result = check_security_investigation_tool(full_audit_data)
        assert result.status == Status.FAIL
        assert "No evidence" in result.details

    def test_fail_with_empty_admin_logs(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_investigation_tool

        full_audit_data["admin_logs"] = []
        result = check_security_investigation_tool(full_audit_data)
        assert result.status == Status.FAIL
        assert "No evidence" in result.details
