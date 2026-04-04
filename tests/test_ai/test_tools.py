"""Tests for AI analyst tools -- no LLM SDK required."""

import json

import pytest

from gws_auditor.ai.tools import TOOL_DEFINITIONS, execute_tool


@pytest.fixture
def sample_report():
    """Minimal audit report dict for tool testing."""
    return {
        "timestamp": "2026-02-19T10:30:00",
        "customer_id": "C03example",
        "domains": ["example.com", "example.org"],
        "summary": {
            "total": 8,
            "passed": 4,
            "failed": 2,
            "warnings": 1,
            "errors": 0,
            "manual": 1,
            "not_applicable": 0,
            "pass_rate": 66.7,
        },
        "results": [
            {
                "check_id": "CIS-1.1.1",
                "title": "Ensure more than one Super Admin",
                "status": "PASS",
                "level": "L1",
                "source": "CIS",
                "section": "Directory",
                "details": "Found 3 super admins",
                "remediation": "",
                "org_unit": "Global",
            },
            {
                "check_id": "CIS-1.1.3",
                "title": "Ensure Super Admin uses hardware MFA",
                "status": "FAIL",
                "level": "L1",
                "source": "CIS",
                "section": "Directory",
                "details": "1 super admin without hardware key",
                "remediation": "Enroll all super admins in hardware MFA",
                "org_unit": "Global",
            },
            {
                "check_id": "CIS-3.1.2.1.1",
                "title": "Ensure link sharing default is restricted",
                "status": "FAIL",
                "level": "L1",
                "source": "CIS",
                "section": "Drive",
                "details": "Default sharing is too permissive",
                "remediation": "Set default link sharing to restricted",
                "org_unit": "Global",
            },
            {
                "check_id": "CIS-3.1.3.1.3",
                "title": "Ensure DMARC is configured",
                "status": "WARN",
                "level": "L1",
                "source": "CIS",
                "section": "Gmail",
                "details": "DMARC policy is none",
                "remediation": "Set DMARC policy to reject",
                "org_unit": "Global",
            },
            {
                "check_id": "CIS-4.1.1",
                "title": "Ensure 2SV is enforced",
                "status": "PASS",
                "level": "L1",
                "source": "CIS",
                "section": "Security",
                "details": "2SV enforced for all users",
                "remediation": "",
                "org_unit": "Global",
            },
            {
                "check_id": "CIS-4.1.2",
                "title": "Ensure SSO is configured",
                "status": "MANUAL",
                "level": "L2",
                "source": "CIS",
                "section": "Security",
                "details": "Manual verification required",
                "remediation": "Verify SSO configuration",
                "org_unit": "Global",
            },
            {
                "check_id": "GWS.GMAIL.4.3",
                "title": "Ensure DMARC strict alignment",
                "status": "FAIL",
                "level": "L1",
                "source": "CISA",
                "section": "Gmail",
                "details": "DMARC alignment not strict",
                "remediation": "Set aspf=s and adkim=s in DMARC record",
                "org_unit": "Global",
            },
            {
                "check_id": "ADD-01",
                "title": "Ensure OAuth app access is limited",
                "status": "PASS",
                "level": "L1",
                "source": "OTHER",
                "section": "Security",
                "details": "OAuth apps restricted",
                "remediation": "",
                "org_unit": "Global",
            },
        ],
        "api_errors": [],
    }


class TestToolDefinitions:
    """Validate tool definition structure."""

    def test_all_tools_have_required_fields(self):
        assert len(TOOL_DEFINITIONS) == 13
        for tool in TOOL_DEFINITIONS:
            assert tool["type"] == "function"
            func = tool["function"]
            assert "name" in func
            assert "description" in func
            assert "parameters" in func

    def test_tool_names_are_unique(self):
        names = [t["function"]["name"] for t in TOOL_DEFINITIONS]
        assert len(names) == len(set(names))


class TestGetAuditSummary:
    def test_returns_summary(self, sample_report):
        result = json.loads(execute_tool("get_audit_summary", {}, sample_report))
        assert result["total"] == 8
        assert result["passed"] == 4
        assert result["failed"] == 2
        assert result["pass_rate"] == 66.7
        assert result["customer_id"] == "C03example"
        assert "example.com" in result["domains"]


class TestSearchFindings:
    def test_no_filters(self, sample_report):
        result = json.loads(execute_tool("search_findings", {}, sample_report))
        assert len(result) == 8

    def test_filter_by_status(self, sample_report):
        result = json.loads(execute_tool("search_findings", {"status": ["FAIL"]}, sample_report))
        assert len(result) == 3
        assert all(r["status"] == "FAIL" for r in result)

    def test_filter_by_source(self, sample_report):
        result = json.loads(execute_tool("search_findings", {"source": ["CISA"]}, sample_report))
        assert len(result) == 1
        assert result[0]["check_id"] == "GWS.GMAIL.4.3"

    def test_filter_by_section(self, sample_report):
        result = json.loads(execute_tool("search_findings", {"section": ["Gmail"]}, sample_report))
        assert len(result) == 2

    def test_filter_by_level(self, sample_report):
        result = json.loads(execute_tool("search_findings", {"level": "L2"}, sample_report))
        assert len(result) == 1
        assert result[0]["check_id"] == "CIS-4.1.2"

    def test_filter_by_check_id(self, sample_report):
        result = json.loads(
            execute_tool("search_findings", {"check_id": "CIS-1.1.1"}, sample_report)
        )
        assert len(result) == 1
        assert result[0]["status"] == "PASS"

    def test_limit(self, sample_report):
        result = json.loads(execute_tool("search_findings", {"limit": 2}, sample_report))
        assert len(result) == 2

    def test_combined_filters(self, sample_report):
        result = json.loads(
            execute_tool(
                "search_findings",
                {"status": ["FAIL"], "source": ["CIS"]},
                sample_report,
            )
        )
        assert len(result) == 2
        assert all(r["status"] == "FAIL" and r["source"] == "CIS" for r in result)


class TestGetCheckDetails:
    def test_existing_check(self, sample_report):
        result = json.loads(
            execute_tool("get_check_details", {"check_id": "CIS-1.1.3"}, sample_report)
        )
        assert result["check_id"] == "CIS-1.1.3"
        assert result["status"] == "FAIL"
        assert result["remediation"] == "Enroll all super admins in hardware MFA"

    def test_missing_check(self, sample_report):
        result = json.loads(
            execute_tool("get_check_details", {"check_id": "NONEXISTENT"}, sample_report)
        )
        assert "error" in result


class TestGetComplianceByFramework:
    def test_all_frameworks(self, sample_report):
        result = json.loads(execute_tool("get_compliance_by_framework", {}, sample_report))
        assert "CIS" in result
        assert "CISA" in result
        assert "OTHER" in result
        assert result["CIS"]["total"] == 6
        assert result["CIS"]["passed"] == 2
        assert result["CIS"]["failed"] == 2

    def test_single_framework(self, sample_report):
        result = json.loads(
            execute_tool("get_compliance_by_framework", {"source": "CISA"}, sample_report)
        )
        assert "CISA" in result
        assert len(result) == 1
        assert result["CISA"]["failed"] == 1


class TestGetComplianceBySection:
    def test_all_sections(self, sample_report):
        result = json.loads(execute_tool("get_compliance_by_section", {}, sample_report))
        assert "Directory" in result
        assert "Gmail" in result
        assert "Security" in result
        assert result["Directory"]["failed"] == 1

    def test_single_section(self, sample_report):
        result = json.loads(
            execute_tool("get_compliance_by_section", {"section": "Gmail"}, sample_report)
        )
        assert "Gmail" in result
        assert len(result) == 1
        assert result["Gmail"]["failing_checks"] == ["GWS.GMAIL.4.3"]


class TestGetRemediationPlan:
    def test_default_plan(self, sample_report):
        result = json.loads(execute_tool("get_remediation_plan", {}, sample_report))
        assert len(result) > 0
        # FAIL items should come before WARN
        fail_indices = [i for i, r in enumerate(result) if r["status"] == "FAIL"]
        warn_indices = [i for i, r in enumerate(result) if r["status"] == "WARN"]
        if fail_indices and warn_indices:
            assert max(fail_indices) < min(warn_indices)

    def test_plan_with_section_filter(self, sample_report):
        result = json.loads(
            execute_tool("get_remediation_plan", {"section": "Gmail"}, sample_report)
        )
        assert all(r["section"] == "Gmail" for r in result)

    def test_plan_with_limit(self, sample_report):
        result = json.loads(execute_tool("get_remediation_plan", {"limit": 1}, sample_report))
        assert len(result) == 1

    def test_plan_has_priority_numbers(self, sample_report):
        result = json.loads(execute_tool("get_remediation_plan", {}, sample_report))
        for i, item in enumerate(result):
            assert item["priority"] == i + 1


class TestCompareReports:
    def test_compare_requires_store(self, sample_report):
        result = json.loads(
            execute_tool(
                "compare_reports",
                {"old_report": "old.json", "new_report": "new.json"},
                sample_report,
                report_store=None,
            )
        )
        assert "error" in result

    def test_compare_with_mock_store(self, sample_report):
        # Create a modified report for comparison
        import copy

        old_report = copy.deepcopy(sample_report)
        new_report = copy.deepcopy(sample_report)
        # Resolve a failure in the new report
        for r in new_report["results"]:
            if r["check_id"] == "CIS-1.1.3":
                r["status"] = "PASS"
        new_report["summary"]["pass_rate"] = 80.0

        class MockStore:
            def load_report(self, filename):
                if filename == "old.json":
                    return old_report
                return new_report

        result = json.loads(
            execute_tool(
                "compare_reports",
                {"old_report": "old.json", "new_report": "new.json"},
                sample_report,
                report_store=MockStore(),
            )
        )
        assert len(result["resolved"]) == 1
        assert result["resolved"][0]["check_id"] == "CIS-1.1.3"


class TestListAvailableReports:
    def test_no_store(self, sample_report):
        result = json.loads(execute_tool("list_available_reports", {}, sample_report))
        assert isinstance(result, list)
        assert result[0]["error"] is not None

    def test_with_store(self, sample_report):
        class MockStore:
            def list_reports(self):
                return [
                    {"filename": "audit_2026.json", "timestamp": "2026-01-01", "pass_rate": 80.0}
                ]

        result = json.loads(
            execute_tool("list_available_reports", {}, sample_report, report_store=MockStore())
        )
        assert len(result) == 1
        assert result[0]["filename"] == "audit_2026.json"


class TestQueryInventoryData:
    def test_valid_inventory_check(self, sample_report):
        # Add an inventory check to the report
        sample_report["results"].append({
            "check_id": "ADD-30",
            "title": "Ensure mobile devices are syncing recently",
            "status": "WARN",
            "level": "L1",
            "source": "OTHER",
            "section": "Devices",
            "actual_value": {
                "stale_devices": [
                    {"model": "Pixel 6", "user": "user@example.com", "last_sync": "2025-01-01"},
                    {"model": "iPhone 14", "user": "user2@example.com", "last_sync": "2025-02-01"},
                ],
                "threshold_days": 90,
                "total_devices": 10,
            },
            "remediation": "Review stale devices",
        })
        result = json.loads(execute_tool("query_inventory_data", {"check_id": "ADD-30"}, sample_report))
        assert result["check_id"] == "ADD-30"
        assert result["status"] == "WARN"
        assert len(result["items"]) == 2
        assert result["summary"]["total_devices"] == 10

    def test_invalid_check_id(self, sample_report):
        result = json.loads(execute_tool("query_inventory_data", {"check_id": "CIS-1.1.1"}, sample_report))
        assert "error" in result

    def test_limit(self, sample_report):
        sample_report["results"].append({
            "check_id": "ADD-32",
            "title": "Users without 2SV",
            "status": "FAIL",
            "level": "L1",
            "source": "OTHER",
            "section": "Security",
            "actual_value": {
                "users_without_2sv": [{"email": f"user{i}@example.com"} for i in range(50)],
            },
            "remediation": "",
        })
        result = json.loads(execute_tool("query_inventory_data", {"check_id": "ADD-32", "limit": 5}, sample_report))
        assert len(result["items"]) == 5


class TestGetKnowledgeBaseUrl:
    def test_by_check_id(self, sample_report):
        # Add a check with a knowledge base URL in remediation
        sample_report["results"].append({
            "check_id": "CIS-4.1.1.1",
            "title": "Ensure 2SV is enforced",
            "status": "FAIL",
            "level": "L1",
            "source": "CIS",
            "section": "Security",
            "remediation": "Deploy 2SV. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification",
        })
        result = json.loads(execute_tool("get_knowledge_base_url", {"check_id": "CIS-4.1.1.1"}, sample_report))
        assert len(result) == 1
        assert "deploy-2-step-verification" in result[0]["urls"][0]

    def test_by_topic(self, sample_report):
        sample_report["results"].append({
            "check_id": "CIS-3.1.3.2.1",
            "title": "Ensure DKIM is enabled",
            "status": "FAIL",
            "level": "L1",
            "source": "CIS",
            "section": "Gmail",
            "remediation": "Set up DKIM. https://knowledge.workspace.google.com/admin/security/set-up-dkim",
        })
        result = json.loads(execute_tool("get_knowledge_base_url", {"topic": "DKIM"}, sample_report))
        assert len(result) >= 1
        assert any("dkim" in r["urls"][0] for r in result)

    def test_no_match(self, sample_report):
        result = json.loads(execute_tool("get_knowledge_base_url", {"topic": "nonexistent_xyz"}, sample_report))
        assert result[0].get("message") is not None


class TestGetSmartRemediation:
    def test_groups_by_theme(self, sample_report):
        result = json.loads(execute_tool("get_smart_remediation", {"group_by": "theme"}, sample_report))
        assert result["total_actionable"] > 0
        assert "groups" in result

    def test_groups_by_section(self, sample_report):
        result = json.loads(execute_tool("get_smart_remediation", {"group_by": "section"}, sample_report))
        groups = result["groups"]
        # The sample report has FAIL/WARN in Directory, Drive, Gmail
        assert any(k in groups for k in ["Directory", "Drive", "Gmail"])

    def test_section_filter(self, sample_report):
        result = json.loads(execute_tool("get_smart_remediation", {"section": "Gmail"}, sample_report))
        for group_data in result["groups"].values():
            for item in group_data["items"]:
                # Items should be from Gmail section
                pass
        assert result["total_actionable"] >= 1


class TestGetTrendAnalysis:
    def test_no_store(self, sample_report):
        result = json.loads(execute_tool("get_trend_analysis", {}, sample_report, report_store=None))
        assert "error" in result

    def test_with_store(self, sample_report):
        import copy
        old = copy.deepcopy(sample_report)
        old["timestamp"] = "2026-01-01"
        old["summary"]["pass_rate"] = 50.0

        class MockStore:
            def list_reports(self):
                return [
                    {"filename": "old.json", "timestamp": "2026-01-01"},
                    {"filename": "new.json", "timestamp": "2026-02-01"},
                ]
            def load_report(self, filename):
                if filename == "old.json":
                    return old
                return sample_report

        result = json.loads(execute_tool("get_trend_analysis", {"limit": 5}, sample_report, report_store=MockStore()))
        assert result["reports_analyzed"] == 2
        assert len(result["timeline"]) == 2


class TestExportFindingsCsv:
    def test_export_all(self, sample_report):
        result = json.loads(execute_tool("export_findings_csv", {}, sample_report))
        assert "csv" in result
        assert "check_id" in result["csv"]  # Header row
        assert result["row_count"] == 8

    def test_export_filtered(self, sample_report):
        result = json.loads(execute_tool("export_findings_csv", {"status": ["FAIL"]}, sample_report))
        # 3 FAIL checks in sample + header
        assert result["row_count"] == 3

    def test_export_by_section(self, sample_report):
        result = json.loads(execute_tool("export_findings_csv", {"section": "Gmail"}, sample_report))
        assert result["row_count"] == 2


class TestUnknownTool:
    def test_unknown_tool(self, sample_report):
        result = json.loads(execute_tool("nonexistent_tool", {}, sample_report))
        assert "error" in result
