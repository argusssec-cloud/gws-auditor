"""Tests for check registry."""

import pytest

from gws_auditor.checks.registry import CheckRegistry


class TestCheckRegistry:
    """Tests for CheckRegistry."""

    def test_load_modules(self):
        registry = CheckRegistry()
        registry.load()
        checks = registry.get_all_checks()
        assert len(checks) > 0

    def test_filter_by_level(self):
        registry = CheckRegistry()
        registry.load()
        l1_checks = registry.get_by_level("L1")
        l2_checks = registry.get_by_level("L2")
        all_checks = registry.get_all_checks()
        assert len(l1_checks) + len(l2_checks) == len(all_checks)

    def test_filter_by_source(self):
        registry = CheckRegistry()
        registry.load()
        cis_checks = registry.get_by_source("CIS")
        assert len(cis_checks) > 0

    def test_get_by_id(self):
        registry = CheckRegistry()
        registry.load()
        check = registry.get_by_id("CIS-1.1.1")
        assert check is not None
        assert check.check_id == "CIS-1.1.1"

    def test_get_by_id_not_found(self):
        registry = CheckRegistry()
        registry.load()
        check = registry.get_by_id("NONEXISTENT")
        assert check is None

    def test_filter_checks(self):
        registry = CheckRegistry()
        registry.load()
        filtered = registry.filter_checks(levels=["L1"], sources=["CIS"])
        for c in filtered:
            assert c.level == "L1"
            assert c.source == "CIS"

    def test_filter_exclude(self):
        registry = CheckRegistry()
        registry.load()
        all_checks = registry.get_all_checks()
        filtered = registry.filter_checks(exclude=["CIS-1.1.1"])
        assert len(filtered) == len(all_checks) - 1

    def test_execute_checks(self, full_audit_data):
        registry = CheckRegistry()
        registry.load()
        check = registry.get_by_id("CIS-1.1.1")
        results = registry.execute_checks(full_audit_data, [check])
        assert len(results) == 1
        assert results[0].check_id == "CIS-1.1.1"

    def test_filter_exclude_sections(self):
        registry = CheckRegistry()
        registry.load()
        all_checks = registry.get_all_checks()
        filtered = registry.filter_checks(exclude_sections=["Google Meet"])
        meet_checks = [c for c in all_checks if c.section == "Google Meet"]
        assert len(meet_checks) > 0, "Precondition: Google Meet checks exist"
        assert len(filtered) == len(all_checks) - len(meet_checks)
        for c in filtered:
            assert c.section != "Google Meet"

    def test_filter_exclude_multiple_sections(self):
        registry = CheckRegistry()
        registry.load()
        all_checks = registry.get_all_checks()
        excluded = ["Google Meet", "Directory"]
        filtered = registry.filter_checks(exclude_sections=excluded)
        excluded_count = sum(1 for c in all_checks if c.section in excluded)
        assert excluded_count > 0
        assert len(filtered) == len(all_checks) - excluded_count

    def test_filter_exclude_sections_with_exclude_ids(self):
        registry = CheckRegistry()
        registry.load()
        filtered = registry.filter_checks(
            exclude=["CIS-1.1.1"],
            exclude_sections=["Google Meet"],
        )
        for c in filtered:
            assert c.check_id != "CIS-1.1.1"
            assert c.section != "Google Meet"

    def test_pass_results_have_remediation(self, full_audit_data):
        """Verify that PASS results get remediation text from the decorator."""
        registry = CheckRegistry()
        registry.load()
        # CIS-1.1.1 has remediation in its decorator; set up data to trigger PASS
        full_audit_data["users"] = [
            {"primary_email": f"admin{i}@example.com", "is_super_admin": True,
             "is_admin": True, "is_delegated_admin": False,
             "is_enrolled_in_2sv": True, "is_enforced_in_2sv": True,
             "last_login_time": "2026-01-01T00:00:00Z",
             "creation_time": "2025-01-01T00:00:00Z",
             "org_unit_path": "/", "recovery_email": ""}
            for i in range(3)
        ]
        check = registry.get_by_id("CIS-1.1.1")
        assert check.remediation, "Decorator should have remediation text"
        results = registry.execute_checks(full_audit_data, [check])
        assert len(results) == 1
        result = results[0]
        from gws_auditor.models import Status
        assert result.status == Status.PASS
        assert result.remediation, "PASS result should have remediation from decorator"
