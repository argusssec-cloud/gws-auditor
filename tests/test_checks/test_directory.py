"""Tests for directory security checks."""

from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.models import Status


class TestSuperAdminCount:
    """Tests for CIS-1.1.1 and CIS-1.1.2."""

    def test_pass_with_two_super_admins(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_min
        result = check_super_admin_count_min(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value == 2

    def test_fail_with_one_super_admin(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_min
        full_audit_data["users"] = [
            u for u in full_audit_data["users"]
            if u["primaryEmail"] != "admin2@example.com"
        ]
        result = check_super_admin_count_min(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value == 1

    def test_fail_with_no_super_admins(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_min
        full_audit_data["users"] = [
            u for u in full_audit_data["users"]
            if not u.get("is_super_admin")
        ]
        result = check_super_admin_count_min(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value == 0

    def test_fail_too_many_super_admins(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_max
        # Add extra super admins
        for i in range(3, 8):
            full_audit_data["users"].append({
                "primaryEmail": f"admin{i}@example.com",
                "isAdmin": True,
                "is_super_admin": True,
                "suspended": False,
                "isEnrolledIn2Sv": True,
                "isEnforcedIn2Sv": True,
                "name": {"fullName": f"Admin {i}"},
            })
        result = check_super_admin_count_max(full_audit_data)
        assert result.status == Status.FAIL

    def test_pass_three_super_admins(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count_max
        # Add 1 more super admin (total 3) — still under the maximum.
        full_audit_data["users"].append({
            "primaryEmail": "admin3@example.com",
            "isAdmin": True,
            "is_super_admin": True,
            "suspended": False,
            "isEnrolledIn2Sv": True,
            "isEnforcedIn2Sv": True,
            "name": {"fullName": "Admin 3"},
        })
        result = check_super_admin_count_max(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value == 3

    def test_fail_four_super_admins(self, full_audit_data):
        """4 is the boundary: CIS-1.1.2 requires *fewer than* 4."""
        from gws_auditor.checks.directory import check_super_admin_count_max
        # Add 2 more super admins (total 4)
        for i in range(3, 5):
            full_audit_data["users"].append({
                "primaryEmail": f"admin{i}@example.com",
                "isAdmin": True,
                "is_super_admin": True,
                "suspended": False,
                "isEnrolledIn2Sv": True,
                "isEnforcedIn2Sv": True,
                "name": {"fullName": f"Admin {i}"},
            })
        result = check_super_admin_count_max(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value == 4


class TestSuperAdminUsage:
    """Tests for CIS-1.1.3: Super admin accounts only for admin tasks."""

    def test_super_admin_low_activity_manual(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_usage
        # Super admins exist but with <= 10 logins → MANUAL (needs human review)
        full_audit_data["login_logs"] = [
            {"actor": {"email": "admin1@example.com"}, "event_name": "login_success"},
        ]
        result = check_super_admin_usage(full_audit_data)
        assert result.status == Status.MANUAL
        assert "appears low" in result.details


class TestDirectorySharing:
    """Tests for CIS-1.2.1.1."""

    def test_pass_external_restricted(self, full_audit_data):
        from gws_auditor.checks.directory import check_directory_external_sharing
        result = check_directory_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_external_not_restricted(self, full_audit_data):
        from gws_auditor.checks.directory import check_directory_external_sharing
        full_audit_data["policies"]["directory"]["sharing_settings"]["external_sharing_restricted"] = False
        result = check_directory_external_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_no_directory_data(self, full_audit_data):
        from gws_auditor.checks.directory import check_directory_external_sharing
        full_audit_data["policies"]["directory"] = {}
        result = check_directory_external_sharing(full_audit_data)
        assert result.status == Status.ERROR
        assert "could not be retrieved" in result.details



class TestDirectorySharingWithSharingOption:
    """Tests for CIS-1.2.1.1 — global setting, not per-OU."""

    def test_pass_requester_basic_profile_only(self, full_audit_data):
        """REQUESTER_BASIC_PROFILE_ONLY means restricted → PASS."""
        from gws_auditor.checks.directory import check_directory_external_sharing

        full_audit_data["policies"]["directory"] = {
            "sharing_settings": {"external_sharing_restricted": True},
        }
        result = check_directory_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_organization_directory_data(self, full_audit_data):
        """ORGANIZATION_DIRECTORY_DATA means not restricted → FAIL."""
        from gws_auditor.checks.directory import check_directory_external_sharing

        full_audit_data["policies"]["directory"] = {
            "sharing_settings": {"external_sharing_restricted": False},
        }
        result = check_directory_external_sharing(full_audit_data)
        assert result.status == Status.FAIL


class TestDirectorySharingNormalization:
    """Test that _map_directory correctly maps sharing_option to sharing_settings."""

    def test_sharing_option_mapped_to_restricted_true(self):
        from gws_auditor.provider import _map_directory

        policies = {
            "directory": {
                "external_directory_sharing": {
                    "sharing_option": "REQUESTER_BASIC_PROFILE_ONLY",
                },
            },
        }
        _map_directory(policies)
        restricted = policies["directory"]["sharing_settings"]["external_sharing_restricted"]
        assert restricted is True

    def test_sharing_option_mapped_to_restricted_false(self):
        from gws_auditor.provider import _map_directory

        policies = {
            "directory": {
                "external_directory_sharing": {
                    "sharing_option": "ORGANIZATION_DIRECTORY_DATA",
                },
            },
        }
        _map_directory(policies)
        restricted = policies["directory"]["sharing_settings"]["external_sharing_restricted"]
        assert restricted is False

    def test_end_to_end_normalization(self, full_audit_data):
        """Full normalize_data flow maps sharing_option correctly."""
        from gws_auditor.provider import normalize_data

        raw_data = dict(full_audit_data)
        raw_data["policies"] = {
            "directory": [
                {
                    "setting": {
                        "type": "settings/directory.external_directory_sharing",
                        "value": {"sharing_option": "REQUESTER_BASIC_PROFILE_ONLY"},
                    },
                    "orgUnit": "/",
                },
            ],
        }
        result = normalize_data(raw_data)
        dir_settings = result["policies"]["directory"].get("sharing_settings", {})
        assert dir_settings.get("external_sharing_restricted") is True


class TestEndToEndOUResolution:
    """End-to-end tests: raw Policy API data → normalize_data → check → verify paths."""

    def test_orgunit_ids_resolved_across_categories(self, full_audit_data):
        """orgUnits/<id> in policies resolve to paths when org_units has the OU."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.base import get_ou_values

        raw = dict(full_audit_data)
        raw["org_units"] = [
            {"orgUnitId": "id:aaa111", "orgUnitPath": "/Engineering"},
            {"orgUnitId": "id:bbb222", "orgUnitPath": "/Sales"},
        ]
        raw["policies"] = {
            "directory": [
                {"setting": {"type": "settings/directory.external_directory_sharing",
                             "value": {"sharing_option": "ORGANIZATION_DIRECTORY_DATA"}},
                 "orgUnit": "orgUnits/aaa111"},
            ],
            "calendar": [
                {"setting": {"type": "settings/calendar.external_invitations",
                             "value": {"warnOnExternalInvitations": False}},
                 "orgUnit": "orgUnits/bbb222"},
            ],
        }
        result = normalize_data(raw)

        dir_entries = get_ou_values(result["policies"]["directory"],
                                    "external_directory_sharing")
        assert dir_entries[0]["org_unit"] == "/Engineering"

        cal_entries = get_ou_values(result["policies"]["calendar"],
                                    "external_invitations")
        assert cal_entries[0]["org_unit"] == "/Sales"

    def test_check_result_uses_mapped_sharing_settings(self, full_audit_data):
        """CIS-1.2.1.1 uses the mapped sharing_settings from normalization."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.directory import check_directory_external_sharing

        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {
            "directory": [
                {"setting": {"type": "settings/directory.external_directory_sharing",
                             "value": {"sharing_option": "ORGANIZATION_DIRECTORY_DATA"}},
                 "orgUnit": "/"},
            ],
        }
        result = normalize_data(raw)
        check_result = check_directory_external_sharing(result)

        assert check_result.status == Status.FAIL

    def test_check_pass_via_normalization(self, full_audit_data):
        """REQUESTER_BASIC_PROFILE_ONLY normalizes to restricted=True → PASS."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.directory import check_directory_external_sharing

        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {
            "directory": [
                {"setting": {"type": "settings/directory.external_directory_sharing",
                             "value": {"sharing_option": "REQUESTER_BASIC_PROFILE_ONLY"}},
                 "orgUnit": "/"},
            ],
        }
        result = normalize_data(raw)
        check_result = check_directory_external_sharing(result)

        assert check_result.status == Status.PASS


class TestBackfillOrgUnits:
    """Tests for Provider._backfill_org_units — fetches missing OUs from API."""

    def _make_provider(self):
        """Create a minimal Provider with mocked auth."""
        from gws_auditor.provider import Provider
        auth = MagicMock()
        config = {"auth": {"customer_id": "C01234567"}}
        return Provider(auth, config)

    def test_backfill_fetches_missing_ou(self):
        """OUs referenced in policies but absent from org_units are fetched."""
        provider = self._make_provider()
        data = {
            "org_units": [],
            "policies": {
                "directory": [
                    {"setting": {"type": "settings/directory.external_directory_sharing",
                                 "value": {}},
                     "orgUnit": "orgUnits/03ph8a2z1rlsact"},
                ],
            },
        }

        fake_ou = {
            "orgUnitId": "id:03ph8a2z1rlsact",
            "orgUnitPath": "/Engineering",
            "name": "Engineering",
        }
        with patch("gws_auditor.api.directory.DirectoryClient") as MockDir:
            mock_client = MagicMock()
            mock_client.get_org_unit.return_value = fake_ou
            mock_client.errors = []
            MockDir.return_value = mock_client

            provider._backfill_org_units(data)

        assert len(data["org_units"]) == 1
        assert data["org_units"][0]["orgUnitPath"] == "/Engineering"
        mock_client.get_org_unit.assert_called_once_with(
            "C01234567", "03ph8a2z1rlsact"
        )

    def test_backfill_skips_known_ous(self):
        """OUs already in org_units are not re-fetched."""
        provider = self._make_provider()
        data = {
            "org_units": [
                {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
            ],
            "policies": {
                "directory": [
                    {"setting": {"type": "settings/directory.external_directory_sharing",
                                 "value": {}},
                     "orgUnit": "orgUnits/03ph8a2z1rlsact"},
                ],
            },
        }

        with patch("gws_auditor.api.directory.DirectoryClient") as MockDir:
            mock_client = MagicMock()
            mock_client.errors = []
            MockDir.return_value = mock_client

            provider._backfill_org_units(data)

        # Should NOT have been called — the OU is already known
        mock_client.get_org_unit.assert_not_called()

    def test_backfill_no_policies_is_noop(self):
        """No policy data → nothing to backfill."""
        provider = self._make_provider()
        data = {"org_units": [], "policies": {}}

        # Should not raise or make API calls
        provider._backfill_org_units(data)
        assert data["org_units"] == []

    def test_backfill_then_normalize_resolves(self):
        """Full flow: backfill + normalize_data → paths in check output."""
        from gws_auditor.provider import normalize_data

        # Simulate post-backfill data (the backfilled OU is in org_units)
        data = {
            "users": [],
            "domains": [{"domainName": "example.com"}],
            "org_units": [
                {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
            ],
            "policies": {
                "directory": [
                    {"setting": {"type": "settings/directory.external_directory_sharing",
                                 "value": {"sharing_option": "ORGANIZATION_DIRECTORY_DATA"}},
                     "orgUnit": "orgUnits/03ph8a2z1rlsact"},
                ],
            },
            "admin_logs": [], "login_logs": [], "token_logs": [],
            "usage_reports": {}, "dns_records": {}, "api_errors": [],
        }
        result = normalize_data(data)

        from gws_auditor.checks.directory import check_directory_external_sharing
        check_result = check_directory_external_sharing(result)
        # CIS-1.2.1.1 is global — the mapped sharing_settings drives the result
        assert check_result.status == Status.FAIL
