"""Tests for Calendar security checks."""

from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


class TestPrimaryCalExternalSharing:
    """Tests for CIS-3.1.1.1.1: primary calendar external sharing."""

    def test_pass_when_only_free_busy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"external_sharing": "only_free_busy"},
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_all_information(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"external_sharing": "all_information"},
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_when_read_write(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"external_sharing": "read_write_access"},
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_empty(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"external_sharing": ""},
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.ERROR

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {}
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.ERROR


class TestPrimaryCalInternalSharing:
    """Tests for CIS-3.1.1.1.2: primary calendar internal sharing."""

    def test_pass_when_only_free_busy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"internal_sharing": "only_free_busy"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_all_information(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"internal_sharing": "all_information"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.ERROR


class TestCalExternalInvitationWarning:
    """Tests for CIS-3.1.1.1.3: external invitation warning."""

    def test_pass_when_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {
            "external_invitation_warning": True,
        }
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {
            "external_invitation_warning": False,
        }
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {
            "external_invitation_warning": None,
        }
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.ERROR

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {}
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.ERROR


class TestSecondaryCalExternalSharing:
    """Tests for CIS-3.1.1.2.1: secondary calendar external sharing."""

    def test_pass_when_only_free_busy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {"external_sharing": "only_free_busy"},
        }
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_all_information(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {"external_sharing": "all_information"},
        }
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {}
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.ERROR


class TestSecondaryCalInternalSharing:
    """Tests for CIS-3.1.1.2.2: secondary calendar internal sharing."""

    def test_pass_when_only_free_busy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {"internal_sharing": "only_free_busy"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_all_information(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {"internal_sharing": "all_information"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.MANUAL


class TestPrimaryCalInternalSharingACL:
    """Tests for CIS-3.1.1.1.2: ACL-based fallback for primary calendar internal sharing."""

    def test_pass_when_acl_free_busy_reader(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"primary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "freeBusyReader", "sampled_user": "admin1@example.com"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.PASS
        assert "ACL sampling" in result.details

    def test_fail_when_acl_reader(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"primary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "reader", "sampled_user": "admin1@example.com"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.FAIL
        assert "reader" in result.details

    def test_fail_when_acl_writer(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"primary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "writer", "sampled_user": "admin1@example.com"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_fail_when_mixed_ous(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"primary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "freeBusyReader", "sampled_user": "admin1@example.com"},
            "/Sales": {"role": "reader", "sampled_user": "sales1@example.com"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details
        assert "1 OU(s)" in result.details

    def test_acl_not_used_when_policy_data_exists(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"internal_sharing": "only_free_busy"},
        }
        full_audit_data["calendar_acls"] = {
            "/": {"role": "reader", "sampled_user": "admin1@example.com"},
        }
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.PASS
        assert "ACL" not in result.details

    def test_manual_when_no_acl_and_no_policy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"primary_calendar": {}}
        full_audit_data["calendar_acls"] = {}
        result = check_primary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.ERROR


class TestSecondaryCalInternalSharingACL:
    """Tests for CIS-3.1.1.2.2: ACL fallback removed for secondary calendars.

    Primary calendar ACLs do not reflect secondary calendar admin settings,
    so the check should return MANUAL when the Policy API has no data.
    """

    def test_manual_when_no_policy_data(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"secondary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "freeBusyReader", "sampled_user": "admin1@example.com"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Policy API" in result.details

    def test_manual_when_acl_reader(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"secondary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "reader", "sampled_user": "admin1@example.com"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.MANUAL

    def test_manual_when_mixed_ous(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"secondary_calendar": {}}
        full_audit_data["calendar_acls"] = {
            "/": {"role": "freeBusyReader", "sampled_user": "admin1@example.com"},
            "/HR": {"role": "writer", "sampled_user": "hr1@example.com"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.MANUAL

    def test_acl_not_used_when_policy_data_exists(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {
            "secondary_calendar": {"internal_sharing": "only_free_busy"},
        }
        full_audit_data["calendar_acls"] = {
            "/": {"role": "reader", "sampled_user": "admin1@example.com"},
        }
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.PASS
        assert "ACL" not in result.details

    def test_manual_when_no_acl_and_no_policy(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_internal_sharing

        full_audit_data["policies"]["calendar"] = {"secondary_calendar": {}}
        full_audit_data["calendar_acls"] = {}
        result = check_secondary_cal_internal_sharing(full_audit_data)
        assert result.status == Status.MANUAL


class TestCalOfflineAccess:
    """Tests for CIS-3.1.1.3.1: Calendar offline access."""

    def test_pass_when_disabled(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        full_audit_data["policies"]["calendar"] = {
            "offline_access_enabled": False,
        }
        result = check_cal_offline_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_when_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        full_audit_data["policies"]["calendar"] = {
            "offline_access_enabled": True,
        }
        result = check_cal_offline_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        full_audit_data["policies"]["calendar"] = {
            "offline_access_enabled": None,
        }
        result = check_cal_offline_access(full_audit_data)
        assert result.status == Status.MANUAL

    def test_manual_when_key_missing(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        full_audit_data["policies"]["calendar"] = {}
        result = check_cal_offline_access(full_audit_data)
        assert result.status == Status.MANUAL

    def test_end_to_end_default_injection(self, full_audit_data):
        """GOOGLE_DEFAULTS entry → MANUAL since DEFAULT values are unconfirmed."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        raw = dict(full_audit_data)
        raw["org_units"] = []
        # Simulate API returning calendar policies WITHOUT offline, plus
        # the GOOGLE_DEFAULTS synthetic entry injected by PolicyClient.
        # DEFAULT entries cannot be trusted to represent admin config.
        raw["policies"] = {
            "calendar": [
                {
                    "name": "policies/_default/calendar.calendar_offline_access",
                    "setting": {
                        "type": "settings/calendar.calendar_offline_access",
                        "value": {"enableOfflineAccess": True},
                    },
                    "type": "DEFAULT",
                    "orgUnit": "/",
                },
            ],
        }
        result = normalize_data(raw)
        check_result = check_cal_offline_access(result)
        assert check_result.status == Status.MANUAL

    def test_end_to_end_disabled(self, full_audit_data):
        """API returns enableOfflineAccess=False → PASS via normalize_data."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_calendar import check_cal_offline_access

        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {
            "calendar": [
                {
                    "setting": {
                        "type": "settings/calendar.calendar_offline_access",
                        "value": {"enableOfflineAccess": False},
                    },
                    "orgUnit": "/",
                },
            ],
        }
        result = normalize_data(raw)
        check_result = check_cal_offline_access(result)
        assert check_result.status == Status.PASS


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------

class TestPrimaryCalExternalSharingOU:
    """OU-aware tests for CIS-3.1.1.1.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "FREE_BUSY_ONLY"}, "/"),
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "ONLY_FREE_BUSY"}, "/Engineering"),
            ],
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_pass_with_external_prefixed_enum(self, full_audit_data):
        """EXTERNAL_FREE_BUSY_ONLY is the real API enum and should pass."""
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"}, "/"),
            ],
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_with_no_free_busy(self, full_audit_data):
        """EXTERNAL_NO_FREE_BUSY (no sharing) is more restrictive and should pass."""
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "EXTERNAL_NO_FREE_BUSY"}, "/"),
            ],
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_with_external_all_info(self, full_audit_data):
        """EXTERNAL_ALL_INFO_READ_ONLY is too permissive and should fail."""
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"}, "/"),
            ],
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "FREE_BUSY_ONLY"}, "/"),
                make_ou_policy("calendar", "primary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "ALL_INFORMATION"}, "/Sales"),
            ],
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_primary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "primary_calendar": {"external_sharing": "only_free_busy"},
        }
        result = check_primary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS


class TestCalExternalInvitationWarningOU:
    """OU-aware tests for CIS-3.1.1.1.3."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "external_invitations",
                                {"warnOnExternalInvitations": True}, "/"),
                make_ou_policy("calendar", "external_invitations",
                                {"warnOnExternalInvitations": True}, "/Engineering"),
            ],
        }
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_cal_external_invitation_warning

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "external_invitations",
                                {"warnOnExternalInvitations": True}, "/"),
                make_ou_policy("calendar", "external_invitations",
                                {"warnOnExternalInvitations": False}, "/Marketing"),
            ],
        }
        result = check_cal_external_invitation_warning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details


class TestSecondaryCalExternalSharingOU:
    """OU-aware tests for CIS-3.1.1.2.1."""

    def test_pass_with_external_prefixed_enum(self, full_audit_data):
        """EXTERNAL_FREE_BUSY_ONLY is the real API enum and should pass."""
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "secondary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"}, "/"),
            ],
        }
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_with_no_free_busy(self, full_audit_data):
        """EXTERNAL_NO_FREE_BUSY (no sharing) is more restrictive and should pass."""
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "secondary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "EXTERNAL_NO_FREE_BUSY"}, "/"),
            ],
        }
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_calendar import check_secondary_cal_external_sharing

        full_audit_data["policies"]["calendar"] = {
            "_ou_policies": [
                make_ou_policy("calendar", "secondary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "FREE_BUSY_ONLY"}, "/"),
                make_ou_policy("calendar", "secondary_calendar_max_allowed_external_sharing",
                                {"maxAllowedExternalSharing": "ALL_INFORMATION"}, "/HR"),
            ],
        }
        result = check_secondary_cal_external_sharing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/HR" in result.details


# -----------------------------------------------------------------------
# OU ID resolution tests
# -----------------------------------------------------------------------

class TestOUIdResolution:
    """Verify that orgUnits/<id> values are resolved to human-readable paths
    and that the lstrip('id:') bug is fixed (removeprefix used instead)."""

    def test_orgunit_id_resolved_in_ou_policies(self, full_audit_data):
        """OU-aware checks should display resolved paths, not raw API IDs."""
        from gws_auditor.provider import _build_ou_id_map, _resolve_org_unit

        org_units = [
            {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
            {"orgUnitId": "id:04ab9c3z2smtbdu", "orgUnitPath": "/Sales"},
        ]
        ou_id_map = _build_ou_id_map(org_units)

        # orgUnits/<bare_id> format used by the Policy API should resolve
        assert _resolve_org_unit("orgUnits/03ph8a2z1rlsact", ou_id_map) == "/Engineering"
        assert _resolve_org_unit("orgUnits/04ab9c3z2smtbdu", ou_id_map) == "/Sales"

    def test_removeprefix_does_not_corrupt_ids(self, full_audit_data):
        """IDs starting with 'i', 'd', or ':' must not be corrupted."""
        from gws_auditor.provider import _build_ou_id_map, _resolve_org_unit

        # 'd1234abc' starts with 'd' — lstrip("id:") would eat the leading 'd'
        org_units = [
            {"orgUnitId": "id:d1234abc", "orgUnitPath": "/Design"},
        ]
        ou_id_map = _build_ou_id_map(org_units)

        # The bare ID should be 'd1234abc', not '1234abc'
        assert "d1234abc" in ou_id_map
        assert ou_id_map["d1234abc"] == "/Design"
        assert _resolve_org_unit("orgUnits/d1234abc", ou_id_map) == "/Design"

    def test_direct_lookup_for_orgunits_format(self, full_audit_data):
        """_resolve_org_unit should match 'orgUnits/<id>' directly in the map."""
        from gws_auditor.provider import _build_ou_id_map, _resolve_org_unit

        org_units = [
            {"orgUnitId": "id:abc123", "orgUnitPath": "/Finance"},
        ]
        ou_id_map = _build_ou_id_map(org_units)

        # Direct key 'orgUnits/abc123' should exist in the map
        assert "orgUnits/abc123" in ou_id_map
        assert _resolve_org_unit("orgUnits/abc123", ou_id_map) == "/Finance"

    def test_root_ou_passthrough(self, full_audit_data):
        """Root OU '/' should pass through unchanged."""
        from gws_auditor.provider import _resolve_org_unit

        assert _resolve_org_unit("/", {}) == "/"
        assert _resolve_org_unit("", {}) == "/"

    def test_ou_path_passthrough(self, full_audit_data):
        """Already-resolved paths like '/Engineering' should pass through."""
        from gws_auditor.provider import _resolve_org_unit

        assert _resolve_org_unit("/Engineering", {}) == "/Engineering"

    def test_end_to_end_policy_normalization(self, full_audit_data):
        """Full normalize_data flow resolves orgUnits/<id> in _ou_policies."""
        from gws_auditor.provider import normalize_data

        raw_data = dict(full_audit_data)
        raw_data["org_units"] = [
            {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
        ]
        raw_data["policies"] = {
            "calendar": [
                {
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnExternalInvitations": True},
                    },
                    "orgUnit": "orgUnits/03ph8a2z1rlsact",
                },
            ],
        }
        result = normalize_data(raw_data)
        ou_policies = result["policies"]["calendar"]["_ou_policies"]
        assert ou_policies[0]["orgUnit"] == "/Engineering"

    def test_ou_id_map_stored_in_category_dict(self, full_audit_data):
        """_normalize_policies stores _ou_id_map for secondary resolution."""
        from gws_auditor.provider import normalize_data

        raw_data = dict(full_audit_data)
        raw_data["org_units"] = [
            {"orgUnitId": "id:abc123", "orgUnitPath": "/Finance"},
        ]
        raw_data["policies"] = {
            "calendar": [
                {
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnExternalInvitations": True},
                    },
                    "orgUnit": "/",
                },
            ],
        }
        result = normalize_data(raw_data)
        cal = result["policies"]["calendar"]
        assert "_ou_id_map" in cal
        assert cal["_ou_id_map"].get("orgUnits/abc123") == "/Finance"

    def test_get_ou_values_secondary_resolution(self, full_audit_data):
        """get_ou_values resolves orgUnit IDs via _ou_id_map as a safety net."""
        from gws_auditor.checks.base import get_ou_values
        from gws_auditor.provider import _build_ou_id_map

        # Simulate a category dict where _ou_policies have unresolved IDs
        # (e.g. _resolve_org_unit missed them on the first pass).
        ou_id_map = _build_ou_id_map([
            {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
        ])
        category_dict = {
            "_ou_id_map": ou_id_map,
            "_ou_policies": [
                {
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnExternalInvitations": False},
                    },
                    "orgUnit": "orgUnits/03ph8a2z1rlsact",  # unresolved
                },
            ],
        }
        results = get_ou_values(category_dict, "external_invitations")
        assert len(results) == 1
        assert results[0]["org_unit"] == "/Engineering"

    def test_get_ou_values_no_map_falls_through(self, full_audit_data):
        """Without _ou_id_map, unresolved IDs pass through unchanged."""
        from gws_auditor.checks.base import get_ou_values

        category_dict = {
            "_ou_policies": [
                {
                    "setting": {
                        "type": "settings/calendar.external_invitations",
                        "value": {"warnOnExternalInvitations": False},
                    },
                    "orgUnit": "orgUnits/unknown_id",
                },
            ],
        }
        results = get_ou_values(category_dict, "external_invitations")
        assert len(results) == 1
        assert results[0]["org_unit"] == "orgUnits/unknown_id"

    def test_dict_branch_resolves_ou_policies(self, full_audit_data):
        """When policies are already dicts, _ou_policies still get resolved."""
        from gws_auditor.provider import normalize_data

        raw_data = dict(full_audit_data)
        raw_data["org_units"] = [
            {"orgUnitId": "id:03ph8a2z1rlsact", "orgUnitPath": "/Engineering"},
        ]
        # Simulate already-normalized data (dict, not list) that has
        # _ou_policies with unresolved orgUnit values.
        raw_data["policies"] = {
            "calendar": {
                "_ou_policies": [
                    {
                        "setting": {
                            "type": "settings/calendar.external_invitations",
                            "value": {"warnOnExternalInvitations": True},
                        },
                        "orgUnit": "orgUnits/03ph8a2z1rlsact",
                    },
                ],
            },
        }
        result = normalize_data(raw_data)
        ou_policies = result["policies"]["calendar"]["_ou_policies"]
        assert ou_policies[0]["orgUnit"] == "/Engineering"


# -----------------------------------------------------------------------
# Calendar 404 fallback tests
# -----------------------------------------------------------------------

class TestCalendarACLFallback:
    """Tests for multi-user fallback when a user's calendar returns 404."""

    def _make_provider(self):
        """Create a minimal DataProvider for testing _get_calendar_acls."""
        from gws_auditor.provider import Provider
        prov = Provider.__new__(Provider)
        prov.auth = MagicMock()
        prov._api_errors = []
        return prov

    def test_fallback_on_calendar_not_found(self):
        """When first user's calendar 404s, the next user is tried."""
        from gws_auditor.api.calendar import CalendarNotFoundError

        prov = self._make_provider()
        data = {
            "users": [
                {"primaryEmail": "bad@example.com", "orgUnitPath": "/"},
                {"primaryEmail": "good@example.com", "orgUnitPath": "/"},
            ],
            "domains": [{"domainName": "example.com", "isPrimary": True}],
        }

        acl_response = [
            {
                "scope": {"type": "domain", "value": "example.com"},
                "role": "freeBusyReader",
            }
        ]

        with patch(
            "gws_auditor.api.calendar.CalendarClient"
        ) as MockCalClient:
            mock_client = MagicMock()
            mock_client.get_calendar_acl.side_effect = [
                CalendarNotFoundError("bad@example.com", "bad@example.com"),
                acl_response,
            ]
            mock_client.errors = []
            MockCalClient.return_value = mock_client

            result = prov._get_calendar_acls(data)

        assert "/" in result
        assert result["/"]["sampled_user"] == "good@example.com"
        assert result["/"]["role"] == "freeBusyReader"
        assert mock_client.get_calendar_acl.call_count == 2

    def test_all_users_404_returns_empty(self):
        """When all users' calendars 404, OU gets no result."""
        from gws_auditor.api.calendar import CalendarNotFoundError

        prov = self._make_provider()
        data = {
            "users": [
                {"primaryEmail": "a@example.com", "orgUnitPath": "/"},
                {"primaryEmail": "b@example.com", "orgUnitPath": "/"},
                {"primaryEmail": "c@example.com", "orgUnitPath": "/"},
                {"primaryEmail": "d@example.com", "orgUnitPath": "/"},
            ],
            "domains": [{"domainName": "example.com", "isPrimary": True}],
        }

        with patch(
            "gws_auditor.api.calendar.CalendarClient"
        ) as MockCalClient:
            mock_client = MagicMock()
            mock_client.get_calendar_acl.side_effect = CalendarNotFoundError(
                "x", "x"
            )
            mock_client.errors = []
            MockCalClient.return_value = mock_client

            result = prov._get_calendar_acls(data)

        assert result == {}
        # Should only try up to _MAX_CALENDAR_FALLBACK_ATTEMPTS (3)
        assert mock_client.get_calendar_acl.call_count == 3

    def test_first_user_succeeds_no_fallback(self):
        """When first user works, no fallback needed."""
        prov = self._make_provider()
        data = {
            "users": [
                {"primaryEmail": "good@example.com", "orgUnitPath": "/"},
                {"primaryEmail": "other@example.com", "orgUnitPath": "/"},
            ],
            "domains": [{"domainName": "example.com", "isPrimary": True}],
        }

        acl_response = [
            {
                "scope": {"type": "domain", "value": "example.com"},
                "role": "reader",
            }
        ]

        with patch(
            "gws_auditor.api.calendar.CalendarClient"
        ) as MockCalClient:
            mock_client = MagicMock()
            mock_client.get_calendar_acl.return_value = acl_response
            mock_client.errors = []
            MockCalClient.return_value = mock_client

            result = prov._get_calendar_acls(data)

        assert "/" in result
        assert result["/"]["sampled_user"] == "good@example.com"
        assert mock_client.get_calendar_acl.call_count == 1
