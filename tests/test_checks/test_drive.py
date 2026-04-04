"""Tests for Drive and Docs security checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


def _set_drive_sharing(data, key, value):
    """Set a Drive sharing policy value."""
    data["policies"]["drive"] = data["policies"].get("drive", {})
    data["policies"]["drive"]["sharing_settings"] = data["policies"]["drive"].get("sharing_settings", {})
    data["policies"]["drive"]["sharing_settings"][key] = value
    return data


def _set_drive_shared(data, key, value):
    """Set a shared drive policy value."""
    data["policies"]["drive"] = data["policies"].get("drive", {})
    data["policies"]["drive"]["shared_drive_settings"] = data["policies"]["drive"].get("shared_drive_settings", {})
    data["policies"]["drive"]["shared_drive_settings"][key] = value
    return data


def _set_drive_feature(data, key, value):
    """Set a Drive feature policy value."""
    data["policies"]["drive"] = data["policies"].get("drive", {})
    data["policies"]["drive"]["features"] = data["policies"]["drive"].get("features", {})
    data["policies"]["drive"]["features"][key] = value
    return data


class TestDriveSharing:
    """Tests for CIS-3.1.2.1.1.x Drive sharing checks."""

    def test_external_sharing_warning_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning
        _set_drive_sharing(full_audit_data, "warn_on_external_sharing", True)
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_external_sharing_warning_fail(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning
        _set_drive_sharing(full_audit_data, "warn_on_external_sharing", False)
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.FAIL

    def test_publish_publicly_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_public_publishing
        _set_drive_sharing(full_audit_data, "allow_public_publishing", False)
        result = check_drive_public_publishing(full_audit_data)
        assert result.status == Status.PASS

    def test_publish_publicly_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_public_publishing
        _set_drive_sharing(full_audit_data, "allow_public_publishing", True)
        result = check_drive_public_publishing(full_audit_data)
        assert result.status == Status.FAIL


class TestSharedDrives:
    """Tests for CIS-3.1.2.1.2.x Shared Drive checks."""

    def test_shared_drive_creation_controlled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_creation
        _set_drive_shared(full_audit_data, "creation_restricted", True)
        result = check_shared_drive_creation(full_audit_data)
        assert result.status == Status.PASS

    def test_shared_drive_members_only_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_member_access
        _set_drive_shared(full_audit_data, "access_restricted_to_members", True)
        result = check_shared_drive_member_access(full_audit_data)
        assert result.status == Status.PASS


class TestDriveFeatures:
    """Tests for CIS-3.1.2.2.x Drive feature checks."""

    def test_offline_access_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_offline_access
        _set_drive_feature(full_audit_data, "offline_access_enabled", False)
        result = check_drive_offline_access(full_audit_data)
        assert result.status == Status.PASS

    def test_offline_access_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_offline_access
        _set_drive_feature(full_audit_data, "offline_access_enabled", True)
        result = check_drive_offline_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_desktop_access_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_desktop_access
        _set_drive_feature(full_audit_data, "desktop_access_enabled", False)
        result = check_drive_desktop_access(full_audit_data)
        assert result.status == Status.PASS

    def test_drive_sdk_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_sdk
        _set_drive_feature(full_audit_data, "drive_sdk_enabled", False)
        result = check_drive_sdk(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# OU-aware tests
# -----------------------------------------------------------------------


class TestDriveExternalSharingWarningOU:
    """OU-aware tests for CIS-3.1.2.1.1.1: external sharing warning."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"warnOnExternalSharing": True}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"warnOnExternalSharing": True}, "/Engineering"),
            ],
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"warnOnExternalSharing": True}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"warnOnExternalSharing": False}, "/Sales"),
            ],
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"warn_on_external_sharing": True},
        }
        result = check_drive_external_sharing_warning(full_audit_data)
        assert result.status == Status.PASS


class TestDrivePublicPublishingOU:
    """OU-aware tests for CIS-3.1.2.1.1.2: public publishing."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_public_publishing

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowPublicPublishing": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowPublicPublishing": False}, "/HR"),
            ],
        }
        result = check_drive_public_publishing(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_public_publishing

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"allowPublicPublishing": False}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"allowPublicPublishing": True}, "/Marketing"),
            ],
        }
        result = check_drive_public_publishing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Marketing" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_public_publishing

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"allow_public_publishing": False},
        }
        result = check_drive_public_publishing(full_audit_data)
        assert result.status == Status.PASS


class TestDriveAccessCheckerOU:
    """OU-aware tests for CIS-3.1.2.1.1.5: Access Checker."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestion": "RECIPIENTS_ONLY"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestion": "DOMAIN_ONLY"}, "/Finance"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestion": "RECIPIENTS_ONLY"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"accessCheckerSuggestion": "ANYONE"}, "/Contractors"),
            ],
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_access_checker

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"access_checker_suggestion": "recipients_only"},
        }
        result = check_drive_access_checker(full_audit_data)
        assert result.status == Status.PASS


class TestDriveExternalDistributionOU:
    """OU-aware tests for CIS-3.1.2.1.1.6: external distribution."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_distribution

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalDistributionAllowedFor": "INTERNAL_USERS_ONLY"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalDistributionAllowedFor": "INTERNAL_USERS_ONLY"}, "/Legal"),
            ],
        }
        result = check_drive_external_distribution(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_distribution

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "external_sharing",
                                {"externalDistributionAllowedFor": "INTERNAL_USERS_ONLY"}, "/"),
                make_ou_policy("drive", "external_sharing",
                                {"externalDistributionAllowedFor": "EVERYONE"}, "/Sales"),
            ],
        }
        result = check_drive_external_distribution(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_external_distribution

        full_audit_data["policies"]["drive"] = {
            "sharing_settings": {"external_distribution_allowed_for": "internal_users_only"},
        }
        result = check_drive_external_distribution(full_audit_data)
        assert result.status == Status.PASS


class TestSharedDriveCreationOU:
    """OU-aware tests for CIS-3.1.2.1.2.1: shared drive creation."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_creation

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowSharedDriveCreation": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowSharedDriveCreation": False}, "/Engineering"),
            ],
        }
        result = check_shared_drive_creation(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_creation

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowSharedDriveCreation": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowSharedDriveCreation": True}, "/Temp"),
            ],
        }
        result = check_shared_drive_creation(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Temp" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_creation

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"creation_restricted": True},
        }
        result = check_shared_drive_creation(full_audit_data)
        assert result.status == Status.PASS


class TestSharedDriveManagerOverrideOU:
    """OU-aware tests for CIS-3.1.2.1.2.2: manager override."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": False}, "/HR"),
            ],
        }
        result = check_shared_drive_manager_override(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowManagersToOverrideSettings": True}, "/Dev"),
            ],
        }
        result = check_shared_drive_manager_override(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Dev" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_manager_override

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"manager_can_override": False},
        }
        result = check_shared_drive_manager_override(full_audit_data)
        assert result.status == Status.PASS


class TestSharedDriveMemberAccessOU:
    """OU-aware tests for CIS-3.1.2.1.2.3: member access."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_member_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": False}, "/Finance"),
            ],
        }
        result = check_shared_drive_member_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_member_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": False}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowNonMemberAccess": True}, "/Guests"),
            ],
        }
        result = check_shared_drive_member_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Guests" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_member_access

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"access_restricted_to_members": True},
        }
        result = check_shared_drive_member_access(full_audit_data)
        assert result.status == Status.PASS


class TestSharedDriveViewerRestrictionsOU:
    """OU-aware tests for CIS-3.1.2.1.2.4: viewer restrictions."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_viewer_restrictions

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowedPartiesForDownloadPrintCopy": "NONE"}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowedPartiesForDownloadPrintCopy": "MANAGERS_ONLY"}, "/Legal"),
            ],
        }
        result = check_shared_drive_viewer_restrictions(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_viewer_restrictions

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowedPartiesForDownloadPrintCopy": "NONE"}, "/"),
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowedPartiesForDownloadPrintCopy": "ALL"}, "/Contractors"),
            ],
        }
        result = check_shared_drive_viewer_restrictions(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_child_ou_editors_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_viewer_restrictions

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "shared_drive_creation",
                                {"allowedPartiesForDownloadPrintCopy": "EDITORS_AND_ABOVE"}, "/"),
            ],
        }
        result = check_shared_drive_viewer_restrictions(full_audit_data)
        assert result.status == Status.FAIL

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_shared_drive_viewer_restrictions

        full_audit_data["policies"]["drive"] = {
            "shared_drive_settings": {"viewer_download_print_copy_disabled": True},
        }
        result = check_shared_drive_viewer_restrictions(full_audit_data)
        assert result.status == Status.PASS


class TestDriveDesktopAccessOU:
    """OU-aware tests for CIS-3.1.2.2.2: Drive for Desktop."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_desktop_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_for_desktop",
                                {"allowDriveForDesktop": False}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"allowDriveForDesktop": False}, "/Engineering"),
            ],
        }
        result = check_drive_desktop_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_desktop_access

        full_audit_data["policies"]["drive"] = {
            "_ou_policies": [
                make_ou_policy("drive", "drive_for_desktop",
                                {"allowDriveForDesktop": False}, "/"),
                make_ou_policy("drive", "drive_for_desktop",
                                {"allowDriveForDesktop": True}, "/Remote"),
            ],
        }
        result = check_drive_desktop_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Remote" in result.details

    def test_fallback(self, full_audit_data):
        from gws_auditor.checks.apps_drive import check_drive_desktop_access

        full_audit_data["policies"]["drive"] = {
            "features": {"desktop_access_enabled": False},
        }
        result = check_drive_desktop_access(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# End-to-end: raw Policy API data (snake_case) → normalize → check
# -----------------------------------------------------------------------


class TestDriveSnakeCaseNormalization:
    """Verify that snake_case field names from the API are correctly
    normalised and made available to checks via both the OU-aware path
    and the flat mapped path.
    """

    def _raw_data_with_policy(self, full_audit_data, setting_suffix, value_dict, org_unit="/"):
        """Create raw data with a drive policy using API snake_case keys."""
        raw = dict(full_audit_data)
        raw["org_units"] = []
        raw["policies"] = {
            "drive": [
                {
                    "setting": {
                        "type": f"settings/drive_and_docs.{setting_suffix}",
                        "value": value_dict,
                    },
                    "orgUnit": org_unit,
                },
            ],
        }
        return raw

    def test_external_sharing_warning_snake_case_pass(self, full_audit_data):
        """API returns warn_for_external_sharing (snake_case) → PASS."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        raw = self._raw_data_with_policy(
            full_audit_data, "external_sharing",
            {"warn_for_external_sharing": True},
        )
        result = normalize_data(raw)
        check_result = check_drive_external_sharing_warning(result)
        assert check_result.status == Status.PASS

    def test_external_sharing_warning_snake_case_fail(self, full_audit_data):
        """API returns warn_for_external_sharing=False (snake_case) → FAIL."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        raw = self._raw_data_with_policy(
            full_audit_data, "external_sharing",
            {"warn_for_external_sharing": False},
        )
        result = normalize_data(raw)
        check_result = check_drive_external_sharing_warning(result)
        assert check_result.status == Status.FAIL

    def test_external_sharing_warning_camel_case_still_works(self, full_audit_data):
        """camelCase field names (e.g. from GOOGLE_DEFAULTS) still work."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_drive import check_drive_external_sharing_warning

        raw = self._raw_data_with_policy(
            full_audit_data, "external_sharing",
            {"warnForExternalSharing": True},
        )
        result = normalize_data(raw)
        check_result = check_drive_external_sharing_warning(result)
        assert check_result.status == Status.PASS

    def test_shared_drive_creation_snake_case(self, full_audit_data):
        """API returns allow_shared_drive_creation (snake_case) → mapped correctly."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_drive import check_shared_drive_creation

        raw = self._raw_data_with_policy(
            full_audit_data, "shared_drive_creation",
            {"allow_shared_drive_creation": False},
        )
        result = normalize_data(raw)
        check_result = check_shared_drive_creation(result)
        assert check_result.status == Status.PASS

    def test_drive_for_desktop_snake_case(self, full_audit_data):
        """API returns allow_drive_for_desktop (snake_case) → mapped correctly."""
        from gws_auditor.provider import normalize_data
        from gws_auditor.checks.apps_drive import check_drive_desktop_access

        raw = self._raw_data_with_policy(
            full_audit_data, "drive_for_desktop",
            {"allow_drive_for_desktop": False},
        )
        result = normalize_data(raw)
        check_result = check_drive_desktop_access(result)
        assert check_result.status == Status.PASS


# -----------------------------------------------------------------------
# Additional Drive checks (ADD-24, ADD-25)
# -----------------------------------------------------------------------


class TestDriveAiClassification:
    """Tests for ADD-24 AI-powered Drive classification."""

    def test_ai_classification_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_ai_classification
        full_audit_data["policies"]["drive"]["classification"] = {
            "ai_classification_enabled": True,
        }
        result = check_drive_ai_classification(full_audit_data)
        assert result.status == Status.PASS

    def test_ai_classification_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_ai_classification
        full_audit_data["policies"]["drive"]["classification"] = {
            "ai_classification_enabled": False,
        }
        result = check_drive_ai_classification(full_audit_data)
        assert result.status == Status.FAIL

    def test_ai_classification_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_ai_classification
        # No classification key
        result = check_drive_ai_classification(full_audit_data)
        assert result.status == Status.MANUAL


class TestDriveTrustRules:
    """Tests for ADD-25 Drive trust rules."""

    def test_trust_rules_configured_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_trust_rules
        full_audit_data["policies"]["drive"]["trust_rules"] = [
            {"name": "Internal sharing only"},
        ]
        result = check_drive_trust_rules(full_audit_data)
        assert result.status == Status.PASS

    def test_trust_rules_empty_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_trust_rules
        full_audit_data["policies"]["drive"]["trust_rules"] = []
        result = check_drive_trust_rules(full_audit_data)
        assert result.status == Status.FAIL

    def test_trust_rules_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_drive_trust_rules
        # No trust_rules key
        result = check_drive_trust_rules(full_audit_data)
        assert result.status == Status.MANUAL
