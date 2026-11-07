"""Tests for security access control checks (OU-aware + fallback)."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_admin_event
from tests.factories import make_ou_policy



# -----------------------------------------------------------------------
# CIS-4.2.1.1: Third-party app access
# -----------------------------------------------------------------------

class TestThirdPartyAppAccess:
    """Tests for CIS-4.2.1.1 (fallback path)."""

    def test_pass_restricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": True,
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS

    def test_pass_trust_policy_restricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": None,
            "trust_policy": "restricted",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS

    def test_fail_unrestricted(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": False,
            "trust_policy": "open",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.FAIL

    def test_manual_when_none(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": None,
            "trust_policy": "",
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.MANUAL


class TestThirdPartyAppAccessOU:
    """OU-aware tests for CIS-4.2.1.1."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "RESTRICTED"}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "BLOCKED"}, "/Engineering"),
            ],
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"]["security"] = {
            "_ou_policies": [
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "RESTRICTED"}, "/"),
                make_ou_policy("security", "unconfigured_third_party_apps",
                                {"accessLevel": "UNRESTRICTED"}, "/Sales"),
            ],
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "third_party_apps_restricted": True,
        }
        result = check_third_party_app_access(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.2.1.2: Third-party app review (non-policy, unchanged)
# -----------------------------------------------------------------------

class TestThirdPartyAppReview:
    """Tests for CIS-4.2.1.2 (uses token_logs, not policy)."""

    def test_no_token_logs_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = []
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.ERROR

    def test_with_token_logs_no_policy_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = [
            {"app_name": "SomeApp", "client_id": "abc123"},
            {"app_name": "AnotherApp", "client_id": "def456"},
        ]
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.FAIL

    def test_with_token_logs_and_policy_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_third_party_app_review
        full_audit_data["token_logs"] = [
            {"app_name": "SomeApp", "client_id": "abc123"},
            {"app_name": "AnotherApp", "client_id": "def456"},
        ]
        full_audit_data["policies"]["access_control"] = {
            "app_access_policy": "restricted",
        }
        result = check_third_party_app_review(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# CIS-4.2.1.3: Internal API access (no OU mapping given, unchanged)
# -----------------------------------------------------------------------

class TestInternalApiAccess:
    """Tests for CIS-4.2.1.3."""

    def test_controlled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": True,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.PASS

    def test_not_controlled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_internal_api_access
        full_audit_data["policies"].setdefault("security", {})["api_access"] = {
            "internal_apps_controlled": False,
        }
        result = check_internal_api_access(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# CIS-4.2.1.4: Domain-wide delegation (no OU mapping, unchanged)
# -----------------------------------------------------------------------



class TestDomainWideDelegation:
    """CIS-4.2.1.4: grants come from AUTHORIZE_API_CLIENT_ACCESS / REMOVE_API_CLIENT_ACCESS admin events
    (API_CLIENT_NAME may list several client IDs); no API lists the clients."""

    _BASE = "https://www.googleapis.com/auth/"

    def _ev(self, name, clients, scopes, time):
        return make_admin_event(name, {"API_CLIENT_NAME": clients, "API_SCOPES": scopes}, time)

    def test_no_event_in_window_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [make_admin_event("CHANGE_APPLICATION_SETTING", {}, "2026-08-01T00:00:00Z")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL
        assert "since 2026-08-01" in result.details

    def test_low_risk_grants_are_review_with_window(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [self._ev(
            "AUTHORIZE_API_CLIENT_ACCESS", "111.apps.googleusercontent.com,222.apps.googleusercontent.com,333.apps.googleusercontent.com",
            f"{self._BASE}drive.file,\n{self._BASE}spreadsheets.currentonly,\n{self._BASE}userinfo.email,\nopenid", "2026-10-19T21:06:23.587Z")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL  # inventory never known complete: review, never PASS
        assert result.actual_value["delegation_count"] == 3  # comma-separated client IDs are split
        assert "since 2026-10-19" in result.details and "not visible" in result.details

    def test_org_wide_write_scopes_warn(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "111", f"{self._BASE}admin.directory.user.readonly", "2026-01-01"),
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify,{self._BASE}drive", "2026-01-02")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.WARN
        assert "222: drive, gmail.modify" in result.details and "111:" not in result.details
        assert result.actual_value == {"delegation_count": 2, "high_risk_clients": 1, "allowlisted_clients": 0, "window_start": "2026-01-01"}

    def test_allowlisted_risky_client_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify", "2026-01-02")]
        full_audit_data["_options"] = {"dwd_allowlist": ["222"]}
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL
        assert "1 client(s) with such scopes are vetted" in result.details
        assert result.actual_value["allowlisted_clients"] == 1

    def test_revocation_after_grant_clears_it(self, full_audit_data):
        from gws_auditor.checks.security_access import check_domain_wide_delegation
        full_audit_data["admin_logs"] = [
            self._ev("AUTHORIZE_API_CLIENT_ACCESS", "222", f"{self._BASE}gmail.modify", "2026-01-02"),
            self._ev("REMOVE_API_CLIENT_ACCESS", "222", "", "2026-01-03")]
        result = check_domain_wide_delegation(full_audit_data)
        assert result.status == Status.MANUAL and result.actual_value["delegation_count"] == 0


# -----------------------------------------------------------------------
# CIS-4.2.2.1: Geo-blocking (no OU mapping, unchanged)
# -----------------------------------------------------------------------

class TestGeoBlocking:
    """Tests for CIS-4.2.2.1."""

    def test_with_regions_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": True,
            "blocked_regions": ["AQ", "BV", "HM"],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS

    def test_no_regions_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"].setdefault("security", {})["context_aware_access"] = {
            "geo_blocking_enabled": False,
            "blocked_regions": [],
        }
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.FAIL

    # Admin-log evidence: exact events observed live on 2026-11-06 (Geo restriction flip).
    _LEVEL = "accessPolicies/134654395911/accessLevels/geo_restriction_fttlt6s2"
    _STATE = ('{\n  "basic": {\n    "conditions": [{\n      "regions": ["AQ"],\n      "negate": true\n    }]\n  },\n'
              '  "title": "Geo restriction",\n  "name": "accessPolicies/134654395911/accessLevels/geo_restriction_fttlt6s2"\n}')

    @classmethod
    def _create(cls, time="2026-11-06T18:23:52.947Z", state=None):
        from tests.factories import make_admin_event
        return make_admin_event("CREATE_ACCESS_LEVEL_V2", {
            "ACCESS_LEVEL_TITLE": "Geo restriction", "ACCESS_LEVEL_NAME": cls._LEVEL,
            "ACCESS_LEVEL_CURR_STATE": cls._STATE if state is None else state,
            "AUTH_PRINCIPLE_EMAIL": "admin@example.com"}, time)

    @classmethod
    def _delete(cls, time="2026-11-06T19:00:00.000Z"):
        from tests.factories import make_admin_event
        return make_admin_event("DELETE_ACCESS_LEVEL_V2", {
            "ACCESS_LEVEL_NAME": cls._LEVEL, "AUTH_PRINCIPLE_EMAIL": "admin@example.com"}, time)

    @staticmethod
    def _assign(app, mode, levels, time="2026-11-06T18:26:28.786Z", removed=False):
        from tests.factories import make_admin_event
        key = "CAA_ACCESS_ASSIGNMENTS_OLD" if removed else "CAA_ACCESS_ASSIGNMENTS_NEW"
        return make_admin_event("CHANGE_CAA_APP_ASSIGNMENTS", {
            "APPLICATION_NAME": app, "CAA_ENFORCEMENT_ENDPOINTS_OLD": "CAA_WEB_VERSION",
            "CAA_ENFORCEMENT_ENDPOINTS_NEW": "CAA_WEB_VERSION_AND_1P_OAUTH_CLIENTS",
            "TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "example.com",
            "MODE": mode, key: list(levels)}, time)

    def test_live_geo_restriction_sequence(self, full_audit_data):
        """Create level -> assign BLOCK to apps -> PASS; delete the level -> back to MANUAL."""
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = []
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"] = [self._create()]
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.MANUAL
        assert "no Block-mode assignment" in result.details
        full_audit_data["admin_logs"] += [self._assign("GMAIL", "BLOCK", ["Geo restriction"]),
                                          self._assign("DRIVE", "BLOCK", ["Geo restriction"], time="2026-11-06T18:26:28.785Z")]
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS
        assert "Geo restriction" in result.details
        full_audit_data["admin_logs"].append(self._delete())
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL

    def test_warn_only_assignment_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = [self._create(), self._assign("GMAIL", "WARN", ["Geo restriction"])]
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.MANUAL and "Warn action only" in result.details

    def test_monitor_mode_or_removed_assignment_is_review(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = [self._create(), self._assign("GMAIL", "MONITOR", ["Geo restriction"])]
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.MANUAL
        assert "monitor mode only" in result.details
        full_audit_data["admin_logs"] = [self._create(), self._assign("GMAIL", "BLOCK", ["Geo restriction"]),
                                         self._assign("GMAIL", "BLOCK", ["Geo restriction"], time="2026-11-06T18:40:00.000Z", removed=True)]
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL

    def test_non_geographic_level_or_other_level_assigned_is_not_geo_blocking(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        device_only = '{"basic": {"conditions": [{"devicePolicy": {"requireScreenlock": true}}]}, "title": "Geo restriction"}'
        full_audit_data["admin_logs"] = [self._create(state=device_only), self._assign("GMAIL", "BLOCK", ["Geo restriction"])]
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"] = [self._create(), self._assign("GMAIL", "BLOCK", ["Corp devices"])]
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL

    def test_caa_disabled_fails_even_with_geo_level(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        from tests.factories import make_admin_event
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = [self._create(), self._assign("GMAIL", "BLOCK", ["Geo restriction"]),
                                         make_admin_event("TOGGLE_CAA_ENABLEMENT", {"OLD_VALUE": "ENABLED", "NEW_VALUE": "DISABLED"},
                                                          "2026-11-06T19:00:00.000Z")]
        assert check_geo_blocking(full_audit_data).status == Status.FAIL

    def test_caa_log_evaluation_of_geo_level_passes_without_assignment_event(self, full_audit_data):
        """Live 2026-11-06: ACCESS_LEVELS_EVALUATED applying Geo restriction proves geo-blocking is enforced."""
        from gws_auditor.checks.security_access import check_geo_blocking
        from tests.test_checks.test_additional import _caa_event
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = [self._create()]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")]
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS
        assert "Context-Aware Access log" in result.details and "GMAIL" in result.details
        # Enforced level whose conditions are unknown (no create event in the window) -> MANUAL.
        full_audit_data["admin_logs"] = []
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Geo restriction" in result.details
        # Monitor-mode evaluation is not enforcement.
        full_audit_data["admin_logs"] = [self._create()]
        full_audit_data["caa_events"] = [_caa_event("MONITOR_MODE_ACCESS_EVALUATED_EVENT", "GMAIL")]
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL

    @staticmethod
    def _acm(*levels):
        """data['access_context'] as the provider returns it (live field names, 2026-11-06)."""
        return {"collected": True, "source": "access_context_manager", "organization": "organizations/18479643020",
                "access_policy": "accessPolicies/134654395911", "bindings": [], "bindings_collected": False,
                "reason": "", "access_levels": list(levels)}

    _GEO = {"name": "accessPolicies/134654395911/accessLevels/geo_restriction_fttlt6s2", "title": "Geo restriction",
            "description": "geo", "basic": {"conditions": [{"negate": True, "regions": ["AQ"]}]}}
    _DEVICE = {"name": "accessPolicies/134654395911/accessLevels/corp", "title": "Corp devices",
               "basic": {"conditions": [{"devicePolicy": {"requireScreenlock": True}}]}}

    def test_access_context_manager_inventory_is_authoritative(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        full_audit_data["admin_logs"] = [self._assign("GMAIL", "BLOCK", ["Geo restriction"])]
        # Geo level from ACM (no create event in the log window) + active assignment -> PASS
        full_audit_data["access_context"] = self._acm(self._GEO, self._DEVICE)
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.PASS
        assert "access context manager" in result.details
        # ACM lists only non-geographic levels -> FAIL, whatever is assigned
        full_audit_data["access_context"] = self._acm(self._DEVICE)
        result = check_geo_blocking(full_audit_data)
        assert result.status == Status.FAIL
        assert "Corp devices" in result.details
        # ACM lists no level at all -> FAIL
        full_audit_data["access_context"] = self._acm()
        assert check_geo_blocking(full_audit_data).status == Status.FAIL
        # Geo level exists but never assigned -> MANUAL
        full_audit_data["access_context"] = self._acm(self._GEO)
        full_audit_data["admin_logs"] = []
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL
        # Not collected -> log inference only (no events -> MANUAL)
        full_audit_data["access_context"] = {"collected": False, "access_levels": [self._GEO], "reason": "403"}
        assert check_geo_blocking(full_audit_data).status == Status.MANUAL

    def test_custom_cel_region_expression_counts(self, full_audit_data):
        from gws_auditor.checks.security_access import check_geo_blocking
        full_audit_data["policies"]["security"].pop("context_aware_access", None)
        custom = '{"custom": {"expr": "!(origin.region_code in [\\"AQ\\", \\"BV\\"])"}, "title": "Geo restriction"}'
        full_audit_data["admin_logs"] = [self._create(state=custom), self._assign("GMAIL", "BLOCK", ["Geo restriction"])]
        assert check_geo_blocking(full_audit_data).status == Status.PASS


# -----------------------------------------------------------------------
# CIS-4.2.4.1: Device Bound Session Credentials (DBSC)
# -----------------------------------------------------------------------

class TestSessionControl:
    """Tests for CIS-4.2.4.1: DBSC."""

    def test_dbsc_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {"dbsc_enabled": True}
        result = check_session_control(full_audit_data)
        assert result.status == Status.PASS

    def test_dbsc_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {"dbsc_enabled": False}
        result = check_session_control(full_audit_data)
        assert result.status == Status.FAIL

    def test_dbsc_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.security_access import check_session_control
        full_audit_data["chrome_policies"] = {}
        result = check_session_control(full_audit_data)
        assert result.status == Status.MANUAL


# -----------------------------------------------------------------------
# CIS-4.2.5.1: Cloud session control (no OU mapping, unchanged)
# -----------------------------------------------------------------------

class TestCloudSessionControl:
    """Tests for CIS-4.2.5.1."""

    def test_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": True,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.PASS

    def test_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.security_access import check_cloud_session_control
        full_audit_data["policies"].setdefault("security", {})["session_management"] = {
            "cloud_session_control_enabled": False,
        }
        result = check_cloud_session_control(full_audit_data)
        assert result.status == Status.FAIL


# -----------------------------------------------------------------------
# _parse_session_duration_hours unit tests
# -----------------------------------------------------------------------

class TestParseSessionDuration:
    """Unit tests for the session duration parser."""

    def test_seconds_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("28800s") == 8.0

    def test_hours_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("12h") == 12.0

    def test_int_seconds(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours(43200) == 12.0

    def test_none_returns_none(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours(None) is None

    def test_invalid_string_returns_none(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("bogus") is None

    def test_plain_numeric_string(self):
        from gws_auditor.checks.security_access import _parse_session_duration_hours
        assert _parse_session_duration_hours("3600") == 1.0
