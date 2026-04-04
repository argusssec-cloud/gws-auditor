"""Tests for Cloud Identity Policy API client."""

from unittest.mock import MagicMock

import pytest

from gws_auditor.api.policy import GOOGLE_DEFAULTS, REQUIRED_SETTINGS, PolicyClient


class _FakeAuthManager:
    """Minimal stub so PolicyClient.__init__ succeeds."""

    def build_service(self, api, version):
        return MagicMock()


def _make_client():
    """Create a PolicyClient with a mocked service."""
    client = PolicyClient(_FakeAuthManager(), max_retries=0, rate_limit_qps=1000)
    client._service = MagicMock()
    return client


class TestGetPolicyByType:
    """Tests for PolicyClient.get_policy_by_type()."""

    def test_returns_policy_when_found(self):
        client = _make_client()
        expected = {
            "name": "policies/axd7lv5wbx5y73hhdpezjp4byykr6",
            "setting": {
                "type": "settings/gmail.confidential_mode",
                "value": {"enableConfidentialMode": True},
            },
        }
        list_request = MagicMock()
        list_request.execute.return_value = {"policies": [expected]}
        client._service.policies().list.return_value = list_request

        result = client.get_policy_by_type("gmail.confidential_mode")
        assert result == expected

    def test_returns_none_when_not_found(self):
        client = _make_client()
        list_request = MagicMock()
        list_request.execute.return_value = {"policies": []}
        client._service.policies().list.return_value = list_request

        result = client.get_policy_by_type("gmail.nonexistent")
        assert result is None

    def test_returns_none_on_api_error(self):
        client = _make_client()
        list_request = MagicMock()
        list_request.execute.side_effect = Exception("API error")
        client._service.policies().list.return_value = list_request

        result = client.get_policy_by_type("gmail.confidential_mode")
        assert result is None


class TestGetPoliciesBackfill:
    """Tests for the backfill logic in get_policies()."""

    def test_backfills_missing_required_settings(self):
        """When the broad policies.list omits a required setting,
        get_policies should fetch it via a narrow list call."""
        client = _make_client()

        # Broad list returns one setting
        broad_response = {
            "policies": [
                {
                    "name": "policies/abc123",
                    "setting": {
                        "type": "settings/gmail.confidential_mode",
                        "value": {"enableConfidentialMode": True},
                    },
                },
            ],
        }

        # Narrow list returns a backfilled setting
        backfilled = {
            "name": "policies/def456",
            "setting": {
                "type": "settings/gmail.mail_delegation",
                "value": {"enableMailDelegation": False},
            },
        }
        narrow_response = {"policies": [backfilled]}

        call_count = {"n": 0}

        def fake_list(**kwargs):
            call_count["n"] += 1
            req = MagicMock()
            cel = kwargs.get("filter", "")
            if "matches" in cel:
                # Broad regex filter
                req.execute.return_value = broad_response
            elif "mail_delegation" in cel:
                # Narrow exact-match filter for mail_delegation
                req.execute.return_value = narrow_response
            else:
                # Other narrow calls return empty
                req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("gmail")

        # Should contain both the broad result and the backfilled one
        setting_types = {
            p["setting"].get("type", "")
            for p in result
        }
        assert "settings/gmail.confidential_mode" in setting_types
        assert "settings/gmail.mail_delegation" in setting_types

    def test_does_not_refetch_already_returned_settings(self):
        """When the broad list already returns a required setting,
        get_policies should NOT issue a narrow list for it."""
        client = _make_client()

        # Broad list returns the only required setting for groups
        broad_response = {
            "policies": [
                {
                    "name": "policies/grp001",
                    "setting": {
                        "type": "settings/groups_for_business.groups_sharing",
                        "value": {"allowExternalMembers": True},
                    },
                },
            ],
        }

        narrow_calls = []

        def fake_list(**kwargs):
            req = MagicMock()
            cel = kwargs.get("filter", "")
            if "matches" in cel:
                req.execute.return_value = broad_response
            else:
                narrow_calls.append(cel)
                req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("groups")

        # groups_sharing was already returned, so no narrow calls should
        # have been made for it
        assert not any("groups_sharing" in c for c in narrow_calls), (
            f"Narrow list was called for already-returned setting: {narrow_calls}"
        )
        assert len(result) == 1

    def test_no_backfill_for_unknown_category(self):
        """Categories without REQUIRED_SETTINGS entries skip backfill."""
        client = _make_client()

        broad_response = {"policies": []}

        narrow_calls = []

        def fake_list(**kwargs):
            req = MagicMock()
            cel = kwargs.get("filter", "")
            if "matches" in cel:
                req.execute.return_value = broad_response
            else:
                narrow_calls.append(cel)
                req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("classroom")

        assert narrow_calls == []
        assert result == []

    def test_backfill_handles_failure_gracefully(self):
        """When a narrow list call fails but a Google default exists,
        the default should be injected."""
        client = _make_client()

        broad_response = {"policies": []}

        def fake_list(**kwargs):
            req = MagicMock()
            cel = kwargs.get("filter", "")
            if "matches" in cel:
                req.execute.return_value = broad_response
            else:
                req.execute.side_effect = Exception("API unavailable")
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("directory")

        # The narrow call fails, but directory.external_directory_sharing
        # has a Google default, so a synthetic DEFAULT policy is injected.
        setting_types = {p["setting"].get("type", "") for p in result}
        assert "settings/directory.external_directory_sharing" in setting_types
        default_policy = [
            p for p in result
            if p.get("_raw", {}).get("type") == "DEFAULT"
        ]
        assert len(default_policy) == 1
        assert default_policy[0]["setting"]["value"]["sharing_option"] == "REQUESTER_BASIC_PROFILE_ONLY"


class TestGoogleDefaults:
    """Tests for the GOOGLE_DEFAULTS fallback in get_policies()."""

    def test_applies_defaults_when_api_returns_nothing(self):
        """When both broad and narrow calls return empty, settings with
        known defaults should be injected as synthetic DEFAULT policies."""
        client = _make_client()

        def fake_list(**kwargs):
            req = MagicMock()
            req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("marketplace")

        # marketplace has 1 required setting (apps_access_options) with a default
        setting_types = {p["setting"].get("type", "") for p in result}
        assert "settings/workspace_marketplace.apps_access_options" in setting_types

        # Verify the synthetic policy has the correct structure
        # After _normalise_policies, the raw dict is preserved under _raw
        default_policy = [
            p for p in result
            if p.get("_raw", {}).get("type") == "DEFAULT"
        ]
        assert len(default_policy) == 1
        assert default_policy[0]["setting"]["value"] == {"accessLevel": "ALLOW_ALL"}
        assert default_policy[0]["name"] == "policies/_default/workspace_marketplace.apps_access_options"

    def test_defaults_not_applied_when_api_returns_data(self):
        """When the narrow backfill call returns real data, defaults
        should NOT be applied."""
        client = _make_client()

        api_policy = {
            "name": "policies/real123",
            "setting": {
                "type": "settings/workspace_marketplace.apps_access_options",
                "value": {"appInstallPolicy": "ALLOW_SPECIFIED"},
            },
        }

        def fake_list(**kwargs):
            req = MagicMock()
            cel = kwargs.get("filter", "")
            if "matches" in cel:
                req.execute.return_value = {"policies": []}
            elif "apps_access_options" in cel:
                req.execute.return_value = {"policies": [api_policy]}
            else:
                req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("marketplace")

        # Should have the real policy, not the default
        assert len(result) == 1
        assert result[0]["setting"]["value"]["appInstallPolicy"] == "ALLOW_SPECIFIED"
        assert result[0].get("_raw", {}).get("type") != "DEFAULT"

    def test_defaults_applied_for_multiple_settings(self):
        """When all API calls return empty for a category with multiple
        required settings, all defaults should be applied."""
        client = _make_client()

        def fake_list(**kwargs):
            req = MagicMock()
            req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        result = client.get_policies("security")

        # security has 6 settings with defaults
        default_types = {
            p["setting"]["type"]
            for p in result
            if p.get("_raw", {}).get("type") == "DEFAULT"
        }
        expected_defaults = {
            f"settings/{st}" for st in GOOGLE_DEFAULTS
            if st.startswith("security.")
        }
        assert default_types == expected_defaults

    def test_all_defaults_have_matching_required_settings(self):
        """Every key in GOOGLE_DEFAULTS must appear in REQUIRED_SETTINGS."""
        all_required = set()
        for settings in REQUIRED_SETTINGS.values():
            all_required.update(settings)
        for setting_type in GOOGLE_DEFAULTS:
            assert setting_type in all_required, (
                f"GOOGLE_DEFAULTS has {setting_type!r} which is not in REQUIRED_SETTINGS"
            )


class TestNormalisePoliciesOrgUnit:
    """Tests for orgUnit extraction in _normalise_policies()."""

    def test_extracts_orgunit_from_policy_query(self):
        """orgUnit should be read from policyQuery.orgUnit when present."""
        client = _make_client()
        raw = [
            {
                "name": "policies/abc",
                "setting": {
                    "type": "settings/gmail.confidential_mode",
                    "value": {"enableConfidentialMode": True},
                },
                "policyQuery": {"orgUnit": "orgUnits/03ph8a2z1"},
            }
        ]
        result = PolicyClient._normalise_policies(raw, "gmail")
        assert result[0]["orgUnit"] == "orgUnits/03ph8a2z1"

    def test_falls_back_to_top_level_orgunit(self):
        """When policyQuery is absent, fall back to policy.orgUnit."""
        client = _make_client()
        raw = [
            {
                "name": "policies/abc",
                "setting": {"type": "settings/gmail.confidential_mode", "value": {}},
                "orgUnit": "/Engineering",
            }
        ]
        result = PolicyClient._normalise_policies(raw, "gmail")
        assert result[0]["orgUnit"] == "/Engineering"

    def test_defaults_to_root_when_no_orgunit(self):
        """When neither policyQuery nor orgUnit is present, default to /."""
        raw = [
            {
                "name": "policies/abc",
                "setting": {"type": "settings/gmail.confidential_mode", "value": {}},
            }
        ]
        result = PolicyClient._normalise_policies(raw, "gmail")
        assert result[0]["orgUnit"] == "/"


class TestOrgUnitResolution:
    """Tests for _build_ou_id_map and _resolve_org_unit in provider.py."""

    def test_build_ou_id_map(self):
        from gws_auditor.provider import _build_ou_id_map
        org_units = [
            {"orgUnitId": "id:03ph8a2z1", "orgUnitPath": "/Engineering"},
            {"orgUnitId": "id:04qj9b3x2", "orgUnitPath": "/Sales"},
        ]
        result = _build_ou_id_map(org_units)
        assert result["id:03ph8a2z1"] == "/Engineering"
        assert result["03ph8a2z1"] == "/Engineering"
        assert result["id:04qj9b3x2"] == "/Sales"

    def test_build_ou_id_map_empty(self):
        from gws_auditor.provider import _build_ou_id_map
        assert _build_ou_id_map([]) == {}

    def test_resolve_org_unit_with_id(self):
        from gws_auditor.provider import _resolve_org_unit
        ou_map = {"03ph8a2z1": "/Engineering"}
        assert _resolve_org_unit("orgUnits/03ph8a2z1", ou_map) == "/Engineering"

    def test_resolve_org_unit_passthrough(self):
        from gws_auditor.provider import _resolve_org_unit
        assert _resolve_org_unit("/Sales", {}) == "/Sales"

    def test_resolve_org_unit_root(self):
        from gws_auditor.provider import _resolve_org_unit
        assert _resolve_org_unit("/", {}) == "/"
        assert _resolve_org_unit("", {}) == "/"

    def test_resolve_org_unit_unknown_id(self):
        from gws_auditor.provider import _resolve_org_unit
        assert _resolve_org_unit("orgUnits/unknown", {}) == "orgUnits/unknown"

    def test_normalize_policies_resolves_orgunit_ids(self):
        from gws_auditor.provider import _normalize_policies
        policies = {
            "gmail": [
                {
                    "category": "gmail",
                    "name": "policies/abc",
                    "setting": {
                        "type": "settings/gmail.confidential_mode",
                        "value": {"enableConfidentialMode": True},
                    },
                    "orgUnit": "orgUnits/03ph8a2z1",
                },
            ],
        }
        ou_map = {"03ph8a2z1": "/Engineering"}
        result = _normalize_policies(policies, ou_map)
        # _ou_policies should have resolved orgUnit
        ou_policies = result["gmail"]["_ou_policies"]
        assert ou_policies[0]["orgUnit"] == "/Engineering"


class TestCustomerFilter:
    """Tests for customer-scoped CEL filter in PolicyClient."""

    def test_get_policies_includes_customer_filter(self):
        """When customer_id is set, get_policies() CEL filter includes
        customer == 'customers/<id>'."""
        client = PolicyClient(
            _FakeAuthManager(), customer_id="C01234567",
            max_retries=0, rate_limit_qps=1000,
        )
        client._service = MagicMock()

        captured_filters = []

        def fake_list(**kwargs):
            captured_filters.append(kwargs.get("filter", ""))
            req = MagicMock()
            req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        client.get_policies("directory")

        # The broad filter should include the customer clause
        assert len(captured_filters) >= 1
        broad_filter = captured_filters[0]
        assert 'customer == "customers/C01234567"' in broad_filter
        assert "setting.type.matches" in broad_filter

    def test_get_policy_by_type_includes_customer_filter(self):
        """When customer_id is set, get_policy_by_type() CEL filter
        includes customer clause."""
        client = PolicyClient(
            _FakeAuthManager(), customer_id="C01234567",
            max_retries=0, rate_limit_qps=1000,
        )
        client._service = MagicMock()

        captured_filters = []

        def fake_list(**kwargs):
            captured_filters.append(kwargs.get("filter", ""))
            req = MagicMock()
            req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        client.get_policy_by_type("directory.external_directory_sharing")

        assert len(captured_filters) == 1
        assert 'customer == "customers/C01234567"' in captured_filters[0]
        assert 'setting.type == "settings/directory.external_directory_sharing"' in captured_filters[0]

    def test_no_customer_filter_when_customer_id_empty(self):
        """When customer_id is not set, CEL filter omits customer clause."""
        client = _make_client()

        captured_filters = []

        def fake_list(**kwargs):
            captured_filters.append(kwargs.get("filter", ""))
            req = MagicMock()
            req.execute.return_value = {"policies": []}
            return req

        client._service.policies().list = fake_list

        client.get_policies("directory")

        broad_filter = captured_filters[0]
        assert "customer ==" not in broad_filter


class TestRequiredSettings:
    """Tests for the REQUIRED_SETTINGS constant."""

    def test_all_categories_use_correct_prefix(self):
        """Every setting type in REQUIRED_SETTINGS should start with
        the corresponding POLICY_CATEGORIES prefix, unless it is a
        cross-category setting (e.g. service_status.sites in the
        sites category) that is fetched via a narrow per-setting call."""
        from gws_auditor.api.policy import POLICY_CATEGORIES

        # Cross-category settings that intentionally live under a
        # different prefix from their owning category.
        CROSS_CATEGORY_SETTINGS = {
            "service_status.sites",
        }

        for category, settings in REQUIRED_SETTINGS.items():
            expected_prefix = POLICY_CATEGORIES.get(category, category)
            for setting in settings:
                if setting in CROSS_CATEGORY_SETTINGS:
                    continue
                assert setting.startswith(f"{expected_prefix}."), (
                    f"Setting {setting!r} in category {category!r} "
                    f"does not start with {expected_prefix!r}"
                )
