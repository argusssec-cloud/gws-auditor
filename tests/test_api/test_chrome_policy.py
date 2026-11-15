"""Tests for Chrome Policy API client."""

from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.api.chrome_policy import ChromePolicyClient


class TestChromePolicyClient:
    """Tests for ChromePolicyClient."""

    def _make_client(self, root_ou_id="03ph8a2z_root"):
        """Create a ChromePolicyClient with a mocked auth_manager.

        Pre-sets ``_root_ou_id`` so tests don't trigger the Directory
        API lookup.
        """
        auth = MagicMock()
        client = ChromePolicyClient(auth)
        # Pre-cache the root OU ID to avoid Directory API calls.
        client._root_ou_id = root_ou_id
        return client

    def test_resolve_policy_success(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        mock_service.customers().policies().resolve().execute.return_value = {
            "resolvedPolicies": [
                {
                    "value": {
                        "value": {"geminiSettings": "GEMINI_SETTINGS_ENUM_DISABLED"},
                    },
                }
            ]
        }

        result = client.resolve_policy(
            "my_customer", "chrome.users.GeminiSettings", org_unit_id="abc123"
        )
        assert len(result) == 1
        assert result[0]["value"]["value"]["geminiSettings"] == "GEMINI_SETTINGS_ENUM_DISABLED"

    def test_resolve_policy_empty(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        mock_service.customers().policies().resolve().execute.return_value = {}

        result = client.resolve_policy(
            "my_customer", "chrome.users.GeminiSettings", org_unit_id="abc123"
        )
        assert result == []

    def test_resolve_policy_error(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        mock_service.customers().policies().resolve().execute.side_effect = (
            Exception("API error")
        )

        result = client.resolve_policy(
            "my_customer", "chrome.users.GeminiSettings", org_unit_id="abc123"
        )
        assert result == []
        assert len(client.errors) == 1
        assert "GeminiSettings" in client.errors[0]["operation"]

    def test_resolve_policy_uses_root_ou_when_no_id_given(self):
        """When no org_unit_id is given, the root OU ID is used."""
        client = self._make_client(root_ou_id="root_ou_123")
        mock_service = MagicMock()
        client._service = mock_service

        mock_service.customers().policies().resolve().execute.return_value = {
            "resolvedPolicies": []
        }

        client.resolve_policy("my_customer", "chrome.users.GeminiSettings")
        # Verify the resolve call used the root OU ID
        call_args = (
            mock_service.customers().policies().resolve.call_args
        )
        body = call_args.kwargs.get("body", call_args[1].get("body", {}))
        assert body["policyTargetKey"]["targetResource"] == "orgunits/root_ou_123"

    def test_resolve_policy_returns_empty_when_no_root_ou(self):
        """When root OU ID cannot be resolved, return empty list."""
        client = self._make_client(root_ou_id="")
        result = client.resolve_policy(
            "my_customer", "chrome.users.GeminiSettings"
        )
        assert result == []

    def test_get_chrome_policies_gemini_disabled(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        def mock_resolve(customer, body):
            schema = body["policySchemaFilter"]
            mock_request = MagicMock()
            if "GeminiSettings" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"geminiSettings": "GEMINI_SETTINGS_ENUM_DISABLED"}}}
                    ]
                }
            elif "BoundSessionCredentials" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"boundSessionCredentialsEnabled": "TRUE"}}}
                    ]
                }
            else:
                mock_request.execute.return_value = {}
            return mock_request

        mock_service.customers().policies().resolve.side_effect = mock_resolve

        result = client.get_chrome_policies("my_customer")
        assert result["gemini_in_chrome_disabled"] is True
        assert result["dbsc_enabled"] is True

    def test_get_chrome_policies_gemini_allowed(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        def mock_resolve(customer, body):
            schema = body["policySchemaFilter"]
            mock_request = MagicMock()
            if "GeminiSettings" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"geminiSettings": "GEMINI_SETTINGS_ENUM_ENABLED"}}}
                    ]
                }
            elif "BoundSessionCredentials" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"boundSessionCredentialsEnabled": "FALSE"}}}
                    ]
                }
            else:
                mock_request.execute.return_value = {}
            return mock_request

        mock_service.customers().policies().resolve.side_effect = mock_resolve

        result = client.get_chrome_policies("my_customer")
        assert result["gemini_in_chrome_disabled"] is False
        assert result["dbsc_enabled"] is False

    def test_get_chrome_policies_no_data(self):
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        def mock_resolve(customer, body):
            mock_request = MagicMock()
            mock_request.execute.return_value = {}
            return mock_request

        mock_service.customers().policies().resolve.side_effect = mock_resolve

        result = client.get_chrome_policies("my_customer")
        assert result == {}

    def test_get_chrome_policies_partial_error(self):
        """One schema succeeds, another fails — partial results."""
        client = self._make_client()
        mock_service = MagicMock()
        client._service = mock_service

        def mock_resolve(customer, body):
            mock_request = MagicMock()
            schema = body["policySchemaFilter"]
            if "GeminiSettings" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"geminiSettings": "GEMINI_SETTINGS_ENUM_DISABLED"}}}
                    ]
                }
            else:
                mock_request.execute.side_effect = Exception("API error")
            return mock_request

        mock_service.customers().policies().resolve.side_effect = mock_resolve

        result = client.get_chrome_policies("my_customer")
        assert result["gemini_in_chrome_disabled"] is True
        assert "dbsc_enabled" not in result
        assert "password_protection_warning_trigger" not in result
        assert len(client.errors) >= 1

    def test_get_root_org_unit_id(self):
        """Test that root OU ID is looked up from Directory API."""
        auth = MagicMock()
        client = ChromePolicyClient(auth)

        mock_dir_service = MagicMock()
        auth.build_service.return_value = mock_dir_service
        mock_dir_service.orgunits().get().execute.return_value = {
            "orgUnitId": "ou_abc123",
            "orgUnitPath": "/",
        }

        ou_id = client._get_root_org_unit_id("my_customer")
        assert ou_id == "ou_abc123"
        # Subsequent calls use the cached value
        assert client._get_root_org_unit_id("my_customer") == "ou_abc123"

    def test_get_root_org_unit_id_strips_id_prefix(self):
        """Directory API returns orgUnitId with 'id:' prefix; it must be stripped."""
        auth = MagicMock()
        client = ChromePolicyClient(auth)

        mock_dir_service = MagicMock()
        auth.build_service.return_value = mock_dir_service
        # Strategy 1: list returns OUs with id:-prefixed parentOrgUnitId
        mock_dir_service.orgunits().list().execute.return_value = {
            "organizationUnits": [
                {
                    "orgUnitPath": "/Engineering",
                    "parentOrgUnitPath": "/",
                    "parentOrgUnitId": "id:01mt6d5e18fc1tl",
                },
            ],
        }

        ou_id = client._get_root_org_unit_id("my_customer")
        assert ou_id == "01mt6d5e18fc1tl"

    def test_get_root_org_unit_id_strips_id_prefix_strategy2(self):
        """Strategy 2 (direct get) also strips 'id:' prefix."""
        auth = MagicMock()
        client = ChromePolicyClient(auth)

        mock_dir_service = MagicMock()
        auth.build_service.return_value = mock_dir_service
        # Strategy 1 fails (no OUs)
        mock_dir_service.orgunits().list().execute.return_value = {
            "organizationUnits": [],
        }
        # Strategy 2 returns id:-prefixed orgUnitId
        mock_dir_service.orgunits().get().execute.return_value = {
            "orgUnitId": "id:01mt6d5e18fc1tl",
            "orgUnitPath": "/",
        }

        ou_id = client._get_root_org_unit_id("my_customer")
        assert ou_id == "01mt6d5e18fc1tl"

    def test_get_root_org_unit_id_failure(self):
        """Test graceful handling when root OU lookup fails."""
        auth = MagicMock()
        client = ChromePolicyClient(auth)

        auth.build_service.side_effect = Exception("Directory API unavailable")

        ou_id = client._get_root_org_unit_id("my_customer")
        assert ou_id == ""


class TestChromePolicyShapes:
    """The client reads only schema names and fields that exist in the live catalogue (2026-11-15)."""

    def _client_with(self, values: dict):
        """Client whose resolve returns *values* ({schema: {field: value}}) and {} for other schemas."""
        client = TestChromePolicyClient._make_client(self) if hasattr(TestChromePolicyClient, "_make_client") else None
        from unittest.mock import MagicMock
        from gws_auditor.api.chrome_policy import ChromePolicyClient
        auth = MagicMock()
        client = ChromePolicyClient(auth)
        client._root_ou_id = "root"
        mock_service = MagicMock()
        client._service = mock_service

        def mock_resolve(customer, body):
            schema = body["policySchemaFilter"]
            req = MagicMock()
            if schema in values:
                req.execute.return_value = {"resolvedPolicies": [{"value": {"policySchema": schema, "value": values[schema]}}]}
            else:
                req.execute.return_value = {}
            return req

        mock_service.customers().policies().resolve.side_effect = mock_resolve
        return client

    def test_every_schema_and_field_is_in_the_live_catalogue(self):
        import json
        from pathlib import Path
        from gws_auditor.api.chrome_policy import CHROME_POLICY_FIELDS
        catalogue = json.loads(Path("tests/fixtures/chrome_policy_schemas.json").read_text())["schemas"]
        for schema, (field, _key) in CHROME_POLICY_FIELDS.items():
            assert schema in catalogue, schema
            assert field in catalogue[schema]["fields"], (schema, field)

    def test_defaults_table_matches_the_live_catalogue(self):
        import json
        from pathlib import Path
        from gws_auditor.api.chrome_policy import CHROME_POLICY_FIELDS
        from gws_auditor.google_defaults import CHROME_POLICY_DEFAULTS
        catalogue = json.loads(Path("tests/fixtures/chrome_policy_schemas.json").read_text())["schemas"]
        for schema, (field, _key) in CHROME_POLICY_FIELDS.items():
            assert schema in CHROME_POLICY_DEFAULTS, schema
            assert CHROME_POLICY_DEFAULTS[schema]["default_value"] == catalogue[schema]["fields"][field]["default"], schema
        assert set(CHROME_POLICY_DEFAULTS) == set(CHROME_POLICY_FIELDS)

    def test_raw_values_are_kept_under_their_keys(self):
        client = self._client_with({
            "chrome.users.SafeBrowsingProtectionLevel": {"safeBrowsingProtectionLevel": "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION"},
            "chrome.users.DisableSafeBrowsingProceedAnyway": {"disableSafeBrowsingProceedAnyway": True},
            "chrome.users.PasswordAlert": {"passwordProtectionWarningTrigger": "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PASSWORD_REUSE"},
            "chrome.users.AutoUpdateCheckPeriodNewV2": {"autoUpdateCheckPeriodMinutesNew": 0},
            "chrome.devices.AutoUpdateSettings": {"updateDisabled": True, "rebootAfterUpdate": False},
        })
        result = client.get_chrome_policies("my_customer")
        assert result["safe_browsing_protection_level"] == "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION"
        assert result["disable_safe_browsing_proceed_anyway"] is True
        assert result["password_protection_warning_trigger"].endswith("WARN_ON_PASSWORD_REUSE")
        assert result["auto_update_check_period_minutes"] == 0
        assert result["chromeos_update_disabled"] is True
        assert "gemini_in_chrome_disabled" not in result and "dbsc_enabled" not in result

    def test_gemini_unset_follows_the_generative_ai_default(self):
        client = self._client_with({
            "chrome.users.GeminiSettings": {"geminiSettings": "GEMINI_SETTINGS_ENUM_UNSET"},
            "chrome.users.GenAiDefaultSettings": {"genAiDefaultSettings": "GEN_AI_DEFAULT_SETTINGS_ENUM_DISABLED"},
        })
        assert client.get_chrome_policies("my_customer")["gemini_in_chrome_disabled"] is True
        client = self._client_with({"chrome.users.GenAiDefaultSettings": {"genAiDefaultSettings": "GEN_AI_DEFAULT_SETTINGS_ENUM_ALLOWED"}})
        assert client.get_chrome_policies("my_customer")["gemini_in_chrome_disabled"] is False

    def test_dbsc_unset_enum_leaves_the_key_absent(self):
        client = self._client_with({"chrome.users.BoundSessionCredentialsEnabled": {"boundSessionCredentialsEnabled": "UNSET"}})
        result = client.get_chrome_policies("my_customer")
        assert result["bound_session_credentials"] == "UNSET" and "dbsc_enabled" not in result

    def test_schema_not_found_is_recorded_as_an_error(self):
        from unittest.mock import MagicMock
        from googleapiclient.errors import HttpError
        from gws_auditor.api.chrome_policy import ChromePolicyClient
        client = ChromePolicyClient(MagicMock())
        client._root_ou_id = "root"
        mock_service = MagicMock()
        client._service = mock_service
        resp = MagicMock(); resp.status = 404; resp.reason = "Not Found"
        mock_service.customers().policies().resolve().execute.side_effect = HttpError(resp, b"schema not found")
        assert client.resolve_policy("my_customer", "chrome.users.DoesNotExist") == []
        assert any("resolve_policy(chrome.users.DoesNotExist)" in e.get("operation", "") for e in client.errors)
