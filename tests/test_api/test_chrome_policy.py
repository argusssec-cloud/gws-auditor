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
                        "value": {"geminiSetting": 1},
                    },
                }
            ]
        }

        result = client.resolve_policy(
            "my_customer", "chrome.users.GeminiSettings", org_unit_id="abc123"
        )
        assert len(result) == 1
        assert result[0]["value"]["value"]["geminiSetting"] == 1

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
                        {"value": {"value": {"geminiSetting": 1}}}
                    ]
                }
            elif "BoundSessionCredentials" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"boundSessionCredentialsEnabled": True}}}
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
                        {"value": {"value": {"geminiSetting": 0}}}
                    ]
                }
            elif "BoundSessionCredentials" in schema:
                mock_request.execute.return_value = {
                    "resolvedPolicies": [
                        {"value": {"value": {"boundSessionCredentialsEnabled": False}}}
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
                        {"value": {"value": {"geminiSetting": 1}}}
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
