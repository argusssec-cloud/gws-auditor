"""Provider._get_access_context: Access Context Manager inventory with graceful degradation."""

from unittest.mock import MagicMock, patch

import httplib2
from googleapiclient.errors import HttpError

from gws_auditor.provider import Provider
from tests.test_api.test_access_context_manager import LIVE_LEVEL, LIVE_POLICY


def _provider(options=None):
    p = Provider(MagicMock(), {"auth": {"customer_id": "C049r06rk"}, "options": options or {}})
    p._domains_cache = [{"domainName": "example.com", "isPrimary": True}]
    return p


def _http_error(status):
    return HttpError(httplib2.Response({"status": status}), b'{"error": {"message": "denied"}}')


@patch("gws_auditor.api.access_context_manager.AccessContextManagerClient")
class TestGetAccessContext:
    def test_discovers_org_and_policy_then_lists_levels(self, client_cls):
        client = client_cls.return_value
        client.organization_name.side_effect = lambda v: f"organizations/{v}" if v else ""
        client.policy_name.side_effect = lambda v: f"accessPolicies/{v}" if v else ""
        client.search_organization.return_value = "organizations/18479643020"
        client.list_access_policies.return_value = [LIVE_POLICY]
        client.list_access_levels.return_value = [LIVE_LEVEL]
        client.list_user_access_bindings.side_effect = _http_error(403)
        client.errors = []
        result = _provider()._get_access_context()
        assert result["collected"] is True
        assert result["access_policy"] == "accessPolicies/134654395911"
        assert result["access_levels"][0]["title"] == "Geo restriction"
        assert result["bindings_collected"] is False and result["bindings"] == []
        client.search_organization.assert_called_once_with(domain="example.com", customer_id="C049r06rk")

    def test_configured_policy_skips_discovery(self, client_cls):
        client = client_cls.return_value
        client.organization_name.side_effect = lambda v: f"organizations/{v}" if v else ""
        client.policy_name.side_effect = lambda v: f"accessPolicies/{v}" if v else ""
        client.list_access_levels.return_value = []
        client.errors = []
        result = _provider({"access_policy_id": "134654395911"})._get_access_context()
        assert result["collected"] is True and result["access_levels"] == []
        client.search_organization.assert_not_called()
        client.list_access_policies.assert_not_called()

    def test_permission_denied_is_not_collected_with_reason(self, client_cls):
        client = client_cls.return_value
        client.organization_name.side_effect = lambda v: f"organizations/{v}" if v else ""
        client.policy_name.side_effect = lambda v: f"accessPolicies/{v}" if v else ""
        client.list_access_levels.side_effect = _http_error(403)
        p = _provider({"access_policy_id": "134654395911"})
        result = p._get_access_context()
        assert result["collected"] is False
        assert "policyReader" in result["reason"]
        assert p._api_errors == []  # expected condition, not an API error

    def test_no_organization_found(self, client_cls):
        client = client_cls.return_value
        client.organization_name.side_effect = lambda v: ""
        client.policy_name.side_effect = lambda v: ""
        client.search_organization.return_value = ""
        result = _provider()._get_access_context()
        assert result["collected"] is False and "cloud_organization_id" in result["reason"]

    def test_no_cloud_identity(self, client_cls):
        client = client_cls.return_value
        client.organization_name.side_effect = lambda v: f"organizations/{v}" if v else ""
        client.policy_name.side_effect = lambda v: f"accessPolicies/{v}" if v else ""
        client.list_access_levels.side_effect = RuntimeError("needs the service account's own cloud-platform credentials")
        result = _provider({"access_policy_id": "1"})._get_access_context()
        assert result["collected"] is False and "cloud-platform" in result["reason"]

    def test_disabled_by_option(self, client_cls):
        result = _provider({"collect_access_context": False})._get_access_context()
        assert result["collected"] is False and "disabled" in result["reason"]
        client_cls.assert_not_called()
