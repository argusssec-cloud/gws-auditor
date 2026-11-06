"""Tests for the Access Context Manager client (Context-Aware Access level inventory)."""

from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.api.access_context_manager import AccessContextManagerClient

# Field names from the live response of 2026-11-06 (accessLevels.list, accessPolicies.list).
LIVE_POLICY = {"name": "accessPolicies/134654395911", "parent": "organizations/18479643020",
               "title": "Access policy created in Cloud Identity Console", "etag": "e8be26dbf140bfec"}
LIVE_LEVEL = {"name": "accessPolicies/134654395911/accessLevels/geo_restriction_fttlt6s2",
              "title": "Geo restriction", "description": "Deny access from one country (geo-block)",
              "basic": {"conditions": [{"negate": True, "regions": ["AQ"]}]}}


def _auth(cloud_creds="creds"):
    auth = MagicMock()
    auth.cloud_credentials.return_value = cloud_creds
    auth.build_authorized_http.return_value = MagicMock(name="http")
    return auth


def _request(response):
    req = MagicMock()
    req.execute.return_value = response
    return req


class TestAccessContextManagerClient:
    def test_requires_cloud_credentials(self):
        client = AccessContextManagerClient(_auth(cloud_creds=None), rate_limit_qps=1000)
        with pytest.raises(RuntimeError, match="cloud-platform"):
            _ = client.service

    def test_name_helpers(self):
        assert AccessContextManagerClient.organization_name("18479643020") == "organizations/18479643020"
        assert AccessContextManagerClient.organization_name("organizations/1") == "organizations/1"
        assert AccessContextManagerClient.organization_name("") == ""
        assert AccessContextManagerClient.policy_name("134654395911") == "accessPolicies/134654395911"
        assert AccessContextManagerClient.policy_name("accessPolicies/2") == "accessPolicies/2"

    @patch("gws_auditor.api.access_context_manager.build")
    def test_list_access_levels_paginates_as_defined(self, build):
        acm = MagicMock()
        levels = acm.accessPolicies.return_value.accessLevels.return_value
        levels.list.side_effect = [
            _request({"accessLevels": [LIVE_LEVEL], "nextPageToken": "p2"}),
            _request({"accessLevels": [dict(LIVE_LEVEL, name="accessPolicies/134654395911/accessLevels/corp",
                                            title="Corp devices", basic={"conditions": [{"devicePolicy": {"requireScreenlock": True}}]})]}),
        ]
        build.return_value = acm
        client = AccessContextManagerClient(_auth(), rate_limit_qps=1000)
        out = client.list_access_levels("134654395911")
        assert [l["title"] for l in out] == ["Geo restriction", "Corp devices"]
        first_call = levels.list.call_args_list[0].kwargs
        assert first_call == {"parent": "accessPolicies/134654395911", "accessLevelFormat": "AS_DEFINED"}
        assert levels.list.call_args_list[1].kwargs["pageToken"] == "p2"
        build.assert_called_once_with("accesscontextmanager", "v1", http=client.auth_manager.build_authorized_http.return_value,
                                      cache_discovery=False)

    @patch("gws_auditor.api.access_context_manager.build")
    def test_list_access_policies(self, build):
        acm = MagicMock()
        acm.accessPolicies.return_value.list.return_value = _request({"accessPolicies": [LIVE_POLICY]})
        build.return_value = acm
        client = AccessContextManagerClient(_auth(), rate_limit_qps=1000)
        assert client.list_access_policies("18479643020")[0]["name"] == "accessPolicies/134654395911"
        assert acm.accessPolicies.return_value.list.call_args.kwargs == {"parent": "organizations/18479643020"}

    @patch("gws_auditor.api.access_context_manager.build")
    def test_search_organization_by_domain_then_customer(self, build):
        crm = MagicMock()
        crm.organizations.return_value.search.side_effect = [
            _request({}),  # domain filter: empty (no organizationViewer)
            _request({"organizations": [{"name": "organizations/18479643020", "displayName": "argussec.io"}]}),
        ]
        build.return_value = crm
        client = AccessContextManagerClient(_auth(), rate_limit_qps=1000)
        assert client.search_organization(domain="example.com", customer_id="C049r06rk") == "organizations/18479643020"
        bodies = [c.kwargs["body"] for c in crm.organizations.return_value.search.call_args_list]
        assert bodies == [{"filter": "domain:example.com"}, {"filter": "owner.directoryCustomerId:C049r06rk"}]

    @patch("gws_auditor.api.access_context_manager.build")
    def test_search_organization_ignores_my_customer(self, build):
        crm = MagicMock()
        crm.organizations.return_value.search.return_value = _request({})
        build.return_value = crm
        client = AccessContextManagerClient(_auth(), rate_limit_qps=1000)
        assert client.search_organization(domain="", customer_id="my_customer") == ""
        assert crm.organizations.return_value.search.call_args.kwargs == {"body": {}}
