"""Per-OU Chrome policy resolution (live shape 2026-11-16).

A child OU is resolved with one wildcard call per namespace (``chrome.users.*``, ``chrome.devices.*``);
each resolved policy carries the OU's *effective* value and a ``sourceKey`` naming the OU that set
it (the root for an inherited value, the OU itself for an override). The client keeps the effective
values and marks the keys the OU sets itself as ``explicit``.
"""

from unittest.mock import MagicMock

from googleapiclient.errors import HttpError

from gws_auditor.api.chrome_policy import ChromePolicyClient

ROOT = "03ph8a2z2g974qd"
GUESTS = "03ph8a2z1fl2xa0"
OUS = [{"orgUnitPath": "/Workspace Guests", "orgUnitId": f"id:{GUESTS}", "parentOrgUnitId": f"id:{ROOT}"}]

SB = "chrome.users.SafeBrowsingProtectionLevel"
SB_STD = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION"
SB_OFF = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_NO_PROTECTION"


def _resolved(schema, value, target, source):
    """One ``resolvedPolicies`` entry as the API returned it on 2026-11-16."""
    return {"targetKey": {"targetResource": f"orgunits/{target}"},
            "value": {"policySchema": schema, "value": value},
            "sourceKey": {"targetResource": f"orgunits/{source}"}}


def _client(root_values: dict, child: dict[str, list], fail_wildcards: tuple = ()):
    """*root_values*: {schema: value dict} answered to single-schema calls at the root.
    *child*: {ou_id: [resolved entries]} answered to wildcard calls; namespaces in *fail_wildcards* raise."""
    client = ChromePolicyClient(MagicMock())
    client._root_ou_id = ROOT
    service = MagicMock()
    client._service = service
    calls = []

    def resolve(customer, body):
        calls.append(body)
        target = body["policyTargetKey"]["targetResource"].removeprefix("orgunits/")
        flt = body["policySchemaFilter"]
        req = MagicMock()
        if flt.endswith(".*"):
            if flt in fail_wildcards:
                resp = MagicMock(); resp.status = 500; resp.reason = "boom"
                req.execute.side_effect = HttpError(resp, b"boom")
            else:
                prefix = flt[:-1]
                entries = [e for e in child.get(target, []) if e["value"]["policySchema"].startswith(prefix)]
                if body.get("pageToken") == "p2":
                    req.execute.return_value = {"resolvedPolicies": entries[1:]}
                elif len(entries) > 1 and target == "paged":
                    req.execute.return_value = {"resolvedPolicies": entries[:1], "nextPageToken": "p2"}
                else:
                    req.execute.return_value = {"resolvedPolicies": entries}
        elif target == ROOT and flt in root_values:
            req.execute.return_value = {"resolvedPolicies": [_resolved(flt, root_values[flt], ROOT, ROOT)]}
        else:
            req.execute.return_value = {}
        return req

    service.customers().policies().resolve.side_effect = resolve
    client._calls = calls
    return client


class TestPerOuResolution:
    def test_inherited_value_is_effective_but_not_explicit(self):
        client = _client({SB: {"safeBrowsingProtectionLevel": SB_STD}},
                         {GUESTS: [_resolved(SB, {"safeBrowsingProtectionLevel": SB_STD}, GUESTS, ROOT)]})
        result = client.get_chrome_policies("my_customer", org_units=OUS)
        assert result["safe_browsing_protection_level"] == SB_STD
        guests = result["_ou_policies"]["/Workspace Guests"]
        assert guests["values"]["safe_browsing_protection_level"] == SB_STD
        assert guests["explicit"] == []
        assert result["_ou_policies"]["/"]["explicit"] == ["safe_browsing_protection_level"]

    def test_override_is_explicit(self):
        client = _client({SB: {"safeBrowsingProtectionLevel": SB_STD}},
                         {GUESTS: [_resolved(SB, {"safeBrowsingProtectionLevel": SB_OFF}, GUESTS, GUESTS),
                                   _resolved("chrome.users.BoundSessionCredentialsEnabled",
                                             {"boundSessionCredentialsEnabled": "FALSE"}, GUESTS, GUESTS),
                                   _resolved("chrome.users.SomethingTheChecksIgnore", {"x": 1}, GUESTS, GUESTS)]})
        result = client.get_chrome_policies("my_customer", org_units=OUS)
        guests = result["_ou_policies"]["/Workspace Guests"]
        assert guests["values"]["safe_browsing_protection_level"] == SB_OFF
        assert guests["values"]["dbsc_enabled"] is False
        assert guests["explicit"] == ["bound_session_credentials", "dbsc_enabled", "safe_browsing_protection_level"]
        assert "x" not in guests["values"]

    def test_two_wildcard_calls_per_child_ou_and_root_untouched(self):
        client = _client({}, {GUESTS: []})
        client.get_chrome_policies("my_customer", org_units=OUS + [{"orgUnitPath": "/", "orgUnitId": f"id:{ROOT}"}])
        wildcard = [c for c in client._calls if c["policySchemaFilter"].endswith(".*")]
        assert sorted(c["policySchemaFilter"] for c in wildcard) == ["chrome.devices.*", "chrome.users.*"]
        assert {c["policyTargetKey"]["targetResource"] for c in wildcard} == {f"orgunits/{GUESTS}"}
        assert all(c["pageSize"] == 1000 for c in wildcard)

    def test_wildcard_pagination(self):
        entries = [_resolved(SB, {"safeBrowsingProtectionLevel": SB_OFF}, "paged", "paged"),
                   _resolved("chrome.users.PasswordManager", {"passwordManagerEnabled": "FALSE"}, "paged", "paged")]
        client = _client({}, {"paged": entries})
        result = client.get_chrome_policies("my_customer", org_units=[{"orgUnitPath": "/Paged", "orgUnitId": "paged"}])
        assert result["_ou_policies"]["/Paged"]["values"] == {"safe_browsing_protection_level": SB_OFF,
                                                               "password_manager_enabled": "FALSE"}

    def test_failed_wildcard_records_an_error_per_schema_for_that_ou(self):
        client = _client({}, {GUESTS: []}, fail_wildcards=("chrome.users.*",))
        result = client.get_chrome_policies("my_customer", org_units=OUS)
        ops = [e["operation"] for e in client.errors]
        assert "resolve_policy(chrome.users.SafeBrowsingProtectionLevel)[/Workspace Guests]" in ops
        assert "resolve_policy(chrome.users.PasswordAlert)[/Workspace Guests]" in ops
        assert not any("chrome.devices" in op for op in ops)
        assert result["_ou_policies"]["/Workspace Guests"] == {"values": {}, "explicit": []}

    def test_malformed_org_units_are_skipped(self):
        client = _client({}, {})
        result = client.get_chrome_policies("my_customer", org_units=[None, {"orgUnitPath": "/NoId"}, {"orgUnitId": "x"}])
        assert list(result["_ou_policies"]) == ["/"]
        assert not any(c["policySchemaFilter"].endswith(".*") for c in client._calls)
