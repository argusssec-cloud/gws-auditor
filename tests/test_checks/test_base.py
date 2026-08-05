"""Tests for shared check helpers in checks/base.py."""

from gws_auditor.checks.base import (
    _check_license_sufficient,
    evaluate_ous,
    format_ou_values_readable,
    is_admin_configured,
    is_default_policy,
    is_external_sharing_ou,
    make_partial,
)
from gws_auditor.models import Status


class TestIsDefaultPolicy:
    def test_admin_entry(self):
        assert not is_default_policy({"_raw": {"type": "ADMIN"}})

    def test_system_entry(self):
        assert is_default_policy({"_raw": {"type": "SYSTEM"}})

    def test_default_entry(self):
        assert is_default_policy({"_raw": {"type": "DEFAULT"}})

    def test_default_in_name(self):
        assert is_default_policy({"name": "policies/_default/foo"})


class TestIsAdminConfigured:
    def test_admin(self):
        assert is_admin_configured({"_raw": {"type": "ADMIN"}})

    def test_default(self):
        assert not is_admin_configured({"_raw": {"type": "DEFAULT"}})


class TestIsExternalSharingOU:
    def test_default_pattern_external(self):
        assert is_external_sharing_ou("/NewDeciphex/Sharing-External", {})

    def test_default_pattern_contractors(self):
        assert is_external_sharing_ou("/Contractors", {})

    def test_default_pattern_third_parties(self):
        assert is_external_sharing_ou("/3rd Parties", {})

    def test_normal_ou_not_excepted(self):
        assert not is_external_sharing_ou("/Staff", {})

    def test_root_not_excepted(self):
        assert not is_external_sharing_ou("/", {})

    def test_config_override_exact_path(self):
        data = {"config": {"options": {"external_sharing_ous": ["/CustomOU"]}}}
        assert is_external_sharing_ou("/CustomOU", data)
        assert not is_external_sharing_ou("/Contractors", data)

    def test_config_override_glob(self):
        data = {"config": {"options": {"external_sharing_ous": ["*Custom*"]}}}
        assert is_external_sharing_ou("/parent/CustomChild", data)

    def test_empty_path(self):
        assert not is_external_sharing_ou("", {})

    def test_options_injected_by_orchestrator(self):
        """The orchestrator injects config options as data["_options"]."""
        data = {"_options": {"external_sharing_ous": ["/CustomOU"]}}
        assert is_external_sharing_ou("/CustomOU", data)
        assert not is_external_sharing_ou("/Contractors", data)

    def test_options_take_precedence_over_config_key(self):
        data = {
            "_options": {"external_sharing_ous": ["/FromOptions"]},
            "config": {"options": {"external_sharing_ous": ["/FromConfig"]}},
        }
        assert is_external_sharing_ou("/FromOptions", data)
        assert not is_external_sharing_ou("/FromConfig", data)

    def test_empty_options_falls_back_to_defaults(self):
        data = {"_options": {}}
        assert is_external_sharing_ou("/Contractors", data)


class TestFormatOUValuesReadable:
    def test_empty_list(self):
        assert format_ou_values_readable([]) == ""

    def test_booleans_humanized(self):
        out = format_ou_values_readable([
            {"org_unit": "/Sales", "value": True},
            {"org_unit": "/Eng", "value": False},
        ])
        assert out == "/Sales → Enabled\n/Eng → Disabled"

    def test_none_is_not_set(self):
        assert format_ou_values_readable(
            [{"org_unit": "/Sales", "value": None}]
        ) == "/Sales → Not set"

    def test_other_values_stringified(self):
        assert format_ou_values_readable(
            [{"org_unit": "/Sales", "value": "ANYONE"}]
        ) == "/Sales → ANYONE"

    def test_custom_humanizer(self):
        out = format_ou_values_readable(
            [{"org_unit": "/Sales", "value": "reader"}],
            lambda v: {"reader": "Can see all event details"}.get(v, v),
        )
        assert out == "/Sales → Can see all event details"

    def test_missing_keys_tolerated(self):
        assert format_ou_values_readable([{}]) == " → Not set"


class TestEvaluateOUs:
    @staticmethod
    def _admin_entry(ou: str, value):
        return {
            "org_unit": ou,
            "value": value,
            "_raw": {"type": "ADMIN"},
        }

    def test_all_safe(self):
        ou_values = [
            self._admin_entry("/", True),
            self._admin_entry("/Staff", True),
        ]
        result = evaluate_ous(ou_values, lambda e: e["value"] is True)
        assert result["safe_ous"] == ["/", "/Staff"]
        assert result["unsafe_ous"] == []
        assert result["exception_ous"] == []
        assert result["default_ous"] == []
        assert result["total"] == 2

    def test_unsafe_in_normal_ou(self):
        ou_values = [
            self._admin_entry("/", False),
            self._admin_entry("/Staff", True),
        ]
        result = evaluate_ous(ou_values, lambda e: e["value"] is True)
        assert "/" in result["unsafe_ous"]
        assert "/Staff" in result["safe_ous"]

    def test_exception_ou_partitioned(self):
        ou_values = [
            self._admin_entry("/", True),
            self._admin_entry("/NewDeciphex/Sharing-External", False),
        ]
        result = evaluate_ous(
            ou_values, lambda e: e["value"] is True, data={}
        )
        assert result["unsafe_ous"] == []
        assert result["exception_ous"] == ["/NewDeciphex/Sharing-External"]

    def test_no_data_means_no_exceptions(self):
        ou_values = [self._admin_entry("/Contractors", False)]
        result = evaluate_ous(ou_values, lambda e: e["value"] is True)
        assert result["unsafe_ous"] == ["/Contractors"]
        assert result["exception_ous"] == []

    def test_default_policy_excluded(self):
        ou_values = [
            {"org_unit": "/", "value": False, "_raw": {"type": "SYSTEM"}},
        ]
        result = evaluate_ous(ou_values, lambda e: e["value"] is True)
        assert result["default_ous"] == ["/"]
        assert result["unsafe_ous"] == []

    def test_predicate_exception_treated_as_unsafe(self):
        ou_values = [self._admin_entry("/", None)]
        # predicate raises on None
        result = evaluate_ous(
            ou_values, lambda e: e["value"].lower() == "ok"
        )
        assert result["unsafe_ous"] == ["/"]


class TestCheckLicenseSufficient:
    def test_no_requirement_passes(self):
        assert _check_license_sufficient("", {}) is True

    def test_unknown_license_runs_check(self):
        assert _check_license_sufficient("enterprise_plus", {}) is True

    def test_tenant_license_meets_requirement(self):
        data = {"subscription_type": "Google Workspace Enterprise Plus"}
        assert _check_license_sufficient("enterprise_standard", data) is True

    def test_tenant_license_below_requirement(self):
        data = {"subscription_type": "Google Workspace Business Starter"}
        assert _check_license_sufficient("enterprise_plus", data) is False

    def test_mixed_tenant_with_higher_tier_present(self):
        """If ANY assigned SKU meets the requirement, feature is available."""
        data = {
            "subscription_info": {
                "edition": "Google Workspace Enterprise Essentials",
                "tier_key": "enterprise_essentials",
                "tier_keys_present": ["enterprise_essentials", "enterprise_standard"],
                "skus": [
                    {"sku_id": "1010060003", "tier_key": "enterprise_essentials"},
                    {"sku_id": "1010020026", "tier_key": "enterprise_standard"},
                ],
            },
        }
        # Primary edition is Essentials (tier 1) but Enterprise Standard
        # (tier 6) is also present — checks gated on enterprise_standard
        # should run and evaluate real settings.
        assert _check_license_sufficient("enterprise_standard", data) is True

    def test_unknown_sku_present_treated_as_ambiguous(self):
        """Unknown SKU in mixed tenant → run the check (don't short-circuit)."""
        data = {
            "subscription_info": {
                "edition": "Google Workspace Business Starter",
                "tier_key": "business_starter",
                "tier_keys_present": ["business_starter"],
                "skus": [
                    {"sku_id": "1010020027", "tier_key": "business_starter"},
                    {"sku_id": "9999999999", "tier_key": ""},
                ],
            },
        }
        assert _check_license_sufficient("enterprise_plus", data) is True

    def test_single_edition_below_requirement_short_circuits(self):
        data = {
            "subscription_info": {
                "edition": "Google Workspace Business Starter",
                "tier_key": "business_starter",
                "tier_keys_present": ["business_starter"],
                "skus": [{"sku_id": "1010020027", "tier_key": "business_starter"}],
            },
        }
        assert _check_license_sufficient("enterprise_plus", data) is False


class TestMakePartial:
    def test_returns_partial_status(self):
        result = make_partial(
            check_id="T-1", title="t", level="L1", source="CIS", section="x"
        )
        assert result.status == Status.PARTIAL

    def test_carries_details(self):
        result = make_partial(
            check_id="T-1", title="t", level="L1", source="CIS", section="x",
            details="Some OUs compliant", actual_value={"unsafe": ["/foo"]},
        )
        assert result.details == "Some OUs compliant"
        assert result.actual_value == {"unsafe": ["/foo"]}
