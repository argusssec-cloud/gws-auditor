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

    def test_default_policy_is_judged_and_listed(self):
        """A SYSTEM policy is the value in force: it is judged like an admin value
        and also reported in default_ous so the caller can state the provenance."""
        ou_values = [
            {"org_unit": "/", "value": False, "_raw": {"type": "SYSTEM"}},
        ]
        result = evaluate_ous(ou_values, lambda e: e["value"] is True)
        assert result["default_ous"] == ["/"]
        assert result["unsafe_ous"] == ["/"]

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


class TestOuVerdictHelper:
    def _entries(self, **ou_to_value):
        return [{"org_unit": ou, "value": v, "_raw": {"type": "ADMIN"}} for ou, v in ou_to_value.items()]

    def _run(self, entries, data=None):
        from gws_auditor.checks.base import field_value, ou_verdict
        return ou_verdict(entries, lambda e: (lambda v: None if v is None else v is False)(field_value(e, "enabled")),
                          check_id="T-1", title="t", level="L1", source="CIS", section="S",
                          fail_text="have it enabled", pass_text="have it disabled", expected_value="Disabled", data=data)

    def test_all_safe_passes(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {"enabled": False}, "/Eng": {"enabled": False}}))
        assert r.status == Status.PASS and "All 2 OU(s) have it disabled." == r.details

    def test_unsafe_child_fails_and_names_it(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {"enabled": False}, "/Sales": {"enabled": True}}))
        assert r.status == Status.FAIL and "/Sales" in r.details and "/Sales → Enabled" in r.actual_value

    def test_unspecified_is_manual_not_fail(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {"enabled": "ENABLED_STATE_UNSPECIFIED"}}))
        assert r.status == Status.MANUAL and "/" in r.details

    def test_absent_field_is_manual(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {}}))
        assert r.status == Status.MANUAL

    def test_unsafe_wins_over_unknown(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {}, "/Sales": {"enabled": True}}))
        assert r.status == Status.FAIL and "Undetermined" in r.details and "/" in r.details

    def test_exception_ou_only_is_partial(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/": {"enabled": False}, "/Contractors": {"enabled": True}}), data={"_options": {}})
        assert r.status == Status.PARTIAL and "/Contractors" in r.details

    def test_exception_plus_real_violation_fails(self):
        from gws_auditor.models import Status
        r = self._run(self._entries(**{"/Contractors": {"enabled": True}, "/Sales": {"enabled": True}}), data={"_options": {}})
        assert r.status == Status.FAIL and "/Sales" in r.details

    def test_judge_exception_is_unknown(self):
        from gws_auditor.checks.base import ou_verdict
        from gws_auditor.models import Status
        r = ou_verdict(self._entries(**{"/": {"x": 1}}), lambda e: e["value"]["missing"],
                       check_id="T-1", title="t", level="L1", source="CIS", section="S",
                       fail_text="f", pass_text="p", expected_value="e")
        assert r.status == Status.MANUAL


class TestAbsentSettingTakesDocumentedDefault:
    """Google: a field absent from the reduced setting takes its documented default. When the API
    was queried for a setting family and returned nothing for one setting, get_ou_values yields a
    root entry built from the documented defaults, marked as a Google default."""

    def _gmail_category(self):
        from tests.factories import make_ou_policy
        return {"_ou_policies": [make_ou_policy("gmail", "pop_access", {"enablePopAccess": True})]}

    def test_absent_documented_setting_is_synthesised(self):
        from gws_auditor.checks.base import get_ou_values, is_default_policy
        entries = get_ou_values(self._gmail_category(), "mail_delegation")
        assert len(entries) == 1
        assert entries[0]["org_unit"] == "/"
        assert entries[0]["value"]["enableMailDelegation"] is False
        assert is_default_policy(entries[0])
        assert "enableMailDelegation" in entries[0]["_defaulted_fields"]

    def test_absent_undocumented_setting_stays_absent(self):
        from gws_auditor.checks.base import get_ou_values
        assert get_ou_values(self._gmail_category(), "comprehensive_mail_storage") == []

    def test_wrong_category_never_synthesises(self):
        """A check probing the security category for a Gmail setting must still get []."""
        from gws_auditor.checks.base import get_ou_values
        from tests.factories import make_ou_policy
        security = {"_ou_policies": [make_ou_policy("security", "password", {"minimumLength": 8})]}
        assert get_ou_values(security, "mail_delegation") == []

    def test_real_entry_wins_over_synthesis(self):
        from gws_auditor.checks.base import get_ou_values
        from tests.factories import make_ou_policy
        cat = {"_ou_policies": [make_ou_policy("gmail", "mail_delegation", {"enableMailDelegation": True})]}
        entries = get_ou_values(cat, "mail_delegation")
        assert entries[0]["value"]["enableMailDelegation"] is True and not entries[0]["_defaulted_fields"]

    def test_check_reports_default_with_provenance(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        from gws_auditor.models import Status
        full_audit_data["policies"]["gmail"] = self._gmail_category()
        result = check_gmail_auto_forwarding(full_audit_data)
        assert result.status == Status.FAIL  # documented default: auto-forwarding enabled
        assert "Google default" in result.details


class TestStaleInjectedDefaultsAreIgnored:
    """A cache written by an older version may carry an injected DEFAULT entry for a setting
    Google documents no default for (P6: calendar offline). It is a guess, not evidence."""

    def test_stale_default_entry_is_dropped(self):
        from gws_auditor.checks.base import get_ou_values
        from tests.factories import make_ou_policy
        stale = make_ou_policy("calendar", "calendar_offline_access", {"enableOfflineAccess": True})
        stale["_raw"] = {"type": "DEFAULT"}; stale["name"] = "policies/_default/calendar.calendar_offline_access"
        assert get_ou_values({"_ou_policies": [stale]}, "calendar_offline_access") == []

    def test_system_policy_is_never_dropped(self):
        from gws_auditor.checks.base import get_ou_values
        from tests.factories import make_ou_policy
        sysp = make_ou_policy("calendar", "calendar_offline_access", {"enableOfflineAccess": True})
        sysp["_raw"] = {"type": "SYSTEM"}
        assert len(get_ou_values({"_ou_policies": [sysp]}, "calendar_offline_access")) == 1

    def test_documented_default_entry_is_kept(self):
        from gws_auditor.checks.base import get_ou_values
        from tests.factories import make_ou_policy
        dflt = make_ou_policy("gmail", "mail_delegation", {"enableMailDelegation": False})
        dflt["_raw"] = {"type": "DEFAULT"}; dflt["name"] = "policies/_default/gmail.mail_delegation"
        assert len(get_ou_values({"_ou_policies": [dflt]}, "mail_delegation")) == 1


class TestEditionSets:
    """requires_license as an explicit any-of tuple (constants.EDITIONS_*), 2026-11-10."""

    def _data(self, *tiers, skus=None):
        from gws_auditor.constants import LICENSE_TIER_NAMES
        return {"subscription_info": {"tier_keys_present": list(tiers),
                                      "edition": "Google Workspace " + LICENSE_TIER_NAMES.get(tiers[0], tiers[0]),
                                      "skus": skus if skus is not None else [{"tier_key": t} for t in tiers]}}

    def test_member_edition_runs(self):
        from gws_auditor.constants import EDITIONS_CAA
        assert _check_license_sufficient(EDITIONS_CAA, self._data("frontline_standard")) is True

    def test_non_member_edition_is_not_applicable(self):
        from gws_auditor.constants import EDITIONS_CAA
        assert _check_license_sufficient(EDITIONS_CAA, self._data("business_plus")) is False

    def test_mixed_tenant_with_one_member_runs(self):
        from gws_auditor.constants import EDITIONS_CSE
        assert _check_license_sufficient(EDITIONS_CSE, self._data("business_starter", "enterprise_plus")) is True

    def test_unknown_sku_keeps_the_check_running(self):
        from gws_auditor.constants import EDITIONS_CSE
        data = self._data("business_starter", skus=[{"tier_key": "business_starter"}, {"tier_key": ""}])
        assert _check_license_sufficient(EDITIONS_CSE, data) is True

    def test_no_detection_runs(self):
        from gws_auditor.constants import EDITIONS_CSE
        assert _check_license_sufficient(EDITIONS_CSE, {}) is True
        assert _check_license_sufficient(EDITIONS_CSE, {"subscription_type": "Google Workspace Enterprise Plus"}) is True
        assert _check_license_sufficient(EDITIONS_CSE, {"subscription_type": "Business Starter"}) is False

    def test_addon_sku_satisfies_only_its_own_set(self):
        from gws_auditor.constants import EDITIONS_ASSURED_CONTROLS
        data = self._data("enterprise_standard", "assured_controls")
        assert _check_license_sufficient(EDITIONS_ASSURED_CONTROLS, data) is True
        assert _check_license_sufficient("enterprise_plus", data) is False  # tier 99 never lifts a minimum-tier gate
        assert _check_license_sufficient(EDITIONS_ASSURED_CONTROLS, self._data("enterprise_plus")) is False

    def test_requirement_text(self):
        from gws_auditor.checks.base import license_requirement_text
        from gws_auditor.constants import EDITIONS_ASSURED_CONTROLS
        assert license_requirement_text("enterprise_plus") == "Enterprise Plus or higher"
        assert license_requirement_text(EDITIONS_ASSURED_CONTROLS).startswith("one of these editions: Assured Controls add-on")
