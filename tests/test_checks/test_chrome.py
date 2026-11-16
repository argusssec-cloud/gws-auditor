"""ADD-67..70: Chrome browser policies from Google's security checklist (Chrome Policy API, live shapes 2026-11-15),
plus the Password Alert / Gemini mapping the provider derives from the same client."""

import pytest

from gws_auditor.checks.chrome import (check_chrome_safe_browsing, check_chrome_password_manager,
                                       check_chrome_downloads_and_isolation, check_chrome_updates)
from gws_auditor.models import Status

SB_STD = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION"
SB_ENH = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_ENHANCED_PROTECTION"
SB_OFF = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_NO_PROTECTION"
SB_USER = "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_USER_CHOICE"
DL_NONE = "DOWNLOAD_RESTRICTION_ENUM_NO_SPECIAL_RESTRICTIONS"
DL_MAL = "DOWNLOAD_RESTRICTION_ENUM_BLOCK_ALL_MALICIOUS_DOWNLOAD"
RL_REQ = "RELAUNCH_NOTIFICATION_ENUM_REQUIRED"
RL_REC = "RELAUNCH_NOTIFICATION_ENUM_RECOMMENDED"


def _collected(data, **chrome):
    data["chrome_policies"] = dict(chrome)
    data["api_errors"] = []
    return data


def _not_collected(data):
    data["chrome_policies"] = {}
    data["api_errors"] = [{"operation": "get_chrome_policies", "error": "403"}]
    return data


class TestSafeBrowsing:
    def test_enforced_and_bypass_disabled_pass(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data, safe_browsing_protection_level=SB_ENH,
                                                  disable_safe_browsing_proceed_anyway=True))
        assert r.status == Status.PASS and "Enhanced" in r.details

    def test_standard_without_bypass_control_fails(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data, safe_browsing_protection_level=SB_STD))
        assert r.status == Status.FAIL and "bypass" in r.details and "Chrome's default" in r.details

    def test_disabled_fails(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data, safe_browsing_protection_level=SB_OFF,
                                                  disable_safe_browsing_proceed_anyway=True))
        assert r.status == Status.FAIL and "never active" in r.details

    def test_user_choice_fails(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data, safe_browsing_protection_level=SB_USER,
                                                  disable_safe_browsing_proceed_anyway=True))
        assert r.status == Status.FAIL and "turn Safe Browsing off" in r.details

    def test_unset_is_google_default_and_fails(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data))
        assert r.status == Status.FAIL and "Allow the user to decide" in r.details
        assert r.actual_value["sources"] == {"level": "default", "bypass": "default"}

    def test_not_collected_is_review(self, full_audit_data):
        assert check_chrome_safe_browsing(_not_collected(full_audit_data)).status == Status.MANUAL
        full_audit_data.pop("chrome_policies")
        full_audit_data["api_errors"] = []
        assert check_chrome_safe_browsing(full_audit_data).status == Status.MANUAL

    def test_one_schema_failed_is_review(self, full_audit_data):
        data = _collected(full_audit_data, safe_browsing_protection_level=SB_STD)
        data["api_errors"] = [{"operation": "resolve_policy(chrome.users.DisableSafeBrowsingProceedAnyway)", "error": "500"}]
        assert check_chrome_safe_browsing(data).status == Status.MANUAL


class TestPasswordManager:
    def test_always_allowed_pass(self, full_audit_data):
        assert check_chrome_password_manager(_collected(full_audit_data, password_manager_enabled="TRUE")).status == Status.PASS

    def test_never_allowed_fails(self, full_audit_data):
        assert check_chrome_password_manager(_collected(full_audit_data, password_manager_enabled="FALSE")).status == Status.FAIL

    def test_unset_and_explicit_user_choice_pass_by_default(self, full_audit_data):
        r = check_chrome_password_manager(_collected(full_audit_data))
        assert r.status == Status.PASS and "Chrome's default" in r.details
        assert check_chrome_password_manager(_collected(full_audit_data, password_manager_enabled="UNSET")).status == Status.PASS

    def test_not_collected_is_review(self, full_audit_data):
        assert check_chrome_password_manager(_not_collected(full_audit_data)).status == Status.MANUAL


class TestDownloadsAndIsolation:
    def test_block_malicious_pass(self, full_audit_data):
        r = check_chrome_downloads_and_isolation(_collected(full_audit_data, download_restrictions=DL_MAL))
        assert r.status == Status.PASS and "Block malicious downloads" in r.details and "Chrome 67" in r.details

    def test_no_restrictions_fails(self, full_audit_data):
        assert check_chrome_downloads_and_isolation(_collected(full_audit_data, download_restrictions=DL_NONE)).status == Status.FAIL

    def test_unset_is_default_and_fails(self, full_audit_data):
        r = check_chrome_downloads_and_isolation(_collected(full_audit_data))
        assert r.status == Status.FAIL and "Chrome's default" in r.details

    def test_isolation_turned_off_warns(self, full_audit_data):
        r = check_chrome_downloads_and_isolation(_collected(full_audit_data, download_restrictions=DL_MAL, site_per_process=False))
        assert r.status == Status.WARN and "turned off" in r.details

    def test_isolation_required_pass(self, full_audit_data):
        r = check_chrome_downloads_and_isolation(_collected(full_audit_data, download_restrictions=DL_MAL, site_per_process=True))
        assert r.status == Status.PASS and "required" in r.details

    def test_not_collected_is_review(self, full_audit_data):
        assert check_chrome_downloads_and_isolation(_not_collected(full_audit_data)).status == Status.MANUAL


class TestUpdates:
    def test_all_set_pass(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data, component_updates_enabled=True, auto_update_check_period_minutes=295,
                                            relaunch_notification=RL_REQ, chromeos_update_disabled=False))
        assert r.status == Status.PASS

    def test_unset_fails_on_relaunch_only(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data))
        assert r.status == Status.FAIL and "relaunch is not forced" in r.details and "component" not in r.details

    def test_component_updates_off_fails(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data, component_updates_enabled=False, relaunch_notification=RL_REQ))
        assert r.status == Status.FAIL and "component updates are disabled" in r.details

    def test_check_period_zero_fails(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data, auto_update_check_period_minutes=0, relaunch_notification=RL_REQ))
        assert r.status == Status.FAIL and "period is 0" in r.details

    def test_recommended_relaunch_fails(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data, relaunch_notification=RL_REC))
        assert r.status == Status.FAIL and "recommending relaunch" in r.details

    def test_chromeos_updates_blocked_fails(self, full_audit_data):
        r = check_chrome_updates(_collected(full_audit_data, relaunch_notification=RL_REQ, chromeos_update_disabled=True))
        assert r.status == Status.FAIL and "ChromeOS" in r.details

    def test_not_collected_is_review(self, full_audit_data):
        assert check_chrome_updates(_not_collected(full_audit_data)).status == Status.MANUAL

    def test_partial_resolve_error_with_passing_values_is_review(self, full_audit_data):
        data = _collected(full_audit_data, relaunch_notification=RL_REQ)
        data["api_errors"] = [{"operation": "resolve_policy(chrome.devices.AutoUpdateSettings)", "error": "500"}]
        assert check_chrome_updates(data).status == Status.MANUAL


def _per_ou(data, root: dict, **ous: dict):
    """Collected Chrome policies with root values and child OUs that set the given keys themselves."""
    data["chrome_policies"] = dict(root)
    data["chrome_policies"]["_ou_policies"] = {"/": {"values": dict(root), "explicit": sorted(root)}}
    for path, values in ous.items():
        explicit = sorted(values.pop("_explicit", list(values)))
        effective = {**root, **values}
        data["chrome_policies"]["_ou_policies"]["/" + path.replace("__", "/")] = {"values": effective, "explicit": explicit}
    data["api_errors"] = []
    return data


class TestPerOrgUnit:
    """Every Chrome check judges the root and each OU that sets one of its policies itself (2026-11-16)."""

    def test_child_override_fails_and_is_named(self, full_audit_data):
        data = _per_ou(full_audit_data, {"safe_browsing_protection_level": SB_ENH, "disable_safe_browsing_proceed_anyway": True},
                       Contractors={"safe_browsing_protection_level": SB_USER})
        r = check_chrome_safe_browsing(data)
        assert r.status == Status.FAIL
        assert "1 of 2 judged OU(s) non-compliant" in r.details and "/Contractors: Safe Browsing protection level is 'Allow the user to decide'" in r.details
        assert set(r.actual_value) == {"/", "/Contractors"}

    def test_inheriting_child_is_not_repeated(self, full_audit_data):
        data = _per_ou(full_audit_data, {"safe_browsing_protection_level": SB_ENH, "disable_safe_browsing_proceed_anyway": True},
                       Sales={"password_manager_enabled": "FALSE"})
        r = check_chrome_safe_browsing(data)
        assert r.status == Status.PASS and "judged OU" not in r.details and "Sales" not in r.details
        r = check_chrome_password_manager(data)
        assert r.status == Status.FAIL and "/Sales: The Chrome password manager is never allowed" in r.details

    def test_child_that_fixes_the_root_still_fails_on_root(self, full_audit_data):
        data = _per_ou(full_audit_data, {}, Secure={"download_restrictions": DL_MAL})
        r = check_chrome_downloads_and_isolation(data)
        assert r.status == Status.FAIL and r.details.startswith("1 of 2 judged OU(s) non-compliant. /: Chrome does not block")

    def test_all_explicit_and_compliant_lists_each_ou(self, full_audit_data):
        data = _per_ou(full_audit_data, {"password_manager_enabled": "TRUE"}, Eng={"password_manager_enabled": "UNSET"})
        r = check_chrome_password_manager(data)
        assert r.status == Status.PASS and r.details.startswith("All 2 judged OU(s) compliant. /: ") and "/Eng: " in r.details

    def test_warn_in_one_ou(self, full_audit_data):
        data = _per_ou(full_audit_data, {"download_restrictions": DL_MAL}, Lab={"site_per_process": False})
        r = check_chrome_downloads_and_isolation(data)
        assert r.status == Status.WARN and "1 of 2 judged OU(s) need attention. /Lab: " in r.details

    def test_child_resolve_failure_is_undetermined(self, full_audit_data):
        data = _per_ou(full_audit_data, {"relaunch_notification": RL_REQ}, Ops={"component_updates_enabled": False})
        data["api_errors"] = [{"operation": "resolve_policy(chrome.users.ComponentUpdates)[/Ops]", "error": "500"}]
        r = check_chrome_updates(data)
        # The explicit failing value still wins; the per-OU error only makes the unset keys unknown.
        assert r.status == Status.FAIL and "/Ops: component updates are disabled" in r.details
        data = _per_ou(full_audit_data, {"relaunch_notification": RL_REQ}, Ops={"relaunch_notification": RL_REQ})
        data["api_errors"] = [{"operation": "resolve_policy(chrome.devices.AutoUpdateSettings)[/Ops]", "error": "500"}]
        r = check_chrome_updates(data)
        assert r.status == Status.MANUAL and "Undetermined in OU(s): /, /Ops" in r.details

    def test_password_alert_gemini_and_dbsc_per_ou(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert, check_gemini_chrome
        from gws_auditor.checks.security_access import check_dbsc
        full_audit_data["policies"].get("security", {}).pop("password_alert", None)
        full_audit_data["policies"].pop("gemini", None)
        reuse = "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PASSWORD_REUSE"
        off = "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_NO_WARNING"
        data = _per_ou(full_audit_data,
                       {"password_protection_warning_trigger": reuse, "gemini_in_chrome_disabled": True, "dbsc_enabled": True},
                       Guests={"password_protection_warning_trigger": off, "gemini_in_chrome_disabled": False,
                               "dbsc_enabled": False, "bound_session_credentials": "FALSE"})
        r = check_password_alert(data)
        assert r.status == Status.FAIL and "/Guests: Password protection warning is disabled" in r.details
        r = check_gemini_chrome(data)
        assert r.status == Status.FAIL and "/Guests: Gemini in Chrome is allowed" in r.details
        r = check_dbsc(data)
        assert r.status == Status.FAIL and "/Guests: Device Bound Session Credentials (DBSC) are not enabled" in r.details

    def test_legacy_cache_without_ou_policies_is_root_only(self, full_audit_data):
        r = check_chrome_safe_browsing(_collected(full_audit_data, safe_browsing_protection_level=SB_ENH,
                                                  disable_safe_browsing_proceed_anyway=True))
        assert r.status == Status.PASS and r.details.startswith("Safe Browsing is enforced")


class TestProviderMapping:
    """``_map_chrome_policies`` turns the PasswordAlert enum and the derived Gemini flag into the legacy keys."""

    def test_password_alert_enum(self):
        from gws_auditor.provider import _map_chrome_policies
        policies = {}
        _map_chrome_policies(policies, {"password_protection_warning_trigger": "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_NO_WARNING"})
        assert policies["security"]["password_alert"]["deployed"] is False
        _map_chrome_policies(policies, {"password_protection_warning_trigger": "PASSWORD_PROTECTION_WARNING_TRIGGER_ENUM_WARN_ON_PASSWORD_REUSE"})
        assert policies["security"]["password_alert"]["deployed"] is True

    def test_gemini_flag(self):
        from gws_auditor.provider import _map_chrome_policies
        policies = {}
        _map_chrome_policies(policies, {"gemini_in_chrome_disabled": True})
        assert policies["gemini"]["chrome"]["enabled"] is False
