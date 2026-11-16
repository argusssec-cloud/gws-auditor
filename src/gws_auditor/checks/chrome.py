# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Chrome browser and ChromeOS policies from Google's security checklist.

Google's "Security checklist for medium and large businesses" (section *Chrome browser and
ChromeOS devices*) asks admins to keep Chrome updated and force a relaunch, to set the basic
policies (password manager allowed, Safe Browsing always on, no bypass of its warnings) and the
advanced ones (block dangerous downloads, site isolation). The values come from the Chrome Policy
API resolved at the root OU and at every child OU (``data["chrome_policies"]``, see
``api/chrome_policy.py``); every schema name, field and enum member was read from the live
``policySchemas`` catalogue on 2026-11-15 (``tests/fixtures/chrome_policy_schemas.json``).

Each check judges the root OU and every OU that sets one of the policies it reads itself
(``checks.base.chrome_ou_rows``); an OU that inherits them follows its parent. An unset policy
resolves to nothing. When the collection recorded no error for the schema that absence is
Chrome's documented default (``CHROME_POLICY_DEFAULTS``) and is judged as such; when the Chrome
policies were not collected or the resolve call failed the verdict is MANUAL.
"""

from .base import check, chrome_ou_verdict, chrome_policy_unset
from ..google_defaults import CHROME_POLICY_DEFAULTS
from ..models import CheckResult

_SECTION = "Chrome Browser"
_CHECKLIST = "https://knowledge.workspace.google.com/admin/security/security-checklist-for-medium-and-large-businesses-100-users"
_CONSOLE = "Admin console > Devices > Chrome > Settings > Users & browsers"


def _policy(data: dict, values: dict, key: str, schema: str) -> tuple:
    """``(value, state)`` for one resolved Chrome policy in one OU's effective *values*.

    ``state`` is ``"set"`` when the policy resolved to a value, ``"default"`` when it is unset and
    the collection recorded no error (value = Google's published default), ``"unknown"`` otherwise.
    """
    if isinstance(values, dict) and key in values and values[key] is not None:
        return values[key], "set"
    if chrome_policy_unset(data, schema):
        return CHROME_POLICY_DEFAULTS[schema]["default_value"], "default"
    return None, "unknown"


def _default_note(schema: str) -> str:
    default = CHROME_POLICY_DEFAULTS[schema]
    return f"not set by policy, so Chrome's default applies: {default['unset']} (source: {default['source']})"


def _unknown_details(what: str) -> str:
    return (f"{what} could not be determined (Chrome policies were not collected or the resolve call failed). "
            f"Verify in {_CONSOLE}.")


# ── Safe Browsing ────────────────────────────────────────────────────────

_SB_SCHEMA = "chrome.users.SafeBrowsingProtectionLevel"
_SB_BYPASS_SCHEMA = "chrome.users.DisableSafeBrowsingProceedAnyway"
_SB_KEYS = ("safe_browsing_protection_level", "disable_safe_browsing_proceed_anyway")
_SB_ON = ("SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION", "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_ENHANCED_PROTECTION")
_SB_LABELS = {
    "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_USER_CHOICE": "Allow the user to decide",
    "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_NO_PROTECTION": "Safe Browsing is never active",
    "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION": "Standard protection",
    "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_ENHANCED_PROTECTION": "Enhanced protection",
}
_SB_REMED = (
    f"{_CONSOLE} > Security > Safe Browsing Protection Level: 'Always enable Safe Browsing' (standard or enhanced "
    "protection), and set 'Disable bypassing Safe Browsing warnings' so users cannot proceed past a warning. "
    f"{_CHECKLIST}"
)


@check(
    check_id="ADD-67",
    title="Ensure Safe Browsing is always on in Chrome and its warnings cannot be bypassed",
    level="L1", source="GOOGLE", section=_SECTION,
    severity="HIGH",
    remediation=_SB_REMED,
)
def check_chrome_safe_browsing(data: dict) -> CheckResult:
    """Google's basic Chrome policies: Safe Browsing 'Always enable', bypass of its warnings disabled."""
    common = dict(check_id="ADD-67", title="Ensure Safe Browsing is always on in Chrome and its warnings cannot be bypassed",
                  level="L1", source="GOOGLE", section=_SECTION)
    expected = "Safe Browsing standard or enhanced protection enforced; bypassing warnings disabled"

    def judge(values: dict) -> tuple:
        level, level_state = _policy(data, values, _SB_KEYS[0], _SB_SCHEMA)
        bypass_disabled, bypass_state = _policy(data, values, _SB_KEYS[1], _SB_BYPASS_SCHEMA)
        if level_state == "unknown" or bypass_state == "unknown":
            return "unknown", "", None
        problems, notes = [], []
        level_label = _SB_LABELS.get(str(level), str(level))
        if str(level) not in _SB_ON:
            problems.append(f"Safe Browsing protection level is '{level_label}'"
                            + (" (" + _default_note(_SB_SCHEMA) + ")" if level_state == "default" else "")
                            + ("" if level_state == "default" else ": users can turn Safe Browsing off" if "USER_CHOICE" in str(level) else ""))
        elif level_state == "default":
            notes.append("protection level " + _default_note(_SB_SCHEMA))
        if bypass_disabled is not True and str(bypass_disabled).lower() != "true":
            problems.append("users can bypass Safe Browsing warnings"
                            + (" (" + _default_note(_SB_BYPASS_SCHEMA) + ")" if bypass_state == "default" else ""))
        actual = {"safe_browsing_protection_level": level, "disable_safe_browsing_proceed_anyway": bypass_disabled,
                  "sources": {"level": level_state, "bypass": bypass_state}}
        if problems:
            return "fail", "; ".join(problems) + ".", actual
        return "pass", (f"Safe Browsing is enforced ({level_label}) and users cannot bypass its warnings."
                        + (" " + "; ".join(notes) + "." if notes else "")), actual

    return chrome_ou_verdict(data, _SB_KEYS, judge, common=common, expected_value=expected, remediation=_SB_REMED,
                             unknown_details=_unknown_details("Safe Browsing protection level or warning bypass"))


# ── Password manager ─────────────────────────────────────────────────────

_PM_SCHEMA = "chrome.users.PasswordManager"
_PM_KEYS = ("password_manager_enabled",)
_PM_REMED = (
    f"{_CONSOLE} > Security > Password manager: 'Always allow use of password manager' (Google's checklist: "
    f"allow the password manager; it is allowed by default). {_CHECKLIST}"
)


@check(
    check_id="ADD-68",
    title="Ensure the Chrome password manager is allowed",
    level="L2", source="GOOGLE", section=_SECTION,
    severity="LOW",
    remediation=_PM_REMED,
)
def check_chrome_password_manager(data: dict) -> CheckResult:
    """Google's basic Chrome policies: 'Allow password manager (Allowed by default)'."""
    common = dict(check_id="ADD-68", title="Ensure the Chrome password manager is allowed",
                  level="L2", source="GOOGLE", section=_SECTION)
    expected = "Password manager allowed (TRUE, or left to the user)"

    def judge(values: dict) -> tuple:
        value, state = _policy(data, values, _PM_KEYS[0], _PM_SCHEMA)
        if state == "unknown":
            return "unknown", "", None
        actual = {"password_manager_enabled": value, "source": state}
        if str(value).upper() == "FALSE":
            return "fail", ("The Chrome password manager is never allowed ('Never allow use of password manager'), "
                            "so users have no managed place to keep unique passwords."), actual
        if str(value).upper() == "TRUE":
            return "pass", "The Chrome password manager is always allowed.", actual
        return "pass", "The Chrome password manager is " + _default_note(_PM_SCHEMA) + ".", actual

    return chrome_ou_verdict(data, _PM_KEYS, judge, common=common, expected_value=expected, remediation=_PM_REMED,
                             unknown_details=_unknown_details("The Chrome password manager policy"))


# ── Downloads and site isolation ────────────────────────────────────────

_DL_SCHEMA = "chrome.users.DownloadRestrictions"
_SI_SCHEMA = "chrome.users.SiteIsolationBrowser"
_DL_KEYS = ("download_restrictions", "site_per_process")
_DL_LABELS = {
    "DOWNLOAD_RESTRICTION_ENUM_NO_SPECIAL_RESTRICTIONS": "No special restrictions",
    "DOWNLOAD_RESTRICTION_ENUM_BLOCK_ALL_MALICIOUS_DOWNLOAD": "Block malicious downloads",
    "DOWNLOAD_RESTRICTION_ENUM_BLOCK_DANGEROUS_DOWNLOAD": "Block malicious downloads and dangerous file types",
    "DOWNLOAD_RESTRICTION_ENUM_BLOCK_POTENTIALLY_DANGEROUS_DOWNLOAD": "Block malicious, uncommon or unwanted downloads and dangerous file types",
    "DOWNLOAD_RESTRICTION_ENUM_BLOCK_ALL_DOWNLOAD": "Block all downloads",
}
_DL_REMED = (
    f"{_CONSOLE} > Security > Download restrictions: at least 'Block malicious downloads' (Google's checklist: "
    "DownloadRestrictions—Block malicious downloads). Keep Site isolation > 'Require site isolation for all websites' "
    f"on. {_CHECKLIST}"
)


@check(
    check_id="ADD-69",
    title="Ensure Chrome blocks malicious downloads and keeps site isolation on",
    level="L2", source="GOOGLE", section=_SECTION,
    severity="MEDIUM",
    remediation=_DL_REMED,
)
def check_chrome_downloads_and_isolation(data: dict) -> CheckResult:
    """Google's advanced Chrome policies: DownloadRestrictions blocks malicious downloads; site isolation stays on."""
    common = dict(check_id="ADD-69", title="Ensure Chrome blocks malicious downloads and keeps site isolation on",
                  level="L2", source="GOOGLE", section=_SECTION)
    expected = "Download restrictions block malicious downloads; site isolation not turned off"

    def judge(values: dict) -> tuple:
        restriction, dl_state = _policy(data, values, _DL_KEYS[0], _DL_SCHEMA)
        isolation, si_state = _policy(data, values, _DL_KEYS[1], _SI_SCHEMA)
        if dl_state == "unknown":
            return "unknown", "", None
        actual = {"download_restrictions": restriction, "site_per_process": isolation,
                  "sources": {"downloads": dl_state, "site_isolation": si_state}}
        if str(restriction) == "DOWNLOAD_RESTRICTION_ENUM_NO_SPECIAL_RESTRICTIONS":
            return "fail", ("Chrome does not block malicious downloads ('No special restrictions'"
                            + (", " + _default_note(_DL_SCHEMA) if dl_state == "default" else "") + ")."), actual
        label = _DL_LABELS.get(str(restriction), str(restriction))
        if si_state == "set" and isolation is False:
            return "warn", (f"Downloads: {label}. Site isolation is turned off by policy "
                            "('Turn off site isolation for all websites'), which removes Chrome's process-per-site defence."), actual
        isolation_note = ("site isolation is required for all websites" if si_state == "set"
                          else "site isolation is " + _default_note(_SI_SCHEMA) if si_state == "default"
                          else "the site isolation policy could not be read")
        return "pass", f"Downloads: {label}; {isolation_note}.", actual

    return chrome_ou_verdict(data, _DL_KEYS, judge, common=common, expected_value=expected, remediation=_DL_REMED,
                             unknown_details=_unknown_details("Chrome download restrictions"))


# ── Updates and relaunch ─────────────────────────────────────────────────

_CU_SCHEMA = "chrome.users.ComponentUpdates"
_AU_SCHEMA = "chrome.users.AutoUpdateCheckPeriodNewV2"
_RL_SCHEMA = "chrome.users.RelaunchNotificationWithDurationV2"
_OS_SCHEMA = "chrome.devices.AutoUpdateSettings"
_UPD_KEYS = ("component_updates_enabled", "auto_update_check_period_minutes", "relaunch_notification", "chromeos_update_disabled")
_RL_LABELS = {
    "RELAUNCH_NOTIFICATION_ENUM_NO_NOTIFICATION": "No relaunch notification",
    "RELAUNCH_NOTIFICATION_ENUM_RECOMMENDED": "Show notification recommending relaunch",
    "RELAUNCH_NOTIFICATION_ENUM_REQUIRED": "Force relaunch after a period",
}
_UPD_REMED = (
    f"{_CONSOLE} > Chrome updates: keep 'Component updates' enabled and the auto-update check period above 0; set "
    "'Relaunch notification' to 'Force relaunch after a period' so pending updates are applied. "
    "Devices > Chrome > Settings > Device > Auto-update settings: 'Allow devices to automatically update OS version'. "
    f"{_CHECKLIST}"
)


@check(
    check_id="ADD-70",
    title="Ensure Chrome and ChromeOS auto-update and force a relaunch to apply updates",
    level="L2", source="GOOGLE", section=_SECTION,
    severity="MEDIUM",
    remediation=_UPD_REMED,
)
def check_chrome_updates(data: dict) -> CheckResult:
    """Google's checklist: keep Chrome and ChromeOS updated and force a relaunch after a deadline."""
    common = dict(check_id="ADD-70", title="Ensure Chrome and ChromeOS auto-update and force a relaunch to apply updates",
                  level="L2", source="GOOGLE", section=_SECTION)
    expected = "Component updates on, auto-update checks on, relaunch forced after a period, ChromeOS updates allowed"

    def judge(values: dict) -> tuple:
        component, cu_state = _policy(data, values, _UPD_KEYS[0], _CU_SCHEMA)
        period, au_state = _policy(data, values, _UPD_KEYS[1], _AU_SCHEMA)
        relaunch, rl_state = _policy(data, values, _UPD_KEYS[2], _RL_SCHEMA)
        os_disabled, os_state = _policy(data, values, _UPD_KEYS[3], _OS_SCHEMA)
        states = {"component_updates": cu_state, "auto_update_check_period": au_state, "relaunch": rl_state, "chromeos": os_state}
        actual = {"component_updates_enabled": component, "auto_update_check_period_minutes": period,
                  "relaunch_notification": relaunch, "chromeos_update_disabled": os_disabled, "sources": states}
        problems = []
        if cu_state != "unknown" and str(component).lower() == "false":
            problems.append("component updates are disabled")
        if au_state != "unknown" and period is not None and str(period).strip() in ("0", "0.0"):
            problems.append("the auto-update check period is 0, which disables all auto-update checks")
        if rl_state != "unknown" and str(relaunch) != "RELAUNCH_NOTIFICATION_ENUM_REQUIRED":
            problems.append(f"relaunch is not forced ('{_RL_LABELS.get(str(relaunch), str(relaunch))}'"
                            + (", " + _default_note(_RL_SCHEMA) if rl_state == "default" else "") + ")")
        if os_state != "unknown" and str(os_disabled).lower() == "true":
            problems.append("ChromeOS devices are blocked from installing OS updates")
        if problems:
            return "fail", "; ".join(problems) + ".", actual
        if "unknown" in states.values():
            return "unknown", "", actual
        return "pass", ("Component updates on, auto-update checks on, relaunch forced after the configured "
                        "period and ChromeOS updates allowed."), actual

    return chrome_ou_verdict(data, _UPD_KEYS, judge, common=common, expected_value=expected, remediation=_UPD_REMED,
                             unknown_details=_unknown_details("One or more Chrome update policies"))
