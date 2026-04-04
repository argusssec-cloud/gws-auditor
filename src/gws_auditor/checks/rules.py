# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 6: Alert Rules checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Alert rule configuration checks.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review
from ..models import CheckResult, Status


# Google system-defined alert rules and their default active status.
# These are built-in rules visible in Admin console > Security > Rules.
# The names list contains lowercase variants used for flexible matching.
SYSTEM_DEFINED_ALERTS: dict[str, dict] = {
    "password_change": {
        "names": ["password changed", "user's password changed",
                  "user password changed", "password change"],
        "default_active": False,
    },
    "government_backed": {
        "names": ["government-backed attacks", "government backed attacks",
                  "government-backed attack", "government backed"],
        "default_active": True,
    },
    "suspicious_activity": {
        "names": ["suspicious activity", "user suspended due to suspicious",
                  "suspicious device activity"],
        "default_active": True,
    },
    "admin_privilege": {
        "names": ["admin privilege", "user granted admin privilege",
                  "admin privilege granted"],
        "default_active": False,
    },
    "suspicious_programmatic_login": {
        "names": ["suspicious programmatic login"],
        "default_active": True,
    },
    "suspicious_login": {
        "names": ["suspicious login", "suspicious sign-in"],
        "default_active": True,
    },
    "leaked_password": {
        "names": ["leaked password", "password has been leaked",
                  "compromised credentials"],
        "default_active": True,
    },
    "employee_spoofing": {
        "names": ["employee spoofing", "potential employee spoofing",
                  "gmail potential employee spoofing"],
        "default_active": True,
    },
}


def _check_alert_rule(data: dict, rule_keyword: str, rule_display: str) -> bool | None:
    """Check if an alert rule matching the keyword is configured.

    Checks multiple data sources for evidence that the alert rule is active:
    1. ``data["admin_logs"]`` — ``SYSTEM_DEFINED_RULE_UPDATED`` events from
       the Admin SDK Reports API.  The most recent event for a matching rule
       name determines its current ON/OFF status.
    2. ``data["alert_center_rules"]`` — rules collected from the Alert Center
       API, each with ``name`` and ``enabled`` fields.
    3. ``data["policies"]["security"]["alert_rules"]`` — policy-based rules.
    4. Known Google system-defined alerts — these are active by default in
       most Google Workspace editions and are treated as active unless
       there is evidence they have been explicitly disabled.

    Returns True if the rule is active, False if explicitly disabled,
    or None if the status cannot be determined.
    """
    admin_logs = data.get("admin_logs", [])
    policies = data.get("policies", {})
    alert_rules = policies.get("security", {}).get("alert_rules", [])

    # Build keyword variants for flexible matching
    system_alert = SYSTEM_DEFINED_ALERTS.get(rule_keyword)
    match_names = list(system_alert["names"]) if system_alert else []
    kw = rule_keyword.lower()
    match_names.extend([kw, kw.replace("_", " "), kw.replace("_", "-")])

    # 1. Check SYSTEM_DEFINED_RULE_UPDATED events in admin logs.
    #    These record ON/OFF toggles for system-defined alert rules.
    #    Take the most recent event per rule to determine current state.
    latest_event: dict | None = None
    latest_time = ""
    for log in admin_logs:
        if log.get("event_name") != "SYSTEM_DEFINED_RULE_UPDATED":
            continue
        params = log.get("parameters", {})
        if not isinstance(params, dict):
            continue
        rule_name = params.get("SYSTEM_DEFINED_RULE_NAME", "").lower()
        if any(n in rule_name for n in match_names):
            event_time = log.get("time", "")
            if event_time > latest_time:
                latest_time = event_time
                latest_event = params

    if latest_event:
        status_change = latest_event.get(
            "SYSTEM_DEFINED_RULE_ACTION_STATUS_CHANGE", ""
        )
        if "to ON" in status_change:
            return True
        if "to OFF" in status_change:
            return False

    # 2. Check alert_center_rules (populated by provider if API is available)
    for rule in data.get("alert_center_rules", []):
        rule_name = rule.get("name", "").lower()
        enabled = rule.get("enabled", rule.get("status", "") == "active")
        if enabled and any(n in rule_name for n in match_names):
            return True

    # 3. Check policies for alert rule definitions
    for rule in alert_rules:
        rule_name = rule.get("name", "").lower()
        rule_type = rule.get("type", "").lower()
        if any(n in rule_name or n in rule_type for n in match_names):
            return True

    # 4. Check known system-defined alerts from Google
    if system_alert and system_alert["default_active"]:
        # Active by default with no log evidence of being disabled
        return True

    # No evidence found — cannot determine
    return None


def _make_alert_result(data: dict, check_id: str, title: str,
                       rule_keyword: str, rule_display: str) -> CheckResult:
    """Run the alert rule check and return the appropriate result."""
    _L, _S, _SEC = "L1", "CIS", "Alert Rules"
    _REMED = (
        "Admin console > Security > Alert center > Manage rules. "
        f"Enable the alert rule for {rule_display} events."
    )
    found = _check_alert_rule(data, rule_keyword, rule_display)

    if found is True:
        return make_pass(
            check_id=check_id, title=title, level=_L, source=_S, section=_SEC,
            details=f"Alert rule for {rule_display} is configured and enabled.",
            actual_value=True, expected_value=True,
        )
    if found is False:
        return make_fail(
            check_id=check_id, title=title, level=_L, source=_S, section=_SEC,
            details=f"Alert rule for {rule_display} is disabled.",
            actual_value=False, expected_value=True, remediation=_REMED,
        )
    return make_review(
        check_id=check_id, title=title, level=_L, source=_S, section=_SEC,
        details=(
            f"Could not determine alert rule status for {rule_display}. "
            "Verify manually in Admin console > Security > Alert center > Manage rules."
        ),
        remediation=_REMED,
    )


@check(
    check_id="CIS-6.1",
    title="Ensure alert for user password change is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Create an alert rule to notify on user password change events. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_password_change(data: dict) -> CheckResult:
    """An alert rule should be configured for user password changes."""
    return _make_alert_result(data, "CIS-6.1",
        "Ensure alert for user password change is configured",
        "password_change", "user password change")


@check(
    check_id="CIS-6.2",
    title="Ensure alert for government-backed attacks is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Ensure the 'Government-backed attack' alert is enabled. "
        "This is a system alert that should be active by default. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_government_attacks(data: dict) -> CheckResult:
    """An alert should be configured for government-backed attack warnings."""
    return _make_alert_result(data, "CIS-6.2",
        "Ensure alert for government-backed attacks is configured",
        "government_backed", "government-backed attacks")


@check(
    check_id="CIS-6.3",
    title="Ensure alert for suspicious activity is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Create or enable an alert rule for suspicious user activity detection. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_suspicious_activity(data: dict) -> CheckResult:
    """An alert should be configured for suspicious user activity."""
    return _make_alert_result(data, "CIS-6.3",
        "Ensure alert for suspicious activity is configured",
        "suspicious_activity", "suspicious activity")


@check(
    check_id="CIS-6.4",
    title="Ensure alert for admin privilege grant is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Create an alert rule to notify when admin privileges are "
        "granted to any user account. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_admin_privilege(data: dict) -> CheckResult:
    """An alert should be configured when admin privileges are granted."""
    return _make_alert_result(data, "CIS-6.4",
        "Ensure alert for admin privilege grant is configured",
        "admin_privilege", "admin privilege grant")


@check(
    check_id="CIS-6.5",
    title="Ensure alert for suspicious programmatic login is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Enable the 'Suspicious programmatic login' system alert. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_suspicious_programmatic_login(data: dict) -> CheckResult:
    """An alert should be configured for suspicious programmatic logins."""
    return _make_alert_result(data, "CIS-6.5",
        "Ensure alert for suspicious programmatic login is configured",
        "suspicious_programmatic_login", "suspicious programmatic login")


@check(
    check_id="CIS-6.6",
    title="Ensure alert for suspicious login is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Enable the 'Suspicious login' system alert to detect "
        "unusual sign-in patterns. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_suspicious_login(data: dict) -> CheckResult:
    """An alert should be configured for suspicious login attempts."""
    return _make_alert_result(data, "CIS-6.6",
        "Ensure alert for suspicious login is configured",
        "suspicious_login", "suspicious login")


@check(
    check_id="CIS-6.7",
    title="Ensure alert for leaked password is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Enable the 'User's password has been leaked' system alert "
        "to detect when credentials appear in known breaches. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_leaked_password(data: dict) -> CheckResult:
    """An alert should be configured for leaked/compromised passwords."""
    return _make_alert_result(data, "CIS-6.7",
        "Ensure alert for leaked password is configured",
        "leaked_password", "leaked password")


@check(
    check_id="CIS-6.8",
    title="Ensure alert for employee spoofing is configured",
    level="L1",
    source="CIS",
    section="Alert Rules",
    remediation=(
        "Admin console > Security > Alert center > Manage rules. "
        "Create a custom alert rule for employee name spoofing "
        "or enable the related Gmail safety alert. https://knowledge.workspace.google.com/admin/security/use-rules-to-turn-alerts-on-or-off"
    ),
)
def check_alert_employee_spoofing(data: dict) -> CheckResult:
    """An alert should be configured for employee name spoofing attempts."""
    return _make_alert_result(data, "CIS-6.8",
        "Ensure alert for employee spoofing is configured",
        "employee_spoofing", "employee spoofing")
