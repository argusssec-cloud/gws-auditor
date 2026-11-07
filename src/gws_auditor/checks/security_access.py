# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 4.2: Access and Data Control checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Access and data control checks.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, drop_unspecified, format_ou_values_readable, is_admin_configured
from ..models import CheckResult, Status


# api_controls.unconfigured_third_party_apps: the Admin console labels the permissive option
# "(Default) Allow users to access any third-party apps"; the API has no enum member for it and
# returns the zero value ACCESS_LEVEL_UNSPECIFIED on the ADMIN policy (console-verified 2026-11-01).
_DEFAULT_ALLOW_LABEL = "ACCESS_LEVEL_UNSPECIFIED (console default: allow any third-party app)"


def _is_default_allow(entry: dict) -> bool:
    level = str(entry.get("value", {}).get("accessLevel", "")).upper()
    return level == "ACCESS_LEVEL_UNSPECIFIED" and is_admin_configured(entry)


@check(
    check_id="CIS-4.2.1.1",
    title="Ensure third-party app access is restricted",
    level="L1",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > API controls > "
        "Settings > Unconfigured third-party apps. "
        "Set to 'Don't allow users to access any third-party apps' or restrict "
        "to trusted applications. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_third_party_app_access(data: dict) -> CheckResult:
    """Third-party app access to Google Workspace data should be restricted."""
    _ID = "CIS-4.2.1.1"
    _TITLE = "Ensure third-party app access is restricted"
    _L, _S, _SEC = "L1", "CIS", "Access Control"
    _REMED = (
        "Admin console > Security > Access and data control > API controls > "
        "Settings > Unconfigured third-party apps. "
        "Set to 'Don't allow users to access any third-party apps' or restrict "
        "to trusted applications. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    )
    # Policy API enums (documented): BLOCK_ALL / ALLOW_SIGN_IN_ONLY; BLOCK_ALL_SCOPES and
    # ALLOW_SIGN_IN_SCOPES_ONLY were returned by older API versions; rest are legacy aliases.
    _SAFE = ("BLOCK_ALL", "BLOCK_ALL_SCOPES", "ALLOW_SIGN_IN_ONLY", "ALLOW_SIGN_IN_SCOPES_ONLY",
             "SIGN_IN_ONLY", "RESTRICTED", "LIMITED", "BLOCKED")

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "unconfigured_third_party_apps")
    if not ou_values:
        ou_values = get_ou_values(policies.get("api_controls", {}), "unconfigured_third_party_apps")
    # An ADMIN policy whose accessLevel is ACCESS_LEVEL_UNSPECIFIED is the console option
    # "(Default) Allow users to access any third-party apps" (verified against the Admin
    # console on 2026-11-01): the permissive state. A SYSTEM-only UNSPECIFIED stays unknown.
    default_allow = [e for e in ou_values if _is_default_allow(e)]
    ou_values = drop_unspecified(ou_values, "accessLevel")  # SYSTEM ACCESS_LEVEL_UNSPECIFIED = unknown
    if ou_values or default_allow:
        unsafe_ous = [{"org_unit": e["org_unit"], "value": _DEFAULT_ALLOW_LABEL} for e in default_allow]
        for entry in ou_values:
            access = entry["value"].get("accessLevel", "")
            if access.upper() not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": access})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not restrict third-party app access: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="RESTRICTED for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict third-party app access.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="RESTRICTED",
        )

    # Fallback: existing mapped value logic
    api_access = security.get("api_access", {})
    third_party_restricted = api_access.get("third_party_apps_restricted", None)
    trust_policy = api_access.get("trust_policy", "")

    if third_party_restricted is True or trust_policy in ("restricted", "limited"):
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Third-party app access is restricted.",
            actual_value={"restricted": third_party_restricted, "trust_policy": trust_policy},
            expected_value="restricted",
        )

    if third_party_restricted is None and not trust_policy:
        # Fallback: check admin logs for CHANGE_UNCONFIGURED_APPS_ACCESS
        # or BLOCK_ALL_THIRD_PARTY_API_ACCESS events.
        admin_logs = data.get("admin_logs", [])
        latest_time = ""
        latest_status = None
        for log in admin_logs:
            event_name = log.get("event_name", "")
            event_time = log.get("time", "")
            if event_name == "BLOCK_ALL_THIRD_PARTY_API_ACCESS":
                if event_time > latest_time:
                    latest_time = event_time
                    latest_status = True
            elif event_name == "UNBLOCK_ALL_THIRD_PARTY_API_ACCESS":
                if event_time > latest_time:
                    latest_time = event_time
                    latest_status = False
            elif event_name == "CHANGE_UNCONFIGURED_APPS_ACCESS":
                params = log.get("parameters", {})
                new_val = params.get("NEW_VALUE", "")
                if event_time > latest_time:
                    latest_time = event_time
                    latest_status = "don't allow" in new_val.lower()

        if latest_status is True:
            return make_pass(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="Third-party app access is blocked (detected from admin logs).",
                actual_value="blocked", expected_value="restricted",
            )
        if latest_status is False:
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details="Third-party app access is not restricted (detected from admin logs).",
                actual_value="allowed", expected_value="restricted",
                remediation=_REMED,
            )

        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine third-party app access settings. "
                "Verify manually in Admin console > Security > Access and data control > "
                "API controls > Settings > Unconfigured third-party apps."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Third-party app access is not properly restricted (policy: '{trust_policy}').",
        actual_value={"restricted": third_party_restricted, "trust_policy": trust_policy},
        expected_value="restricted",
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.2.1.2",
    title="Ensure third-party apps are reviewed",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > API controls > App access control. "
        "Configure an app access policy to restrict third-party app access. "
        "Trust only verified, necessary apps. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_third_party_app_review(data: dict) -> CheckResult:
    """Third-party OAuth app grants should be reviewed regularly."""
    token_logs = data.get("token_logs", [])

    # Collect unique app names from token grants
    oauth_apps = set()
    for log in token_logs:
        app_name = log.get("app_name", "") or log.get("client_id", "")
        if app_name:
            oauth_apps.add(app_name)

    if not token_logs:
        return make_manual(
            check_id="CIS-4.2.1.2",
            title="Ensure third-party apps are reviewed",
            level="L2", source="CIS", section="Access Control",
            details=(
                "No token/OAuth grant logs available to analyze. "
                "Manual review of authorized third-party apps is recommended."
            ),
            remediation=(
                "Admin console > Security > Access and data control > API controls > App access control. "
                "Review the list of third-party apps that have been granted access "
                "to organizational data. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    # Check if the org has an app access control policy configured
    policies = data.get("policies", {})
    access_control = policies.get("access_control", {})
    app_access_policy = access_control.get("app_access_policy", "")

    # The Policy API exposes this as api_controls.unconfigured_third_party_apps.accessLevel
    if not app_access_policy:
        ou_values = get_ou_values(policies.get("security", {}), "unconfigured_third_party_apps")
        if not ou_values:
            ou_values = get_ou_values(policies.get("api_controls", {}), "unconfigured_third_party_apps")
        reported = [e for e in ou_values if e["value"].get("accessLevel")]
        levels = [str(e["value"]["accessLevel"]) for e in drop_unspecified(reported, "accessLevel")]
        levels += ["ALLOW_ALL (console default)" for e in reported if _is_default_allow(e)]
        if levels:
            restricted = all(lv in ("BLOCK_ALL", "BLOCK_ALL_SCOPES") or "SIGN_IN" in lv for lv in levels)
            app_access_policy = "restricted" if restricted else "unrestricted"
        elif reported:
            # Only ACCESS_LEVEL_UNSPECIFIED came back: the configured policy is unknown, not absent
            return make_review(
                check_id="CIS-4.2.1.2",
                title="Ensure third-party apps are reviewed",
                level="L2", source="CIS", section="Access Control",
                details=(
                    f"Found {len(oauth_apps)} unique third-party app(s) with OAuth grants. The Policy API did not "
                    "report the unconfigured-apps access level (ACCESS_LEVEL_UNSPECIFIED) — verify the app access "
                    "policy in Admin console > Security > Access and data control > API controls."
                ),
                remediation=(
                    "Admin console > Security > Access and data control > API controls > App access control. "
                    "Review the list of third-party apps that have been granted access to organizational data."
                ),
            )

    # If no app access control policy is configured, this is a failure
    if not app_access_policy or app_access_policy.lower() in ("unrestricted", ""):
        return make_fail(
            check_id="CIS-4.2.1.2",
            title="Ensure third-party apps are reviewed",
            level="L2", source="CIS", section="Access Control",
            details=(
                f"Found {len(oauth_apps)} unique third-party app(s) with OAuth grants "
                "but no app access control policy is configured to restrict them."
            ),
            actual_value={"app_count": len(oauth_apps), "policy": app_access_policy or "none"},
            expected_value="App access control policy configured",
            remediation=(
                "Admin console > Security > Access and data control > API controls > App access control. "
                "Configure an app access policy to restrict third-party app access. "
                "Trust only verified, necessary apps. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_review(
        check_id="CIS-4.2.1.2",
        title="Ensure third-party apps are reviewed",
        level="L2", source="CIS", section="Access Control",
        details=(
            f"Found {len(oauth_apps)} unique third-party app(s) with OAuth grants. "
            f"App access policy is '{app_access_policy}'. "
            "Manual review is recommended to validate each app's access is appropriate."
        ),
        remediation=(
            "Admin console > Security > Access and data control > API controls > App access control. "
            "Review each authorized app and revoke access for unneeded applications. "
            "Establish a periodic review process for third-party app access. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )


@check(
    check_id="CIS-4.2.1.3",
    title="Ensure internal app API access is controlled",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > API controls. "
        "Configure API access controls for internal applications. "
        "Use OAuth client allowlisting. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
    ),
)
def check_internal_api_access(data: dict) -> CheckResult:
    """Internal app API access should be properly controlled."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    api_access = security.get("api_access", {})
    internal_apps_controlled = api_access.get("internal_apps_controlled", None)

    if internal_apps_controlled is True:
        return make_pass(
            check_id="CIS-4.2.1.3",
            title="Ensure internal app API access is controlled",
            level="L2", source="CIS", section="Access Control",
            details="Internal app API access is controlled.",
            actual_value=internal_apps_controlled,
            expected_value="Enabled for all OUs",
        )

    if internal_apps_controlled is None:
        return make_manual(
            check_id="CIS-4.2.1.3",
            title="Ensure internal app API access is controlled",
            level="L2", source="CIS", section="Access Control",
            details="Could not determine internal app API access control settings.",
            remediation=(
                "Admin console > Security > Access and data control > API controls. "
                "Review and configure API access controls for internal applications. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.1.3",
        title="Ensure internal app API access is controlled",
        level="L2", source="CIS", section="Access Control",
        details="Internal app API access is not properly controlled.",
        actual_value=internal_apps_controlled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Access and data control > API controls. "
            "Configure API access controls for internal applications. "
            "Use OAuth client allowlisting. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
        ),
    )



@check(
    check_id="CIS-4.2.1.4",
    title="Ensure domain-wide delegation is reviewed",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > API controls > Domain-wide delegation. "
        "Review each service account and its authorized scopes. "
        "Remove unnecessary delegations and restrict scopes to minimum required. https://knowledge.workspace.google.com/admin/apps/control-api-access-with-domain-wide-delegation"
    ),
)
def check_domain_wide_delegation(data: dict) -> CheckResult:
    """Domain-wide delegation grants should be reviewed regularly and follow least privilege.

    No API lists the authorized clients; the admin audit log records each grant
    (``AUTHORIZE_API_CLIENT_ACCESS``, whose ``API_CLIENT_NAME`` may hold several comma-separated
    client IDs) and revocation (``REMOVE_API_CLIENT_ACCESS``). Grants older than the log
    retention are invisible, so the check can establish WARN (a risky grant observed) but never
    PASS: a clean window is reported for review together with its start date.
    """
    _ID = "CIS-4.2.1.4"
    _TITLE = "Ensure domain-wide delegation is reviewed"
    _L, _S, _SEC = "L2", "CIS", "Access Control"
    _REMED = (
        "Admin console > Security > Access and data control > API controls > "
        "Domain-wide delegation. Review each service account and its authorized "
        "scopes. Remove unnecessary delegations and restrict scopes to minimum required. https://knowledge.workspace.google.com/admin/apps/control-api-access-with-domain-wide-delegation"
    )
    from .additional import _classify_scope_risk

    admin_logs = data.get("admin_logs", [])
    latest: dict[str, tuple[str, str, str]] = {}
    earliest = ""
    for log in admin_logs:
        when = str(log.get("time", ""))
        if when and (not earliest or when < earliest):
            earliest = when
        event = log.get("event_name")
        if event not in ("AUTHORIZE_API_CLIENT_ACCESS", "REMOVE_API_CLIENT_ACCESS"):
            continue
        params = log.get("parameters", {}) or {}
        for client_id in (c.strip() for c in str(params.get("API_CLIENT_NAME", "")).split(",") if c.strip()):
            if client_id not in latest or when >= latest[client_id][0]:
                latest[client_id] = (when, event, str(params.get("API_SCOPES", "")))
    window = f"since {earliest[:10]}" if earliest else "in the audit-log window"

    if not latest:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"No domain-wide delegation grant or revocation appears in the admin audit log {window}. "
                "No API lists the authorized clients, so verify the inventory in Admin console > Security > "
                "Access and data control > API controls > Domain-wide delegation."
            ),
            remediation=_REMED,
        )

    grants = {c: scopes for c, (_, event, scopes) in latest.items() if event == "AUTHORIZE_API_CLIENT_ACCESS"}
    allowlist = {str(c).strip() for c in (data.get("_options", {}) or {}).get("dwd_allowlist", []) or [] if str(c).strip()}

    # Delegated scopes apply to every user in the domain, so write access to mail, Drive
    # or the directory is org-wide impersonation. Read-only scopes are reported, not flagged.
    risky: dict[str, list[str]] = {}
    vetted: dict[str, list[str]] = {}
    for client_id, scopes in grants.items():
        for scope in (s.strip() for s in scopes.replace(" ", ",").split(",") if s.strip()):
            if scope.endswith(".readonly"):
                continue
            if _classify_scope_risk(scope) in ("CRITICAL", "HIGH"):
                (vetted if client_id in allowlist else risky).setdefault(client_id, []).append(scope.rsplit("/", 1)[-1])

    actual = {"delegation_count": len(grants), "high_risk_clients": len(risky),
              "allowlisted_clients": len(vetted), "window_start": earliest[:10]}
    if risky:
        summary = "; ".join(f"{c}: {', '.join(sorted(set(s))[:6])}" for c, s in sorted(risky.items()))
        return make_warn(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"{len(risky)} of {len(grants)} domain-wide delegation client(s) authorized {window} hold high-risk "
                f"write scopes that allow org-wide impersonation: {summary}. Vetted clients can be listed in "
                "options.dwd_allowlist."
            ),
            actual_value=actual,
            expected_value="Delegations limited to least-privilege scopes",
            remediation=_REMED,
        )
    vetted_note = (f"; {len(vetted)} client(s) with such scopes are vetted in options.dwd_allowlist" if vetted else "")
    # The audit log only shows grants changed inside its retention, so the inventory is never
    # known to be complete: "nothing risky observed" is a review item, not a PASS.
    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            f"{len(grants)} domain-wide delegation client(s) authorized {window} carry no org-wide write "
            f"scopes{vetted_note}. Grants older than the audit-log retention are not visible, so confirm the "
            "full list in Admin console > Security > Access and data control > API controls > Domain-wide delegation."
        ),
        actual_value=actual,
        expected_value="Delegations limited to least-privilege scopes",
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.2.2.1",
    scored=False,  # P3: Context-Aware Access policies are not exposed by the Policy API; MANUAL by design
    title="Ensure geo-blocking is configured",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > Context-Aware Access. "
        "Configure access levels to restrict sign-ins from "
        "countries where your organization does not operate. https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
    ),
    requires_license="enterprise_standard",
)
def check_geo_blocking(data: dict) -> CheckResult:
    """Context-aware access with geo-blocking should be configured."""
    _ID, _TITLE = "CIS-4.2.2.1", "Ensure geo-blocking is configured"
    _L, _S, _SEC = "L2", "CIS", "Access Control"
    _REMED = (
        "Admin console > Security > Access and data control > Context-Aware Access. "
        "Configure access levels to restrict sign-ins from "
        "countries where your organization does not operate. https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
    )
    _EXPECTED = "A geographic access level assigned to apps in Block mode"

    # Context-Aware Access is not in the Policy API. The admin audit log (180 days) records access
    # levels (CREATE/UPDATE/DELETE_ACCESS_LEVEL_V2 with the level's JSON state, seen live 2026-11-06)
    # and per-app assignments (CHANGE_CAA_APP_ASSIGNMENTS). A live level with a region condition that
    # is assigned in an active mode is geo-blocking in force. Levels created before the window are
    # invisible, so the absence of events is unknown (MANUAL), never FAIL.
    from .additional import (
        _CAA_BLOCKING_MODES, _access_level_restricts_region, _caa_app_assignment_evidence,
        _caa_assigned_level_titles, _caa_enforcement_events, caa_access_levels,
    )
    admin_logs = data.get("admin_logs", [])
    inventory, inventory_source = caa_access_levels(data)
    authoritative = inventory_source == "access_context_manager"
    evidence = _caa_app_assignment_evidence(admin_logs, [])
    toggle = evidence["toggle"]
    geo_levels = {name: lvl for name, lvl in inventory.items()
                  if not lvl["deleted"] and _access_level_restricts_region(lvl["state"])}
    geo_titles = {lvl["title"] for lvl in geo_levels.values()}
    # Active-mode evaluations in the CAA log name the levels actually applied; a geographic level
    # among them proves enforcement even when the assignment predates the admin-log window.
    evaluations = [e for e in _caa_enforcement_events(data.get("caa_events", [])) if e["applied"]]
    evaluated_geo = sorted({t for e in evaluations for t in e["applied"] if t in geo_titles})
    newest_eval = max((e["time"] for e in evaluations), default="")
    if toggle == "DISABLED" and not (evaluations and newest_eval > evidence["toggle_time"]):
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Context-Aware Access was turned off (latest admin-log change), so no geographic access level is enforced.",
            actual_value={"caa_enabled": toggle, "geo_access_levels": sorted(geo_titles)},
            expected_value=_EXPECTED, remediation=_REMED,
        )
    if evaluated_geo:
        apps = sorted({e["app"] for e in evaluations if e["app"] and set(e["applied"]) & geo_titles})
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Geographic access level(s) enforced per the Context-Aware Access log: "
                     f"{', '.join(evaluated_geo)} applied on {', '.join(apps[:8])}."),
            actual_value={"geo_access_levels": evaluated_geo, "evaluated_apps": apps},
            expected_value=_EXPECTED,
        )
    if geo_levels:
        assigned = _caa_assigned_level_titles(admin_logs)
        blocking_titles = set().union(*(assigned.get(mode, set()) for mode in _CAA_BLOCKING_MODES))
        enforced = sorted(t for t in geo_titles if t in blocking_titles)
        if enforced:
            return make_pass(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=(f"Geographic access level(s) ({inventory_source.replace('_', ' ')}) assigned to apps in "
                         f"Block mode per the admin log: {', '.join(enforced)}."),
                actual_value={"geo_access_levels": enforced, "assigned_modes": sorted(assigned),
                              "inventory_source": inventory_source},
                expected_value=_EXPECTED,
            )
        warned = sorted(t for t in geo_titles if t in assigned.get("WARN", set()))
        all_assigned = set().union(*assigned.values()) if assigned else set()
        monitored = sorted(l["title"] for l in geo_levels.values() if l["title"] in all_assigned)
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Geographic access level(s) exist per the admin log ({', '.join(sorted(l['title'] for l in geo_levels.values()))}) "
                     + ("but are assigned with the Warn action only, which warns users and still allows sign-in" if warned else
                        "but are assigned in monitor mode only" if monitored else
                        "but no Block-mode assignment to an app appears in the log window")
                     + ". Verify the assignment in Admin console > Security > Access and data control > Context-Aware Access."),
            actual_value={"geo_access_levels": sorted(l["title"] for l in geo_levels.values()),
                          "assigned_modes": sorted(assigned)},
            expected_value=_EXPECTED, remediation=_REMED,
        )

    if authoritative:
        # Every level of the organisation is known and none restricts regions: geo-blocking is not
        # configured, whatever the assignments.
        titles = sorted(l["title"] for l in inventory.values())
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=("Access Context Manager lists " + (f"{len(titles)} access level(s) ({', '.join(titles[:5])}), none of which "
                     "restricts regions" if titles else "no access level for the organisation") + ", so geo-blocking is not configured."),
            actual_value={"access_levels": titles, "geo_access_levels": [], "inventory_source": inventory_source},
            expected_value=_EXPECTED, remediation=_REMED,
        )
    if evaluations:
        # Levels are enforced but none of them is known to restrict regions (created before the
        # admin-log window, so their conditions are invisible). A human must look at the level.
        levels = sorted({t for e in evaluations for t in e["applied"]})
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(f"Context-Aware Access is enforcing access level(s) {', '.join(levels[:5])} (CAA log), but "
                     "their conditions are not in the admin-log window, so whether any restricts regions is "
                     "unknown. Check the level in Admin console > Security > Context-Aware Access > Access levels."),
            actual_value={"enforced_access_levels": levels, "geo_access_levels": []},
            expected_value=_EXPECTED, remediation=_REMED,
        )

    policies = data.get("policies", {})
    security = policies.get("security", {})
    context_aware = security.get("context_aware_access", {})
    geo_blocking = context_aware.get("geo_blocking_enabled", None)
    blocked_regions = context_aware.get("blocked_regions", [])

    if geo_blocking is True and len(blocked_regions) > 0:
        return make_pass(
            check_id="CIS-4.2.2.1",
            title="Ensure geo-blocking is configured",
            level="L2", source="CIS", section="Access Control",
            details=f"Geo-blocking is configured with {len(blocked_regions)} region(s) blocked.",
            actual_value={"enabled": True, "blocked_count": len(blocked_regions)},
            expected_value="Geo-blocking enabled with regions configured",
        )

    if geo_blocking is None:
        return make_review(
            check_id="CIS-4.2.2.1",
            title="Ensure geo-blocking is configured",
            level="L2", source="CIS", section="Access Control",
            details=(
                "Context-Aware Access policies are not exposed by the Cloud Identity Policy API and "
                "no access level with a geographic condition was created, updated or assigned within "
                "the admin audit-log window. Verify in Admin console > Security > Context-Aware Access."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id="CIS-4.2.2.1",
        title="Ensure geo-blocking is configured",
        level="L2", source="CIS", section="Access Control",
        details="Geo-blocking is not configured or no regions are blocked.",
        actual_value={"enabled": geo_blocking, "blocked_count": len(blocked_regions)},
        expected_value="Geo-blocking enabled with regions configured",
        remediation=(
            "Admin console > Security > Access and data control > Context-Aware Access. "
            "Configure access levels to restrict sign-ins from "
            "countries where your organization does not operate. https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
        ),
    )


@check(
    check_id="CIS-4.2.3.1",
    title="Ensure DLP policies are configured for Drive",
    level="L1",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > Data protection > Manage rules. "
        "Create DLP rules to detect sensitive data (PII, financial data, etc.) "
        "and prevent unauthorized sharing from Drive. https://knowledge.workspace.google.com/admin/security/create-dlp-for-drive-rules-and-custom-content-detectors"
    ),
    requires_license="enterprise_standard",
)
def check_drive_dlp(data: dict) -> CheckResult:
    """Data Loss Prevention policies should be configured for Google Drive."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    dlp = security.get("dlp", {})
    drive_dlp_enabled = dlp.get("drive_dlp_enabled", None)
    rule_count = dlp.get("drive_rule_count", 0)

    if drive_dlp_enabled is True and rule_count > 0:
        # Also check if rules have conditions/triggers configured
        drive_rules = dlp.get("drive_rules", [])
        unconfigured_rules = []
        if drive_rules:
            for rule in drive_rules:
                conditions = rule.get("conditions", [])
                triggers = rule.get("triggers", [])
                if not conditions and not triggers:
                    unconfigured_rules.append(rule.get("name", "unnamed"))

        if unconfigured_rules:
            return make_warn(
                check_id="CIS-4.2.3.1",
                title="Ensure DLP policies are configured for Drive",
                level="L1", source="CIS", section="Access Control",
                details=(
                    f"DLP is enabled with {rule_count} rule(s), but "
                    f"{len(unconfigured_rules)} rule(s) lack conditions/triggers: "
                    f"{', '.join(unconfigured_rules[:5])}"
                ),
                actual_value={"enabled": True, "rule_count": rule_count, "unconfigured": len(unconfigured_rules)},
                expected_value="DLP enabled with properly configured rules",
                remediation=(
                    "Admin console > Security > Access and data control > Data protection > Manage rules. "
                    "Review each DLP rule and ensure conditions and triggers are configured. https://knowledge.workspace.google.com/admin/security/create-dlp-for-drive-rules-and-custom-content-detectors"
                ),
            )

        return make_pass(
            check_id="CIS-4.2.3.1",
            title="Ensure DLP policies are configured for Drive",
            level="L1", source="CIS", section="Access Control",
            details=f"DLP is enabled for Drive with {rule_count} rule(s) configured.",
            actual_value={"enabled": True, "rule_count": rule_count},
            expected_value="DLP enabled with rules configured",
        )

    if drive_dlp_enabled is None:
        return make_review(
            check_id="CIS-4.2.3.1",
            title="Ensure DLP policies are configured for Drive",
            level="L1", source="CIS", section="Access Control",
            details=(
                "DLP rules are not exposed by the Cloud Identity Policy API — "
                "verify Drive DLP coverage in Admin console."
            ),
            remediation=(
                "Admin console > Security > Access and data control > Data protection > Manage rules. "
                "Create DLP rules to detect and protect sensitive data in Drive. https://knowledge.workspace.google.com/admin/security/create-dlp-for-drive-rules-and-custom-content-detectors"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.3.1",
        title="Ensure DLP policies are configured for Drive",
        level="L1", source="CIS", section="Access Control",
        details="DLP policies are not configured for Drive.",
        actual_value={"enabled": drive_dlp_enabled, "rule_count": rule_count},
        expected_value="DLP enabled with rules configured",
        remediation=(
            "Admin console > Security > Access and data control > Data protection > Manage rules. "
            "Create DLP rules to detect sensitive data (PII, financial data, etc.) "
            "and prevent unauthorized sharing from Drive. https://knowledge.workspace.google.com/admin/security/create-dlp-for-drive-rules-and-custom-content-detectors"
        ),
    )


@check(
    check_id="CIS-4.2.4.1",
    title="Ensure Device Bound Session Credentials (DBSC) are enabled",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Devices > Chrome > Settings > User & browser settings > Security > "
        "Device Bound Session Credentials. Enable \'Device Bound Session "
        "Credentials (DBSC)' to bind sessions to the device. https://knowledge.workspace.google.com/admin/security/prevent-cookie-theft-with-session-binding"
    ),
)
def check_session_control(data: dict) -> CheckResult:
    """Device Bound Session Credentials (DBSC) should be enabled."""
    _ID = "CIS-4.2.4.1"
    _TITLE = "Ensure Device Bound Session Credentials (DBSC) are enabled"
    _L, _S, _SEC = "L2", "CIS", "Access Control"
    _REMED = (
        "Admin console > Devices > Chrome > Settings > User & browser settings > Security > "
        "Device Bound Session Credentials. Enable \'Device Bound Session "
        "Credentials (DBSC)' to bind sessions to the device. https://knowledge.workspace.google.com/admin/security/prevent-cookie-theft-with-session-binding"
    )

    chrome_policies = data.get("chrome_policies", {})
    dbsc_enabled = chrome_policies.get("dbsc_enabled", None)

    if dbsc_enabled is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Device Bound Session Credentials (DBSC) are enabled.",
            actual_value=True, expected_value="Enabled for all OUs",
        )

    if dbsc_enabled is False:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Device Bound Session Credentials (DBSC) are not enabled.",
            actual_value=False, expected_value="Enabled for all OUs",
            remediation=_REMED,
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Could not determine DBSC setting. Verify manually in "
            "Admin console > Devices > Chrome > Settings > User & browser settings > Security > "
            "Device Bound Session Credentials."
        ),
        remediation=_REMED,
    )


def _parse_session_duration_hours(duration) -> float | None:
    """Parse a session duration value into hours.

    Handles:
    - int/float: assumed to be in seconds
    - str like "28800s": seconds with suffix
    - str like "8h": hours with suffix
    - None: returns None
    """
    if duration is None:
        return None
    if isinstance(duration, (int, float)):
        return duration / 3600
    if isinstance(duration, str):
        duration = duration.strip()
        if duration.endswith("s"):
            try:
                return float(duration[:-1]) / 3600
            except ValueError:
                return None
        if duration.endswith("h"):
            try:
                return float(duration[:-1])
            except ValueError:
                return None
        try:
            return float(duration) / 3600
        except ValueError:
            return None
    return None


@check(
    check_id="CIS-4.2.5.1",
    scored=False,  # P3: Google Cloud session control is not exposed by the Policy API; MANUAL by design
    title="Ensure cloud session control is configured",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Access and data control > Google Cloud session control. "
        "Enable reauthentication policy and set an appropriate "
        "session duration for Google Cloud access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
    ),
    requires_license="enterprise_plus",
)
def check_cloud_session_control(data: dict) -> CheckResult:
    """Google Cloud session control should be configured for GCP access."""
    policies = data.get("policies", {})
    security = policies.get("security", {})
    session = security.get("session_management", {})
    cloud_session = session.get("cloud_session_duration_hours", None)
    cloud_control_enabled = session.get("cloud_session_control_enabled", None)

    if cloud_control_enabled is True:
        details = "Cloud session control is enabled"
        if cloud_session is not None:
            details += f" with duration set to {cloud_session} hours"
        details += "."
        return make_pass(
            check_id="CIS-4.2.5.1",
            title="Ensure cloud session control is configured",
            level="L2", source="CIS", section="Access Control",
            details=details,
            actual_value={
                "enabled": cloud_control_enabled,
                "duration_hours": cloud_session,
            },
            expected_value="Cloud session control enabled",
        )

    if cloud_control_enabled is None:
        return make_manual(
            check_id="CIS-4.2.5.1",
            title="Ensure cloud session control is configured",
            level="L2", source="CIS", section="Access Control",
            details="Could not determine cloud session control setting.",
            remediation=(
                "Admin console > Security > Access and data control > Google Cloud session control. "
                "Enable and configure reauthentication policy for Google Cloud. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.5.1",
        title="Ensure cloud session control is configured",
        level="L2", source="CIS", section="Access Control",
        details="Cloud session control is not enabled.",
        actual_value=cloud_control_enabled,
        expected_value="Enabled for all OUs",
        remediation=(
            "Admin console > Security > Access and data control > Google Cloud session control. "
            "Enable reauthentication policy and set an appropriate "
            "session duration for Google Cloud access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
        ),
    )
