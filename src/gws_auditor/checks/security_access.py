# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 4.2: Access and Data Control checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Access and data control checks.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
from ..models import CheckResult, Status


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
    _SAFE = ("RESTRICTED", "LIMITED", "BLOCKED")

    policies = data.get("policies", {})
    security = policies.get("security", {})

    # OU-aware path
    ou_values = get_ou_values(security, "unconfigured_third_party_apps")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            access = entry["value"].get("accessLevel", "")
            if access.upper() not in _SAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": access})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not restrict third-party app access: {ou_list}",
                actual_value=unsafe_ous, expected_value="RESTRICTED for all OUs",
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
        "Admin console > Security > API controls > App access control. "
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
                "Admin console > Security > API controls > App access control. "
                "Review the list of third-party apps that have been granted access "
                "to organizational data. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    # Check if the org has an app access control policy configured
    policies = data.get("policies", {})
    access_control = policies.get("access_control", {})
    app_access_policy = access_control.get("app_access_policy", "")

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
                "Admin console > Security > API controls > App access control. "
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
            "Admin console > Security > API controls > App access control. "
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
        "Admin console > Security > API controls. "
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
            expected_value=True,
        )

    if internal_apps_controlled is None:
        return make_manual(
            check_id="CIS-4.2.1.3",
            title="Ensure internal app API access is controlled",
            level="L2", source="CIS", section="Access Control",
            details="Could not determine internal app API access control settings.",
            remediation=(
                "Admin console > Security > API controls. "
                "Review and configure API access controls for internal applications. https://knowledge.workspace.google.com/admin/apps/control-which-third-party-and-internal-apps-access-google-workspace-data"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.1.3",
        title="Ensure internal app API access is controlled",
        level="L2", source="CIS", section="Access Control",
        details="Internal app API access is not properly controlled.",
        actual_value=internal_apps_controlled,
        expected_value=True,
        remediation=(
            "Admin console > Security > API controls. "
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
        "Admin console > Security > API controls > Domain-wide delegation. "
        "Review each service account and its authorized scopes. "
        "Remove unnecessary delegations and restrict scopes to minimum required. https://knowledge.workspace.google.com/admin/apps/control-api-access-with-domain-wide-delegation"
    ),
)
def check_domain_wide_delegation(data: dict) -> CheckResult:
    """Domain-wide delegation grants should be reviewed regularly."""
    _ID = "CIS-4.2.1.4"
    _TITLE = "Ensure domain-wide delegation is reviewed"
    _L, _S, _SEC = "L2", "CIS", "Access Control"
    _REMED = (
        "Admin console > Security > Access and data control > API controls > "
        "Domain-wide delegation. Review each service account and its authorized "
        "scopes. Remove unnecessary delegations and restrict scopes to minimum required. https://knowledge.workspace.google.com/admin/apps/control-api-access-with-domain-wide-delegation"
    )

    # Primary: check policy data
    policies = data.get("policies", {})
    security = policies.get("security", {})
    api_access = security.get("api_access", {})
    dwd_clients = api_access.get("domain_wide_delegation_clients", [])

    if isinstance(dwd_clients, list) and len(dwd_clients) > 0:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {len(dwd_clients)} service account(s) with domain-wide delegation. "
                "Manual review is required to ensure each delegation is necessary "
                "and scoped appropriately."
            ),
            remediation=_REMED,
        )

    # Fallback: detect DWD clients from AUTHORIZE_API_CLIENT_ACCESS admin log events
    admin_logs = data.get("admin_logs", [])
    dwd_client_ids: set[str] = set()
    for log in admin_logs:
        if log.get("event_name") == "AUTHORIZE_API_CLIENT_ACCESS":
            params = log.get("parameters", {})
            client_id = params.get("API_CLIENT_NAME", "")
            if client_id:
                dwd_client_ids.add(client_id)

    if dwd_client_ids:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                f"Found {len(dwd_client_ids)} service account(s) with domain-wide delegation "
                f"(detected from admin logs). Manual review is required to ensure each "
                f"delegation is necessary and scoped appropriately."
            ),
            actual_value={"delegation_count": len(dwd_client_ids)},
            expected_value="All delegations reviewed",
            remediation=_REMED,
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Could not determine domain-wide delegation status. "
            "Verify manually in Admin console > Security > Access and data control > "
            "API controls > Domain-wide delegation."
        ),
        remediation=_REMED,
    )


@check(
    check_id="CIS-4.2.2.1",
    title="Ensure geo-blocking is configured",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Context-aware access. "
        "Configure access levels to restrict sign-ins from "
        "countries where your organization does not operate. https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
    ),
    requires_license="enterprise_standard",
)
def check_geo_blocking(data: dict) -> CheckResult:
    """Context-aware access with geo-blocking should be configured."""
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
        return make_manual(
            check_id="CIS-4.2.2.1",
            title="Ensure geo-blocking is configured",
            level="L2", source="CIS", section="Access Control",
            details="Could not determine geo-blocking configuration.",
            remediation=(
                "Admin console > Security > Context-aware access. "
                "Configure access levels to restrict sign-ins from "
                "countries where your organization does not operate. https://knowledge.workspace.google.com/admin/security/about-context-aware-access"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.2.1",
        title="Ensure geo-blocking is configured",
        level="L2", source="CIS", section="Access Control",
        details="Geo-blocking is not configured or no regions are blocked.",
        actual_value={"enabled": geo_blocking, "blocked_count": len(blocked_regions)},
        expected_value="Geo-blocking enabled with regions configured",
        remediation=(
            "Admin console > Security > Context-aware access. "
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
        "Admin console > Security > Data protection > Manage rules. "
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
                    "Admin console > Security > Data protection > Manage rules. "
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
        return make_manual(
            check_id="CIS-4.2.3.1",
            title="Ensure DLP policies are configured for Drive",
            level="L1", source="CIS", section="Access Control",
            details="Could not determine DLP configuration for Drive.",
            remediation=(
                "Admin console > Security > Data protection > Manage rules. "
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
            "Admin console > Security > Data protection > Manage rules. "
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
        "Admin console > Security > Access and data control > "
        "Google Cloud session control. Enable 'Device Bound Session "
        "Credentials (DBSC)' to bind sessions to the device. https://knowledge.workspace.google.com/admin/security/prevent-cookie-theft-with-session-binding"
    ),
)
def check_session_control(data: dict) -> CheckResult:
    """Device Bound Session Credentials (DBSC) should be enabled."""
    _ID = "CIS-4.2.4.1"
    _TITLE = "Ensure Device Bound Session Credentials (DBSC) are enabled"
    _L, _S, _SEC = "L2", "CIS", "Access Control"
    _REMED = (
        "Admin console > Security > Access and data control > "
        "Google Cloud session control. Enable 'Device Bound Session "
        "Credentials (DBSC)' to bind sessions to the device. https://knowledge.workspace.google.com/admin/security/prevent-cookie-theft-with-session-binding"
    )

    chrome_policies = data.get("chrome_policies", {})
    dbsc_enabled = chrome_policies.get("dbsc_enabled", None)

    if dbsc_enabled is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Device Bound Session Credentials (DBSC) are enabled.",
            actual_value=True, expected_value=True,
        )

    if dbsc_enabled is False:
        return make_fail(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Device Bound Session Credentials (DBSC) are not enabled.",
            actual_value=False, expected_value=True,
            remediation=_REMED,
        )

    return make_review(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=(
            "Could not determine DBSC setting. Verify manually in "
            "Admin console > Security > Access and data control > "
            "Google Cloud session control."
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
    title="Ensure cloud session control is configured",
    level="L2",
    source="CIS",
    section="Access Control",
    remediation=(
        "Admin console > Security > Google Cloud session control. "
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
                "Admin console > Security > Google Cloud session control. "
                "Enable and configure reauthentication policy for Google Cloud. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
            ),
        )

    return make_fail(
        check_id="CIS-4.2.5.1",
        title="Ensure cloud session control is configured",
        level="L2", source="CIS", section="Access Control",
        details="Cloud session control is not enabled.",
        actual_value=cloud_control_enabled,
        expected_value=True,
        remediation=(
            "Admin console > Security > Google Cloud session control. "
            "Enable reauthentication policy and set an appropriate "
            "session duration for Google Cloud access. https://knowledge.workspace.google.com/admin/security/set-session-length-for-google-services"
        ),
    )
