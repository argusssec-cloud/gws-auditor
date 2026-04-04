# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Inventory page -- dedicated tabs for the inventory checks (ADD-28..ADD-35)."""

from __future__ import annotations

import dash
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from dash import Input, Output, callback, dcc, html

from gws_auditor.dashboard.components import (
    create_inventory_status_banner,
    create_inventory_table,
    create_metric_card,
    create_remediation_alert,
    extract_inventory_data,
)
from gws_auditor.dashboard.theme import METRIC_COLORS, PLOTLY_TEMPLATE

dash.register_page(__name__, path="/inventory", name="Inventory")

# ------------------------------------------------------------------
# Tab metadata (order matters)
# ------------------------------------------------------------------

_TABS = [
    ("ADD-28", "Stale Groups"),
    ("ADD-29", "Inactive Spaces"),
    ("ADD-30", "Stale Mobile"),
    ("ADD-31", "Stale ChromeOS"),
    ("ADD-32", "2SV Enrollment"),
    ("ADD-33", "OAuth Risk"),
    ("ADD-34", "App Passwords"),
    ("ADD-35", "Shared Drives"),
]

# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

layout = html.Div(
    [
        html.H4("Inventory", className="page-header"),
        html.P(
            "These checks provide asset and posture inventory data. "
            "They are separated from the audit checks and do not "
            "affect compliance pass rates.",
            className="text-muted mb-3",
            style={"fontSize": "0.9rem"},
        ),
        html.Div(id="inventory-content"),
    ],
)


# ------------------------------------------------------------------
# Callback
# ------------------------------------------------------------------


@callback(
    Output("inventory-content", "children"),
    Input("report-data", "data"),
)
def update_inventory(report_data):
    inventory = extract_inventory_data(report_data)
    if not inventory:
        return dbc.Alert("No inventory data available. Select a report.", color="secondary")

    tabs = []
    for check_id, label in _TABS:
        data = inventory.get(check_id)
        if not data:
            continue
        # Add warning indicator to tab label when status is WARN or FAIL
        status = data.get("status", "")
        tab_label = f"{label} (!)" if status in ("WARN", "FAIL") else label

        tabs.append(
            dbc.Tab(
                html.Div(
                    _render_check_tab(check_id, data),
                    className="inventory-tab-content pt-3",
                ),
                label=tab_label,
                tab_id=f"tab-{check_id}",
            ),
        )

    if not tabs:
        return dbc.Alert("No inventory checks found in this report.", color="secondary")

    return dbc.Tabs(tabs, className="mb-3")


# ------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------

_RENDERERS: dict[str, object] = {}


def _render_check_tab(check_id: str, data: dict) -> list:
    renderer = {
        "ADD-28": _render_groups,
        "ADD-29": _render_chat_spaces,
        "ADD-30": _render_mobile_devices,
        "ADD-31": _render_chromeos_devices,
        "ADD-32": _render_2sv_enrollment,
        "ADD-33": _render_oauth_risk,
        "ADD-34": _render_app_passwords,
        "ADD-35": _render_shared_drives,
    }.get(check_id)
    if renderer is None:
        return [html.P("No renderer available for this check.")]
    return renderer(data)


# ------------------------------------------------------------------
# ADD-28: Stale Groups
# ------------------------------------------------------------------


def _render_groups(data: dict) -> list:
    raw = data.get("raw_data", {})
    empty = raw.get("empty_groups", [])
    inactive = raw.get("all_inactive_groups", [])
    total = raw.get("total_analyzed", 0)

    children: list = [
        html.H5("Stale Groups"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Groups", total, METRIC_COLORS["total"]),
                create_metric_card("Empty Groups", len(empty), "#d69e2e" if empty else "#38a169"),
                create_metric_card("All-Inactive", len(inactive), "#d69e2e" if inactive else "#38a169"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if empty:
        children.append(html.H6("Empty Groups", className="mt-3"))
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "#", "id": "idx"},
                    {"name": "Group Email", "id": "email"},
                ],
                data=[{"idx": i + 1, "email": e} for i, e in enumerate(empty)],
                table_id="inv-empty-groups-table",
            ),
        )

    if inactive:
        children.append(html.H6("Groups With Only Inactive Members", className="mt-3"))
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "#", "id": "idx"},
                    {"name": "Group Email", "id": "email"},
                ],
                data=[{"idx": i + 1, "email": e} for i, e in enumerate(inactive)],
                table_id="inv-inactive-groups-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-29: Inactive Chat Spaces
# ------------------------------------------------------------------


def _render_chat_spaces(data: dict) -> list:
    raw = data.get("raw_data", {})
    spaces = raw.get("inactive_spaces", [])
    total = raw.get("total_spaces", 0)
    threshold = raw.get("threshold_days", 90)

    children: list = [
        html.H5("Inactive Chat Spaces"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Spaces", total, METRIC_COLORS["total"]),
                create_metric_card("Inactive", len(spaces), "#d69e2e" if spaces else "#38a169"),
                create_metric_card("Threshold", f"{threshold}d", "#718096"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if spaces:
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "Space Name", "id": "name"},
                    {"name": "Space ID", "id": "space_id"},
                    {"name": "Last Active", "id": "last_active"},
                ],
                data=spaces,
                table_id="inv-chat-spaces-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-30: Stale Mobile Devices
# ------------------------------------------------------------------


def _render_mobile_devices(data: dict) -> list:
    raw = data.get("raw_data", {})
    stale = raw.get("stale_devices", [])
    total = raw.get("total_devices", 0)
    threshold = raw.get("threshold_days", 90)

    children: list = [
        html.H5("Stale Mobile Devices"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Devices", total, METRIC_COLORS["total"]),
                create_metric_card("Stale", len(stale), "#d69e2e" if stale else "#38a169"),
                create_metric_card("Threshold", f"{threshold}d", "#718096"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if stale:
        table_data = []
        for dev in stale:
            user = dev.get("user", "")
            if isinstance(user, list):
                user = ", ".join(str(u) for u in user)
            table_data.append({
                "model": dev.get("model", ""),
                "user": user,
                "last_sync": dev.get("last_sync", ""),
                "status": dev.get("status", ""),
            })
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "Model", "id": "model"},
                    {"name": "User", "id": "user"},
                    {"name": "Last Sync", "id": "last_sync"},
                    {"name": "Status", "id": "status"},
                ],
                data=table_data,
                table_id="inv-mobile-devices-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-31: Stale ChromeOS Devices
# ------------------------------------------------------------------


def _render_chromeos_devices(data: dict) -> list:
    raw = data.get("raw_data", {})
    stale = raw.get("stale_devices", [])
    total = raw.get("total_devices", 0)
    threshold = raw.get("threshold_days", 90)

    children: list = [
        html.H5("Stale ChromeOS Devices"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Devices", total, METRIC_COLORS["total"]),
                create_metric_card("Stale", len(stale), "#d69e2e" if stale else "#38a169"),
                create_metric_card("Threshold", f"{threshold}d", "#718096"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if stale:
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "Model", "id": "model"},
                    {"name": "User", "id": "user"},
                    {"name": "Serial", "id": "serial"},
                    {"name": "Last Sync", "id": "last_sync"},
                    {"name": "Status", "id": "status"},
                ],
                data=stale,
                table_id="inv-chromeos-devices-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-32: 2SV Enrollment
# ------------------------------------------------------------------


def _render_2sv_enrollment(data: dict) -> list:
    raw = data.get("raw_data", {})
    summary = raw.get("summary", {})
    per_ou = raw.get("per_ou", [])

    total_users = summary.get("total_users", 0)
    enrolled = summary.get("enrolled", 0)
    not_enrolled = summary.get("not_enrolled", 0)
    rate = summary.get("enrollment_rate", "0%")

    children: list = [
        html.H5("2-Step Verification Enrollment"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Users", total_users, METRIC_COLORS["total"]),
                create_metric_card("Enrolled", enrolled, "#38a169"),
                create_metric_card("Not Enrolled", not_enrolled, "#e53e3e" if not_enrolled else "#38a169"),
                create_metric_card("Enrollment Rate", rate, "#2b6cb0"),
            ],
            className="g-3 mb-4",
        ),
    ]

    # Donut chart: unenrolled users by OU
    ou_unenrolled = [
        (ou.get("org_unit", "/"), ou.get("not_enrolled", 0))
        for ou in per_ou
        if ou.get("not_enrolled", 0) > 0
    ]
    if ou_unenrolled:
        labels, values = zip(*ou_unenrolled)
        fig = go.Figure(
            go.Pie(
                labels=list(labels),
                values=list(values),
                hole=0.5,
                textinfo="label+value",
                hovertemplate="%{label}: %{value} unenrolled (%{percent})<extra></extra>",
            ),
        )
        fig.update_layout(
            title="Unenrolled Users by Org Unit",
            template=PLOTLY_TEMPLATE,
            showlegend=True,
        )
        children.append(
            dbc.Card(
                dbc.CardBody(dcc.Graph(figure=fig)),
                className="chart-card mb-3",
            ),
        )

    # Per-OU table
    if per_ou:
        table_data = []
        for ou in per_ou:
            users_list = ou.get("users_without_2sv", [])
            if len(users_list) > 5:
                display = ", ".join(users_list[:5]) + f" +{len(users_list) - 5} more"
            elif users_list:
                display = ", ".join(users_list)
            else:
                display = "All enrolled"
            table_data.append({
                "org_unit": ou.get("org_unit", "/"),
                "total": ou.get("total", 0),
                "enrolled": ou.get("enrolled", 0),
                "not_enrolled": ou.get("not_enrolled", 0),
                "rate": ou.get("enrollment_rate", "0%"),
                "unenrolled_users": display,
            })
        children.append(html.H6("Per-OU Breakdown", className="mt-3"))
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "Org Unit", "id": "org_unit"},
                    {"name": "Total", "id": "total"},
                    {"name": "Enrolled", "id": "enrolled"},
                    {"name": "Not Enrolled", "id": "not_enrolled"},
                    {"name": "Rate", "id": "rate"},
                    {"name": "Unenrolled Users", "id": "unenrolled_users"},
                ],
                data=table_data,
                table_id="inv-2sv-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-33: OAuth Risk
# ------------------------------------------------------------------

_SCOPE_CATEGORIES = [
    ("gmail", "Full Gmail Access", "mail.google.com"),
    ("gmail_modify", "Gmail Modify Access", "gmail.modify"),
    ("drive", "Full Drive Access", "/auth/drive"),
    ("admin", "Admin Directory Access", "admin.directory"),
    ("cloud", "Cloud Platform Access", "cloud-platform"),
    ("calendar", "Calendar Access", "/auth/calendar"),
    ("contacts", "Contacts Access", "/auth/contacts"),
    ("other", "Other Dangerous Scopes", None),
]

_SCOPE_CATEGORY_DESCRIPTIONS = {
    "gmail": "Apps that can read, send, and delete ALL emails.",
    "gmail_modify": "Apps that can modify, label, and delete emails.",
    "drive": "Apps with access to ALL files in Drive.",
    "admin": "Apps that can read/modify user accounts, groups, and OUs.",
    "cloud": "Apps with full access to Google Cloud resources.",
    "calendar": "Apps that can read, create, and delete calendar events.",
    "contacts": "Apps with full access to the user's contacts.",
    "other": "Apps with other dangerous scope grants.",
}

_RISK_SORT_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}

_RISK_BADGE_COLORS = {
    "CRITICAL": "danger",
    "HIGH": "warning",
    "MEDIUM": "info",
}


def _categorize_app(scopes: list[str]) -> str:
    """Return the first matching scope category key for an app's scopes."""
    for key, _label, pattern in _SCOPE_CATEGORIES:
        if pattern is None:
            continue
        for scope in scopes:
            if pattern in scope:
                return key
    return "other"


def _render_oauth_risk(data: dict) -> list:
    raw = data.get("raw_data", {})
    dangerous_apps = raw.get("dangerous_apps", {})
    total_grants = raw.get("total_grants", 0)

    app_list = list(dangerous_apps.values()) if isinstance(dangerous_apps, dict) else []

    # Risk counts
    critical = sum(1 for a in app_list if a.get("risk_level") == "CRITICAL")
    high = sum(1 for a in app_list if a.get("risk_level") == "HIGH")

    # Category counts for Gmail/Drive metrics
    gmail_full = sum(
        1 for a in app_list
        if any("mail.google.com" in s for s in a.get("dangerous_scopes", []))
    )
    drive_full = sum(
        1 for a in app_list
        if any("/auth/drive" in s for s in a.get("dangerous_scopes", []))
    )

    children: list = [
        html.H5("OAuth Risk Analysis"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Grants", total_grants, METRIC_COLORS["total"]),
                create_metric_card("Dangerous Apps", len(app_list), "#e53e3e" if app_list else "#38a169"),
                create_metric_card("Critical", critical, "#e53e3e" if critical else "#38a169"),
                create_metric_card("High", high, "#d69e2e" if high else "#38a169"),
                create_metric_card("Full Gmail", gmail_full, "#e53e3e" if gmail_full else "#38a169"),
                create_metric_card("Full Drive", drive_full, "#e53e3e" if drive_full else "#38a169"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if not app_list:
        children.append(create_remediation_alert(data.get("remediation", "")))
        return children

    # Categorize apps
    categorized: dict[str, list[dict]] = {key: [] for key, _, _ in _SCOPE_CATEGORIES}
    for app in app_list:
        cat = _categorize_app(app.get("dangerous_scopes", []))
        categorized[cat].append(app)

    # Risk Distribution table
    risk_rows = []
    for key, label, _pattern in _SCOPE_CATEGORIES:
        cat_apps = categorized[key]
        if not cat_apps:
            continue
        max_risk = "MEDIUM"
        for a in cat_apps:
            rl = a.get("risk_level", "MEDIUM")
            if _RISK_SORT_ORDER.get(rl, 2) < _RISK_SORT_ORDER.get(max_risk, 2):
                max_risk = rl
        risk_rows.append(
            html.Tr([
                html.Td(dbc.Badge(max_risk, color=_RISK_BADGE_COLORS.get(max_risk, "secondary"), className=f"oauth-risk-{max_risk.lower()}")),
                html.Td(label),
                html.Td(html.Strong(str(len(cat_apps)))),
                html.Td(_SCOPE_CATEGORY_DESCRIPTIONS.get(key, "")),
            ]),
        )

    if risk_rows:
        children.append(html.H6("Risk Distribution", className="mt-3"))
        children.append(
            dbc.Table(
                [
                    html.Thead(html.Tr([
                        html.Th("Risk"), html.Th("Category"),
                        html.Th("Count"), html.Th("Description"),
                    ])),
                    html.Tbody(risk_rows),
                ],
                bordered=True,
                hover=True,
                size="sm",
                className="mb-4",
            ),
        )

    # Flattened DataTable of all dangerous apps
    scope_prefix = "https://www.googleapis.com/auth/"
    table_rows = []
    for app in app_list:
        scopes_raw = app.get("dangerous_scopes", [])
        scopes_short = ", ".join(
            s.replace(scope_prefix, "").replace("https://", "")
            for s in scopes_raw
        )
        granted_by = app.get("granted_by", [])
        granted_str = ", ".join(granted_by) if isinstance(granted_by, list) else str(granted_by)
        table_rows.append({
            "category": _categorize_app(scopes_raw),
            "app_name": app.get("app_name", ""),
            "client_id": app.get("client_id", ""),
            "risk": app.get("risk_level", ""),
            "scopes": scopes_short,
            "granted_by": granted_str,
            "grants": app.get("grant_count", 0),
        })

    # Sort: CRITICAL first, then HIGH, then MEDIUM; within same risk by grants desc
    table_rows.sort(key=lambda r: (_RISK_SORT_ORDER.get(r["risk"], 99), -r["grants"]))

    children.append(html.H6("All Dangerous Apps", className="mt-3"))
    children.append(
        create_inventory_table(
            columns=[
                {"name": "Category", "id": "category"},
                {"name": "App Name", "id": "app_name"},
                {"name": "Client ID", "id": "client_id"},
                {"name": "Risk", "id": "risk"},
                {"name": "Scopes", "id": "scopes"},
                {"name": "Granted By", "id": "granted_by"},
                {"name": "Grants", "id": "grants"},
            ],
            data=table_rows,
            table_id="inv-oauth-apps-table",
        ),
    )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-34: App Passwords
# ------------------------------------------------------------------


def _render_app_passwords(data: dict) -> list:
    raw = data.get("raw_data", {})
    total_asps = raw.get("total_asps", 0)
    users_with_asps = raw.get("users_with_asps", 0)
    never_used = raw.get("never_used_asps", 0)
    asps_by_user = raw.get("asps_by_user", [])

    children: list = [
        html.H5("App-Specific Passwords"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total ASPs", total_asps, "#e53e3e" if total_asps else "#38a169"),
                create_metric_card("Users With ASPs", users_with_asps, "#e53e3e" if users_with_asps else "#38a169"),
                create_metric_card("Never Used", never_used, "#d69e2e" if never_used else "#38a169"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if asps_by_user:
        table_data = []
        for entry in asps_by_user:
            user = entry.get("user", "")
            for asp in entry.get("asps", []):
                table_data.append({
                    "user": user,
                    "name": asp.get("name", ""),
                    "created": asp.get("created", ""),
                    "last_used": asp.get("last_used", ""),
                })
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "User", "id": "user"},
                    {"name": "Password Name", "id": "name"},
                    {"name": "Created", "id": "created"},
                    {"name": "Last Used", "id": "last_used"},
                ],
                data=table_data,
                table_id="inv-app-passwords-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children


# ------------------------------------------------------------------
# ADD-35: Shared Drives
# ------------------------------------------------------------------


def _render_shared_drives(data: dict) -> list:
    raw = data.get("raw_data", {})
    total_drives = raw.get("total_drives", 0)
    insecure_drives = raw.get("insecure_drives", 0)
    drives = raw.get("drives", [])

    children: list = [
        html.H5("Shared Drives Security"),
        create_inventory_status_banner(data["status"], data["details"]),
        dbc.Row(
            [
                create_metric_card("Total Drives", total_drives, METRIC_COLORS["total"]),
                create_metric_card("Insecure Drives", insecure_drives, "#e53e3e" if insecure_drives else "#38a169"),
            ],
            className="g-3 mb-4",
        ),
    ]

    if drives:
        table_data = []
        for drv in drives:
            issues = drv.get("issues", [])
            table_data.append({
                "name": drv.get("name", ""),
                "domain_users_only": "Yes" if drv.get("domain_users_only") else "No",
                "members_only": "Yes" if drv.get("drive_members_only") else "No",
                "admin_managed": "Yes" if drv.get("admin_managed") else "No",
                "sharing_req_org": "Yes" if drv.get("sharing_requires_organizer") else "No",
                "issues": ", ".join(issues) if issues else "None",
            })
        children.append(
            create_inventory_table(
                columns=[
                    {"name": "Name", "id": "name"},
                    {"name": "Domain Only", "id": "domain_users_only"},
                    {"name": "Members Only", "id": "members_only"},
                    {"name": "Admin Managed", "id": "admin_managed"},
                    {"name": "Sharing Req Org", "id": "sharing_req_org"},
                    {"name": "Issues", "id": "issues"},
                ],
                data=table_data,
                table_id="inv-shared-drives-table",
            ),
        )

    children.append(create_remediation_alert(data.get("remediation", "")))
    return children
