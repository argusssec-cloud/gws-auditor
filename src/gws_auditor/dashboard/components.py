# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Reusable dashboard UI components."""

from __future__ import annotations

import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objects as go
from dash import dash_table, dcc, html, no_update

from .theme import METRIC_COLORS, PLOTLY_TEMPLATE, SOURCE_COLORS, SOURCE_TAG_CLASS, STATUS_BADGE_CLASS, STATUS_COLORS

# Inventory checks are separated from audit checks in the dashboard
INVENTORY_CHECK_IDS = frozenset({"ADD-28", "ADD-29", "ADD-30", "ADD-31", "ADD-32", "ADD-33", "ADD-34", "ADD-35", "ADD-38", "ADD-39"})


# ------------------------------------------------------------------
# Shared helpers used by multiple pages
# ------------------------------------------------------------------

def empty_fig(title: str = "") -> go.Figure:
    """Create a placeholder figure with a 'No data' annotation."""
    fig = go.Figure()
    fig.update_layout(
        title=title,
        template=PLOTLY_TEMPLATE,
        annotations=[{"text": "No data", "showarrow": False, "font": {"size": 16, "color": "#a0aec0"}}],
    )
    return fig


def build_df(report_data: dict | None, *, exclude_inventory: bool = True) -> pd.DataFrame:
    """Build a DataFrame from the report data dict (client-side Store).

    Args:
        report_data: The report dict from the dcc.Store.
        exclude_inventory: When ``True`` (default), rows for inventory
            checks (ADD-28 through ADD-35) are removed so that audit
            metrics and charts only reflect the audit checks.
    """
    if not report_data:
        return pd.DataFrame()
    results = report_data.get("results", [])
    if not results:
        return pd.DataFrame()
    df = pd.DataFrame(results)
    df["status"] = df["status"].str.upper().str.replace(" ", "_")
    if exclude_inventory and "check_id" in df.columns:
        df = df[~df["check_id"].isin(INVENTORY_CHECK_IDS)]
    return df


def extract_inventory_data(report_data: dict | None) -> dict[str, dict]:
    """Extract inventory check results from a report data dict.

    Returns a dict keyed by check_id with fields: check_id, title,
    status, details, remediation, raw_data.
    """
    if not report_data:
        return {}
    results = report_data.get("results", [])
    inventory: dict[str, dict] = {}
    for r in results:
        cid = r.get("check_id", "")
        if cid in INVENTORY_CHECK_IDS:
            av = r.get("actual_value")
            inventory[cid] = {
                "check_id": cid,
                "title": r.get("title", ""),
                "status": (r.get("status", "") or "").upper().replace(" ", "_"),
                "details": r.get("details", ""),
                "remediation": r.get("remediation", ""),
                "raw_data": av if isinstance(av, dict) else {},
            }
    return inventory


# ------------------------------------------------------------------
# Source tag helper
# ------------------------------------------------------------------

def source_tag(source: str) -> html.Span:
    """Colored source tag badge (CIS, CISA, GOOGLE, OTHER)."""
    cls = SOURCE_TAG_CLASS.get(source, "source-tag")
    return html.Span(source, className=cls)


# ------------------------------------------------------------------
# Status badge helper
# ------------------------------------------------------------------

def status_badge(status: str) -> html.Span:
    """Colored status pill badge."""
    cls = STATUS_BADGE_CLASS.get(status, "status-badge")
    label = status.replace("_", " ")
    return html.Span(label, className=f"status-badge {cls}")


# ------------------------------------------------------------------
# Check ID display (monospace + source tag)
# ------------------------------------------------------------------

def check_id_display(check_id: str, source: str = "") -> html.Span:
    """Monospace check ID with optional source tag."""
    children = [html.Code(check_id, className="check-id-code")]
    if source:
        children.append(source_tag(source))
    return html.Span(children)


# ------------------------------------------------------------------
# Critical Security Findings banner
# ------------------------------------------------------------------


def create_critical_findings_banner(df: pd.DataFrame) -> html.Div:
    """Red banner listing critical security findings (FAIL + severity CRITICAL).

    Returns an empty Div when there are no critical failures.
    """
    if df.empty or "severity" not in df.columns:
        return html.Div()

    crit = df[(df["status"] == "FAIL") & (df["severity"].str.upper() == "CRITICAL")]
    if crit.empty:
        return html.Div()

    count = len(crit)
    items = []
    for _, row in crit.iterrows():
        check_id = row.get("check_id", "")
        title = row.get("title", "")
        reason = row.get("critical_reason", "")
        item_children = [
            html.Div(
                [
                    html.Code(check_id, className="critical-item-id"),
                    html.Span(title),
                ],
                className="critical-item-header",
            ),
        ]
        if reason:
            item_children.append(
                html.Div(reason, className="critical-reason"),
            )
        items.append(html.Div(item_children, className="critical-item"))

    return html.Div(
        [
            html.Div(
                [
                    html.Span("\u26A0", className="critical-icon"),
                    html.Strong(
                        f" {count} Critical Security Finding{'s' if count != 1 else ''}",
                    ),
                    html.Span(
                        " \u2014 These represent severe security risks requiring immediate attention",
                        className="critical-subtitle",
                    ),
                ],
                className="critical-header",
            ),
            html.Div(items, className="critical-list"),
        ],
        className="critical-banner mb-3",
    )


# ------------------------------------------------------------------
# Metric cards
# ------------------------------------------------------------------

def create_metric_card(
    label: str,
    value,
    color: str,
    card_id: str = "",
    active: bool = False,
    proportion: float = 0,
) -> dbc.Col:
    """Single KPI card with a colored left border and optional proportion bar."""
    wrapper_style: dict = {"cursor": "pointer"}
    if active:
        wrapper_style.update({
            "outline": "2px solid #3182ce",
            "outlineOffset": "2px",
            "borderRadius": "0.5rem",
        })

    card_children = [
        html.Div(label, className="metric-label"),
        html.Div(
            value,
            className="metric-value",
            style={"color": color},
        ),
    ]

    # Add proportion bar at bottom
    if proportion > 0:
        card_children.append(
            html.Div(
                className="metric-proportion-bar",
                style={
                    "width": f"{proportion:.1f}%",
                    "backgroundColor": color,
                },
            ),
        )

    return dbc.Col(
        html.Div(
            dbc.Card(
                dbc.CardBody(card_children),
                className="metric-card",
                style={"borderLeft": f"4px solid {color}"},
            ),
            id=card_id,
            n_clicks=0,
            style=wrapper_style,
        ),
        xs=6, sm=4, md=True,
    )


def create_metric_cards_row(summary: dict, active_metric: str | None = None) -> dbc.Row:
    """Row of 8 metric cards from a report summary dict."""
    total = summary.get("total", 0) or 1  # avoid div by zero
    pass_rate = summary.get("pass_rate", 0)
    cards = [
        create_metric_card("Total Checks", summary.get("total", 0), METRIC_COLORS["total"], "metric-total", active_metric == "metric-total"),
        create_metric_card("Passed", summary.get("passed", 0), METRIC_COLORS["passed"], "metric-passed", active_metric == "metric-passed", summary.get("passed", 0) / total * 100),
        create_metric_card("Failed", summary.get("failed", 0), METRIC_COLORS["failed"], "metric-failed", active_metric == "metric-failed", summary.get("failed", 0) / total * 100),
        create_metric_card("Warnings", summary.get("warnings", 0), METRIC_COLORS["warnings"], "metric-warnings", active_metric == "metric-warnings", summary.get("warnings", 0) / total * 100),
        create_metric_card("Errors", summary.get("errors", 0), METRIC_COLORS["errors"], "metric-errors", active_metric == "metric-errors", summary.get("errors", 0) / total * 100),
        create_metric_card("Manual", summary.get("manual", 0), METRIC_COLORS["manual"], "metric-manual", active_metric == "metric-manual", summary.get("manual", 0) / total * 100),
        create_metric_card("N/A", summary.get("na", 0), METRIC_COLORS["na"], "metric-na", active_metric == "metric-na", summary.get("na", 0) / total * 100),
        create_metric_card("Pass Rate", f"{pass_rate:.1f}%", METRIC_COLORS["pass_rate"], "metric-pass-rate", active_metric == "metric-pass-rate"),
    ]
    # Posture score (may be absent for old reports)
    ps = summary.get("posture_score")
    pg = summary.get("posture_grade", "")
    if ps is not None and pg:
        cards.append(
            create_metric_card(
                "Posture Score",
                f"{ps}/100 ({pg})",
                METRIC_COLORS["posture_score"],
                "metric-posture-score",
                active_metric == "metric-posture-score",
            ),
        )
    return dbc.Row(cards, className="g-3 mb-4")


# ------------------------------------------------------------------
# Filter dropdowns
# ------------------------------------------------------------------

def create_filter_row(options: dict[str, list[str]], prefix: str) -> dbc.Row:
    """Row of multi-select filter dropdowns."""
    def _dropdown(col_id: str, label: str):
        return dbc.Col(
            [
                html.Label(label, className="filter-label", style={"fontSize": "0.75rem", "fontWeight": 600}),
                dcc.Dropdown(
                    id=f"{prefix}-filter-{col_id}",
                    options=[{"label": v, "value": v} for v in options.get(col_id, [])],
                    multi=True,
                    placeholder=f"All {label}s",
                ),
            ],
            xs=12, sm=6, md=3,
        )

    return dbc.Row(
        [
            _dropdown("source", "Source"),
            _dropdown("section", "Section"),
            _dropdown("level", "Level"),
            _dropdown("status", "Status"),
        ],
        className="g-2 mb-3 filter-row",
    )


# ------------------------------------------------------------------
# Results data table
# ------------------------------------------------------------------

_STATUS_ROW_COLORS = {
    "PASS": "#f0fff4",
    "FAIL": "#fff5f5",
    "WARN": "#fffff0",
    "ERROR": "#fff5f5",
    "MANUAL": "#ebf8ff",
    "NOT_APPLICABLE": "#f7fafc",
}


def create_check_detail_modal(modal_id: str) -> dbc.Modal:
    """Modal for displaying full check details, matching HTML report style."""
    return dbc.Modal(
        [
            dbc.ModalHeader(
                html.Div(
                    [
                        html.Span(id=f"{modal_id}-check-id", className="modal-check-id"),
                        html.Span(id=f"{modal_id}-source-tag"),
                    ],
                    style={"display": "flex", "alignItems": "center", "gap": "0.5rem"},
                ),
            ),
            dbc.ModalBody(
                [
                    # Title on its own line
                    html.Div(id=f"{modal_id}-title", className="modal-title-text"),
                    # Meta row: status badge + level + section
                    html.Div(
                        [
                            html.Span(id=f"{modal_id}-status"),
                            html.Span([html.Strong("Level: "), html.Span(id=f"{modal_id}-level")]),
                            html.Span([html.Strong("Section: "), html.Span(id=f"{modal_id}-section")]),
                        ],
                        className="modal-meta-row",
                    ),
                    # Manual override (visible only for MANUAL checks)
                    html.Div(
                        [
                            html.Div("Override Status", className="modal-section-label"),
                            html.Div(
                                [
                                    dcc.Dropdown(
                                        id=f"{modal_id}-override-status",
                                        options=[
                                            {"label": "MANUAL (no override)", "value": ""},
                                            {"label": "PASS", "value": "PASS"},
                                            {"label": "FAIL", "value": "FAIL"},
                                        ],
                                        value="",
                                        clearable=False,
                                        style={"width": "220px"},
                                    ),
                                    html.Div(
                                        id=f"{modal_id}-override-status-msg",
                                        className="mt-1",
                                        style={"fontSize": "0.8rem", "color": "#38a169"},
                                    ),
                                ],
                            ),
                        ],
                        id=f"{modal_id}-override-section",
                        className="modal-section-block mt-2",
                        style={"display": "none"},
                    ),
                    html.Hr(),
                    # Details section
                    html.Div(
                        [
                            html.Div("Details", className="modal-section-label"),
                            html.Div(id=f"{modal_id}-details", className="modal-section-content"),
                        ],
                        className="modal-section-block",
                    ),
                    # Actual / Expected side by side
                    dbc.Row(
                        [
                            dbc.Col(
                                html.Div(
                                    [
                                        html.Div("Actual Value", className="modal-section-label"),
                                        html.Div(id=f"{modal_id}-actual", className="modal-section-content"),
                                    ],
                                    className="modal-section-block",
                                ),
                                md=6,
                            ),
                            dbc.Col(
                                html.Div(
                                    [
                                        html.Div("Expected Value", className="modal-section-label"),
                                        html.Div(id=f"{modal_id}-expected", className="modal-section-content"),
                                    ],
                                    className="modal-section-block",
                                ),
                                md=6,
                            ),
                        ],
                    ),
                    # Org Unit
                    html.Div(
                        [
                            html.Div("Org Unit", className="modal-section-label"),
                            html.Div(id=f"{modal_id}-org-unit", className="modal-section-content"),
                        ],
                        className="modal-section-block",
                    ),
                    html.Hr(),
                    # Remediation
                    html.Div(
                        [
                            html.Div("Remediation", className="modal-section-label"),
                            html.Div(id=f"{modal_id}-remediation", className="modal-section-content"),
                        ],
                        className="modal-section-block",
                    ),
                    html.Hr(),
                    # Comments section
                    html.Div(
                        [
                            html.Div("Comments", className="modal-section-label"),
                            dcc.Textarea(
                                id=f"{modal_id}-comment-text",
                                placeholder="Add a comment...",
                                style={"width": "100%", "minHeight": "80px", "resize": "vertical"},
                            ),
                            html.Div(
                                [
                                    dbc.Input(
                                        id=f"{modal_id}-comment-author",
                                        placeholder="Your name (optional)",
                                        size="sm",
                                        style={"width": "200px", "display": "inline-block"},
                                        className="me-2 mt-2",
                                    ),
                                    dbc.Button(
                                        "Save Comment",
                                        id=f"{modal_id}-save-comment",
                                        color="primary",
                                        size="sm",
                                        className="mt-2",
                                    ),
                                ],
                            ),
                            html.Div(
                                id=f"{modal_id}-comment-status",
                                className="mt-2",
                                style={"fontSize": "0.8rem", "color": "#38a169"},
                            ),
                        ],
                        className="modal-section-block",
                    ),
                ],
            ),
        ],
        id=modal_id,
        is_open=False,
        size="lg",
    )


def create_results_table(table_id: str = "results-table") -> dash_table.DataTable:
    """Configurable DataTable for check results."""
    return dash_table.DataTable(
        id=table_id,
        columns=[
            {"name": "Check ID", "id": "check_id", "hideable": True},
            {"name": "Title", "id": "title", "hideable": True},
            {"name": "Status", "id": "status", "hideable": True},
            {"name": "Level", "id": "level", "hideable": True},
            {"name": "Source", "id": "source", "hideable": True},
            {"name": "Section", "id": "section", "hideable": True},
            {"name": "Details", "id": "details", "hideable": True},
            {"name": "Remediation", "id": "remediation", "hideable": True},
            {"name": "Actual Value", "id": "actual_value", "hideable": True},
            {"name": "Expected Value", "id": "expected_value", "hideable": True},
            {"name": "Org Unit", "id": "org_unit", "hideable": True},
            {"name": "Original Status", "id": "original_status"},
            {"name": "Comment", "id": "comment", "editable": True, "hideable": True},
        ],
        hidden_columns=["actual_value", "expected_value", "org_unit", "original_status"],
        editable=False,
        data=[],
        page_size=20,
        sort_action="native",
        filter_action="native",
        style_table={"overflowX": "auto"},
        style_cell={
            "textAlign": "left",
            "padding": "8px 12px",
            "fontFamily": "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            "fontSize": "0.85rem",
        },
        style_header={
            "backgroundColor": "#2d3748",
            "color": "white",
            "fontWeight": "600",
            "textTransform": "uppercase",
            "fontSize": "0.8rem",
        },
        style_data_conditional=[
            {
                "if": {"filter_query": f'{{status}} = "{status}"'},
                "backgroundColor": bg,
            }
            for status, bg in _STATUS_ROW_COLORS.items()
        ],
        style_cell_conditional=[
            {"if": {"column_id": "details"}, "maxWidth": "300px", "overflow": "hidden", "textOverflow": "ellipsis"},
            {"if": {"column_id": "remediation"}, "maxWidth": "300px", "overflow": "hidden", "textOverflow": "ellipsis"},
            {"if": {"column_id": "title"}, "maxWidth": "250px", "overflow": "hidden", "textOverflow": "ellipsis"},
            {"if": {"column_id": "check_id"}, "fontFamily": "'SF Mono', Monaco, Consolas, monospace", "fontWeight": "600", "fontSize": "0.82rem"},
            {"if": {"column_id": "comment"}, "minWidth": "150px", "maxWidth": "300px", "overflow": "hidden", "textOverflow": "ellipsis"},
        ],
        tooltip_delay=0,
        tooltip_duration=None,
        export_format="csv",
    )


# ------------------------------------------------------------------
# Source / framework summary card
# ------------------------------------------------------------------

def create_source_card(name: str, total: int, passed: int, failed: int, pass_rate: float) -> dbc.Col:
    """Framework summary card with a progress bar."""
    color = SOURCE_COLORS.get(name, "#718096")
    return dbc.Col(
        dbc.Card(
            dbc.CardBody(
                [
                    html.H6(name, style={"color": color, "fontWeight": 700}),
                    html.Div(
                        [
                            html.Span(f"{total} checks", className="text-muted", style={"fontSize": "0.8rem"}),
                            html.Span(f" | ", className="text-muted"),
                            html.Span(
                                f"{pass_rate:.0f}% pass",
                                style={"fontSize": "0.8rem", "fontWeight": 600, "color": color},
                            ),
                        ],
                    ),
                    html.Div(
                        html.Div(
                            style={
                                "width": f"{pass_rate}%",
                                "height": "100%",
                                "backgroundColor": color,
                                "borderRadius": "3px",
                            },
                        ),
                        className="mt-2",
                        style={
                            "height": "6px",
                            "backgroundColor": "#e2e8f0",
                            "borderRadius": "3px",
                            "overflow": "hidden",
                        },
                    ),
                    html.Div(
                        [
                            html.Span(f"{passed} passed", style={"color": "#38a169", "fontSize": "0.75rem"}),
                            html.Span(" / "),
                            html.Span(f"{failed} failed", style={"color": "#e53e3e", "fontSize": "0.75rem"}),
                        ],
                        className="mt-1",
                    ),
                ],
            ),
            className="source-card",
            style={"borderTop": f"3px solid {color}"},
        ),
        xs=12, sm=6, md=3,
    )


# ------------------------------------------------------------------
# Accordion section header helpers
# ------------------------------------------------------------------

def build_accordion_header(section_name: str, sec_df: pd.DataFrame) -> str:
    """Build rich accordion header text with stats. Returns plain text for title."""
    sec_total = len(sec_df)
    sec_passed = int((sec_df["status"] == "PASS").sum())
    sec_failed = int((sec_df["status"] == "FAIL").sum())
    sec_evaluated = sec_passed + sec_failed
    sec_rate = (sec_passed / sec_evaluated * 100) if sec_evaluated else 0
    return f"{section_name}  —  {sec_total} checks, {sec_rate:.0f}% pass"


def build_section_stat_badges(sec_df: pd.DataFrame) -> list:
    """Return list of section stat badge Spans for pass/fail/warn/error/manual."""
    badges = []
    for status_key, css_class in [
        ("PASS", "section-stat--pass"),
        ("FAIL", "section-stat--fail"),
        ("WARN", "section-stat--warn"),
        ("ERROR", "section-stat--error"),
        ("MANUAL", "section-stat--manual"),
    ]:
        count = int((sec_df["status"] == status_key).sum())
        if count > 0:
            label = status_key.lower()
            badges.append(html.Span(f"{count} {label}", className=f"section-stat {css_class}"))
    return badges


def build_section_status_bar(sec_df: pd.DataFrame) -> html.Div:
    """Multi-color status bar for a section."""
    sec_total = len(sec_df)
    if sec_total == 0:
        return html.Div()
    segments = []
    for status_key, color in [
        ("PASS", "#38a169"),
        ("FAIL", "#e53e3e"),
        ("WARN", "#d69e2e"),
        ("ERROR", "#9b2c2c"),
        ("MANUAL", "#3182ce"),
        ("NOT_APPLICABLE", "#a0aec0"),
    ]:
        count = int((sec_df["status"] == status_key).sum())
        if count > 0:
            pct = count / sec_total * 100
            segments.append(
                html.Span(style={"width": f"{pct:.1f}%", "background": color}),
            )
    return html.Div(segments, className="section-status-bar")


# ------------------------------------------------------------------
# Inventory page helpers
# ------------------------------------------------------------------

_INVENTORY_STATUS_COLORS = {
    "PASS": "#38a169",
    "FAIL": "#e53e3e",
    "WARN": "#d69e2e",
    "MANUAL": "#3182ce",
    "ERROR": "#9b2c2c",
}

_INVENTORY_BADGE_COLORS = {
    "PASS": "success",
    "FAIL": "danger",
    "WARN": "warning",
    "MANUAL": "info",
    "ERROR": "danger",
}


def create_inventory_status_banner(status: str, details: str) -> html.Div:
    """Colored left-border banner showing check status and details."""
    color = _INVENTORY_STATUS_COLORS.get(status, "#718096")
    badge_color = _INVENTORY_BADGE_COLORS.get(status, "secondary")
    return html.Div(
        [
            dbc.Badge(status, color=badge_color, className="me-2"),
            html.Span(details, style={"fontSize": "0.9rem"}),
        ],
        className="inventory-status-banner mb-3 p-3",
        style={
            "borderLeft": f"4px solid {color}",
            "backgroundColor": "#f7fafc",
            "borderRadius": "0.375rem",
        },
    )


def create_inventory_table(
    columns: list[dict],
    data: list[dict],
    table_id: str,
    page_size: int = 15,
) -> dash_table.DataTable:
    """DataTable styled for inventory tabs with sort, filter, and CSV export."""
    return dash_table.DataTable(
        id=table_id,
        columns=columns,
        data=data,
        page_size=page_size,
        sort_action="native",
        filter_action="native",
        export_format="csv",
        style_table={"overflowX": "auto"},
        style_cell={
            "textAlign": "left",
            "padding": "8px 12px",
            "fontFamily": "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            "fontSize": "0.85rem",
        },
        style_header={
            "backgroundColor": "#2d3748",
            "color": "white",
            "fontWeight": "600",
            "textTransform": "uppercase",
            "fontSize": "0.8rem",
        },
    )


def apply_overrides(df: pd.DataFrame, comments_data: dict) -> pd.DataFrame:
    """Apply manual status overrides from the sidecar comments data.

    Only MANUAL checks can be overridden to PASS or FAIL.
    """
    if not comments_data:
        return df
    override_map = {}
    for check_id, entry in comments_data.items():
        ov = entry.get("override_status", "")
        if ov in ("PASS", "FAIL"):
            override_map[check_id] = ov
    if not override_map:
        return df
    df = df.copy()
    mask = (df["check_id"].isin(override_map)) & (df["status"] == "MANUAL")
    df.loc[mask, "status"] = df.loc[mask, "check_id"].map(override_map)
    return df


def create_remediation_alert(text: str) -> dbc.Alert:
    """Info alert box for remediation guidance."""
    if not text:
        return html.Div()
    return dbc.Alert(
        [html.Strong("Remediation: "), text],
        color="info",
        className="mt-3",
    )
