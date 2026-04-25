# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Overview page – summary metrics, charts, and findings table."""

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html

from gws_auditor.dashboard.app import get_report_store
from gws_auditor.dashboard.components import (
    apply_overrides,
    build_df,
    check_id_display,
    create_check_detail_modal,
    create_critical_findings_banner,
    create_filter_row,
    create_metric_cards_row,
    create_results_table,
    empty_fig,
    source_tag,
    status_badge,
)
from gws_auditor.dashboard.theme import PLOTLY_TEMPLATE, STATUS_COLORS, STATUS_ORDER

dash.register_page(__name__, path="/", name="Overview")

# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

METRIC_IDS = [
    "metric-total", "metric-passed", "metric-failed",
    "metric-warnings", "metric-errors", "metric-manual",
    "metric-na", "metric-pass-rate",
]
METRIC_STATUS_MAP = {
    "metric-passed": ["PASS"],
    "metric-failed": ["FAIL"],
    "metric-warnings": ["WARN"],
    "metric-errors": ["ERROR"],
    "metric-manual": ["MANUAL"],
    "metric-na": ["NOT_APPLICABLE"],
}

layout = html.Div(
    [
        html.H4("Overview", className="page-header"),
        dcc.Store(id="overview-active-metric", data=None),

        # Report metadata bar (customer, edition, domains)
        html.Div(id="overview-report-meta", className="mb-3"),

        # Placeholder rows – populated by callback
        html.Div(id="overview-filters"),
        html.Div(id="overview-metrics"),

        # Critical Security Findings banner (populated by callback)
        html.Div(id="overview-critical-findings"),

        dbc.Row(
            [
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="overview-status-donut")), className="chart-card"), md=6),
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="overview-section-bar")), className="chart-card"), md=6),
            ],
            className="g-3 mb-3",
        ),
        dbc.Row(
            [
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="overview-source-bar")), className="chart-card"), md=6),
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="overview-level-bar")), className="chart-card"), md=6),
            ],
            className="g-3 mb-3",
        ),

        html.Div(
            [
                html.H5("Detailed Findings", className="mt-4 mb-0"),
                dcc.Dropdown(
                    id="overview-page-size",
                    options=[
                        {"label": "10 per page", "value": 10},
                        {"label": "20 per page", "value": 20},
                        {"label": "50 per page", "value": 50},
                        {"label": "100 per page", "value": 100},
                        {"label": "All", "value": 0},
                    ],
                    value=20,
                    clearable=False,
                    style={"width": "150px"},
                    className="page-size-dropdown",
                ),
            ],
            style={"display": "flex", "alignItems": "center", "gap": "1rem"},
            className="mb-3",
        ),
        create_results_table("overview-results-table"),
        create_check_detail_modal("overview-detail-modal"),
        dcc.Download(id="overview-download"),
        dcc.Download(id="overview-download-html"),
        html.Div(
            [
                dbc.Button("Export CSV", id="overview-export-btn", color="secondary", size="sm", className="mt-2 me-2"),
                dbc.Button("Export HTML with Comments", id="overview-export-html-btn", color="primary", size="sm", className="mt-2"),
            ],
        ),
    ],
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_apply_overrides = apply_overrides


def _apply_filters(df: pd.DataFrame, sources, sections, levels, statuses) -> pd.DataFrame:
    if sources:
        df = df[df["source"].isin(sources)]
    if sections:
        df = df[df["section"].isin(sections)]
    if levels:
        df = df[df["level"].isin(levels)]
    if statuses:
        df = df[df["status"].isin(statuses)]
    return df


def _compute_summary(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "errors": 0, "manual": 0, "na": 0, "pass_rate": 0}
    counts = df["status"].value_counts()
    passed = int(counts.get("PASS", 0))
    failed = int(counts.get("FAIL", 0))
    evaluated = passed + failed
    return {
        "total": len(df),
        "passed": passed,
        "failed": failed,
        "warnings": int(counts.get("WARN", 0)),
        "errors": int(counts.get("ERROR", 0)),
        "manual": int(counts.get("MANUAL", 0)),
        "na": int(counts.get("NOT_APPLICABLE", 0)),
        "pass_rate": (passed / evaluated * 100) if evaluated else 0,
    }


# ------------------------------------------------------------------
# Callbacks
# ------------------------------------------------------------------

@callback(
    Output("overview-report-meta", "children"),
    Input("report-data", "data"),
)
def update_report_meta(report_data):
    if not report_data:
        return html.Div()
    customer_id = report_data.get("customer_id", "")
    subscription = report_data.get("subscription_type", "")
    domains = report_data.get("domains", [])
    timestamp = report_data.get("timestamp", "")
    items = []
    if customer_id:
        items.append(html.Span([html.Strong("Customer: "), customer_id], className="me-4"))
    if subscription:
        items.append(html.Span([html.Strong("Edition: "), subscription], className="me-4"))
    if domains:
        items.append(html.Span([html.Strong("Domains: "), ", ".join(domains)], className="me-4"))
    if timestamp:
        items.append(html.Span([html.Strong("Scan: "), timestamp], className="me-4"))
    if not items:
        return html.Div()
    return dbc.Card(
        dbc.CardBody(html.Div(items, style={"fontSize": "0.9rem"})),
        className="mb-0",
    )


@callback(
    Output("overview-filters", "children"),
    Input("report-data", "data"),
)
def update_filters(report_data):
    df = build_df(report_data)
    if df.empty:
        return html.Div()
    opts: dict[str, list[str]] = {}
    for col in ("source", "section", "level", "status"):
        if col in df.columns:
            opts[col] = sorted(df[col].dropna().unique().tolist())
        else:
            opts[col] = []
    return create_filter_row(opts, "overview")


@callback(
    Output("overview-active-metric", "data"),
    [Input(mid, "n_clicks") for mid in METRIC_IDS],
    State("overview-active-metric", "data"),
    prevent_initial_call=True,
)
def set_active_metric(*args):
    triggered = dash.ctx.triggered_id
    current = args[-1]  # last arg is State
    if triggered == current:
        return None  # toggle off
    return triggered


@callback(
    Output("overview-metrics", "children"),
    Output("overview-critical-findings", "children"),
    Output("overview-status-donut", "figure"),
    Output("overview-section-bar", "figure"),
    Output("overview-source-bar", "figure"),
    Output("overview-level-bar", "figure"),
    Output("overview-results-table", "data"),
    Output("overview-results-table", "tooltip_data"),
    Input("overview-filter-source", "value"),
    Input("overview-filter-section", "value"),
    Input("overview-filter-level", "value"),
    Input("overview-filter-status", "value"),
    Input("overview-active-metric", "data"),
    Input("comments-data", "data"),
    State("report-data", "data"),
)
def update_overview(sources, sections, levels, statuses, active_metric, comments_data, report_data):
    df = build_df(report_data)
    if df.empty:
        empty = empty_fig()
        return html.Div(), html.Div(), empty, empty, empty, empty, [], []

    # Apply manual overrides from comments sidecar
    comments_data = comments_data or {}
    df = _apply_overrides(df, comments_data)

    # Compute posture score (override-aware, before filters)
    from gws_auditor.scoring import compute_posture_score_from_report
    override_map = {
        cid: entry.get("override_status", "")
        for cid, entry in comments_data.items()
        if entry.get("override_status") in ("PASS", "FAIL")
    }
    posture = compute_posture_score_from_report(
        report_data or {}, overrides=override_map,
    )

    df = _apply_filters(df, sources, sections, levels, statuses)
    summary = _compute_summary(df)
    summary["posture_score"] = posture["score"]
    summary["posture_grade"] = posture["grade"]

    # --- Metric cards (active_metric drives highlight) ---
    cards = create_metric_cards_row(summary, active_metric)

    # --- Critical findings banner (before metric card filtering) ---
    critical_banner = create_critical_findings_banner(df)

    # --- Apply metric card filter ---
    if active_metric and active_metric in METRIC_STATUS_MAP:
        df = df[df["status"].isin(METRIC_STATUS_MAP[active_metric])]

    # --- Status donut ---
    status_counts = df["status"].value_counts()
    ordered = [s for s in STATUS_ORDER if s in status_counts.index]
    donut = go.Figure(
        go.Pie(
            labels=ordered,
            values=[int(status_counts[s]) for s in ordered],
            hole=0.5,
            marker={"colors": [STATUS_COLORS.get(s, "#718096") for s in ordered]},
            textinfo="label+value",
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        ),
    )
    donut.update_layout(title="Status Distribution", template=PLOTLY_TEMPLATE, showlegend=True)

    # --- Section stacked bar ---
    if "section" in df.columns:
        section_status = df.groupby(["section", "status"]).size().unstack(fill_value=0)
        sec_fig = go.Figure()
        for status in STATUS_ORDER:
            if status in section_status.columns:
                sec_fig.add_trace(
                    go.Bar(
                        y=section_status.index,
                        x=section_status[status],
                        name=status,
                        orientation="h",
                        marker_color=STATUS_COLORS.get(status, "#718096"),
                    ),
                )
        sec_fig.update_layout(
            title="Results by Section",
            barmode="stack",
            template=PLOTLY_TEMPLATE,
            yaxis={"categoryorder": "total ascending"},
            height=max(300, len(section_status) * 30 + 100),
        )
    else:
        sec_fig = empty_fig("Results by Section")

    # --- Source grouped bar ---
    if "source" in df.columns:
        source_status = df.groupby(["source", "status"]).size().unstack(fill_value=0)
        src_fig = go.Figure()
        for status in STATUS_ORDER:
            if status in source_status.columns:
                src_fig.add_trace(
                    go.Bar(
                        x=source_status.index,
                        y=source_status[status],
                        name=status,
                        marker_color=STATUS_COLORS.get(status, "#718096"),
                    ),
                )
        src_fig.update_layout(title="Results by Source", barmode="group", template=PLOTLY_TEMPLATE)
    else:
        src_fig = empty_fig("Results by Source")

    # --- Level distribution ---
    if "level" in df.columns:
        level_status = df.groupby(["level", "status"]).size().unstack(fill_value=0)
        lvl_fig = go.Figure()
        for status in STATUS_ORDER:
            if status in level_status.columns:
                lvl_fig.add_trace(
                    go.Bar(
                        x=level_status.index,
                        y=level_status[status],
                        name=status,
                        marker_color=STATUS_COLORS.get(status, "#718096"),
                    ),
                )
        lvl_fig.update_layout(title="L1 vs L2 Distribution", barmode="stack", template=PLOTLY_TEMPLATE)
    else:
        lvl_fig = empty_fig("L1 vs L2 Distribution")

    # --- Table data (include hidden fields for modal) ---
    keep = ["check_id", "title", "status", "level", "source", "section", "details", "remediation", "actual_value", "expected_value", "org_unit"]
    table_data = df[[c for c in keep if c in df.columns]].fillna("").to_dict("records")

    # Merge inline comments and track original status for the dropdown
    for row in table_data:
        cid = row.get("check_id", "")
        entry = comments_data.get(cid, {})
        row["comment"] = entry.get("comment", "")
        # Track original status so the Status dropdown stays visible
        # for checks that were originally MANUAL (even if now overridden)
        if entry.get("override_status") in ("PASS", "FAIL"):
            row["original_status"] = "MANUAL"
        else:
            row["original_status"] = row.get("status", "")

    # --- Tooltips for truncated columns ---
    tooltip_data = [
        {
            "title": {"value": str(row.get("title", "")), "type": "text"},
            "details": {"value": str(row.get("details", "")), "type": "text"},
            "remediation": {"value": str(row.get("remediation", "")), "type": "text"},
            "comment": {"value": str(row.get("comment", "")), "type": "text"},
        }
        for row in table_data
    ]

    return cards, critical_banner, donut, sec_fig, src_fig, lvl_fig, table_data, tooltip_data


@callback(
    Output("overview-download", "data"),
    Input("overview-export-btn", "n_clicks"),
    State("overview-results-table", "data"),
    prevent_initial_call=True,
)
def export_csv(n_clicks, table_data):
    if not table_data:
        return dash.no_update
    df = pd.DataFrame(table_data)
    return dcc.send_data_frame(df.to_csv, "gws_audit_findings.csv", index=False)


@callback(
    Output("overview-results-table", "page_size"),
    Input("overview-page-size", "value"),
)
def update_page_size(value):
    """Update the findings table page size.  0 means 'All'."""
    if value is None:
        return 20
    return value if value > 0 else 99999


@callback(
    Output("overview-detail-modal", "is_open"),
    Output("overview-detail-modal-check-id", "children"),
    Output("overview-detail-modal-source-tag", "children"),
    Output("overview-detail-modal-title", "children"),
    Output("overview-detail-modal-status", "children"),
    Output("overview-detail-modal-level", "children"),
    Output("overview-detail-modal-section", "children"),
    Output("overview-detail-modal-details", "children"),
    Output("overview-detail-modal-actual", "children"),
    Output("overview-detail-modal-expected", "children"),
    Output("overview-detail-modal-org-unit", "children"),
    Output("overview-detail-modal-remediation", "children"),
    Output("overview-detail-modal-comment-text", "value"),
    Output("overview-detail-modal-comment-author", "value"),
    Output("overview-detail-modal-comment-status", "children"),
    Output("overview-detail-modal-override-section", "style"),
    Output("overview-detail-modal-override-status", "value"),
    Output("overview-detail-modal-override-status-msg", "children"),
    Input("overview-results-table", "active_cell"),
    State("overview-results-table", "data"),
    State("comments-data", "data"),
    prevent_initial_call=True,
)
def open_overview_modal(active_cell, table_data, comments_data):
    n_outputs = 18
    if not active_cell or not table_data:
        return (False,) + ("",) * (n_outputs - 1)
    # Don't open modal when clicking the editable comment column
    if active_cell.get("column_id") == "comment":
        return (dash.no_update,) * n_outputs
    row = table_data[active_cell["row"]]
    check_id = row.get("check_id", "")
    src = row.get("source", "")
    st = row.get("status", "")
    original = row.get("original_status", st)
    existing = (comments_data or {}).get(check_id, {})
    # Show override section only for originally-MANUAL checks
    if original == "MANUAL":
        override_style = {"display": "block"}
        override_value = existing.get("override_status", "")
    else:
        override_style = {"display": "none"}
        override_value = ""
    return (
        True,
        check_id,
        source_tag(src) if src else "",
        row.get("title", ""),
        status_badge(st) if st else "",
        row.get("level", ""),
        row.get("section", ""),
        row.get("details", ""),
        str(row.get("actual_value", "")) or "N/A",
        str(row.get("expected_value", "")) or "N/A",
        row.get("org_unit", "") or "/",
        row.get("remediation", "") or "None",
        existing.get("comment", ""),
        existing.get("author", ""),
        "",
        override_style,
        override_value,
        "",
    )


@callback(
    Output("comments-data", "data", allow_duplicate=True),
    Output("overview-detail-modal-override-status-msg", "children", allow_duplicate=True),
    Input("overview-detail-modal-override-status", "value"),
    State("overview-detail-modal-check-id", "children"),
    State("report-filename", "data"),
    prevent_initial_call=True,
)
def save_overview_override(override_value, check_id, filename):
    if not check_id or not filename:
        return dash.no_update, ""
    store = get_report_store()
    updated = store.save_override(filename, check_id, override_value or "")
    if override_value in ("PASS", "FAIL"):
        return updated, f"Status overridden to {override_value}."
    return updated, "Override cleared."


@callback(
    Output("comments-data", "data", allow_duplicate=True),
    Output("overview-detail-modal-comment-status", "children", allow_duplicate=True),
    Input("overview-detail-modal-save-comment", "n_clicks"),
    State("overview-detail-modal-check-id", "children"),
    State("overview-detail-modal-comment-text", "value"),
    State("overview-detail-modal-comment-author", "value"),
    State("report-filename", "data"),
    prevent_initial_call=True,
)
def save_overview_comment(n_clicks, check_id, comment, author, filename):
    if not n_clicks or not check_id or not filename:
        return dash.no_update, ""
    store = get_report_store()
    updated = store.save_comment(filename, check_id, comment or "", author or "")
    return updated, "Comment saved."


@callback(
    Output("overview-download-html", "data"),
    Input("overview-export-html-btn", "n_clicks"),
    State("report-data", "data"),
    State("comments-data", "data"),
    prevent_initial_call=True,
)
def export_html_with_comments(n_clicks, report_data, comments_data):
    if not n_clicks or not report_data:
        return dash.no_update
    from gws_auditor.dashboard.export import generate_html_export
    html_content = generate_html_export(report_data, comments_data or {})
    return dict(content=html_content, filename="gws_audit_with_comments.html")


@callback(
    Output("comments-data", "data", allow_duplicate=True),
    Input("overview-results-table", "data_timestamp"),
    State("overview-results-table", "data"),
    State("overview-results-table", "data_previous"),
    State("comments-data", "data"),
    State("report-filename", "data"),
    prevent_initial_call=True,
)
def save_inline_edits(ts, data, data_prev, comments_data, filename):
    """Persist inline comment edits from the table."""
    if not data or not data_prev or not filename:
        return dash.no_update
    store = get_report_store()
    comments_data = comments_data or {}
    changed = False
    for cur, prev in zip(data, data_prev):
        cid = cur.get("check_id", "")
        if not cid:
            continue
        # Check for comment changes
        cur_comment = cur.get("comment", "")
        prev_comment = prev.get("comment", "")
        if cur_comment != prev_comment:
            comments_data = store.save_comment(filename, cid, cur_comment or "")
            changed = True
    if changed:
        return comments_data
    return dash.no_update
