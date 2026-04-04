# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Compliance page – per-framework view with section drill-down."""

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.graph_objects as go
from dash import Input, Output, State, callback, dcc, html

from gws_auditor.dashboard.app import get_report_store
from gws_auditor.dashboard.components import (
    apply_overrides,
    build_df,
    build_section_stat_badges,
    build_section_status_bar,
    create_check_detail_modal,
    create_source_card,
    empty_fig,
    source_tag,
    status_badge,
)
from gws_auditor.dashboard.theme import PLOTLY_TEMPLATE, SOURCE_COLORS, STATUS_COLORS, STATUS_ORDER

dash.register_page(__name__, path="/compliance", name="Compliance")

# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

layout = html.Div(
    [
        html.H4("Compliance", className="page-header"),

        dbc.Row(
            dbc.Col(
                [
                    html.Label("Framework", style={"fontSize": "0.75rem", "fontWeight": 600}),
                    dcc.Dropdown(
                        id="compliance-framework",
                        placeholder="All frameworks",
                    ),
                ],
                md=4,
            ),
            className="mb-3",
        ),

        html.Div(id="compliance-source-cards"),

        dbc.Row(
            [
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="compliance-donut")), className="chart-card"), md=6),
                dbc.Col(dbc.Card(dbc.CardBody(dcc.Graph(id="compliance-top-failed")), className="chart-card"), md=6),
            ],
            className="g-3 mb-3",
        ),

        html.H5("Section Details", className="mt-4 mb-3"),
        html.Div(id="compliance-sections-accordion"),
        create_check_detail_modal("compliance-detail-modal"),
        dcc.Store(id="compliance-section-data", data=[]),
    ],
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _source_stats(df: pd.DataFrame, source: str) -> dict:
    sub = df[df["source"] == source]
    total = len(sub)
    passed = int((sub["status"] == "PASS").sum())
    failed = int((sub["status"] == "FAIL").sum())
    evaluated = passed + failed
    return {
        "name": source,
        "total": total,
        "passed": passed,
        "failed": failed,
        "pass_rate": (passed / evaluated * 100) if evaluated else 0,
    }


# ------------------------------------------------------------------
# Callbacks
# ------------------------------------------------------------------

@callback(
    Output("compliance-framework", "options"),
    Input("report-data", "data"),
)
def populate_framework_dropdown(report_data):
    df = build_df(report_data)
    if df.empty or "source" not in df.columns:
        return []
    sources = sorted(df["source"].dropna().unique().tolist())
    return [{"label": s, "value": s} for s in sources]


@callback(
    Output("compliance-source-cards", "children"),
    Output("compliance-donut", "figure"),
    Output("compliance-top-failed", "figure"),
    Output("compliance-sections-accordion", "children"),
    Output("compliance-section-data", "data"),
    Input("compliance-framework", "value"),
    Input("comments-data", "data"),
    State("report-data", "data"),
)
def update_compliance(selected_framework, comments_data, report_data):
    df = build_df(report_data)
    if df.empty:
        empty = empty_fig()
        return html.Div(), empty, empty, html.Div(), []

    # Apply manual overrides
    df = apply_overrides(df, comments_data or {})

    # --- Source cards (always show all) ---
    sources = sorted(df["source"].dropna().unique().tolist())
    source_cards = dbc.Row(
        [create_source_card(**_source_stats(df, s)) for s in sources],
        className="g-3 mb-4",
    )

    # Filter to selected framework
    if selected_framework:
        df = df[df["source"] == selected_framework]
    if df.empty:
        empty = empty_fig()
        return source_cards, empty, empty, html.Div(), []

    fw_label = selected_framework or "All Frameworks"

    # --- Compliance donut ---
    counts = df["status"].value_counts()
    ordered = [s for s in STATUS_ORDER if s in counts.index]
    donut = go.Figure(
        go.Pie(
            labels=ordered,
            values=[int(counts[s]) for s in ordered],
            hole=0.5,
            marker={"colors": [STATUS_COLORS.get(s, "#718096") for s in ordered]},
            textinfo="label+value",
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        ),
    )
    donut.update_layout(title=f"{fw_label} – Compliance Status", template=PLOTLY_TEMPLATE)

    # --- Top 10 failed sections ---
    failed_df = df[df["status"] == "FAIL"]
    if not failed_df.empty and "section" in failed_df.columns:
        top_failed = failed_df["section"].value_counts().head(10).sort_values()
        bar_fig = go.Figure(
            go.Bar(
                y=top_failed.index,
                x=top_failed.values,
                orientation="h",
                marker_color="#e53e3e",
            ),
        )
        bar_fig.update_layout(title="Top Failed Sections", template=PLOTLY_TEMPLATE)
    else:
        bar_fig = empty_fig("Top Failed Sections")

    # --- Section accordion ---
    accordion_items = []
    all_section_rows: list[dict] = []
    row_index = 0
    if "section" in df.columns:
        for section_name in sorted(df["section"].dropna().unique()):
            sec_df = df[df["section"] == section_name]
            sec_passed = int((sec_df["status"] == "PASS").sum())
            sec_failed = int((sec_df["status"] == "FAIL").sum())
            sec_total = len(sec_df)
            sec_evaluated = sec_passed + sec_failed
            sec_rate = (sec_passed / sec_evaluated * 100) if sec_evaluated else 0

            # Build header with stat badges
            stat_badges = build_section_stat_badges(sec_df)
            header_text = f"{section_name}  —  {sec_total} checks, {sec_rate:.0f}% pass"

            rows = []
            for _, r in sec_df.iterrows():
                st = r.get("status", "")
                badge_cls = {
                    "PASS": "badge-pass", "FAIL": "badge-fail", "WARN": "badge-warn",
                    "ERROR": "badge-error", "MANUAL": "badge-manual", "NOT_APPLICABLE": "badge-na",
                }.get(st, "")
                details_text = str(r.get("details", "") or "")
                src = r.get("source", "")
                all_section_rows.append({
                    "check_id": r.get("check_id", ""),
                    "title": r.get("title", ""),
                    "status": st,
                    "level": r.get("level", ""),
                    "source": src,
                    "section": section_name,
                    "details": details_text,
                    "actual_value": str(r.get("actual_value", "") or ""),
                    "expected_value": str(r.get("expected_value", "") or ""),
                    "org_unit": r.get("org_unit", "") or "",
                    "remediation": str(r.get("remediation", "") or ""),
                })
                rows.append(
                    html.Tr(
                        [
                            html.Td(
                                html.Span([
                                    html.Code(r.get("check_id", ""), className="check-id-code"),
                                    source_tag(src) if src else "",
                                ]),
                            ),
                            html.Td(r.get("title", ""), style={"maxWidth": "350px", "overflow": "hidden", "textOverflow": "ellipsis"}),
                            html.Td(html.Span(st, className=f"status-badge status-badge--{st}")),
                            html.Td(r.get("level", "")),
                            html.Td(
                                details_text,
                                title=details_text,
                                style={"maxWidth": "300px", "overflow": "hidden", "textOverflow": "ellipsis", "whiteSpace": "nowrap"},
                            ),
                        ],
                        id={"type": "compliance-row", "index": row_index},
                        style={"cursor": "pointer"},
                        n_clicks=0,
                    ),
                )
                row_index += 1

            table = dbc.Table(
                [
                    html.Thead(
                        html.Tr(
                            [html.Th("Check ID"), html.Th("Title"), html.Th("Status"), html.Th("Level"), html.Th("Details")],
                        ),
                    ),
                    html.Tbody(rows),
                ],
                bordered=True,
                hover=True,
                size="sm",
                className="mb-0",
            )

            # Multi-color status bar
            status_bar = build_section_status_bar(sec_df)

            # Stat badges row
            badges_row = html.Div(stat_badges, className="mb-2") if stat_badges else html.Div()

            accordion_items.append(
                dbc.AccordionItem(
                    [status_bar, badges_row, table],
                    title=header_text,
                ),
            )

    accordion = dbc.Accordion(accordion_items, start_collapsed=True) if accordion_items else html.Div("No sections found.")

    return source_cards, donut, bar_fig, accordion, all_section_rows


@callback(
    Output("compliance-detail-modal", "is_open"),
    Output("compliance-detail-modal-check-id", "children"),
    Output("compliance-detail-modal-source-tag", "children"),
    Output("compliance-detail-modal-title", "children"),
    Output("compliance-detail-modal-status", "children"),
    Output("compliance-detail-modal-level", "children"),
    Output("compliance-detail-modal-section", "children"),
    Output("compliance-detail-modal-details", "children"),
    Output("compliance-detail-modal-actual", "children"),
    Output("compliance-detail-modal-expected", "children"),
    Output("compliance-detail-modal-org-unit", "children"),
    Output("compliance-detail-modal-remediation", "children"),
    Output("compliance-detail-modal-comment-text", "value"),
    Output("compliance-detail-modal-comment-author", "value"),
    Output("compliance-detail-modal-comment-status", "children"),
    Input({"type": "compliance-row", "index": dash.ALL}, "n_clicks"),
    State("compliance-section-data", "data"),
    State("comments-data", "data"),
    prevent_initial_call=True,
)
def open_compliance_modal(n_clicks_list, section_data, comments_data):
    if not n_clicks_list or not section_data or not any(n_clicks_list):
        return False, "", "", "", "", "", "", "", "", "", "", "", "", "", ""
    triggered = dash.ctx.triggered_id
    if not triggered or not isinstance(triggered, dict):
        return (dash.no_update,) * 15
    idx = triggered.get("index")
    if idx is None or idx >= len(section_data):
        return False, "", "", "", "", "", "", "", "", "", "", "", "", "", ""
    row = section_data[idx]
    check_id = row.get("check_id", "")
    src = row.get("source", "")
    st = row.get("status", "")
    existing = (comments_data or {}).get(check_id, {})
    return (
        True,
        check_id,
        source_tag(src) if src else "",
        row.get("title", ""),
        status_badge(st) if st else "",
        row.get("level", ""),
        row.get("section", ""),
        row.get("details", ""),
        row.get("actual_value", "") or "N/A",
        row.get("expected_value", "") or "N/A",
        row.get("org_unit", "") or "/",
        row.get("remediation", "") or "None",
        existing.get("comment", ""),
        existing.get("author", ""),
        "",
    )


@callback(
    Output("comments-data", "data", allow_duplicate=True),
    Output("compliance-detail-modal-comment-status", "children", allow_duplicate=True),
    Input("compliance-detail-modal-save-comment", "n_clicks"),
    State("compliance-detail-modal-check-id", "children"),
    State("compliance-detail-modal-comment-text", "value"),
    State("compliance-detail-modal-comment-author", "value"),
    State("report-filename", "data"),
    prevent_initial_call=True,
)
def save_compliance_comment(n_clicks, check_id, comment, author, filename):
    if not n_clicks or not check_id or not filename:
        return dash.no_update, ""
    store = get_report_store()
    updated = store.save_comment(filename, check_id, comment or "", author or "")
    return updated, "Comment saved."
