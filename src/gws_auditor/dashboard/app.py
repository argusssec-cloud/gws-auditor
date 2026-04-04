# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Dash application factory for GWS Security Auditor dashboard."""

from pathlib import Path

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback, dcc, html

from .data_loader import ReportStore

# Module-level store, set by create_app()
_report_store: ReportStore | None = None


def get_report_store() -> ReportStore:
    """Access the global ReportStore instance."""
    assert _report_store is not None, "ReportStore not initialised"
    return _report_store


def _build_sidebar() -> html.Div:
    """Create the fixed dark sidebar with toggle button."""
    return html.Div(
        [
            # Toggle button – always visible, independently positioned
            html.Button(
                html.Span("☰", style={"fontSize": "1.25rem"}),
                id="sidebar-toggle",
                className="sidebar-toggle-btn",
                n_clicks=0,
            ),
            # Collapsible sidebar panel
            html.Div(
                [
                    html.Div(
                        [
                            html.H4("GWS Auditor", className="sidebar-brand"),
                            html.Hr(className="sidebar-divider"),
                        ],
                    ),
                    html.Div(
                        [
                            html.Label("Report", className="sidebar-label"),
                            dcc.Dropdown(
                                id="report-selector",
                                placeholder="Select a report...",
                                className="sidebar-dropdown",
                            ),
                        ],
                        className="sidebar-section",
                    ),
                    html.Hr(className="sidebar-divider"),
                    dbc.Nav(
                        [
                            dbc.NavLink(
                                "Overview",
                                href="/",
                                active="exact",
                                className="sidebar-link",
                            ),
                            dbc.NavLink(
                                "Compliance",
                                href="/compliance",
                                active="exact",
                                className="sidebar-link",
                            ),
                            dbc.NavLink(
                                "Inventory",
                                href="/inventory",
                                active="exact",
                                className="sidebar-link",
                            ),
                            dbc.NavLink(
                                "AI Analyst",
                                href="/analyst",
                                active="exact",
                                className="sidebar-link",
                            ),
                        ],
                        vertical=True,
                        pills=True,
                    ),
                    html.Hr(className="sidebar-divider"),
                    html.Div(
                        [html.Span("🌙", style={"marginRight": "0.4rem"}), "Dark Mode"],
                        id="theme-toggle",
                        className="theme-toggle-sidebar",
                    ),
                ],
                id="sidebar-panel",
                className="sidebar-panel",
            ),
        ],
    )


def _build_layout() -> html.Div:
    """Build the top-level layout with sidebar + content area."""
    return html.Div(
        [
            dcc.Store(id="report-data", storage_type="memory"),
            dcc.Store(id="report-filename", storage_type="memory"),
            dcc.Store(id="comments-data", storage_type="memory", data={}),
            dcc.Store(id="sidebar-open", data=True),
            _build_sidebar(),
            html.Div(
                dash.page_container,
                id="content-area",
                className="content-area",
            ),
        ],
    )


def create_app(reports_dir: str = "./reports", **kwargs) -> dash.Dash:
    """Create and configure the Dash application.

    Args:
        reports_dir: Path to the directory containing audit JSON reports.
        **kwargs: Extra keyword arguments forwarded to ``Dash()``.

    Returns:
        A configured ``dash.Dash`` instance ready to be run.
    """
    global _report_store
    _report_store = ReportStore(reports_dir)

    from gws_auditor._frozen import resolve_package_path
    _dir = resolve_package_path(__file__)
    pages_dir = str(_dir / "pages")
    assets_dir = str(_dir / "assets")

    app = dash.Dash(
        __name__,
        use_pages=True,
        pages_folder=pages_dir,
        assets_folder=assets_dir,
        external_stylesheets=[dbc.themes.FLATLY],
        suppress_callback_exceptions=True,
        **kwargs,
    )

    app.layout = _build_layout()

    # ------------------------------------------------------------------
    # App-level callbacks
    # ------------------------------------------------------------------

    @app.callback(
        Output("sidebar-open", "data"),
        Output("sidebar-panel", "className"),
        Output("content-area", "className"),
        Output("sidebar-toggle", "className"),
        Input("sidebar-toggle", "n_clicks"),
        State("sidebar-open", "data"),
        prevent_initial_call=True,
    )
    def toggle_sidebar(n_clicks, is_open):
        """Open / close the sidebar."""
        new_state = not is_open
        if new_state:
            panel_cls = "sidebar-panel"
            content_cls = "content-area"
            btn_cls = "sidebar-toggle-btn"
        else:
            panel_cls = "sidebar-panel sidebar-panel-closed"
            content_cls = "content-area content-area-collapsed"
            btn_cls = "sidebar-toggle-btn sidebar-toggle-btn-collapsed"
        return new_state, panel_cls, content_cls, btn_cls

    @app.callback(
        Output("report-selector", "options"),
        Output("report-selector", "value"),
        Input("report-selector", "id"),  # fires once on load
    )
    def populate_report_selector(_id):
        """Fill the report dropdown from discovered files."""
        store = get_report_store()
        reports = store.list_reports()
        options = [
            {
                "label": f"{r['timestamp']} ({r['customer_id']}) - {r['pass_rate']:.0f}%",
                "value": r["filename"],
            }
            for r in reports
        ]
        # Auto-select the first (most recent) report
        value = options[0]["value"] if options else None
        return options, value

    @app.callback(
        Output("report-data", "data"),
        Output("report-filename", "data"),
        Output("comments-data", "data"),
        Input("report-selector", "value"),
        prevent_initial_call=True,
    )
    def load_report_data(filename):
        """Load the selected report and its comments into client-side Stores."""
        if not filename:
            return dash.no_update, dash.no_update, dash.no_update
        store = get_report_store()
        report = store.load_report(filename)
        comments = store.load_comments(filename)
        return report, filename, comments

    # Dark mode toggle is handled by assets/theme_toggle.js (pure JS)

    return app
