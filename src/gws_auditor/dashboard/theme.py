# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Color constants and Plotly template for the dashboard."""

# Status colors (matching existing HTML report)
STATUS_COLORS = {
    "PASS": "#38a169",
    "FAIL": "#e53e3e",
    "WARN": "#d69e2e",
    "ERROR": "#9b2c2c",
    "MANUAL": "#3182ce",
    "NOT_APPLICABLE": "#a0aec0",
}

STATUS_ORDER = ["PASS", "FAIL", "WARN", "ERROR", "MANUAL", "NOT_APPLICABLE"]

# CSS class suffix for status badges
STATUS_BADGE_CLASS = {
    "PASS": "status-badge--PASS",
    "FAIL": "status-badge--FAIL",
    "WARN": "status-badge--WARN",
    "ERROR": "status-badge--ERROR",
    "MANUAL": "status-badge--MANUAL",
    "NOT_APPLICABLE": "status-badge--NOT_APPLICABLE",
}

# Source / framework colors
SOURCE_COLORS = {
    "CIS": "#3182ce",
    "CISA": "#805ad5",
    "GOOGLE": "#dd6b20",
    "OTHER": "#38b2ac",
}

# CSS class for source tags
SOURCE_TAG_CLASS = {
    "CIS": "source-tag source-tag--CIS",
    "CISA": "source-tag source-tag--CISA",
    "GOOGLE": "source-tag source-tag--GOOGLE",
    "OTHER": "source-tag source-tag--OTHER",
}

# Sidebar / chrome
SIDEBAR_BG = "#1a2540"
SIDEBAR_BG_END = "#2b3d5b"
SIDEBAR_TEXT = "#cbd5e0"
SIDEBAR_ACTIVE = "#3182ce"
CONTENT_BG = "#f7fafc"

# Card metric colors
METRIC_COLORS = {
    "total": "#2d3748",
    "passed": "#38a169",
    "failed": "#e53e3e",
    "warnings": "#d69e2e",
    "errors": "#9b2c2c",
    "manual": "#3182ce",
    "na": "#a0aec0",
    "pass_rate": "#2b6cb0",
    "posture_score": "#2c5282",
}

# Plotly layout template (light mode default; JS updates colors on theme toggle)
PLOTLY_TEMPLATE = {
    "layout": {
        "paper_bgcolor": "rgba(0,0,0,0)",
        "plot_bgcolor": "rgba(0,0,0,0)",
        "font": {
            "family": "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
            "color": "#2d3748",
        },
        "margin": {"l": 40, "r": 20, "t": 60, "b": 40},
        "legend": {"orientation": "h", "yanchor": "top", "y": -0.15, "xanchor": "center", "x": 0.5},
        "title": {"y": 0.97, "yanchor": "top"},
    },
}

# Dark mode Plotly colors (applied by theme_toggle.js)
PLOTLY_DARK_FONT_COLOR = "#f3f4f6"
PLOTLY_DARK_GRID_COLOR = "#374151"
