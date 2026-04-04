# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""AI Analyst chat page for the dashboard."""

import threading
import time

import dash
import dash_bootstrap_components as dbc
from dash import Input, Output, State, callback, ctx, dcc, html

dash.register_page(__name__, path="/analyst", name="AI Analyst")

# Module-level session cache
_analyst_session = None
_session_report_ts = None

# Shared streaming state
_stream_buffer = ""
_stream_complete = False
_stream_error = None
_stream_lock = threading.Lock()
_stream_start_time = 0.0


def _get_or_create_session(report_data):
    """Lazily create or refresh the AnalystSession."""
    global _analyst_session, _session_report_ts

    try:
        from gws_auditor.ai.config import load_ai_config
        from gws_auditor.ai.providers import get_provider
        from gws_auditor.ai.session import AnalystSession
    except ImportError:
        return None

    if report_data is None:
        return None

    report_ts = report_data.get("timestamp", "")

    if _analyst_session is None or _session_report_ts != report_ts:
        try:
            from gws_auditor.dashboard.app import get_report_store
            report_store = get_report_store()
        except Exception:
            report_store = None

        # Load the main config.yaml so the ai: section (with api_key) is picked up
        from gws_auditor.config import load_config
        full_config = load_config("config.yaml")
        config = load_ai_config(config_dict=full_config.get("ai"))
        provider = get_provider(config)
        _analyst_session = AnalystSession(
            provider=provider,
            report_data=report_data,
            report_store=report_store,
            business_context=config.business_context,
        )
        _session_report_ts = report_ts

    return _analyst_session


def _render_messages(messages):
    """Convert message list to styled Dash components."""
    children = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if role == "user":
            children.append(
                html.Div(
                    html.Div(content, className="chat-bubble chat-bubble-user"),
                    className="chat-message chat-message-user",
                )
            )
        elif role == "assistant":
            children.append(
                html.Div(
                    html.Div(
                        dcc.Markdown(content, className="chat-markdown"),
                        className="chat-bubble chat-bubble-assistant",
                    ),
                    className="chat-message chat-message-assistant",
                )
            )
    return children


def _run_stream(session, user_input):
    """Run in background thread -- stream tokens from the LLM incrementally."""
    global _stream_buffer, _stream_complete, _stream_error
    try:
        for token in session.ask_stream(user_input):
            with _stream_lock:
                _stream_buffer += token
    except Exception as exc:
        with _stream_lock:
            _stream_error = exc
    finally:
        with _stream_lock:
            _stream_complete = True


# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

layout = html.Div(
    [
        html.H4("AI Security Analyst", className="page-header"),
        html.Div(id="analyst-status", className="mb-3"),

        # Chat area
        html.Div(
            id="analyst-messages",
            className="chat-container",
            children=[
                html.Div(
                    "Ask me about your audit findings, compliance posture, "
                    "or remediation priorities.",
                    className="text-muted p-3",
                )
            ],
        ),

        # Input row
        dbc.InputGroup(
            [
                dbc.Input(
                    id="analyst-input",
                    placeholder="Ask about your security audit...",
                    type="text",
                    debounce=True,
                    className="chat-input",
                ),
                dbc.Button(
                    "Send",
                    id="analyst-send-btn",
                    color="primary",
                    className="chat-send-btn",
                ),
            ],
            className="chat-input-group mt-2",
        ),

        # Client-side stores
        dcc.Store(id="analyst-history", storage_type="memory", data=[]),
        dcc.Store(id="analyst-streaming", storage_type="memory", data=False),

        # Polling interval for streaming updates (starts disabled)
        dcc.Interval(id="analyst-poll", interval=300, disabled=True),
    ],
)


# ------------------------------------------------------------------
# Callbacks
# ------------------------------------------------------------------

@callback(
    Output("analyst-status", "children"),
    Input("report-data", "data"),
)
def update_status(report_data):
    """Show model info or install instructions."""
    try:
        from gws_auditor.ai.config import load_ai_config
        from gws_auditor.config import load_config
        full_config = load_config("config.yaml")
        config = load_ai_config(config_dict=full_config.get("ai"))
        return html.Small(
            f"Provider: {config.provider} | Model: {config.model or 'default'}",
            className="text-muted",
        )
    except ImportError:
        return dbc.Alert(
            [
                "AI dependencies not installed. Run: ",
                html.Code('pip install gws-security-auditor[ai]'),
            ],
            color="warning",
        )


NO_UPDATE_7 = (dash.no_update,) * 7


@callback(
    Output("analyst-messages", "children"),
    Output("analyst-history", "data"),
    Output("analyst-input", "value"),
    Output("analyst-poll", "disabled"),
    Output("analyst-streaming", "data"),
    Output("analyst-send-btn", "disabled"),
    Output("analyst-input", "disabled"),
    Input("analyst-send-btn", "n_clicks"),
    Input("analyst-input", "n_submit"),
    Input("analyst-poll", "n_intervals"),
    State("analyst-input", "value"),
    State("analyst-history", "data"),
    State("analyst-streaming", "data"),
    State("report-data", "data"),
    prevent_initial_call=True,
)
def handle_chat(n_clicks, n_submit, n_intervals, user_input, history, is_streaming, report_data):
    """Unified callback: handle send + poll in one callback (no allow_duplicate)."""
    global _stream_buffer, _stream_complete, _stream_error, _stream_start_time

    trigger = ctx.triggered_id

    # ---- Polling branch ----
    if trigger == "analyst-poll":
        if not is_streaming:
            return NO_UPDATE_7

        with _stream_lock:
            current_text = _stream_buffer
            done = _stream_complete
            error = _stream_error

        if error:
            history = list(history or [])
            history.append({"role": "assistant", "content": f"Error: {error}"})
            return _render_messages(history), history, dash.no_update, True, False, False, False

        if done:
            history = list(history or [])
            history.append({"role": "assistant", "content": current_text})
            return _render_messages(history), history, dash.no_update, True, False, False, False

        # Still streaming -- show partial text or a waiting indicator
        if current_text:
            partial_history = list(history or []) + [
                {"role": "assistant", "content": current_text + "\u258c"}
            ]
            messages_ui = _render_messages(partial_history)
        else:
            # No tokens yet — show elapsed timer so user knows it's working
            elapsed = int(time.time() - _stream_start_time)
            thinking_bubble = html.Div(
                html.Div(
                    [
                        html.Span("Thinking", className="chat-thinking"),
                        html.Span(
                            f"  {elapsed}s",
                            style={"color": "#a0aec0", "fontSize": "0.8rem"},
                        ),
                    ],
                    className="chat-bubble chat-bubble-assistant",
                ),
                className="chat-message chat-message-assistant",
            )
            messages_ui = _render_messages(list(history or [])) + [thinking_bubble]

        return (messages_ui, dash.no_update,
                dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update)

    # ---- Send branch (button click or Enter) ----
    if is_streaming:
        return NO_UPDATE_7

    if not user_input or not user_input.strip():
        return NO_UPDATE_7

    user_input = user_input.strip()
    history = list(history or [])

    # Add user message
    history.append({"role": "user", "content": user_input})

    # Try to get the session
    session = _get_or_create_session(report_data)
    if session is None:
        history.append({
            "role": "assistant",
            "content": (
                "AI analyst is not available. Please install AI dependencies:\n\n"
                "```\npip install gws-security-auditor[ai]\n```"
            ),
        })
        return _render_messages(history), history, "", True, False, False, False

    # Reset shared buffer and start background stream
    _stream_start_time = time.time()
    with _stream_lock:
        _stream_buffer = ""
        _stream_complete = False
        _stream_error = None

    thread = threading.Thread(target=_run_stream, args=(session, user_input), daemon=True)
    thread.start()

    # Render user message + thinking indicator
    thinking_bubble = html.Div(
        html.Div(
            html.Span("Thinking", className="chat-thinking"),
            className="chat-bubble chat-bubble-assistant",
        ),
        className="chat-message chat-message-assistant",
    )
    messages_ui = _render_messages(history) + [thinking_bubble]

    # Return immediately: enable polling, mark streaming, disable input
    return messages_ui, history, "", False, True, True, True
