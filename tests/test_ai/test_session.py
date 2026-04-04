"""Tests for AnalystSession with MockProvider -- no LLM SDK required."""

import json
from typing import Iterator

import pytest

from gws_auditor.ai.providers.base import LLMProvider, Message, StreamChunk, ToolCall
from gws_auditor.ai.session import AnalystSession


class MockProvider(LLMProvider):
    """Mock LLM provider with pre-configured responses for testing."""

    def __init__(self, responses: list[Message] | None = None):
        self.responses = list(responses or [])
        self._call_count = 0
        self.received_messages: list[list[Message]] = []

    def chat(self, messages: list[Message], tools: list[dict] | None = None) -> Message:
        self.received_messages.append(list(messages))
        if self._call_count < len(self.responses):
            resp = self.responses[self._call_count]
            self._call_count += 1
            return resp
        return Message(role="assistant", content="No more responses configured.")

    def stream_chat(
        self, messages: list[Message], tools: list[dict] | None = None
    ) -> Iterator[StreamChunk]:
        msg = self.chat(messages, tools)
        if msg.tool_calls:
            yield StreamChunk(tool_calls=msg.tool_calls, finish_reason="tool_calls")
        else:
            # Yield text in small chunks
            text = msg.content
            for i in range(0, len(text), 10):
                yield StreamChunk(delta_text=text[i : i + 10])
            yield StreamChunk(finish_reason="stop")


@pytest.fixture
def sample_report():
    return {
        "timestamp": "2026-02-19T10:30:00",
        "customer_id": "C03example",
        "domains": ["example.com"],
        "summary": {
            "total": 3,
            "passed": 2,
            "failed": 1,
            "warnings": 0,
            "errors": 0,
            "manual": 0,
            "not_applicable": 0,
            "pass_rate": 66.7,
        },
        "results": [
            {
                "check_id": "CIS-1.1.1",
                "title": "Ensure more than one Super Admin",
                "status": "PASS",
                "level": "L1",
                "source": "CIS",
                "section": "Directory",
                "details": "Found 3 super admins",
                "remediation": "",
            },
            {
                "check_id": "CIS-1.1.3",
                "title": "Super Admin hardware MFA",
                "status": "FAIL",
                "level": "L1",
                "source": "CIS",
                "section": "Directory",
                "details": "1 admin without HW key",
                "remediation": "Enroll in hardware MFA",
            },
            {
                "check_id": "CIS-4.1.1",
                "title": "Ensure 2SV enforced",
                "status": "PASS",
                "level": "L1",
                "source": "CIS",
                "section": "Security",
                "details": "2SV enforced",
                "remediation": "",
            },
        ],
    }


class TestSimpleTextResponse:
    def test_ask_returns_text(self, sample_report):
        provider = MockProvider([
            Message(role="assistant", content="The audit shows 3 checks total.")
        ])
        session = AnalystSession(provider, sample_report)
        result = session.ask("Summarise the audit")
        assert "3 checks" in result

    def test_history_includes_user_and_assistant(self, sample_report):
        provider = MockProvider([
            Message(role="assistant", content="Done.")
        ])
        session = AnalystSession(provider, sample_report)
        session.ask("Hello")
        # system + user + assistant
        assert len(session.history) == 3
        assert session.history[0].role == "system"
        assert session.history[1].role == "user"
        assert session.history[1].content == "Hello"
        assert session.history[2].role == "assistant"


class TestToolCallingLoop:
    def test_tool_call_then_text(self, sample_report):
        """LLM requests a tool call, gets result, then responds with text."""
        provider = MockProvider([
            # First response: tool call
            Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="call_1",
                        name="get_audit_summary",
                        arguments={},
                    )
                ],
            ),
            # Second response: text based on tool result
            Message(
                role="assistant",
                content="Your audit has 3 checks with a 66.7% pass rate.",
            ),
        ])
        session = AnalystSession(provider, sample_report)
        result = session.ask("What's the audit summary?")
        assert "66.7%" in result

        # Verify the tool result was injected into history
        tool_msgs = [m for m in session.history if m.role == "tool"]
        assert len(tool_msgs) == 1
        tool_result = json.loads(tool_msgs[0].content)
        assert tool_result["total"] == 3

    def test_tool_result_contains_data(self, sample_report):
        """Verify tool executor returns correct data."""
        provider = MockProvider([
            Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(
                        id="call_1",
                        name="search_findings",
                        arguments={"status": ["FAIL"]},
                    )
                ],
            ),
            Message(role="assistant", content="Found 1 failure."),
        ])
        session = AnalystSession(provider, sample_report)
        session.ask("Show failures")

        tool_msgs = [m for m in session.history if m.role == "tool"]
        findings = json.loads(tool_msgs[0].content)
        assert len(findings) == 1
        assert findings[0]["check_id"] == "CIS-1.1.3"


class TestReset:
    def test_reset_clears_history(self, sample_report):
        provider = MockProvider([
            Message(role="assistant", content="Hi.")
        ])
        session = AnalystSession(provider, sample_report)
        session.ask("Hello")
        assert len(session.history) == 3

        session.reset()
        assert len(session.history) == 1
        assert session.history[0].role == "system"


class TestStreaming:
    def test_stream_text(self, sample_report):
        provider = MockProvider([
            Message(role="assistant", content="Streaming response here.")
        ])
        session = AnalystSession(provider, sample_report)
        tokens = list(session.ask_stream("Hello"))
        full_text = "".join(tokens)
        assert full_text == "Streaming response here."

    def test_stream_with_tool_call(self, sample_report):
        """Streaming should handle tool calls and resume."""
        provider = MockProvider([
            Message(
                role="assistant",
                content="",
                tool_calls=[
                    ToolCall(id="call_1", name="get_audit_summary", arguments={})
                ],
            ),
            Message(role="assistant", content="Summary: 3 checks."),
        ])
        session = AnalystSession(provider, sample_report)
        tokens = list(session.ask_stream("Summarise"))
        full_text = "".join(tokens)
        assert "3 checks" in full_text


class TestBusinessContext:
    def test_business_context_in_system_prompt(self, sample_report):
        provider = MockProvider([
            Message(role="assistant", content="Ok.")
        ])
        session = AnalystSession(
            provider, sample_report, business_context="Healthcare HIPAA org"
        )
        system_msg = session.history[0]
        assert "Healthcare HIPAA org" in system_msg.content

    def test_no_business_context(self, sample_report):
        provider = MockProvider([])
        session = AnalystSession(provider, sample_report)
        system_msg = session.history[0]
        assert "Business Context" not in system_msg.content


class TestSetReport:
    def test_set_report_updates_prompt(self, sample_report):
        provider = MockProvider([])
        session = AnalystSession(provider, sample_report)

        new_report = dict(sample_report)
        new_report["customer_id"] = "C04different"
        session.set_report(new_report)

        assert "C04different" in session.history[0].content
        assert len(session.history) == 1  # reset happened
