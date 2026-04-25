# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""AnalystSession -- conversation orchestrator with tool-calling loop."""

from __future__ import annotations

import json
from typing import Any, Iterator

from .prompt import build_system_prompt
from .providers.base import LLMProvider, Message, StreamChunk, ToolCall
from .tools import TOOL_DEFINITIONS, execute_tool

_MAX_TOOL_ITERATIONS = 10


class AnalystSession:
    """Manages a conversation between the user and the AI security analyst.

    The session maintains conversation history, handles the tool-calling loop,
    and delegates LLM calls to the configured provider.
    """

    def __init__(
        self,
        provider: LLMProvider,
        report_data: dict,
        report_store: Any = None,
        business_context: str = "",
    ) -> None:
        self.provider = provider
        self.report_data = report_data
        self.report_store = report_store
        self.business_context = business_context

        self._system_prompt = build_system_prompt(report_data, business_context)
        self.history: list[Message] = [
            Message(role="system", content=self._system_prompt),
        ]

    def ask(self, user_message: str) -> tuple[str, int, int]:
        """Send a user message and return (response_text, input_tokens, output_tokens).

        Handles the tool-calling loop internally: if the LLM requests tool
        calls, they are executed and the results fed back until the LLM
        produces a text response. Token counts are aggregated across all
        provider calls in the loop.
        """
        self.history.append(Message(role="user", content=user_message))
        total_input = 0
        total_output = 0

        for _ in range(_MAX_TOOL_ITERATIONS):
            response = self.provider.chat(self.history, tools=TOOL_DEFINITIONS)
            total_input += response.input_tokens
            total_output += response.output_tokens
            self.history.append(response)

            if not response.tool_calls:
                return response.content, total_input, total_output

            # Execute each tool call and append results
            for tc in response.tool_calls:
                result_str = execute_tool(
                    tc.name, tc.arguments, self.report_data, self.report_store,
                )
                self.history.append(
                    Message(
                        role="tool",
                        content=result_str,
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

        # Safety: if we hit the max iterations, return whatever we have
        text = self.history[-1].content if self.history else ""
        return text, total_input, total_output

    def ask_stream(self, user_message: str) -> Iterator[str]:
        """Streaming variant of ``ask``.

        Yields text tokens as they arrive. Tool calls are handled internally
        (no tokens yielded during tool execution).
        """
        self.history.append(Message(role="user", content=user_message))

        for _ in range(_MAX_TOOL_ITERATIONS):
            # Collect the full response while streaming text tokens
            collected_text = ""
            collected_tool_calls: list[ToolCall] = []

            for chunk in self.provider.stream_chat(self.history, tools=TOOL_DEFINITIONS):
                if chunk.delta_text:
                    collected_text += chunk.delta_text
                    yield chunk.delta_text
                if chunk.tool_calls:
                    collected_tool_calls.extend(chunk.tool_calls)

            # Build the assistant message
            response = Message(
                role="assistant",
                content=collected_text,
                tool_calls=collected_tool_calls,
            )
            self.history.append(response)

            if not collected_tool_calls:
                return

            # Execute tool calls
            for tc in collected_tool_calls:
                result_str = execute_tool(
                    tc.name, tc.arguments, self.report_data, self.report_store,
                )
                self.history.append(
                    Message(
                        role="tool",
                        content=result_str,
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

    def reset(self) -> None:
        """Clear conversation history, keeping the system prompt."""
        self.history = [Message(role="system", content=self._system_prompt)]

    def set_report(self, report_data: dict) -> None:
        """Switch to a different report and rebuild the system prompt."""
        self.report_data = report_data
        self._system_prompt = build_system_prompt(report_data, self.business_context)
        self.reset()
