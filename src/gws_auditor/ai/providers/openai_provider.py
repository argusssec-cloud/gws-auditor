# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""OpenAI SDK adapter for the AI analyst."""

from __future__ import annotations

import json
import uuid
from typing import Iterator

from .base import LLMProvider, Message, StreamChunk, ToolCall

_DEFAULT_MODEL = "gpt-4o"


class OpenAIProvider(LLMProvider):
    """LLM provider using the OpenAI Python SDK."""

    def __init__(
        self,
        api_key: str,
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
        base_url: str = "",
    ) -> None:
        from openai import OpenAI

        client_kwargs: dict = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url

        self.client = OpenAI(**client_kwargs)
        self.model = model or _DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_api_messages(messages: list[Message]) -> list[dict]:
        api_msgs: list[dict] = []
        for m in messages:
            if m.role == "tool":
                api_msgs.append({
                    "role": "tool",
                    "content": m.content,
                    "tool_call_id": m.tool_call_id,
                })
            elif m.role == "assistant" and m.tool_calls:
                api_msgs.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in m.tool_calls
                    ],
                })
            else:
                api_msgs.append({"role": m.role, "content": m.content})
        return api_msgs

    @staticmethod
    def _parse_tool_calls(api_tool_calls) -> list[ToolCall]:
        if not api_tool_calls:
            return []
        result = []
        for tc in api_tool_calls:
            args = tc.function.arguments
            try:
                parsed = json.loads(args) if isinstance(args, str) else args
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            result.append(ToolCall(id=tc.id, name=tc.function.name, arguments=parsed))
        return result

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    def chat(self, messages: list[Message], tools: list[dict] | None = None) -> Message:
        kwargs: dict = {
            "model": self.model,
            "messages": self._to_api_messages(messages),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        msg = choice.message

        return Message(
            role="assistant",
            content=msg.content or "",
            tool_calls=self._parse_tool_calls(msg.tool_calls),
        )

    def stream_chat(
        self, messages: list[Message], tools: list[dict] | None = None
    ) -> Iterator[StreamChunk]:
        kwargs: dict = {
            "model": self.model,
            "messages": self._to_api_messages(messages),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "stream": True,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        stream = self.client.chat.completions.create(**kwargs)

        # Accumulate tool calls across chunks
        tool_call_accum: dict[int, dict] = {}

        for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            finish = chunk.choices[0].finish_reason if chunk.choices else None

            text = ""
            if delta and delta.content:
                text = delta.content

            # Accumulate tool call deltas
            if delta and delta.tool_calls:
                for tc_delta in delta.tool_calls:
                    idx = tc_delta.index
                    if idx not in tool_call_accum:
                        tool_call_accum[idx] = {
                            "id": tc_delta.id or "",
                            "name": "",
                            "arguments": "",
                        }
                    if tc_delta.id:
                        tool_call_accum[idx]["id"] = tc_delta.id
                    if tc_delta.function:
                        if tc_delta.function.name:
                            tool_call_accum[idx]["name"] = tc_delta.function.name
                        if tc_delta.function.arguments:
                            tool_call_accum[idx]["arguments"] += tc_delta.function.arguments

            # On finish, emit accumulated tool calls
            completed_tools: list[ToolCall] = []
            if finish:
                for _idx in sorted(tool_call_accum.keys()):
                    tc_data = tool_call_accum[_idx]
                    try:
                        args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
                    except json.JSONDecodeError:
                        args = {}
                    completed_tools.append(
                        ToolCall(
                            id=tc_data["id"] or str(uuid.uuid4()),
                            name=tc_data["name"],
                            arguments=args,
                        )
                    )
                tool_call_accum.clear()

            yield StreamChunk(
                delta_text=text,
                tool_calls=completed_tools,
                finish_reason=finish,
            )
