# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Anthropic SDK adapter for the AI analyst."""

from __future__ import annotations

import json
import uuid
from typing import Iterator

from .base import LLMProvider, Message, StreamChunk, ToolCall

_DEFAULT_MODEL = "claude-sonnet-4-20250514"


class AnthropicProvider(LLMProvider):
    """LLM provider using the Anthropic Python SDK."""

    def __init__(
        self,
        api_key: str,
        model: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        from anthropic import Anthropic

        self.client = Anthropic(api_key=api_key)
        self.model = model or _DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _convert_tools(tools: list[dict] | None) -> list[dict]:
        """Convert OpenAI-style tool defs to Anthropic format."""
        if not tools:
            return []
        result = []
        for t in tools:
            func = t.get("function", t)
            result.append({
                "name": func["name"],
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
            })
        return result

    def _to_api_messages(self, messages: list[Message]) -> tuple[str, list[dict]]:
        """Split messages into system prompt + API messages list.

        Anthropic takes the system prompt as a separate parameter.
        """
        system_prompt = ""
        api_msgs: list[dict] = []

        for m in messages:
            if m.role == "system":
                system_prompt = m.content
                continue

            if m.role == "user":
                api_msgs.append({"role": "user", "content": m.content})

            elif m.role == "assistant":
                content_blocks: list[dict] = []
                if m.content:
                    content_blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })
                if content_blocks:
                    api_msgs.append({"role": "assistant", "content": content_blocks})

            elif m.role == "tool":
                # Anthropic expects tool results in user messages
                api_msgs.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": m.tool_call_id,
                            "content": m.content,
                        }
                    ],
                })

        return system_prompt, api_msgs

    @staticmethod
    def _parse_response(response) -> Message:
        content_text = ""
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(id=block.id, name=block.name, arguments=block.input or {})
                )

        return Message(role="assistant", content=content_text, tool_calls=tool_calls)

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    def chat(self, messages: list[Message], tools: list[dict] | None = None) -> Message:
        system_prompt, api_msgs = self._to_api_messages(messages)

        kwargs: dict = {
            "model": self.model,
            "messages": api_msgs,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        response = self.client.messages.create(**kwargs)
        return self._parse_response(response)

    def stream_chat(
        self, messages: list[Message], tools: list[dict] | None = None
    ) -> Iterator[StreamChunk]:
        system_prompt, api_msgs = self._to_api_messages(messages)

        kwargs: dict = {
            "model": self.model,
            "messages": api_msgs,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system_prompt:
            kwargs["system"] = system_prompt
        anthropic_tools = self._convert_tools(tools)
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        # Track current tool-use block being built
        current_tool_id = ""
        current_tool_name = ""
        current_tool_args = ""

        with self.client.messages.stream(**kwargs) as stream:
            for event in stream:
                if hasattr(event, "type"):
                    if event.type == "content_block_start":
                        block = event.content_block
                        if block.type == "tool_use":
                            current_tool_id = block.id
                            current_tool_name = block.name
                            current_tool_args = ""

                    elif event.type == "content_block_delta":
                        delta = event.delta
                        if delta.type == "text_delta":
                            yield StreamChunk(delta_text=delta.text)
                        elif delta.type == "input_json_delta":
                            current_tool_args += delta.partial_json

                    elif event.type == "content_block_stop":
                        if current_tool_name:
                            try:
                                args = json.loads(current_tool_args) if current_tool_args else {}
                            except json.JSONDecodeError:
                                args = {}
                            yield StreamChunk(
                                tool_calls=[
                                    ToolCall(
                                        id=current_tool_id or str(uuid.uuid4()),
                                        name=current_tool_name,
                                        arguments=args,
                                    )
                                ],
                            )
                            current_tool_id = ""
                            current_tool_name = ""
                            current_tool_args = ""

                    elif event.type == "message_stop":
                        yield StreamChunk(finish_reason="end_turn")
