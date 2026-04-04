# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""AWS Bedrock Converse API adapter for the AI analyst."""

from __future__ import annotations

import json
import uuid
from typing import Iterator

from .base import LLMProvider, Message, StreamChunk, ToolCall

_DEFAULT_MODEL = "anthropic.claude-sonnet-4-20250514-v1:0"


class BedrockProvider(LLMProvider):
    """LLM provider using the boto3 Bedrock Runtime converse API."""

    def __init__(
        self,
        model: str = "",
        region: str = "us-east-1",
        profile: str = "",
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        import boto3

        session_kwargs: dict = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile

        session = boto3.Session(**session_kwargs)
        self.client = session.client("bedrock-runtime")
        self.model = model or _DEFAULT_MODEL
        self.temperature = temperature
        self.max_tokens = max_tokens

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _convert_tools(tools: list[dict] | None) -> dict | None:
        """Convert OpenAI-style tool defs to Bedrock toolConfig format."""
        if not tools:
            return None
        tool_list = []
        for t in tools:
            func = t.get("function", t)
            tool_list.append({
                "toolSpec": {
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "inputSchema": {
                        "json": func.get("parameters", {"type": "object", "properties": {}}),
                    },
                }
            })
        return {"tools": tool_list}

    def _to_api_messages(self, messages: list[Message]) -> tuple[list[dict], list[dict]]:
        """Convert to Bedrock format, returning (system, messages)."""
        system_blocks: list[dict] = []
        api_msgs: list[dict] = []

        for m in messages:
            if m.role == "system":
                system_blocks.append({"text": m.content})

            elif m.role == "user":
                api_msgs.append({
                    "role": "user",
                    "content": [{"text": m.content}],
                })

            elif m.role == "assistant":
                content_blocks: list[dict] = []
                if m.content:
                    content_blocks.append({"text": m.content})
                for tc in m.tool_calls:
                    content_blocks.append({
                        "toolUse": {
                            "toolUseId": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }
                    })
                if content_blocks:
                    api_msgs.append({"role": "assistant", "content": content_blocks})

            elif m.role == "tool":
                api_msgs.append({
                    "role": "user",
                    "content": [
                        {
                            "toolResult": {
                                "toolUseId": m.tool_call_id,
                                "content": [{"text": m.content}],
                            }
                        }
                    ],
                })

        return system_blocks, api_msgs

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    def chat(self, messages: list[Message], tools: list[dict] | None = None) -> Message:
        system_blocks, api_msgs = self._to_api_messages(messages)

        kwargs: dict = {
            "modelId": self.model,
            "messages": api_msgs,
            "inferenceConfig": {
                "temperature": self.temperature,
                "maxTokens": self.max_tokens,
            },
        }
        if system_blocks:
            kwargs["system"] = system_blocks
        tool_config = self._convert_tools(tools)
        if tool_config:
            kwargs["toolConfig"] = tool_config

        response = self.client.converse(**kwargs)

        # Parse response
        content_text = ""
        tool_calls: list[ToolCall] = []

        for block in response.get("output", {}).get("message", {}).get("content", []):
            if "text" in block:
                content_text += block["text"]
            elif "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append(
                    ToolCall(
                        id=tu.get("toolUseId", str(uuid.uuid4())),
                        name=tu["name"],
                        arguments=tu.get("input", {}),
                    )
                )

        return Message(role="assistant", content=content_text, tool_calls=tool_calls)

    def stream_chat(
        self, messages: list[Message], tools: list[dict] | None = None
    ) -> Iterator[StreamChunk]:
        system_blocks, api_msgs = self._to_api_messages(messages)

        kwargs: dict = {
            "modelId": self.model,
            "messages": api_msgs,
            "inferenceConfig": {
                "temperature": self.temperature,
                "maxTokens": self.max_tokens,
            },
        }
        if system_blocks:
            kwargs["system"] = system_blocks
        tool_config = self._convert_tools(tools)
        if tool_config:
            kwargs["toolConfig"] = tool_config

        response = self.client.converse_stream(**kwargs)

        current_tool_id = ""
        current_tool_name = ""
        current_tool_args = ""

        for event in response.get("stream", []):
            if "contentBlockStart" in event:
                start = event["contentBlockStart"].get("start", {})
                if "toolUse" in start:
                    current_tool_id = start["toolUse"].get("toolUseId", "")
                    current_tool_name = start["toolUse"].get("name", "")
                    current_tool_args = ""

            elif "contentBlockDelta" in event:
                delta = event["contentBlockDelta"].get("delta", {})
                if "text" in delta:
                    yield StreamChunk(delta_text=delta["text"])
                elif "toolUse" in delta:
                    current_tool_args += delta["toolUse"].get("input", "")

            elif "contentBlockStop" in event:
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

            elif "messageStop" in event:
                yield StreamChunk(finish_reason="end_turn")
