# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Abstract base classes and data types for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class ToolCall:
    """An LLM-requested tool invocation."""

    id: str
    name: str
    arguments: dict


@dataclass
class Message:
    """A single conversation message."""

    role: str  # "system", "user", "assistant", "tool"
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class StreamChunk:
    """A single chunk from a streaming LLM response."""

    delta_text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str | None = None


class LLMProvider(ABC):
    """Abstract interface that all LLM provider adapters must implement."""

    @abstractmethod
    def chat(self, messages: list[Message], tools: list[dict] | None = None) -> Message:
        """Send messages and return the assistant's reply (blocking)."""

    @abstractmethod
    def stream_chat(
        self, messages: list[Message], tools: list[dict] | None = None
    ) -> Iterator[StreamChunk]:
        """Send messages and yield streaming chunks."""
