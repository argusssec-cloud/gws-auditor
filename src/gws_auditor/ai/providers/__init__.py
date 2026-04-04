# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""LLM provider factory with lazy imports."""

from __future__ import annotations

from ..config import AIConfig
from .base import LLMProvider


def get_provider(config: AIConfig) -> LLMProvider:
    """Create the appropriate LLM provider based on config.

    Only the selected provider's SDK needs to be installed.
    """
    if config.provider == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(
            api_key=config.api_key,
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            base_url=config.base_url,
        )
    elif config.provider == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(
            api_key=config.api_key,
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
    elif config.provider == "bedrock":
        from .bedrock_provider import BedrockProvider

        return BedrockProvider(
            model=config.model,
            region=config.aws_region,
            profile=config.aws_profile,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )
    else:
        raise ValueError(f"Unknown AI provider: {config.provider!r}")
