# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""AI analyst configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class AIConfig:
    """Configuration for the AI security analyst."""

    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 4096
    business_context: str = ""
    aws_region: str = "us-east-1"
    aws_profile: str = ""
    base_url: str = ""


def load_ai_config(
    config_dict: dict | None = None,
    cli_args: dict | None = None,
) -> AIConfig:
    """Build an AIConfig by layering defaults < config.yaml < env vars < CLI args.

    Args:
        config_dict: The ``ai`` section from ``config.yaml`` (or ``None``).
        cli_args: CLI argument overrides as a flat dict (or ``None``).

    Returns:
        A fully-resolved :class:`AIConfig`.
    """
    cfg = AIConfig()

    # --- Layer 1: config.yaml ai: section ---
    if config_dict:
        for key in (
            "provider", "model", "api_key", "temperature", "max_tokens",
            "business_context", "aws_region", "aws_profile", "base_url",
        ):
            if key in config_dict and config_dict[key] != "":
                val = config_dict[key]
                if key == "temperature":
                    val = float(val)
                elif key == "max_tokens":
                    val = int(val)
                setattr(cfg, key, val)

    # --- Layer 2: environment variables ---
    env_map = {
        "GWS_AI_PROVIDER": "provider",
        "GWS_AI_MODEL": "model",
        "GWS_AI_API_KEY": "api_key",
        "GWS_AI_TEMPERATURE": "temperature",
        "GWS_AI_MAX_TOKENS": "max_tokens",
        "GWS_AI_BUSINESS_CONTEXT": "business_context",
        "GWS_AI_AWS_REGION": "aws_region",
        "GWS_AI_AWS_PROFILE": "aws_profile",
        "GWS_AI_BASE_URL": "base_url",
    }
    for env_var, attr in env_map.items():
        val = os.environ.get(env_var)
        if val:
            if attr == "temperature":
                val = float(val)
            elif attr == "max_tokens":
                val = int(val)
            setattr(cfg, attr, val)

    # --- Layer 3: CLI argument overrides ---
    if cli_args:
        for key in ("provider", "model", "api_key", "base_url"):
            val = cli_args.get(key)
            if val:
                setattr(cfg, key, val)

    # Provider-specific API key fallbacks (after CLI overrides so
    # --provider anthropic correctly picks up ANTHROPIC_API_KEY)
    if not cfg.api_key:
        if cfg.provider == "openai":
            cfg.api_key = os.environ.get("OPENAI_API_KEY", "")
        elif cfg.provider == "anthropic":
            cfg.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    return cfg
