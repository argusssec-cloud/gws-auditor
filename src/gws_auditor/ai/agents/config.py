# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Configuration for check analysis agents."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class AgentConfig:
    """Configuration for the PydanticAI check-analysis agents."""

    provider: str = "openai"
    model: str = ""
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 8192
    output_dir: str = "./agent_reports"
    sections: list[str] = field(default_factory=list)
    dry_run: bool = False
    mode: str = "quality"
    report_path: str = ""
    cache_dir: str = ""


_PROVIDER_MODEL_DEFAULTS: dict[str, str] = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-20250514",
    "bedrock": "anthropic.claude-sonnet-4-20250514-v1:0",
}


def _load_config_yaml() -> dict:
    """Load the ai: section from config.yaml if it exists."""
    for candidate in (Path("config.yaml"), Path("config.yml")):
        if candidate.exists():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data.get("ai", {}) or {}
            except Exception:
                pass
    return {}


def load_agent_config(
    cli_args: dict | None = None,
) -> AgentConfig:
    """Build an AgentConfig from config.yaml, env vars, and CLI overrides.

    Resolution order: defaults < config.yaml < environment variables < CLI args.
    """
    cfg = AgentConfig()

    # --- config.yaml ai: section ---
    yaml_cfg = _load_config_yaml()
    yaml_map = {
        "provider": "provider",
        "model": "model",
        "api_key": "api_key",
        "temperature": "temperature",
        "max_tokens": "max_tokens",
    }
    for yaml_key, attr in yaml_map.items():
        val = yaml_cfg.get(yaml_key)
        if val is not None and val != "":
            setattr(cfg, attr, val)

    # --- Environment variables ---
    env_map = {
        "GWS_AGENT_PROVIDER": "provider",
        "GWS_AGENT_MODEL": "model",
        "GWS_AGENT_API_KEY": "api_key",
        "GWS_AGENT_OUTPUT_DIR": "output_dir",
    }
    for env_var, attr in env_map.items():
        val = os.environ.get(env_var)
        if val:
            setattr(cfg, attr, val)

    # Provider-specific API key fallbacks
    if not cfg.api_key:
        if cfg.provider == "openai":
            cfg.api_key = os.environ.get("OPENAI_API_KEY", "")
        elif cfg.provider == "anthropic":
            cfg.api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    # --- CLI overrides ---
    if cli_args:
        for key in ("provider", "model", "api_key", "output_dir"):
            val = cli_args.get(key)
            if val:
                setattr(cfg, key, val)
        if cli_args.get("sections"):
            cfg.sections = cli_args["sections"]
        if cli_args.get("dry_run"):
            cfg.dry_run = True
        if cli_args.get("mode"):
            cfg.mode = cli_args["mode"]
        if cli_args.get("report_path"):
            cfg.report_path = cli_args["report_path"]
        if cli_args.get("cache_dir"):
            cfg.cache_dir = cli_args["cache_dir"]

    # Default model per provider
    if not cfg.model:
        cfg.model = _PROVIDER_MODEL_DEFAULTS.get(cfg.provider, "gpt-4o")

    return cfg


def get_pydantic_ai_model_string(cfg: AgentConfig) -> str:
    """Return the model string PydanticAI expects.

    PydanticAI uses prefixed strings like ``openai:gpt-4o`` or
    ``anthropic:claude-sonnet-4-20250514``.
    """
    provider_prefix = cfg.provider
    if provider_prefix == "bedrock":
        provider_prefix = "bedrock"
    return f"{provider_prefix}:{cfg.model}"
