"""Tests for AI configuration loading."""

import os
from unittest.mock import patch

import pytest

from gws_auditor.ai.config import AIConfig, load_ai_config


class TestAIConfigDefaults:
    def test_default_values(self):
        cfg = AIConfig()
        assert cfg.provider == "openai"
        assert cfg.model == ""
        assert cfg.api_key == ""
        assert cfg.temperature == 0.1
        assert cfg.max_tokens == 4096
        assert cfg.business_context == ""
        assert cfg.aws_region == "us-east-1"
        assert cfg.aws_profile == ""
        assert cfg.base_url == ""


class TestLoadAIConfig:
    def test_defaults_when_no_args(self):
        cfg = load_ai_config()
        assert cfg.provider == "openai"
        assert cfg.temperature == 0.1

    def test_config_dict_overrides(self):
        cfg = load_ai_config(config_dict={
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "temperature": 0.5,
            "max_tokens": 2048,
        })
        assert cfg.provider == "anthropic"
        assert cfg.model == "claude-sonnet-4-20250514"
        assert cfg.temperature == 0.5
        assert cfg.max_tokens == 2048

    def test_empty_string_in_config_dict_ignored(self):
        cfg = load_ai_config(config_dict={"model": ""})
        assert cfg.model == ""  # stays default

    @patch.dict(os.environ, {"GWS_AI_PROVIDER": "bedrock", "GWS_AI_TEMPERATURE": "0.7"})
    def test_env_vars_override_config(self):
        cfg = load_ai_config(config_dict={"provider": "openai"})
        assert cfg.provider == "bedrock"
        assert cfg.temperature == 0.7

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test123"}, clear=False)
    def test_openai_api_key_fallback(self):
        cfg = load_ai_config(config_dict={"provider": "openai"})
        assert cfg.api_key == "sk-test123"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "ant-key"}, clear=False)
    def test_anthropic_api_key_fallback(self):
        cfg = load_ai_config(config_dict={"provider": "anthropic"})
        assert cfg.api_key == "ant-key"

    @patch.dict(os.environ, {"GWS_AI_API_KEY": "explicit-key", "OPENAI_API_KEY": "fallback"})
    def test_explicit_env_key_takes_precedence(self):
        cfg = load_ai_config(config_dict={"provider": "openai"})
        assert cfg.api_key == "explicit-key"

    def test_cli_args_override_all(self):
        cfg = load_ai_config(
            config_dict={"provider": "openai", "model": "gpt-4"},
            cli_args={"provider": "anthropic", "model": "claude-sonnet-4-20250514"},
        )
        assert cfg.provider == "anthropic"
        assert cfg.model == "claude-sonnet-4-20250514"

    def test_cli_args_none_values_ignored(self):
        cfg = load_ai_config(
            config_dict={"provider": "anthropic"},
            cli_args={"provider": None, "model": None},
        )
        assert cfg.provider == "anthropic"

    def test_business_context_from_config(self):
        cfg = load_ai_config(config_dict={
            "business_context": "500-person healthcare company, HIPAA required",
        })
        assert "healthcare" in cfg.business_context

    @patch.dict(os.environ, {"GWS_AI_MAX_TOKENS": "8192"})
    def test_max_tokens_env_var(self):
        cfg = load_ai_config()
        assert cfg.max_tokens == 8192
