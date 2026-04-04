"""Tests for configuration loading."""

import os
import pytest
import yaml

from gws_auditor.config import load_config, _deep_merge, _deep_copy_dict, DEFAULT_CONFIG


class TestDeepCopyDict:
    def test_returns_new_dict(self):
        original = {"a": 1, "b": [2, 3]}
        copy = _deep_copy_dict(original)
        assert copy == original
        assert copy is not original
        copy["a"] = 99
        assert original["a"] == 1

    def test_deep_copies_nested_dicts(self):
        original = {"outer": {"inner": "value"}}
        copy = _deep_copy_dict(original)
        copy["outer"]["inner"] = "changed"
        assert original["outer"]["inner"] == "value"

    def test_deep_copies_lists(self):
        original = {"items": [1, 2, 3]}
        copy = _deep_copy_dict(original)
        copy["items"].append(4)
        assert original["items"] == [1, 2, 3]


class TestDeepMerge:
    def test_merges_flat_keys(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99, "c": 3}
        _deep_merge(base, override)
        assert base == {"a": 1, "b": 99, "c": 3}

    def test_merges_nested_dicts(self):
        base = {"auth": {"method": "oauth", "subject": "old"}}
        override = {"auth": {"subject": "new"}}
        _deep_merge(base, override)
        assert base["auth"]["method"] == "oauth"
        assert base["auth"]["subject"] == "new"

    def test_override_replaces_non_dict(self):
        base = {"checks": {"levels": ["L1"]}}
        override = {"checks": {"levels": ["L1", "L2"]}}
        _deep_merge(base, override)
        assert base["checks"]["levels"] == ["L1", "L2"]


class TestLoadConfig:
    def test_returns_defaults_when_no_file(self):
        config = load_config(None)
        assert config["auth"]["method"] == "service_account"
        assert "CISA" in config["checks"]["sources"]

    def test_returns_defaults_when_file_missing(self):
        config = load_config("/nonexistent/config.yaml")
        assert config == _deep_copy_dict(DEFAULT_CONFIG)

    def test_loads_yaml_and_merges(self, tmp_path):
        yaml_content = {"auth": {"subject": "test@example.com"}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(yaml_content))
        config = load_config(str(config_file))
        assert config["auth"]["subject"] == "test@example.com"
        assert config["auth"]["method"] == "service_account"  # default preserved

    def test_yaml_overrides_defaults(self, tmp_path):
        yaml_content = {"checks": {"levels": ["L1"], "sources": ["CIS"]}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(yaml_content))
        config = load_config(str(config_file))
        assert config["checks"]["levels"] == ["L1"]
        assert config["checks"]["sources"] == ["CIS"]

    def test_empty_yaml_returns_defaults(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        config = load_config(str(config_file))
        assert config == _deep_copy_dict(DEFAULT_CONFIG)

    def test_default_config_includes_cisa(self):
        assert "CISA" in DEFAULT_CONFIG["checks"]["sources"]

    def test_default_config_has_ai_section(self):
        assert "ai" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["ai"]["provider"] == "openai"

    def test_default_config_has_exclude_sections(self):
        assert "exclude_sections" in DEFAULT_CONFIG["checks"]
        assert DEFAULT_CONFIG["checks"]["exclude_sections"] == []

    def test_default_config_has_network_section(self):
        assert "network" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["network"]["proxy"] is None
        assert DEFAULT_CONFIG["network"]["no_proxy"] is None
        assert DEFAULT_CONFIG["network"]["ca_cert"] is None
        assert DEFAULT_CONFIG["network"]["disable_ssl_verification"] is False

    def test_yaml_network_proxy_merges(self, tmp_path):
        yaml_content = {"network": {"proxy": "http://proxy:8080"}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(yaml_content))
        config = load_config(str(config_file))
        assert config["network"]["proxy"] == "http://proxy:8080"
        assert config["network"]["no_proxy"] is None  # default preserved
