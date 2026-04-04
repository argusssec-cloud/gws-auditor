"""Tests for CLI argument parsing."""

import pytest
from gws_auditor.cli import parse_args, apply_cli_overrides
from gws_auditor.config import _deep_copy_dict, DEFAULT_CONFIG


class TestParseArgs:
    def test_no_args_defaults_to_audit(self):
        args = parse_args([])
        assert args.command == "audit"

    def test_dashboard_subcommand(self):
        args = parse_args(["dashboard"])
        assert args.command == "dashboard"
        assert args.port == 8050
        assert args.host == "127.0.0.1"

    def test_dashboard_custom_port(self):
        args = parse_args(["dashboard", "--port", "9000"])
        assert args.port == 9000

    def test_analyst_subcommand(self):
        args = parse_args(["analyst"])
        assert args.command == "analyst"

    def test_analyst_with_provider(self):
        args = parse_args(["analyst", "--provider", "anthropic"])
        assert args.provider == "anthropic"

    def test_source_accepts_cisa(self):
        args = parse_args(["--source", "CISA"])
        assert args.source == ["CISA"]

    def test_source_accepts_all_four(self):
        args = parse_args([
            "--source", "CIS",
            "--source", "OTHER",
            "--source", "GOOGLE",
            "--source", "CISA",
        ])
        assert set(args.source) == {"CIS", "OTHER", "GOOGLE", "CISA"}

    def test_level_filter(self):
        args = parse_args(["--level", "L1"])
        assert args.level == ["L1"]

    def test_verbose_flag(self):
        args = parse_args(["-v"])
        assert args.verbose == 1

    def test_debug_flag(self):
        args = parse_args(["-vv"])
        assert args.verbose == 2

    def test_dry_run(self):
        args = parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_list_checks(self):
        args = parse_args(["--list-checks"])
        assert args.list_checks is True

    def test_single_check(self):
        args = parse_args(["--check", "CIS-1.1.1"])
        assert args.check == "CIS-1.1.1"

    def test_exclude(self):
        args = parse_args(["--exclude", "CIS-1.1.1", "--exclude", "CIS-1.1.2"])
        assert args.exclude == ["CIS-1.1.1", "CIS-1.1.2"]

    def test_exclude_section(self):
        args = parse_args(["--exclude-section", "Google Meet", "--exclude-section", "Directory"])
        assert args.exclude_section == ["Google Meet", "Directory"]

    def test_exclude_section_default_empty(self):
        args = parse_args([])
        assert args.exclude_section == []

    def test_resume_flag(self):
        args = parse_args(["--resume"])
        assert args.resume is True

    def test_resume_default_false(self):
        args = parse_args([])
        assert args.resume is False


class TestApplyCliOverrides:
    def _make_config(self):
        return _deep_copy_dict(DEFAULT_CONFIG)

    def test_overrides_credentials(self):
        config = self._make_config()
        args = parse_args(["--credentials", "new_creds.json"])
        apply_cli_overrides(config, args)
        assert config["auth"]["credentials_file"] == "new_creds.json"

    def test_overrides_subject(self):
        config = self._make_config()
        args = parse_args(["--subject", "admin@test.com"])
        apply_cli_overrides(config, args)
        assert config["auth"]["subject"] == "admin@test.com"

    def test_overrides_source(self):
        config = self._make_config()
        args = parse_args(["--source", "CIS", "--source", "CISA"])
        apply_cli_overrides(config, args)
        assert config["checks"]["sources"] == ["CIS", "CISA"]

    def test_overrides_output_dir(self):
        config = self._make_config()
        args = parse_args(["--output-dir", "/tmp/reports"])
        apply_cli_overrides(config, args)
        assert config["output"]["directory"] == "/tmp/reports"

    def test_overrides_exclude_sections(self):
        config = self._make_config()
        args = parse_args(["--exclude-section", "Google Meet", "--exclude-section", "Directory"])
        apply_cli_overrides(config, args)
        assert config["checks"]["exclude_sections"] == ["Google Meet", "Directory"]

    def test_no_overrides_preserves_defaults(self):
        config = self._make_config()
        args = parse_args([])
        apply_cli_overrides(config, args)
        assert config["auth"]["method"] == "service_account"
        assert "CISA" in config["checks"]["sources"]


class TestProxyArguments:
    def test_proxy_argument(self):
        args = parse_args(["--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_no_proxy_argument(self):
        args = parse_args(["--no-proxy", "localhost,.internal"])
        assert args.no_proxy == "localhost,.internal"

    def test_proxy_defaults_to_none(self):
        args = parse_args([])
        assert args.proxy is None
        assert args.no_proxy is None

    def test_proxy_cli_overrides(self):
        config = _deep_copy_dict(DEFAULT_CONFIG)
        args = parse_args(["--proxy", "http://p:8080"])
        apply_cli_overrides(config, args)
        assert config["network"]["proxy"] == "http://p:8080"

    def test_no_proxy_cli_overrides(self):
        config = _deep_copy_dict(DEFAULT_CONFIG)
        args = parse_args(["--no-proxy", "localhost,127.0.0.1"])
        apply_cli_overrides(config, args)
        assert config["network"]["no_proxy"] == "localhost,127.0.0.1"

    def test_proxy_overrides_config_value(self):
        config = _deep_copy_dict(DEFAULT_CONFIG)
        config["network"]["proxy"] = "http://old:3128"
        args = parse_args(["--proxy", "http://new:8080"])
        apply_cli_overrides(config, args)
        assert config["network"]["proxy"] == "http://new:8080"

    def test_proxy_override_creates_network_key(self):
        """CLI override works even if network key is missing from config."""
        config = {"auth": {}, "checks": {}, "output": {}}
        args = parse_args(["--proxy", "http://p:8080"])
        apply_cli_overrides(config, args)
        assert config["network"]["proxy"] == "http://p:8080"

    def test_ca_cert_argument(self):
        args = parse_args(["--ca-cert", "/path/to/ca.pem"])
        assert args.ca_cert == "/path/to/ca.pem"

    def test_ca_cert_cli_overrides(self):
        config = _deep_copy_dict(DEFAULT_CONFIG)
        args = parse_args(["--ca-cert", "/path/to/burp-ca.pem"])
        apply_cli_overrides(config, args)
        assert config["network"]["ca_cert"] == "/path/to/burp-ca.pem"

    def test_disable_ssl_verification_argument(self):
        args = parse_args(["--disable-ssl-verification"])
        assert args.disable_ssl_verification is True

    def test_disable_ssl_verification_cli_overrides(self):
        config = _deep_copy_dict(DEFAULT_CONFIG)
        args = parse_args(["--disable-ssl-verification"])
        apply_cli_overrides(config, args)
        assert config["network"]["disable_ssl_verification"] is True

    def test_disable_ssl_verification_default_false(self):
        args = parse_args([])
        assert args.disable_ssl_verification is False
