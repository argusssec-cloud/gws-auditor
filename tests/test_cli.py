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


class TestCachedModeSkipsAuthValidation:
    """--cached re-scores an existing cache file and makes no API calls,
    so it must not demand credentials."""

    def _run(self, monkeypatch, argv):
        import gws_auditor.__main__ as m

        validated = []
        monkeypatch.setattr(
            m, "_validate_auth_config",
            lambda config, args: validated.append(args),
        )

        class _FakeOrchestrator:
            def __init__(self, config):
                self.config = config
                self.cached_path = None

            def run_cached(self, path, check_id=None):
                self.cached_path = path

        monkeypatch.setattr(m, "Orchestrator", _FakeOrchestrator)
        monkeypatch.setattr(m, "show_banner", lambda *a, **k: None, raising=False)
        rc = m.main(argv)
        return rc, validated

    def test_cached_skips_validation(self, monkeypatch, tmp_path):
        cache = tmp_path / "audit.json"
        cache.write_text("{}")
        rc, validated = self._run(monkeypatch, ["--cached", str(cache)])
        assert rc == 0
        assert validated == []

    def test_normal_run_still_validates(self, monkeypatch):
        import gws_auditor.__main__ as m

        validated = []
        monkeypatch.setattr(
            m, "_validate_auth_config",
            lambda config, args: validated.append(args),
        )

        class _FakeOrchestrator:
            def __init__(self, config):
                pass

            def dry_run(self):
                return True

        monkeypatch.setattr(m, "Orchestrator", _FakeOrchestrator)
        rc = m.main(["--dry-run"])
        assert rc == 0
        assert len(validated) == 1


class TestCachedMetavar:
    def test_cached_accepts_file_path(self):
        args = parse_args(["--cached", "./cache/audit_20260803.json"])
        assert args.cached == "./cache/audit_20260803.json"


class TestMainExitCodesAndErrors:
    """Behaviour found wrong on 2026-11-15: --check ignored in cached mode, unknown ids and missing files
    exiting 0, cached runs never failing the CI gate, every OSError swallowed as a broken pipe."""

    class _Summary:
        def __init__(self, failed=0, critical=0):
            self.failed, self.critical_failed = failed, critical

    class _Report:
        def __init__(self, failed=0, critical=0):
            self.summary = TestMainExitCodesAndErrors._Summary(failed, critical)

    def _fake(self, monkeypatch, report=None, known=("CIS-1.1.1",)):
        import gws_auditor.__main__ as m
        calls = {}
        outer = self

        class _Registry:
            def load(self):
                pass

            def get_by_id(self, cid):
                return object() if cid in known else None

        class _Orch:
            def __init__(self, config):
                self.registry = _Registry()

            def run_cached(self, path, check_id=None):
                calls["cached"] = (path, check_id)
                return report or outer._Report()

            def run_single_check(self, cid):
                calls["single"] = cid
                return report or outer._Report()

            def run(self):
                calls["run"] = True
                return report or outer._Report()

            def dry_run(self):
                raise FileNotFoundError("credentials.json")

        monkeypatch.setattr(m, "Orchestrator", _Orch)
        monkeypatch.setattr(m, "_validate_auth_config", lambda config, args: None)
        return m, calls

    def test_explicit_missing_config_exits_1(self, monkeypatch, capsys):
        m, _ = self._fake(monkeypatch)
        assert m.main(["--config", "/nonexistent/config.yaml", "--list-checks"]) == 1
        assert "config file not found" in capsys.readouterr().err

    def test_unknown_check_id_exits_1(self, monkeypatch, capsys, tmp_path):
        m, calls = self._fake(monkeypatch)
        cache = tmp_path / "c.json"; cache.write_text("{}")
        assert m.main(["--cached", str(cache), "--check", "NOPE-1", "--skip-update-check", "--no-cloud-info"]) == 1
        assert "unknown check id" in capsys.readouterr().err and not calls

    def test_cached_honours_check(self, monkeypatch, tmp_path):
        m, calls = self._fake(monkeypatch)
        cache = tmp_path / "c.json"; cache.write_text("{}")
        assert m.main(["--cached", str(cache), "--check", "CIS-1.1.1", "--skip-update-check", "--no-cloud-info"]) == 0
        assert calls["cached"] == (str(cache), "CIS-1.1.1")

    def test_missing_cache_file_exits_1(self, monkeypatch, capsys):
        m, calls = self._fake(monkeypatch)
        assert m.main(["--cached", "/nonexistent/cache.json", "--skip-update-check", "--no-cloud-info"]) == 1
        assert "cache file not found" in capsys.readouterr().err and not calls

    def test_cached_exit_codes_match_live(self, monkeypatch, tmp_path):
        cache = tmp_path / "c.json"; cache.write_text("{}")
        m, _ = self._fake(monkeypatch, report=self._Report(failed=3, critical=1))
        assert m.main(["--cached", str(cache), "--skip-update-check", "--no-cloud-info"]) == 1
        assert m.main(["--cached", str(cache), "--fail-on-critical", "--skip-update-check", "--no-cloud-info"]) == 2
        m, _ = self._fake(monkeypatch, report=self._Report(failed=0))
        assert m.main(["--cached", str(cache), "--fail-on-critical", "--skip-update-check", "--no-cloud-info"]) == 0

    def test_auth_error_is_one_line_not_a_traceback(self, monkeypatch, capsys):
        m, _ = self._fake(monkeypatch)
        assert m.main(["--dry-run", "--skip-update-check", "--no-cloud-info"]) == 1
        err = capsys.readouterr().err
        assert "ERROR: FileNotFoundError" in err and "Traceback" not in err

    def test_unknown_profile_exits_1(self, monkeypatch, capsys):
        m, _ = self._fake(monkeypatch)
        monkeypatch.setattr(m, "apply_cli_overrides", lambda config, args: (_ for _ in ()).throw(ValueError("Profile 'x' not found")))
        assert m.main(["--profile", "x", "--list-checks"]) == 1
        assert "Profile 'x' not found" in capsys.readouterr().err

    def test_oserror_is_not_swallowed_but_broken_pipe_is(self, monkeypatch, capsys):
        import gws_auditor.__main__ as m
        monkeypatch.setattr(m, "_main", lambda argv: (_ for _ in ()).throw(ConnectionRefusedError(111, "proxy refused")))
        assert m.main([]) == 1 and "proxy refused" in capsys.readouterr().err
        monkeypatch.setattr(m, "_main", lambda argv: (_ for _ in ()).throw(BrokenPipeError()))
        assert m.main([]) == 0

    def test_quiet_silences_the_console(self, monkeypatch, tmp_path):
        from gws_auditor import orchestrator as orch
        m, _ = self._fake(monkeypatch)
        cache = tmp_path / "c.json"; cache.write_text("{}")
        orch.console.quiet = False
        try:
            m.main(["--cached", str(cache), "-q", "--skip-update-check", "--no-cloud-info"])
            assert orch.console.quiet is True
        finally:
            orch.console.quiet = False


class TestSetupNonInteractiveGuards:
    """2026-11-15: `setup --non-interactive` without --subject overwrote config.yaml with an empty subject."""

    def test_requires_subject(self, capsys):
        from gws_auditor.setup import SetupWizard
        assert SetupWizard(non_interactive=True).run() == 1
        assert "requires --subject" in capsys.readouterr().out

    def test_keeps_existing_config(self, tmp_path, monkeypatch, capsys):
        from gws_auditor.setup import SetupWizard
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.yaml").write_text("auth:\n  subject: keep@example.com\n")
        wizard = SetupWizard(subject="admin@example.com", non_interactive=True)
        wizard._sa_key_path = "credentials/sa.json"
        wizard._step_generate_config()
        assert "keep@example.com" in (tmp_path / "config.yaml").read_text()
        assert "Keeping existing" in capsys.readouterr().out


    def test_closed_pipe_exits_0_through_rich(self):
        import pytest
        from gws_auditor import orchestrator as orch
        with pytest.raises(BrokenPipeError):
            orch.console.on_broken_pipe()
        orch.console.quiet = False
