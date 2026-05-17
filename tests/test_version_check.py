"""Tests for the version check and auto-update module."""

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from gws_auditor.version_check import (
    _PYPI_PACKAGE,
    _PYPI_URL,
    check_and_prompt_update,
    fetch_latest_version,
    get_installed_version,
    is_editable_install,
    is_newer,
    perform_update,
    prompt_for_update,
    run_update_only,
)


# ------------------------------------------------------------------
# get_installed_version
# ------------------------------------------------------------------

class TestGetInstalledVersion:
    def test_returns_string(self):
        version = get_installed_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_matches_package_version(self):
        from gws_auditor import __version__
        assert get_installed_version() == __version__


# ------------------------------------------------------------------
# is_newer
# ------------------------------------------------------------------

class TestIsNewer:
    @pytest.mark.parametrize("latest,current,expected", [
        ("0.2.0", "0.1.0", True),
        ("1.0.0", "0.9.9", True),
        ("0.1.1", "0.1.0", True),
        ("0.1.0", "0.1.0", False),
        ("0.0.9", "0.1.0", False),
        ("2.0.0", "1.99.99", True),
    ])
    def test_version_comparison(self, latest, current, expected):
        assert is_newer(latest, current) is expected

    def test_prerelease_less_than_release(self):
        assert is_newer("1.0.0", "1.0.0a1") is True

    def test_same_prerelease(self):
        assert is_newer("1.0.0a1", "1.0.0a1") is False

    def test_invalid_version_returns_false(self):
        assert is_newer("not-a-version", "0.1.0") is False

    def test_empty_strings_return_false(self):
        assert is_newer("", "") is False


# ------------------------------------------------------------------
# fetch_latest_version
# ------------------------------------------------------------------

class TestFetchLatestVersion:
    def test_success(self):
        mock_data = json.dumps({"info": {"version": "99.0.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=mock_resp):
            result = fetch_latest_version(timeout=1.0)
        assert result == "99.0.0"

    def test_network_error_returns_none(self):
        with patch(
            "gws_auditor.version_check.urllib.request.urlopen",
            side_effect=OSError("network unreachable"),
        ):
            result = fetch_latest_version(timeout=1.0)
        assert result is None

    def test_malformed_json_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=mock_resp):
            result = fetch_latest_version(timeout=1.0)
        assert result is None

    def test_missing_key_returns_none(self):
        mock_data = json.dumps({"info": {}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=mock_resp):
            result = fetch_latest_version(timeout=1.0)
        assert result is None

    def test_falls_back_to_github_when_pypi_fails(self):
        """When PyPI fails, GitHub Releases is consulted as a fallback."""
        with patch(
            "gws_auditor.version_check._fetch_pypi_latest",
            return_value=None,
        ):
            with patch(
                "gws_auditor.version_check._fetch_github_latest",
                return_value="1.2.0",
            ) as mock_gh:
                result = fetch_latest_version(timeout=1.0)
        assert result == "1.2.0"
        mock_gh.assert_called_once()

    def test_pypi_wins_when_available(self):
        """GitHub fallback is not consulted when PyPI returns a version."""
        with patch(
            "gws_auditor.version_check._fetch_pypi_latest",
            return_value="1.2.0",
        ):
            with patch(
                "gws_auditor.version_check._fetch_github_latest",
            ) as mock_gh:
                result = fetch_latest_version(timeout=1.0)
        assert result == "1.2.0"
        mock_gh.assert_not_called()

    def test_both_fail_returns_none(self):
        with patch(
            "gws_auditor.version_check._fetch_pypi_latest",
            return_value=None,
        ):
            with patch(
                "gws_auditor.version_check._fetch_github_latest",
                return_value=None,
            ):
                result = fetch_latest_version(timeout=1.0)
        assert result is None


class TestGithubFallback:
    """Tests for the GitHub Releases fallback."""

    def _mock_resp(self, payload):
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_strips_leading_v(self):
        from gws_auditor.version_check import _fetch_github_latest
        resp = self._mock_resp({"tag_name": "v1.2.0"})
        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=resp):
            result = _fetch_github_latest(timeout=1.0)
        assert result == "1.2.0"

    def test_no_v_prefix_preserved(self):
        from gws_auditor.version_check import _fetch_github_latest
        resp = self._mock_resp({"tag_name": "1.2.0"})
        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=resp):
            result = _fetch_github_latest(timeout=1.0)
        assert result == "1.2.0"

    def test_empty_tag_returns_none(self):
        from gws_auditor.version_check import _fetch_github_latest
        resp = self._mock_resp({"tag_name": ""})
        with patch("gws_auditor.version_check.urllib.request.urlopen", return_value=resp):
            result = _fetch_github_latest(timeout=1.0)
        assert result is None

    def test_network_error_returns_none(self):
        from gws_auditor.version_check import _fetch_github_latest
        with patch(
            "gws_auditor.version_check.urllib.request.urlopen",
            side_effect=OSError("network unreachable"),
        ):
            result = _fetch_github_latest(timeout=1.0)
        assert result is None


# ------------------------------------------------------------------
# is_editable_install
# ------------------------------------------------------------------

class TestIsEditableInstall:
    def test_editable_true(self):
        mock_dist = MagicMock()
        mock_dist.read_text.return_value = json.dumps(
            {"dir_info": {"editable": True}}
        )
        with patch(
            "gws_auditor.version_check.distribution", create=True,
            return_value=mock_dist,
        ):
            # Need to patch the actual import inside the function
            with patch("importlib.metadata.distribution", return_value=mock_dist):
                assert is_editable_install() is True

    def test_not_editable(self):
        mock_dist = MagicMock()
        mock_dist.read_text.return_value = json.dumps(
            {"dir_info": {"editable": False}}
        )
        with patch("importlib.metadata.distribution", return_value=mock_dist):
            assert is_editable_install() is False

    def test_no_direct_url(self):
        mock_dist = MagicMock()
        mock_dist.read_text.return_value = None
        with patch("importlib.metadata.distribution", return_value=mock_dist):
            assert is_editable_install() is False

    def test_exception_returns_false(self):
        with patch(
            "importlib.metadata.distribution",
            side_effect=Exception("not found"),
        ):
            assert is_editable_install() is False


# ------------------------------------------------------------------
# perform_update
# ------------------------------------------------------------------

class TestPerformUpdate:
    def test_normal_install_success(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            assert perform_update(editable=False) is True
        cmd = mock_run.call_args[0][0]
        assert "--upgrade" in cmd
        assert _PYPI_PACKAGE in cmd

    def test_normal_install_failure(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=1)):
            assert perform_update(editable=False) is False

    def test_editable_install(self):
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            with patch(
                "gws_auditor.version_check._find_project_root",
                return_value="/fake/project",
            ):
                assert perform_update(editable=True) is True
        cmd = mock_run.call_args[0][0]
        assert "-e" in cmd
        assert "/fake/project" in cmd


# ------------------------------------------------------------------
# prompt_for_update
# ------------------------------------------------------------------

class TestPromptForUpdate:
    def test_non_tty_returns_false(self, capsys):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            result = prompt_for_update("0.1.0", "0.2.0")
        assert result is False

    def test_tty_user_confirms(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            with patch(
                "gws_auditor.version_check.Confirm",
                create=True,
            ):
                from rich.prompt import Confirm
                with patch.object(Confirm, "ask", return_value=True):
                    result = prompt_for_update("0.1.0", "0.2.0")
        assert result is True

    def test_tty_user_declines(self):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = True
            from rich.prompt import Confirm
            with patch.object(Confirm, "ask", return_value=False):
                result = prompt_for_update("0.1.0", "0.2.0")
        assert result is False


# ------------------------------------------------------------------
# check_and_prompt_update
# ------------------------------------------------------------------

class TestCheckAndPromptUpdate:
    def test_skip_returns_immediately(self):
        with patch(
            "gws_auditor.version_check.fetch_latest_version"
        ) as mock_fetch:
            check_and_prompt_update(skip=True)
        mock_fetch.assert_not_called()

    def test_frozen_build_still_queries(self):
        """Frozen builds DO check for updates (banner-only, no in-place upgrade)."""
        with patch("gws_auditor._frozen.is_frozen", return_value=True):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="0.0.1",  # older than current, so no prompt
            ) as mock_fetch:
                check_and_prompt_update(skip=False)
        mock_fetch.assert_called_once()

    def test_frozen_newer_version_shows_release_url(self, capsys):
        """Frozen + newer available → quiet banner points at GH releases page."""
        with patch("gws_auditor._frozen.is_frozen", return_value=True):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                check_and_prompt_update(skip=False, quiet=True)
        captured = capsys.readouterr()
        assert "99.0.0" in captured.err
        assert "github.com" in captured.err
        assert "releases" in captured.err

    def test_no_newer_version_no_prompt(self):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="0.0.1",
            ):
                with patch(
                    "gws_auditor.version_check.prompt_for_update"
                ) as mock_prompt:
                    check_and_prompt_update(skip=False)
        mock_prompt.assert_not_called()

    def test_pypi_unreachable_no_crash(self):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value=None,
            ):
                with patch(
                    "gws_auditor.version_check.prompt_for_update"
                ) as mock_prompt:
                    check_and_prompt_update(skip=False)
        mock_prompt.assert_not_called()

    def test_newer_version_prompts(self):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                with patch(
                    "gws_auditor.version_check.prompt_for_update",
                    return_value=False,
                ) as mock_prompt:
                    check_and_prompt_update(skip=False)
        mock_prompt.assert_called_once()

    def test_quiet_mode_no_prompt(self, capsys):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                with patch(
                    "gws_auditor.version_check.prompt_for_update"
                ) as mock_prompt:
                    check_and_prompt_update(skip=False, quiet=True)
        mock_prompt.assert_not_called()
        captured = capsys.readouterr()
        assert "99.0.0" in captured.err

    def test_exception_swallowed(self):
        """Any exception in the version check must not propagate."""
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                side_effect=RuntimeError("unexpected"),
            ):
                # Should not raise
                check_and_prompt_update(skip=False)


# ------------------------------------------------------------------
# run_update_only
# ------------------------------------------------------------------

class TestRunUpdateOnly:
    def test_frozen_no_newer_returns_0(self):
        """Frozen + already latest → 0 (no upgrade needed, no error)."""
        current = get_installed_version()
        with patch("gws_auditor._frozen.is_frozen", return_value=True):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value=current,
            ):
                assert run_update_only() == 0

    def test_frozen_newer_directs_to_release_page(self, capsys):
        """Frozen + newer → 0 with directive to download from GH releases."""
        with patch("gws_auditor._frozen.is_frozen", return_value=True):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                assert run_update_only() == 0
        captured = capsys.readouterr()
        assert "99.0.0" in captured.err
        assert "github.com" in captured.err and "releases" in captured.err

    def test_latest_unreachable_returns_1(self):
        """Both PyPI and GitHub fail → can't determine latest → exit 1."""
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value=None,
            ):
                assert run_update_only() == 1

    def test_already_latest(self, capsys):
        current = get_installed_version()
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value=current,
            ):
                assert run_update_only() == 0
        captured = capsys.readouterr()
        assert "already the latest" in captured.out

    def test_update_success(self, capsys):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                with patch(
                    "gws_auditor.version_check.is_editable_install",
                    return_value=False,
                ):
                    with patch(
                        "gws_auditor.version_check.perform_update",
                        return_value=True,
                    ):
                        assert run_update_only() == 0
        captured = capsys.readouterr()
        assert "Successfully updated" in captured.out

    def test_update_failure(self):
        with patch("gws_auditor._frozen.is_frozen", return_value=False):
            with patch(
                "gws_auditor.version_check.fetch_latest_version",
                return_value="99.0.0",
            ):
                with patch(
                    "gws_auditor.version_check.is_editable_install",
                    return_value=False,
                ):
                    with patch(
                        "gws_auditor.version_check.perform_update",
                        return_value=False,
                    ):
                        assert run_update_only() == 1
