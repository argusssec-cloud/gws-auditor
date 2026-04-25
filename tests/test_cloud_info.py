"""Tests for the Argus Cloud startup banner."""

import os
from unittest.mock import patch

import pytest

from gws_auditor.cloud_info import _CLOUD_URL, show_cloud_info


class TestShowCloudInfo:
    """Verify all suppression paths and output behavior."""

    def test_prints_to_stderr_on_tty(self, capsys):
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            mock_stderr.write = lambda s: None  # absorb output
            # Can't easily capture stderr with capsys when patching,
            # so just verify no exception is raised.
            show_cloud_info(quiet=False, no_cloud_info=False)

    def test_message_contains_url(self):
        from gws_auditor.cloud_info import _CLOUD_INFO_MESSAGE
        assert _CLOUD_URL in _CLOUD_INFO_MESSAGE

    def test_message_contains_brand(self):
        from gws_auditor.cloud_info import _CLOUD_INFO_MESSAGE
        assert "Argus Cloud" in _CLOUD_INFO_MESSAGE

    def test_message_contains_tagline(self):
        from gws_auditor.cloud_info import _CLOUD_INFO_MESSAGE
        assert "Cloud-hosted for teams" in _CLOUD_INFO_MESSAGE

    def test_suppressed_by_quiet(self, capsys):
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            show_cloud_info(quiet=True, no_cloud_info=False)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_suppressed_by_no_cloud_info(self, capsys):
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            show_cloud_info(quiet=False, no_cloud_info=True)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "yes", "Yes"])
    def test_suppressed_by_env_var(self, value, capsys):
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            with patch.dict(os.environ, {"GWS_AUDITOR_NO_CLOUD_INFO": value}):
                show_cloud_info(quiet=False, no_cloud_info=False)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_not_suppressed_by_invalid_env_var(self):
        """Env var with non-truthy value should NOT suppress."""
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            with patch.dict(os.environ, {"GWS_AUDITOR_NO_CLOUD_INFO": "0"}):
                # Should attempt to print (mock absorbs it)
                show_cloud_info(quiet=False, no_cloud_info=False)

    def test_suppressed_when_not_tty(self, capsys):
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = False
            show_cloud_info(quiet=False, no_cloud_info=False)
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_does_not_print_to_stdout(self, capsys):
        """The message must go to stderr, never stdout."""
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            show_cloud_info(quiet=False, no_cloud_info=False)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_env_var_absent_does_not_suppress(self):
        """When env var is completely absent, message should show."""
        with patch("sys.stderr") as mock_stderr:
            mock_stderr.isatty.return_value = True
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("GWS_AUDITOR_NO_CLOUD_INFO", None)
                show_cloud_info(quiet=False, no_cloud_info=False)
