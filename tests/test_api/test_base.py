"""Tests for base API client."""

import http.client
import socket
import ssl
from unittest.mock import MagicMock, patch

import httplib2
import pytest

from gws_auditor.api.base import BaseAPIClient, RETRYABLE_TRANSPORT_ERRORS


class TestBaseAPIClient:
    """Tests for BaseAPIClient."""

    def test_error_recording(self):
        client = BaseAPIClient.__new__(BaseAPIClient)
        client.errors = []
        client.record_error("test_operation", Exception("test error"))
        assert len(client.errors) == 1
        assert client.errors[0]["operation"] == "test_operation"
        assert "test error" in client.errors[0]["message"]

    def test_errors_property(self):
        client = BaseAPIClient.__new__(BaseAPIClient)
        client.errors = []
        client.record_error("op1", Exception("err1"))
        client.record_error("op2", Exception("err2"))
        assert len(client.errors) == 2


def _make_client(max_retries=3):
    """Create a BaseAPIClient with a fast token bucket for testing."""
    client = BaseAPIClient.__new__(BaseAPIClient)
    client.max_retries = max_retries
    client.rate_limit_qps = 1000
    client.errors = []
    # Fast bucket that never blocks
    from gws_auditor.api.base import _TokenBucket
    client._bucket = _TokenBucket(1000)
    return client


class TestTransportErrorRetry:
    """Tests for transport-level error retry in execute_with_retry."""

    @patch("time.sleep", return_value=None)
    def test_success_after_transport_retry(self, mock_sleep):
        """Transport error on first attempt, success on second."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=[
                http.client.UnknownProtocol("HTTP/2"),
                {"result": "ok"},
            ]
        )
        result = client.execute_with_retry(request)
        assert result == {"result": "ok"}
        assert request.execute.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("time.sleep", return_value=None)
    def test_transport_error_exhaustion(self, mock_sleep):
        """All retries exhausted with transport errors raises the error."""
        client = _make_client(max_retries=2)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=http.client.RemoteDisconnected("Remote end closed")
        )
        with pytest.raises(http.client.RemoteDisconnected):
            client.execute_with_retry(request)
        # Initial attempt + 2 retries = 3 calls
        assert request.execute.call_count == 3

    @patch("time.sleep", return_value=None)
    def test_non_retryable_exception_raises_immediately(self, mock_sleep):
        """Non-retryable exceptions are not retried."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(side_effect=ValueError("bad value"))
        with pytest.raises(ValueError, match="bad value"):
            client.execute_with_retry(request)
        assert request.execute.call_count == 1
        mock_sleep.assert_not_called()

    @patch("time.sleep", return_value=None)
    def test_connection_error_is_retried(self, mock_sleep):
        """ConnectionError (includes ConnectionResetError) is retried."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=[
                ConnectionResetError("Connection reset by peer"),
                {"ok": True},
            ]
        )
        result = client.execute_with_retry(request)
        assert result == {"ok": True}
        assert request.execute.call_count == 2

    @patch("time.sleep", return_value=None)
    def test_socket_timeout_is_retried(self, mock_sleep):
        """socket.timeout is retried."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=[
                socket.timeout("timed out"),
                {"ok": True},
            ]
        )
        result = client.execute_with_retry(request)
        assert result == {"ok": True}

    @patch("time.sleep", return_value=None)
    def test_ssl_error_is_retried(self, mock_sleep):
        """ssl.SSLError on first attempt, success on second."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=[
                ssl.SSLError(1, "[SSL] internal error"),
                {"ok": True},
            ]
        )
        result = client.execute_with_retry(request)
        assert result == {"ok": True}
        assert request.execute.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("time.sleep", return_value=None)
    def test_ssl_eof_error_is_retried(self, mock_sleep):
        """ssl.SSLEOFError (subclass of SSLError) is retried."""
        client = _make_client(max_retries=3)
        request = MagicMock()
        request.execute = MagicMock(
            side_effect=[
                ssl.SSLEOFError(8, "EOF occurred in violation of protocol"),
                {"ok": True},
            ]
        )
        result = client.execute_with_retry(request)
        assert result == {"ok": True}
        assert request.execute.call_count == 2
        assert mock_sleep.call_count == 1
