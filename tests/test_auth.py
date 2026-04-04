"""Tests for authentication and proxy transport."""

from unittest.mock import MagicMock, patch

import httplib2
from httplib2 import socks
import pytest

from gws_auditor.auth import AuthManager


class TestBuildHttp:
    """Tests for AuthManager._build_http proxy transport construction."""

    def test_build_http_no_proxy(self):
        """Default Http with no proxy configured."""
        auth = AuthManager({"auth": {}, "network": {}})
        http = auth._build_http()
        assert isinstance(http, httplib2.Http)

    def test_build_http_no_network_key(self):
        """Works when network key is absent from config."""
        auth = AuthManager({"auth": {}})
        http = auth._build_http()
        assert isinstance(http, httplib2.Http)

    def test_build_http_with_proxy(self):
        """Proxy URL results in Http with ProxyInfo set."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://proxy.corp.com:8080"},
        })
        http = auth._build_http()
        assert isinstance(http, httplib2.Http)
        assert http.proxy_info is not None
        assert http.proxy_info.proxy_type == socks.PROXY_TYPE_HTTP
        assert http.proxy_info.proxy_host == "proxy.corp.com"
        assert http.proxy_info.proxy_port == 8080

    def test_build_http_with_proxy_auth(self):
        """Proxy URL with credentials extracts user and password."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://alice:s3cret@proxy:3128"},
        })
        http = auth._build_http()
        assert http.proxy_info is not None
        assert http.proxy_info.proxy_user == "alice"
        assert http.proxy_info.proxy_pass == "s3cret"
        assert http.proxy_info.proxy_port == 3128

    def test_build_http_with_no_proxy(self):
        """no_proxy is forwarded to ProxyInfo bypass_hosts."""
        auth = AuthManager({
            "auth": {},
            "network": {
                "proxy": "http://proxy:8080",
                "no_proxy": "localhost,.internal",
            },
        })
        http = auth._build_http()
        assert http.proxy_info is not None
        assert http.proxy_info.bypass_host("localhost") is True
        assert http.proxy_info.bypass_host("foo.internal") is True
        assert http.proxy_info.bypass_host("googleapis.com") is False

    def test_build_http_proxy_none_no_proxy_info(self):
        """Explicit proxy=None behaves like no proxy."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": None},
        })
        http = auth._build_http()
        assert isinstance(http, httplib2.Http)

    def test_build_http_raises_without_socks(self):
        """Raises ImportError with clear message if PySocks is missing."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://proxy:8080"},
        })
        with patch("gws_auditor.auth.httplib2_socks", None):
            with pytest.raises(ImportError, match="PySocks"):
                auth._build_http()

    def test_build_http_proxy_isgood(self):
        """Proxy info is functional (isgood=True) when socks is available."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://proxy:8080"},
        })
        http = auth._build_http()
        assert http.proxy_info.isgood() is True

    def test_build_http_default_port(self):
        """Falls back to port 8080 when no port specified in URL."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://proxy"},
        })
        http = auth._build_http()
        assert http.proxy_info.proxy_port == 8080


class TestBuildService:
    """Tests for AuthManager.build_service proxy integration."""

    @patch("gws_auditor.auth.build")
    def test_build_service_passes_authed_http(self, mock_build):
        """build_service passes an AuthorizedHttp as the http= parameter."""
        import google_auth_httplib2

        auth = AuthManager({
            "auth": {"method": "service_account"},
            "network": {"proxy": "http://proxy:8080"},
        })
        # Provide mock credentials
        mock_creds = MagicMock()
        auth._credentials = mock_creds

        auth.build_service("admin", "directory_v1")

        mock_build.assert_called_once()
        call_kwargs = mock_build.call_args
        http_arg = call_kwargs.kwargs.get("http") or call_kwargs[1].get("http")
        assert isinstance(http_arg, google_auth_httplib2.AuthorizedHttp)

    @patch("gws_auditor.auth.build")
    def test_build_service_no_proxy(self, mock_build):
        """build_service works without proxy config."""
        auth = AuthManager({"auth": {}})
        mock_creds = MagicMock()
        auth._credentials = mock_creds

        auth.build_service("admin", "directory_v1")

        mock_build.assert_called_once()
        call_kwargs = mock_build.call_args
        http_arg = call_kwargs.kwargs.get("http") or call_kwargs[1].get("http")
        # Still uses AuthorizedHttp even without proxy
        import google_auth_httplib2
        assert isinstance(http_arg, google_auth_httplib2.AuthorizedHttp)


class TestBuildAuthorizedHttp:
    """Tests for AuthManager.build_authorized_http."""

    def test_returns_authorized_http_with_default_creds(self):
        """Uses self.credentials when no credentials argument given."""
        import google_auth_httplib2

        auth = AuthManager({"auth": {}, "network": {"proxy": "http://proxy:8080"}})
        mock_creds = MagicMock()
        auth._credentials = mock_creds

        result = auth.build_authorized_http()
        assert isinstance(result, google_auth_httplib2.AuthorizedHttp)

    def test_returns_authorized_http_with_custom_creds(self):
        """Uses provided credentials instead of self.credentials."""
        import google_auth_httplib2

        auth = AuthManager({"auth": {}, "network": {"proxy": "http://proxy:8080"}})
        auth._credentials = MagicMock()
        custom_creds = MagicMock()

        result = auth.build_authorized_http(custom_creds)
        assert isinstance(result, google_auth_httplib2.AuthorizedHttp)
        # The underlying http should have proxy info
        assert result.http.proxy_info is not None
        assert result.http.proxy_info.proxy_port == 8080

    def test_proxy_propagated_to_underlying_http(self):
        """Proxy config is set on the underlying httplib2.Http."""
        auth = AuthManager({
            "auth": {},
            "network": {"proxy": "http://corp-proxy:3128"},
        })
        auth._credentials = MagicMock()

        result = auth.build_authorized_http()
        assert result.http.proxy_info is not None
        assert result.http.proxy_info.proxy_host == "corp-proxy"
        assert result.http.proxy_info.proxy_port == 3128


class TestBuildHttpSSL:
    """Tests for CA certificate and SSL verification options."""

    def test_custom_ca_cert(self, tmp_path):
        """ca_cert sets the ca_certs on the Http object."""
        ca_file = tmp_path / "custom-ca.pem"
        ca_file.write_text("--- PEM ---")
        auth = AuthManager({
            "auth": {},
            "network": {"ca_cert": str(ca_file)},
        })
        http = auth._build_http()
        assert http.ca_certs == str(ca_file)

    def test_ca_cert_file_not_found(self):
        """Raises FileNotFoundError when ca_cert path doesn't exist."""
        auth = AuthManager({
            "auth": {},
            "network": {"ca_cert": "/nonexistent/ca.pem"},
        })
        with pytest.raises(FileNotFoundError, match="ca.pem"):
            auth._build_http()

    def test_disable_ssl_verification(self):
        """disable_ssl_verification disables cert checking."""
        auth = AuthManager({
            "auth": {},
            "network": {"disable_ssl_verification": True},
        })
        http = auth._build_http()
        assert http.disable_ssl_certificate_validation is True

    def test_ssl_verification_enabled_by_default(self):
        """SSL verification is on by default."""
        auth = AuthManager({"auth": {}, "network": {}})
        http = auth._build_http()
        assert http.disable_ssl_certificate_validation is False

    def test_ca_cert_with_proxy(self, tmp_path):
        """ca_cert and proxy work together."""
        ca_file = tmp_path / "burp-ca.pem"
        ca_file.write_text("--- PEM ---")
        auth = AuthManager({
            "auth": {},
            "network": {
                "proxy": "http://192.168.44.24:8080",
                "ca_cert": str(ca_file),
            },
        })
        http = auth._build_http()
        assert http.ca_certs == str(ca_file)
        assert http.proxy_info is not None
        assert http.proxy_info.proxy_host == "192.168.44.24"
