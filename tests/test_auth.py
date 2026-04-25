"""Tests for authentication and proxy transport."""

import json
from unittest.mock import MagicMock, patch

import httplib2
from httplib2 import socks
import pytest

from gws_auditor.auth import AuthManager
from gws_auditor.constants import SCOPES, SERVICE_ACCOUNT_SCOPES


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


class TestAuthMethods:
    """Tests for different authentication methods."""

    def test_authenticate_unknown_method_raises(self):
        auth = AuthManager({"auth": {"method": "bogus"}})
        with pytest.raises(ValueError, match="Unknown auth method"):
            auth.authenticate()

    def test_gce_method_accepted(self):
        """GCE auth method is dispatched without ValueError."""
        auth = AuthManager({"auth": {"method": "gce", "subject": "admin@co.com"}})
        with patch("gws_auditor.auth.AuthManager._authenticate_gce") as mock:
            auth.authenticate()
        mock.assert_called_once()

    def test_workload_identity_method_accepted(self):
        """WIF auth method is dispatched without ValueError."""
        auth = AuthManager({"auth": {"method": "workload_identity", "subject": "admin@co.com"}})
        with patch("gws_auditor.auth.AuthManager._authenticate_workload_identity") as mock:
            auth.authenticate()
        mock.assert_called_once()

    def test_gce_without_subject(self):
        """GCE auth without subject uses base compute credentials."""
        auth = AuthManager({"auth": {"method": "gce"}})
        mock_creds = MagicMock()
        mock_creds.service_account_email = "sa@project.iam.gserviceaccount.com"
        with patch("google.auth.compute_engine.Credentials", return_value=mock_creds):
            auth._authenticate_gce()
        assert auth._credentials is mock_creds

    def test_workload_identity_without_subject(self):
        """WIF auth without subject uses google.auth.default() directly."""
        auth = AuthManager({"auth": {"method": "workload_identity"}})
        mock_creds = MagicMock()
        with patch("google.auth.default", return_value=(mock_creds, "project-123")):
            auth._authenticate_workload_identity()
        assert auth._credentials is mock_creds

    def test_workload_identity_with_subject_and_with_subject(self):
        """WIF creds that support with_subject use it directly."""
        auth = AuthManager({"auth": {"method": "workload_identity", "subject": "admin@co.com"}})
        mock_creds = MagicMock()
        mock_creds_delegated = MagicMock()
        mock_creds.with_subject.return_value = mock_creds_delegated
        with patch("google.auth.default", return_value=(mock_creds, "project-123")):
            auth._authenticate_workload_identity()
        mock_creds.with_subject.assert_called_once_with("admin@co.com")
        assert auth._credentials is mock_creds_delegated

    def test_resolve_customer_id_non_sa_uses_existing_creds(self):
        """For GCE/WIF, resolve_customer_id uses existing credentials (no key file)."""
        auth = AuthManager({"auth": {"method": "gce", "customer_id": "auto"}})
        mock_creds = MagicMock()
        auth._credentials = mock_creds

        mock_service = MagicMock()
        mock_service.users().list().execute.return_value = {
            "users": [{"customerId": "C12345"}]
        }
        with patch("gws_auditor.auth.build", return_value=mock_service):
            result = auth.resolve_customer_id()
        assert result == "C12345"


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


class TestDWDScopeProbe:
    """Tests for the per-scope domain-wide delegation probe."""

    @staticmethod
    def _write_fake_creds(tmp_path, client_id="111314288134129980759"):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({
            "type": "service_account",
            "client_id": client_id,
            "client_email": "sa@p.iam.gserviceaccount.com",
        }))
        return creds_file

    @staticmethod
    def _make_refresh_error(message: str):
        from google.auth.exceptions import RefreshError
        return RefreshError(message)

    def test_extract_client_id(self, tmp_path):
        creds_file = self._write_fake_creds(tmp_path, client_id="999")
        auth = AuthManager({"auth": {"credentials_file": str(creds_file)}})
        assert auth._extract_client_id() == "999"

    def test_extract_client_id_missing_file(self, tmp_path):
        auth = AuthManager({"auth": {"credentials_file": str(tmp_path / "nope.json")}})
        assert auth._extract_client_id() == ""

    def test_probe_all_scopes_authorized(self, tmp_path):
        creds_file = self._write_fake_creds(tmp_path)
        auth = AuthManager({"auth": {
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
        }})

        mock_creds = MagicMock()
        mock_creds.with_subject.return_value = mock_creds
        mock_creds.refresh.return_value = None
        with patch(
            "gws_auditor.auth.service_account.Credentials.from_service_account_file",
            return_value=mock_creds,
        ):
            result = auth._probe_dwd_scope_authorization()

        total = len(SCOPES) + len(SERVICE_ACCOUNT_SCOPES)
        assert len(result["authorized"]) == total
        assert result["unauthorized"] == []
        assert result["errors"] == []
        assert result["client_id"] == "111314288134129980759"

    def test_probe_partial_unauthorized(self, tmp_path):
        creds_file = self._write_fake_creds(tmp_path)
        auth = AuthManager({"auth": {
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
        }})

        missing = {
            "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
            "https://www.googleapis.com/auth/admin.directory.user.security",
        }

        def fake_from_file(path, scopes):
            scope = scopes[0]
            mock = MagicMock()
            mock.with_subject.return_value = mock
            if scope in missing:
                mock.refresh.side_effect = self._make_refresh_error(
                    "('unauthorized_client: Client is unauthorized to retrieve "
                    "access tokens using this method', '...')"
                )
            else:
                mock.refresh.return_value = None
            return mock

        with patch(
            "gws_auditor.auth.service_account.Credentials.from_service_account_file",
            side_effect=fake_from_file,
        ):
            result = auth._probe_dwd_scope_authorization()

        unauthorized_scopes = {scope for scope, _ in result["unauthorized"]}
        assert unauthorized_scopes == missing
        assert len(result["authorized"]) == (
            len(SCOPES) + len(SERVICE_ACCOUNT_SCOPES) - len(missing)
        )

    def test_probe_all_unauthorized(self, tmp_path):
        creds_file = self._write_fake_creds(tmp_path)
        auth = AuthManager({"auth": {
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
        }})

        mock_creds = MagicMock()
        mock_creds.with_subject.return_value = mock_creds
        mock_creds.refresh.side_effect = self._make_refresh_error(
            "('unauthorized_client: ...', '...')"
        )
        with patch(
            "gws_auditor.auth.service_account.Credentials.from_service_account_file",
            return_value=mock_creds,
        ):
            result = auth._probe_dwd_scope_authorization()

        assert result["authorized"] == []
        assert len(result["unauthorized"]) == len(SCOPES) + len(SERVICE_ACCOUNT_SCOPES)
        assert result["errors"] == []

    def test_probe_non_unauthorized_error_routed_to_errors(self, tmp_path):
        creds_file = self._write_fake_creds(tmp_path)
        auth = AuthManager({"auth": {
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
        }})

        mock_creds = MagicMock()
        mock_creds.with_subject.return_value = mock_creds
        mock_creds.refresh.side_effect = ConnectionError("network down")
        with patch(
            "gws_auditor.auth.service_account.Credentials.from_service_account_file",
            return_value=mock_creds,
        ):
            result = auth._probe_dwd_scope_authorization()

        assert result["authorized"] == []
        assert result["unauthorized"] == []
        assert len(result["errors"]) == len(SCOPES) + len(SERVICE_ACCOUNT_SCOPES)


class TestValidateAccessScopeReporting:
    """Integration tests for validate_access scope diagnostics."""

    @staticmethod
    def _write_fake_creds(tmp_path, client_id="111314288134129980759"):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({
            "type": "service_account",
            "client_id": client_id,
            "client_email": "sa@p.iam.gserviceaccount.com",
        }))
        return creds_file

    def test_partial_missing_scopes_reported_per_scope(self, tmp_path):
        """Each missing scope appears as a distinct row with the client ID."""
        creds_file = self._write_fake_creds(tmp_path, client_id="CID-123")
        auth = AuthManager({"auth": {
            "method": "service_account",
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
            "customer_id": "C12345",
        }})

        missing = {
            "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
            "https://www.googleapis.com/auth/apps.licensing",
        }
        probe_result = {
            "client_id": "CID-123",
            "authorized": [
                s for s in SCOPES + SERVICE_ACCOUNT_SCOPES if s not in missing
            ],
            "unauthorized": [
                (s, Exception("unauthorized_client")) for s in missing
            ],
            "errors": [],
        }

        with patch.object(AuthManager, "authenticate"), \
             patch.object(AuthManager, "_probe_dwd_scope_authorization",
                          return_value=probe_result), \
             patch.object(AuthManager, "resolve_customer_id",
                          return_value="C12345"), \
             patch.object(AuthManager, "build_service") as mock_build:
            mock_build.side_effect = Exception("skip api probes")
            results = auth.validate_access()

        # One row per missing scope, each naming the scope and client.
        scope_rows = [
            r for r in results if r["api"].startswith("DWD Scope:")
        ]
        assert len(scope_rows) == len(missing)
        for row in scope_rows:
            assert row["status"] == "error"
            assert "CID-123" in row["remediation"]
            short = row["api"].removeprefix("DWD Scope: ")
            assert any(s.endswith(short) for s in missing)

        # Aggregate row reports scope counts.
        agg = next(r for r in results if r["api"] == "DWD Scope Authorization")
        assert agg["status"] == "ok"
        assert "CID-123" in agg["message"]

    def test_all_scopes_unauthorized_reports_dwd_or_subject(self, tmp_path):
        """When every scope fails, surface a single DWD/subject diagnostic."""
        creds_file = self._write_fake_creds(tmp_path, client_id="CID-999")
        auth = AuthManager({"auth": {
            "method": "service_account",
            "credentials_file": str(creds_file),
            "subject": "admin@example.com",
            "customer_id": "C12345",
        }})

        probe_result = {
            "client_id": "CID-999",
            "authorized": [],
            "unauthorized": [
                (s, Exception("unauthorized_client"))
                for s in SCOPES + SERVICE_ACCOUNT_SCOPES
            ],
            "errors": [],
        }

        with patch.object(AuthManager, "authenticate"), \
             patch.object(AuthManager, "_probe_dwd_scope_authorization",
                          return_value=probe_result), \
             patch.object(AuthManager, "resolve_customer_id",
                          return_value="C12345"), \
             patch.object(AuthManager, "build_service") as mock_build:
            mock_build.side_effect = Exception(
                "('unauthorized_client: ...', '...')"
            )
            results = auth.validate_access()

        agg = next(r for r in results if r["api"] == "DWD Scope Authorization")
        assert agg["status"] == "error"
        assert "CID-999" in agg["message"]
        assert "admin@example.com" in agg["remediation"]

        # Per-API redundant unauthorized_client errors are suppressed
        # when scopes were already pinpointed in step 2.
        per_api_unauth = [
            r for r in results
            if r["status"] == "error"
            and "unauthorized_client" in r["message"].lower()
            and r["api"] != "DWD Scope Authorization"
        ]
        assert per_api_unauth == []
