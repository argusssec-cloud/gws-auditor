# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Authentication for GWS Security Auditor.

Supports two modes:
- Service Account with domain-wide delegation (recommended for automation)
- OAuth 2.0 user consent flow (for interactive use)
"""

import json
import logging
import os

from urllib.parse import urlparse

import httplib2
from httplib2 import ProxyInfo, socks as httplib2_socks
import google_auth_httplib2
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from .constants import SCOPES, SERVICE_ACCOUNT_SCOPES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Force HTTP/1.1 — httplib2 only supports HTTP/1.1 but some proxies /
# load balancers negotiate HTTP/2 via ALPN during the TLS handshake,
# which causes ``http.client.UnknownProtocol: HTTP/2`` errors.  We patch
# httplib2's internal SSL-context builder to restrict ALPN to HTTP/1.1.
# ---------------------------------------------------------------------------
_orig_build_ssl_context = getattr(httplib2, "_build_ssl_context", None)

if _orig_build_ssl_context is not None:

    def _patched_build_ssl_context(*args, **kwargs):
        ctx = _orig_build_ssl_context(*args, **kwargs)
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass  # Older Python/OpenSSL without ALPN support — harmless.
        return ctx

    httplib2._build_ssl_context = _patched_build_ssl_context
    logger.debug("Patched httplib2._build_ssl_context to force HTTP/1.1 ALPN")


class AuthManager:
    """Manages authentication to Google Workspace APIs."""

    def __init__(self, config: dict):
        self.config = config.get("auth", {})
        self.method = self.config.get("method", "service_account")
        self.credentials_file = self.config.get("credentials_file", "credentials.json")
        self.subject = self.config.get("subject", "")
        self.customer_id = self.config.get("customer_id", "my_customer")
        self._credentials = None
        self._network = config.get("network", {})

    def authenticate(self):
        """Authenticate based on configured method."""
        if self.method == "service_account":
            self._authenticate_service_account()
        elif self.method == "oauth":
            self._authenticate_oauth()
        else:
            raise ValueError(f"Unknown auth method: {self.method}")

        logger.info("Authentication successful (method=%s)", self.method)
        return self._credentials

    def _authenticate_service_account(self):
        """Authenticate using a service account with domain-wide delegation."""
        if not os.path.exists(self.credentials_file):
            raise FileNotFoundError(
                f"Service account credentials file not found: {self.credentials_file}"
            )

        all_scopes = SCOPES + SERVICE_ACCOUNT_SCOPES
        self._credentials = service_account.Credentials.from_service_account_file(
            self.credentials_file, scopes=all_scopes
        )

        if self.subject:
            self._credentials = self._credentials.with_subject(self.subject)

    def _authenticate_oauth(self):
        """Authenticate using OAuth 2.0 user consent flow."""
        token_file = self.config.get("token_file", "token.json")

        if os.path.exists(token_file):
            from google.oauth2.credentials import Credentials
            self._credentials = Credentials.from_authorized_user_file(token_file, SCOPES)

        if not self._credentials or not self._credentials.valid:
            if self._credentials and self._credentials.expired and self._credentials.refresh_token:
                try:
                    http = self._build_http()
                    request = google_auth_httplib2.Request(http)
                    self._credentials.refresh(request)
                except Exception as exc:
                    if "invalid_scope" in str(exc).lower():
                        logger.warning(
                            "Token refresh failed (scope mismatch); "
                            "deleting stale token and re-authenticating"
                        )
                        os.remove(token_file)
                        self._credentials = None
                    else:
                        raise

            if self._credentials is None:
                if not os.path.exists(self.credentials_file):
                    raise FileNotFoundError(
                        f"OAuth client secrets file not found: {self.credentials_file}"
                    )
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_file, SCOPES
                )
                self._credentials = flow.run_local_server(port=0)

            with open(token_file, "w") as token:
                token.write(self._credentials.to_json())

    @property
    def credentials(self):
        if self._credentials is None:
            self.authenticate()
        return self._credentials

    def _build_http(self) -> httplib2.Http:
        """Build an httplib2.Http, optionally configured with a proxy and CA."""
        kwargs = {}

        # --- CA certificate / SSL verification ---
        ca_cert = self._network.get("ca_cert")
        disable_ssl = self._network.get("disable_ssl_verification", False)
        if disable_ssl:
            logger.warning("SSL certificate verification is DISABLED")
            kwargs["disable_ssl_certificate_validation"] = True
        elif ca_cert:
            if not os.path.exists(ca_cert):
                raise FileNotFoundError(
                    f"CA certificate file not found: {ca_cert}"
                )
            logger.debug("Using custom CA bundle: %s", ca_cert)
            kwargs["ca_certs"] = ca_cert

        # --- Proxy ---
        proxy_url = self._network.get("proxy")
        if proxy_url:
            # httplib2 proxy support requires the socks module (PySocks).
            # Without it, ProxyInfo.isgood() returns falsy and all
            # requests silently bypass the proxy.
            if httplib2_socks is None:
                raise ImportError(
                    "Proxy support requires the PySocks package. "
                    "Install it with:  pip install PySocks"
                )
            parsed = urlparse(proxy_url)
            no_proxy = self._network.get("no_proxy") or ""
            bypass_hosts = (
                [h.strip() for h in no_proxy.split(",") if h.strip()]
                if no_proxy else []
            )
            proxy_info = ProxyInfo(
                proxy_type=httplib2_socks.PROXY_TYPE_HTTP,
                proxy_host=parsed.hostname,
                proxy_port=parsed.port or 8080,
                proxy_user=parsed.username or None,
                proxy_pass=parsed.password or None,
            )
            proxy_info.bypass_hosts = bypass_hosts
            logger.debug(
                "Using HTTP proxy %s:%s (no_proxy=%s)",
                proxy_info.proxy_host,
                proxy_info.proxy_port,
                no_proxy or "<none>",
            )
            kwargs["proxy_info"] = proxy_info

        return httplib2.Http(**kwargs)

    def build_authorized_http(self, credentials=None):
        """Build a proxy-aware AuthorizedHttp for the given credentials.

        Parameters
        ----------
        credentials:
            Google auth credentials to wrap.  Defaults to
            ``self.credentials`` when *None*.

        Returns
        -------
        google_auth_httplib2.AuthorizedHttp
        """
        if credentials is None:
            credentials = self.credentials
        http = self._build_http()
        return google_auth_httplib2.AuthorizedHttp(credentials, http=http)

    def build_service(self, service_name: str, version: str, **kwargs):
        """Build a Google API service client with proxy support."""
        authed_http = self.build_authorized_http()
        return build(
            service_name,
            version,
            http=authed_http,
            cache_discovery=False,
            **kwargs,
        )


    def resolve_customer_id(self) -> str:
        """Auto-discover the real customer ID from the authenticated credentials.

        Uses a **narrow-scope credential** (single scope) so that DWD
        authorization issues with other scopes don't block discovery.
        Falls back to ``"my_customer"`` (valid API alias) on any error.
        """
        if self.customer_id and self.customer_id not in ("my_customer", "auto", ""):
            logger.debug("Using configured customer_id: %s", self.customer_id)
            return self.customer_id

        try:
            # Build a single-scope credential for discovery to avoid
            # failing when optional scopes aren't authorized in DWD.
            discovery_scope = "https://www.googleapis.com/auth/admin.directory.user.readonly"
            discovery_creds = service_account.Credentials.from_service_account_file(
                self.credentials_file, scopes=[discovery_scope]
            )
            if self.subject:
                discovery_creds = discovery_creds.with_subject(self.subject)
            authed_http = self.build_authorized_http(discovery_creds)
            service = build("admin", "directory_v1", http=authed_http, cache_discovery=False)
            result = service.users().list(
                customer="my_customer", maxResults=1,
            ).execute()
            users = result.get("users", [])
            if users:
                real_id = users[0].get("customerId", "")
                if real_id:
                    logger.info("Auto-discovered customer ID: %s", real_id)
                    self.customer_id = real_id
                    return real_id
        except Exception as exc:
            logger.debug("Customer ID discovery failed: %s", exc)

        fallback = "my_customer"
        self.customer_id = fallback
        return fallback

    def test_connection(self) -> bool:
        """Test API connectivity by making a simple directory API call."""
        try:
            service = self.build_service("admin", "directory_v1")
            service.users().list(
                customer=self.customer_id, maxResults=1
            ).execute()
            logger.info("API connectivity test passed")
            return True
        except Exception as e:
            logger.error("API connectivity test failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Comprehensive access validation
    # ------------------------------------------------------------------

    # Each entry: (display_name, service_name, api_version, test_callable_factory)
    # The test_callable_factory takes a service object and the customer_id
    # and returns a callable that performs a minimal API request.
    _API_PROBES = [
        (
            "Admin SDK - Directory (Users)",
            "admin", "directory_v1",
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            lambda svc, cid: svc.users().list(customer=cid, maxResults=1).execute,
            "Admin SDK API",
        ),
        (
            "Admin SDK - Directory (Domains)",
            "admin", "directory_v1",
            "https://www.googleapis.com/auth/admin.directory.domain.readonly",
            lambda svc, cid: svc.domains().list(customer=cid).execute,
            "Admin SDK API",
        ),
        (
            "Admin SDK - Directory (Org Units)",
            "admin", "directory_v1",
            "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
            lambda svc, cid: svc.orgunits().list(customerId=cid).execute,
            "Admin SDK API",
        ),
        (
            "Admin SDK - Directory (Groups)",
            "admin", "directory_v1",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
            lambda svc, cid: svc.groups().list(customer=cid, maxResults=1).execute,
            "Admin SDK API",
        ),
        (
            "Admin SDK - Reports (Admin Activity)",
            "admin", "reports_v1",
            "https://www.googleapis.com/auth/admin.reports.audit.readonly",
            lambda svc, cid: svc.activities().list(
                userKey="all", applicationName="admin", maxResults=1
            ).execute,
            "Admin SDK API",
        ),
        (
            "Admin SDK - Reports (Usage)",
            "admin", "reports_v1",
            "https://www.googleapis.com/auth/admin.reports.usage.readonly",
            # Usage reports need a date; use a recent one
            lambda svc, cid: svc.customerUsageReports().get(
                date="2026-02-23"
            ).execute,
            "Admin SDK API",
        ),
        (
            "Groups Settings API",
            "groupssettings", "v1",
            "https://www.googleapis.com/auth/apps.groups.settings",
            None,  # Probed separately in _probe_groups_settings
            "Groups Settings API",
        ),
        (
            "Cloud Identity - Policy API",
            "cloudidentity", "v1",
            "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
            lambda svc, cid: svc.policies().list(
                filter=f"setting.type.matches('^settings/security\\\\..*$')"
                       f' && customer == "customers/{cid}"',
                pageSize=1,
            ).execute,
            "Cloud Identity API",
        ),
        (
            "Chrome Policy API",
            "chromepolicy", "v1",
            "https://www.googleapis.com/auth/chrome.management.policy.readonly",
            None,  # Probed separately in _probe_chrome_policy
            "Chrome Policy API",
        ),
    ]

    def _probe_groups_settings(self, scope: str, gcp_api_name: str) -> dict:
        """Probe Groups Settings API using a real group from the directory."""
        from googleapiclient.errors import HttpError

        api_name = "Groups Settings API"
        try:
            # Fetch one group to get a valid email for the probe
            dir_svc = self.build_service("admin", "directory_v1")
            result = dir_svc.groups().list(
                customer=self.customer_id, maxResults=1
            ).execute()
            groups = result.get("groups", [])
            if not groups:
                return {
                    "api": api_name,
                    "status": "ok",
                    "message": "No groups in domain (nothing to probe)",
                    "remediation": None,
                }
            group_email = groups[0]["email"]
            gs_svc = self.build_service("groupssettings", "v1")
            gs_svc.groups().get(groupUniqueId=group_email).execute()
            return {
                "api": api_name,
                "status": "ok",
                "message": "API accessible",
                "remediation": None,
            }
        except HttpError as exc:
            status = exc.resp.status if exc.resp else 0
            return {
                "api": api_name,
                "status": "error",
                "message": f"HTTP {status}: {exc}",
                "remediation": self._api_error_remediation(
                    api_name, gcp_api_name, scope, status, exc
                ),
            }
        except Exception as exc:
            return {
                "api": api_name,
                "status": "error",
                "message": str(exc),
                "remediation": self._api_error_remediation(
                    api_name, gcp_api_name, scope, 0, exc
                ),
            }

    def _probe_chrome_policy(self, scope: str, gcp_api_name: str) -> dict:
        """Probe Chrome Policy API using the root OU."""
        from googleapiclient.errors import HttpError

        api_name = "Chrome Policy API"
        try:
            # Resolve root OU ID from a child OU's parentOrgUnitId
            dir_svc = self.build_service("admin", "directory_v1")
            result = dir_svc.orgunits().list(
                customerId=self.customer_id, type="children"
            ).execute()
            org_units = result.get("organizationUnits", [])
            if not org_units:
                return {
                    "api": api_name,
                    "status": "ok",
                    "message": "No child OUs (cannot resolve root OU for probe)",
                    "remediation": None,
                }
            ou_id = org_units[0].get("parentOrgUnitId", "").removeprefix("id:")

            svc = self.build_service("chromepolicy", "v1")
            svc.customers().policies().resolve(
                customer=f"customers/{self.customer_id}",
                body={
                    "policySchemaFilter": "chrome.users.BrowserSignin",
                    "policyTargetKey": {
                        "targetResource": f"orgunits/{ou_id}",
                    },
                },
            ).execute()
            return {
                "api": api_name,
                "status": "ok",
                "message": "API accessible",
                "remediation": None,
            }
        except HttpError as exc:
            status = exc.resp.status if exc.resp else 0
            if status == 404:
                return {
                    "api": api_name,
                    "status": "ok",
                    "message": "API accessible (policy schema not available for this tenant)",
                    "remediation": None,
                }
            return {
                "api": api_name,
                "status": "error",
                "message": f"HTTP {status}: {exc}",
                "remediation": self._api_error_remediation(
                    api_name, gcp_api_name, scope, status, exc
                ),
            }
        except Exception as exc:
            return {
                "api": api_name,
                "status": "error",
                "message": str(exc),
                "remediation": self._api_error_remediation(
                    api_name, gcp_api_name, scope, 0, exc
                ),
            }

    _CUSTOM_PROBES = {
        "Groups Settings API": _probe_groups_settings,
        "Chrome Policy API": _probe_chrome_policy,
    }

    def validate_access(self) -> list[dict]:
        """Validate credentials, API enablement, and scope access.

        Probes each required Google API with a minimal request and
        returns a list of result dicts with detailed diagnostics::

            [
                {
                    "api": "Admin SDK - Directory (Users)",
                    "status": "ok" | "error",
                    "message": "...",
                    "remediation": "..." | None,
                },
                ...
            ]

        Call :meth:`authenticate` before this method.
        """
        from datetime import datetime, timedelta, timezone
        from googleapiclient.errors import HttpError

        results: list[dict] = []

        # --- Step 0: credential file ---
        if not os.path.exists(self.credentials_file):
            results.append({
                "api": "Credentials File",
                "status": "error",
                "message": f"Credentials file not found: {self.credentials_file}",
                "remediation": (
                    f"Create or download the credentials file to "
                    f"'{self.credentials_file}'. For service accounts, "
                    f"download the JSON key from the GCP Console under "
                    f"IAM & Admin > Service Accounts."
                ),
            })
            return results  # Can't proceed without credentials

        results.append({
            "api": "Credentials File",
            "status": "ok",
            "message": f"Found {self.credentials_file}",
            "remediation": None,
        })

        # --- Step 1: authenticate ---
        try:
            self.authenticate()
        except Exception as exc:
            results.append({
                "api": "Authentication",
                "status": "error",
                "message": f"Authentication failed: {exc}",
                "remediation": self._auth_remediation(exc),
            })
            return results

        results.append({
            "api": "Authentication",
            "status": "ok",
            "message": f"Authenticated via {self.method}",
            "remediation": None,
        })

        # --- Step 2: check granted scopes (service account only) ---
        if self.method == "service_account":
            cred_scopes = set(getattr(self._credentials, "scopes", None) or [])
            required = set(SCOPES + SERVICE_ACCOUNT_SCOPES)
            missing = required - cred_scopes
            if missing:
                short = [s.rsplit("/", 1)[-1] for s in sorted(missing)]
                results.append({
                    "api": "OAuth Scopes",
                    "status": "error",
                    "message": f"Missing scopes: {', '.join(short)}",
                    "remediation": (
                        "Add the missing scopes to the service account's "
                        "domain-wide delegation in the Google Admin Console: "
                        "Security > API controls > Domain-wide Delegation. "
                        f"Required scopes:\n"
                        + "\n".join(f"  - {s}" for s in sorted(missing))
                    ),
                })
            else:
                results.append({
                    "api": "OAuth Scopes",
                    "status": "ok",
                    "message": f"All {len(required)} required scopes present",
                    "remediation": None,
                })

        # --- Step 2b: resolve customer ID ---
        self.resolve_customer_id()

        # --- Step 3: probe each API ---
        # Use a recent date for usage reports
        recent_date = (
            datetime.now(timezone.utc) - timedelta(days=2)
        ).strftime("%Y-%m-%d")

        for entry in self._API_PROBES:
            api_name, svc_name, svc_ver, scope, factory, gcp_api_name = entry

            if factory is None:
                # Use custom probe methods for APIs that need extra context
                probe_method = self._CUSTOM_PROBES.get(api_name)
                if probe_method:
                    results.append(probe_method(self, scope, gcp_api_name))
                else:
                    results.append({
                        "api": api_name,
                        "status": "ok",
                        "message": "Skipped (requires additional context to probe)",
                        "remediation": None,
                    })
                continue

            try:
                svc = self.build_service(svc_name, svc_ver)
                call = factory(svc, self.customer_id)
                call()
                results.append({
                    "api": api_name,
                    "status": "ok",
                    "message": "API accessible",
                    "remediation": None,
                })
            except HttpError as exc:
                status = exc.resp.status if exc.resp else 0
                # 404 on a probe with a dummy resource means the API is
                # reachable and auth succeeded — the resource just doesn't
                # exist, which is expected.
                if status == 404:
                    results.append({
                        "api": api_name,
                        "status": "ok",
                        "message": "API accessible",
                        "remediation": None,
                    })
                    continue
                results.append({
                    "api": api_name,
                    "status": "error",
                    "message": f"HTTP {status}: {exc}",
                    "remediation": self._api_error_remediation(
                        api_name, gcp_api_name, scope, status, exc
                    ),
                })
            except Exception as exc:
                results.append({
                    "api": api_name,
                    "status": "error",
                    "message": str(exc),
                    "remediation": self._api_error_remediation(
                        api_name, gcp_api_name, scope, 0, exc
                    ),
                })

        return results

    @staticmethod
    def _auth_remediation(exc: Exception) -> str:
        """Return remediation guidance for authentication failures."""
        msg = str(exc).lower()
        if "invalid_grant" in msg or "unauthorized_client" in msg:
            return (
                "The service account cannot impersonate the subject user. "
                "Ensure domain-wide delegation is enabled:\n"
                "  1. Go to Google Admin Console > Security > API controls > "
                "Domain-wide Delegation\n"
                "  2. Add the service account's Client ID\n"
                "  3. Add all required OAuth scopes\n"
                "  4. Verify the 'subject' email in config.yaml is a "
                "super-admin in the target domain"
            )
        if "file" in msg and "not found" in msg:
            return (
                "Download the service account JSON key from GCP Console: "
                "IAM & Admin > Service Accounts > Keys > Add Key > JSON"
            )
        if "could not deserialize" in msg or "json" in msg:
            return (
                "The credentials file appears malformed. Re-download the "
                "service account JSON key from the GCP Console."
            )
        return (
            f"Authentication error: {exc}. "
            "Check that the credentials file is valid and that the service "
            "account has domain-wide delegation configured."
        )

    @staticmethod
    def _api_error_remediation(
        api_name: str,
        gcp_api_name: str,
        scope: str,
        status: int,
        exc: Exception,
    ) -> str:
        """Return remediation guidance based on HTTP error status."""
        msg = str(exc).lower()
        short_scope = scope.rsplit("/", 1)[-1]

        if status == 403:
            if "not been used" in msg or "access not configured" in msg or "disabled" in msg:
                return (
                    f"The {gcp_api_name} is not enabled in the GCP project. "
                    f"Enable it:\n"
                    f"  1. Go to https://console.cloud.google.com/apis/library\n"
                    f"  2. Search for '{gcp_api_name}'\n"
                    f"  3. Click 'Enable'"
                )
            if "insufficient" in msg or "permission" in msg or "forbidden" in msg:
                return (
                    f"The service account lacks permission for {api_name}. "
                    f"Ensure:\n"
                    f"  1. Domain-wide delegation includes the scope:\n"
                    f"     {scope}\n"
                    f"  2. The subject user ({short_scope}) is a super-admin\n"
                    f"  3. The scope is listed in Admin Console > Security > "
                    f"API controls > Domain-wide Delegation"
                )
            return (
                f"Access denied for {api_name} (HTTP 403). Check:\n"
                f"  - API is enabled in GCP project\n"
                f"  - Domain-wide delegation includes: {scope}\n"
                f"  - Subject user is a super-admin"
            )

        if status == 401:
            return (
                f"Unauthorized for {api_name}. The credentials may be "
                f"expired or invalid. Try re-authenticating or regenerating "
                f"the service account key."
            )

        if status == 404:
            return (
                f"Resource not found for {api_name} (HTTP 404). Check:\n"
                f"  - The customer_id in config.yaml is correct\n"
                f"  - The API endpoint is available for your GWS edition"
            )

        # Transport / network errors
        if "unknownprotocol" in msg:
            return (
                f"HTTP/2 protocol error for {api_name}. This typically means "
                f"a proxy or load balancer is returning HTTP/2 responses. "
                f"The ALPN patch should handle this — check network/proxy "
                f"configuration."
            )

        return (
            f"Error accessing {api_name}: {exc}\n"
            f"  - Ensure {gcp_api_name} is enabled in GCP project\n"
            f"  - Ensure domain-wide delegation includes: {scope}\n"
            f"  - Check network connectivity and proxy settings"
        )
