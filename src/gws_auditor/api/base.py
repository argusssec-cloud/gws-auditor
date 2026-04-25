# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Base API client with retry, rate limiting, pagination, and error tracking."""

import http.client
import logging
import random
import socket
import ssl
import time
from typing import Any, Callable

import httplib2
from googleapiclient.errors import HttpError

from ..constants import DEFAULT_MAX_RETRIES, DEFAULT_RATE_LIMIT_QPS

logger = logging.getLogger(__name__)

# HTTP status codes that trigger a retry.
RETRYABLE_STATUS_CODES = (429, 500, 503)

# Transport-level errors that are safe to retry.  These typically arise when
# a proxy/LB returns an unexpected protocol version (``UnknownProtocol``) or
# drops the connection mid-flight.
RETRYABLE_TRANSPORT_ERRORS = (
    http.client.UnknownProtocol,
    http.client.RemoteDisconnected,
    http.client.IncompleteRead,
    httplib2.ServerNotFoundError,
    ConnectionError,           # includes ConnectionResetError, BrokenPipeError
    BrokenPipeError,
    socket.timeout,
    ssl.SSLError,              # includes SSLEOFError, SSLZeroReturnError
)


class _TokenBucket:
    """Simple token-bucket rate limiter.

    Tokens are replenished at *qps* tokens per second.  A call to
    :meth:`consume` blocks until a token is available.
    """

    def __init__(self, qps: float):
        self.qps = max(qps, 0.1)
        # Allow at least 1 token so that sub-1 QPS rates (e.g. 0.4 for
        # the Policy API) can issue the first request immediately.
        self.tokens = max(self.qps, 1.0)
        self.max_tokens = max(self.qps, 1.0)
        self._last_refill = time.monotonic()

    def consume(self) -> None:
        """Block until a token is available, then consume one."""
        while True:
            self._refill()
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            # Sleep just long enough for the next token.
            deficit = 1.0 - self.tokens
            time.sleep(deficit / self.qps)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.qps)
        self._last_refill = now


class BaseAPIClient:
    """Base class for all Google Workspace API clients.

    Provides:
    * Exponential-backoff retry for transient HTTP errors.
    * Token-bucket rate limiting (configurable QPS).
    * Pagination helper for APIs that use the ``nextPageToken`` pattern.
    * A shared list for collecting non-fatal API errors encountered during
      an audit run.

    Parameters
    ----------
    auth_manager:
        An :class:`~gws_auditor.auth.AuthManager` instance used to build
        Google API service objects.
    max_retries:
        Maximum number of retry attempts for transient errors.
    rate_limit_qps:
        Queries-per-second cap enforced via a **per-client** token bucket.
        When multiple API clients run concurrently during ``collect_all()``,
        the effective QPS is multiplied by the number of active clients.
        For quota-sensitive APIs (e.g. Cloud Identity Policy API at ~0.4 QPS),
        pass a lower ``rate_limit_qps`` to stay within project-level quotas.
    """

    def __init__(
        self,
        auth_manager,
        max_retries: int = DEFAULT_MAX_RETRIES,
        rate_limit_qps: float = DEFAULT_RATE_LIMIT_QPS,
    ):
        self.auth_manager = auth_manager
        self.max_retries = max_retries
        self.rate_limit_qps = rate_limit_qps
        self._bucket = _TokenBucket(rate_limit_qps)
        self.errors: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Retry
    # ------------------------------------------------------------------

    def execute_with_retry(self, request) -> Any:
        """Execute a Google API request with exponential backoff.

        Retries automatically on 429 (rate-limited), 500 (internal server
        error), and 503 (service unavailable) responses.

        Parameters
        ----------
        request:
            A Google API ``HttpRequest`` object (the return value of
            methods like ``service.users().list(...)``).

        Returns
        -------
        The parsed JSON response body.

        Raises
        ------
        HttpError
            If all retry attempts are exhausted or the error is not
            retryable.
        """
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                self._bucket.consume()
                return request.execute()
            except HttpError as exc:
                last_error = exc
                status = exc.resp.status if exc.resp else 0

                if status not in RETRYABLE_STATUS_CODES:
                    raise

                if attempt == self.max_retries:
                    logger.exception(
                        "Max retries (%d) exhausted for request (HTTP %s)",
                        self.max_retries,
                        status,
                    )
                    raise

                backoff = min(2 ** attempt + random.uniform(0, 1), 60)
                logger.warning(
                    "Retryable HTTP %s error (attempt %d/%d). "
                    "Backing off %.1f s …",
                    status,
                    attempt + 1,
                    self.max_retries,
                    backoff,
                )
                time.sleep(backoff)
            except RETRYABLE_TRANSPORT_ERRORS as exc:
                last_error = exc
                if attempt == self.max_retries:
                    logger.exception(
                        "Max retries (%d) exhausted for request "
                        "(transport error: %s)",
                        self.max_retries,
                        exc,
                    )
                    raise

                backoff = min(2 ** attempt + random.uniform(0, 1), 60)
                logger.warning(
                    "Retryable transport error %s (attempt %d/%d). "
                    "Backing off %.1f s …",
                    type(exc).__name__,
                    attempt + 1,
                    self.max_retries,
                    backoff,
                )
                time.sleep(backoff)
            except Exception as exc:
                # Non-HTTP, non-transport errors are not retried.
                raise

        # Should be unreachable, but satisfy the type-checker.
        raise last_error  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def paginate(
        self,
        request_builder: Callable[..., Any],
        items_key: str,
        *,
        max_items: int = 0,
        **kwargs,
    ) -> list[Any]:
        """Auto-paginate through a Google API list endpoint.

        Parameters
        ----------
        request_builder:
            A callable that, given keyword arguments (including an optional
            ``pageToken``), returns an ``HttpRequest``.  Typically this is
            a bound method such as ``service.users().list``.
        items_key:
            The key in the response JSON that contains the list of items
            (e.g., ``"users"``, ``"activities"``).
        max_items:
            Stop collecting after this many items.  ``0`` means no limit
            (collect all pages).  When the limit is reached, a debug log
            message is emitted and pagination stops.
        **kwargs:
            Additional keyword arguments forwarded to *request_builder*
            on every page request.

        Returns
        -------
        A flat list of all collected items across every page.
        """
        all_items: list[Any] = []
        page_token: str | None = None

        while True:
            if page_token:
                kwargs["pageToken"] = page_token

            request = request_builder(**kwargs)
            response = self.execute_with_retry(request)

            items = response.get(items_key, [])
            all_items.extend(items)

            if max_items and len(all_items) >= max_items:
                logger.debug(
                    "Reached max_items limit (%d); stopping pagination "
                    "(collected %d items, key=%s)",
                    max_items,
                    len(all_items),
                    items_key,
                )
                break

            page_token = response.get("nextPageToken")
            if not page_token:
                break

        logger.debug(
            "Paginated %d items (key=%s)", len(all_items), items_key
        )
        return all_items

    # ------------------------------------------------------------------
    # Error tracking
    # ------------------------------------------------------------------

    def record_error(self, operation: str, error: Exception) -> None:
        """Record a non-fatal API error for later inclusion in the report.

        Parameters
        ----------
        operation:
            A human-readable description of the operation that failed
            (e.g., ``"list_users"``).
        error:
            The exception that was raised.
        """
        entry = {
            "operation": operation,
            "error_type": type(error).__name__,
            "message": str(error),
        }
        self.errors.append(entry)
        logger.warning("API error recorded – %s: %s", operation, error)
