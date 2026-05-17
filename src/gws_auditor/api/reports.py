# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Admin SDK Reports API client.

Wraps the ``admin`` / ``reports_v1`` service and provides methods for
retrieving audit activity events and usage reports.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import BaseAPIClient
from ..constants import DEFAULT_USAGE_REPORT_LOOKBACK_DAYS

logger = logging.getLogger(__name__)

# Default lookback window when no explicit start_time is provided.
_DEFAULT_LOOKBACK_DAYS = DEFAULT_USAGE_REPORT_LOOKBACK_DAYS


def _default_start_time() -> str:
    """Return an RFC 3339 timestamp for the default lookback window."""
    dt = datetime.now(timezone.utc) - timedelta(days=_DEFAULT_LOOKBACK_DAYS)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class ReportsClient(BaseAPIClient):
    """Client for the Admin SDK Reports API (``reports_v1``)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    # ------------------------------------------------------------------
    # Service (lazy build)
    # ------------------------------------------------------------------

    @property
    def service(self):
        """Lazily build and cache the Reports API service."""
        if self._service is None:
            logger.debug("Building Admin SDK Reports service")
            self._service = self.auth_manager.build_service(
                "admin", "reports_v1"
            )
        return self._service

    # ------------------------------------------------------------------
    # Activity reports
    # ------------------------------------------------------------------

    def get_admin_activities(
        self,
        customer_id: str,
        start_time: str | None = None,
        filters: str | None = None,
        event_name: str | None = None,
        max_items: int = 0,
    ) -> list[dict[str, Any]]:
        """Retrieve admin audit activity events.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        start_time:
            RFC 3339 formatted timestamp for the start of the query
            window.  Defaults to the last 180 days.
        filters:
            Optional event filter string (e.g.,
            ``"event_name==ADD_PRIVILEGE"``).
        event_name:
            Optional event name filter (e.g., ``"CHANGE_SETTING"``).
        max_items:
            Stop collecting after this many items.  ``0`` means no limit.

        Returns
        -------
        A list of activity resource dicts.
        """
        try:
            kwargs: dict[str, Any] = {
                "userKey": "all",
                "applicationName": "admin",
                "customerId": customer_id,
                "startTime": start_time or _default_start_time(),
                "maxResults": 1000,
            }
            if filters:
                kwargs["filters"] = filters
            if event_name:
                kwargs["eventName"] = event_name

            activities = self.paginate(
                self.service.activities().list,
                items_key="items",
                max_items=max_items,
                **kwargs,
            )
            logger.info("Retrieved %d admin activity events", len(activities))
            return activities
        except Exception as exc:
            self.record_error("get_admin_activities", exc)
            return []

    def get_login_activities(
        self,
        customer_id: str,
        start_time: str | None = None,
        event_name: str | None = None,
        max_items: int = 0,
    ) -> list[dict[str, Any]]:
        """Retrieve login activity events.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        start_time:
            RFC 3339 formatted timestamp.  Defaults to the last 180 days.
        event_name:
            Optional event name filter (e.g., ``"login_failure"``).
        max_items:
            Stop collecting after this many items.  ``0`` means no limit.

        Returns
        -------
        A list of login activity resource dicts.
        """
        try:
            kwargs: dict[str, Any] = {
                "userKey": "all",
                "applicationName": "login",
                "customerId": customer_id,
                "startTime": start_time or _default_start_time(),
                "maxResults": 1000,
            }
            if event_name:
                kwargs["eventName"] = event_name

            activities = self.paginate(
                self.service.activities().list,
                items_key="items",
                max_items=max_items,
                **kwargs,
            )
            logger.info("Retrieved %d login activity events", len(activities))
            return activities
        except Exception as exc:
            self.record_error("get_login_activities", exc)
            return []

    def get_token_activities(
        self,
        customer_id: str,
        start_time: str | None = None,
        max_items: int = 0,
    ) -> list[dict[str, Any]]:
        """Retrieve OAuth token grant activity events.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        start_time:
            RFC 3339 formatted timestamp for the start of the query
            window.  Defaults to the last 180 days.
        max_items:
            Stop collecting after this many items.  ``0`` means no limit.

        Returns
        -------
        A list of token activity resource dicts.
        """
        try:
            activities = self.paginate(
                self.service.activities().list,
                items_key="items",
                max_items=max_items,
                userKey="all",
                applicationName="token",
                customerId=customer_id,
                startTime=start_time or _default_start_time(),
                maxResults=1000,
            )
            logger.info("Retrieved %d token activity events", len(activities))
            return activities
        except Exception as exc:
            self.record_error("get_token_activities", exc)
            return []

    def get_caa_activities(
        self,
        customer_id: str,
        start_time: str | None = None,
        max_items: int = 0,
    ) -> list[dict[str, Any]]:
        """Retrieve Context-Aware Access denial events.

        Queries ``applicationName=context_aware_access`` which exposes a
        single documented event ``ACCESS_DENY_EVENT`` — fired whenever a
        CAA policy blocks an access attempt.  Used as positive evidence
        that CAA is actively enforcing for the tenant.

        Reference: https://developers.google.com/admin-sdk/reports/v1/appendix/activity/context-aware-access
        """
        try:
            activities = self.paginate(
                self.service.activities().list,
                items_key="items",
                max_items=max_items,
                userKey="all",
                applicationName="context_aware_access",
                customerId=customer_id,
                startTime=start_time or _default_start_time(),
                maxResults=1000,
            )
            logger.info("Retrieved %d CAA activity events", len(activities))
            return activities
        except Exception as exc:
            self.record_error("get_caa_activities", exc)
            return []

    # ------------------------------------------------------------------
    # Usage reports
    # ------------------------------------------------------------------

    def get_user_usage_report(
        self,
        customer_id: str,
        date: str,
    ) -> list[dict[str, Any]]:
        """Retrieve per-user usage statistics for a given date.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        date:
            The date for the report in ``YYYY-MM-DD`` format.

        Returns
        -------
        A list of user-usage resource dicts.
        """
        try:
            usage = self.paginate(
                self.service.userUsageReport().get,
                items_key="usageReports",
                userKey="all",
                date=date,
                customerId=customer_id,
            )
            logger.info(
                "Retrieved %d user usage reports for %s", len(usage), date
            )
            return usage
        except Exception as exc:
            self.record_error(f"get_user_usage_report({date})", exc)
            return []

    def get_customer_usage_report(
        self,
        customer_id: str,
        date: str,
    ) -> list[dict[str, Any]]:
        """Retrieve customer-level usage statistics for a given date.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        date:
            The date for the report in ``YYYY-MM-DD`` format.

        Returns
        -------
        A list of customer-usage resource dicts.
        """
        try:
            usage = self.paginate(
                self.service.customerUsageReports().get,
                items_key="usageReports",
                date=date,
                customerId=customer_id,
            )
            logger.info(
                "Retrieved %d customer usage reports for %s",
                len(usage),
                date,
            )
            return usage
        except Exception as exc:
            self.record_error(f"get_customer_usage_report({date})", exc)
            return []
