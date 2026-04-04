# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Calendar API client.

Wraps the ``calendar`` / ``v3`` service and provides methods for listing
calendars and retrieving calendar ACLs.
"""

import logging
from typing import Any

from googleapiclient.errors import HttpError

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class CalendarNotFoundError(Exception):
    """Raised when a user's calendar does not exist or is inaccessible (HTTP 404)."""

    def __init__(self, user_email: str, calendar_id: str):
        self.user_email = user_email
        self.calendar_id = calendar_id
        super().__init__(
            f"Calendar not found: {calendar_id} (user={user_email})"
        )


class CalendarClient(BaseAPIClient):
    """Client for the Google Calendar API (``v3``).

    Calendar endpoints require domain-wide delegation so the auditor can
    inspect each user's calendar settings.
    """

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._services: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Service (lazy build, per-user delegation)
    # ------------------------------------------------------------------

    def _get_service(self, user_email: str):
        """Return a Calendar service instance delegated to *user_email*.

        With service-account credentials, delegation via ``with_subject``
        is used to impersonate the target user.  With OAuth credentials
        (which authenticate as the logged-in admin), we use the
        credentials directly — the admin can read ACLs for any user's
        calendar.
        """
        if user_email not in self._services:
            logger.debug("Building Calendar service for %s", user_email)
            creds = self.auth_manager.credentials
            if hasattr(creds, "with_subject"):
                creds = creds.with_subject(user_email)
            from googleapiclient.discovery import build

            authed_http = self.auth_manager.build_authorized_http(creds)
            self._services[user_email] = build(
                "calendar",
                "v3",
                http=authed_http,
                cache_discovery=False,
            )
        return self._services[user_email]

    # ------------------------------------------------------------------
    # Calendars
    # ------------------------------------------------------------------

    def list_calendars(self, user_email: str) -> list[dict[str, Any]]:
        """List calendars visible to a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        A list of calendar-list-entry resource dicts.
        """
        try:
            service = self._get_service(user_email)
            calendars = self.paginate(
                service.calendarList().list,
                items_key="items",
            )
            logger.debug(
                "%s has %d calendars", user_email, len(calendars)
            )
            return calendars
        except Exception as exc:
            self.record_error(f"list_calendars({user_email})", exc)
            return []

    # ------------------------------------------------------------------
    # ACLs
    # ------------------------------------------------------------------

    def get_calendar_acl(
        self, user_email: str, calendar_id: str
    ) -> list[dict[str, Any]]:
        """Get the access control list for a specific calendar.

        Parameters
        ----------
        user_email:
            The user's primary email address (used for delegation).
        calendar_id:
            The calendar identifier (often the user's email for the
            primary calendar, or a calendar-specific ID).

        Returns
        -------
        A list of ACL rule resource dicts.
        """
        try:
            service = self._get_service(user_email)
            acl_entries = self.paginate(
                service.acl().list,
                items_key="items",
                calendarId=calendar_id,
            )
            logger.debug(
                "Calendar %s (%s) has %d ACL rules",
                calendar_id,
                user_email,
                len(acl_entries),
            )
            return acl_entries
        except HttpError as exc:
            status = exc.resp.status if exc.resp else 0
            if status == 404:
                raise CalendarNotFoundError(user_email, calendar_id) from exc
            self.record_error(
                f"get_calendar_acl({user_email}, {calendar_id})", exc
            )
            return []
        except Exception as exc:
            self.record_error(
                f"get_calendar_acl({user_email}, {calendar_id})", exc
            )
            return []
