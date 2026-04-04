# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Gmail API client.

Wraps the ``gmail`` / ``v1`` service and provides methods for inspecting
per-user mail settings that are relevant to security auditing (forwarding,
delegation, IMAP/POP access, send-as aliases).
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class GmailClient(BaseAPIClient):
    """Client for the Gmail API (``v1``).

    Gmail per-user settings endpoints require domain-wide delegation and
    the ``gmail.settings.basic`` scope.  Each method accepts a
    *user_email* parameter so the auditor can iterate over all users in
    the domain.
    """

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._services: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Service (lazy build, per-user delegation)
    # ------------------------------------------------------------------

    def _get_service(self, user_email: str):
        """Return a Gmail service instance delegated to *user_email*.

        The Admin SDK uses a single service for all users, but the Gmail
        API requires per-user impersonation.  We cache each delegated
        service to avoid repeatedly building the same object.
        """
        if user_email not in self._services:
            logger.debug("Building Gmail service for %s", user_email)
            # Build credentials scoped to this user.
            creds = self.auth_manager.credentials
            delegated = creds.with_subject(user_email)
            from googleapiclient.discovery import build

            authed_http = self.auth_manager.build_authorized_http(delegated)
            self._services[user_email] = build(
                "gmail",
                "v1",
                http=authed_http,
                cache_discovery=False,
            )
        return self._services[user_email]

    # ------------------------------------------------------------------
    # Forwarding
    # ------------------------------------------------------------------

    def get_forwarding_addresses(
        self, user_email: str
    ) -> list[dict[str, Any]]:
        """List forwarding addresses configured for a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        A list of forwarding-address resource dicts.
        """
        try:
            service = self._get_service(user_email)
            request = (
                service.users()
                .settings()
                .forwardingAddresses()
                .list(userId="me")
            )
            response = self.execute_with_retry(request)
            addresses = response.get("forwardingAddresses", [])
            logger.debug(
                "%s has %d forwarding addresses",
                user_email,
                len(addresses),
            )
            return addresses
        except Exception as exc:
            self.record_error(
                f"get_forwarding_addresses({user_email})", exc
            )
            return []

    # ------------------------------------------------------------------
    # Delegates
    # ------------------------------------------------------------------

    def get_delegates(self, user_email: str) -> list[dict[str, Any]]:
        """List mail delegates for a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        A list of delegate resource dicts.
        """
        try:
            service = self._get_service(user_email)
            request = (
                service.users()
                .settings()
                .delegates()
                .list(userId="me")
            )
            response = self.execute_with_retry(request)
            delegates = response.get("delegates", [])
            logger.debug(
                "%s has %d delegates", user_email, len(delegates)
            )
            return delegates
        except Exception as exc:
            self.record_error(f"get_delegates({user_email})", exc)
            return []

    # ------------------------------------------------------------------
    # IMAP / POP
    # ------------------------------------------------------------------

    def get_imap_settings(self, user_email: str) -> dict[str, Any] | None:
        """Get IMAP settings for a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        An IMAP settings dict, or ``None`` on failure.
        """
        try:
            service = self._get_service(user_email)
            request = (
                service.users().settings().getImap(userId="me")
            )
            settings = self.execute_with_retry(request)
            logger.debug("%s IMAP enabled: %s", user_email, settings.get("enabled"))
            return settings
        except Exception as exc:
            self.record_error(f"get_imap_settings({user_email})", exc)
            return None

    def get_pop_settings(self, user_email: str) -> dict[str, Any] | None:
        """Get POP settings for a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        A POP settings dict, or ``None`` on failure.
        """
        try:
            service = self._get_service(user_email)
            request = (
                service.users().settings().getPop(userId="me")
            )
            settings = self.execute_with_retry(request)
            logger.debug(
                "%s POP accessWindow: %s",
                user_email,
                settings.get("accessWindow"),
            )
            return settings
        except Exception as exc:
            self.record_error(f"get_pop_settings({user_email})", exc)
            return None

    # ------------------------------------------------------------------
    # Send-as aliases
    # ------------------------------------------------------------------

    def get_send_as_settings(self, user_email: str) -> list[dict[str, Any]]:
        """List send-as aliases configured for a user.

        Parameters
        ----------
        user_email:
            The user's primary email address.

        Returns
        -------
        A list of send-as resource dicts.
        """
        try:
            service = self._get_service(user_email)
            request = (
                service.users()
                .settings()
                .sendAs()
                .list(userId="me")
            )
            response = self.execute_with_retry(request)
            aliases = response.get("sendAs", [])
            logger.debug(
                "%s has %d send-as aliases", user_email, len(aliases)
            )
            return aliases
        except Exception as exc:
            self.record_error(f"get_send_as_settings({user_email})", exc)
            return []
