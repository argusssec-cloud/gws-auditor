# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Groups Settings API client.

Wraps the ``groupssettings`` / ``v1`` service and provides methods for
retrieving the configuration of Google Groups, which is critical for
detecting overly-permissive group settings.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class GroupsClient(BaseAPIClient):
    """Client for the Groups Settings API (``groupssettings`` ``v1``)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    # ------------------------------------------------------------------
    # Service (lazy build)
    # ------------------------------------------------------------------

    @property
    def service(self):
        """Lazily build and cache the Groups Settings API service."""
        if self._service is None:
            logger.debug("Building Groups Settings service")
            self._service = self.auth_manager.build_service(
                "groupssettings", "v1"
            )
        return self._service

    # ------------------------------------------------------------------
    # Group settings
    # ------------------------------------------------------------------

    def get_group_settings(
        self, group_email: str
    ) -> dict[str, Any] | None:
        """Retrieve the settings for a single group.

        Parameters
        ----------
        group_email:
            The group's email address.

        Returns
        -------
        A group-settings resource dict, or ``None`` on failure.
        Key fields include ``whoCanPostMessage``, ``whoCanJoin``,
        ``whoCanViewMembership``, ``whoCanViewGroup``,
        ``allowExternalMembers``, ``isArchived``, etc.
        """
        try:
            request = self.service.groups().get(
                groupUniqueId=group_email, alt="json"
            )
            settings = self.execute_with_retry(request)
            logger.debug("Retrieved settings for group %s", group_email)
            return settings
        except Exception as exc:
            self.record_error(
                f"get_group_settings({group_email})", exc
            )
            return None

    def batch_get_group_settings(
        self,
        group_emails: list[str],
        batch_size: int = 100,
    ) -> dict[str, dict[str, Any]]:
        """Retrieve settings for multiple groups using batch HTTP requests.

        Uses the Google API client's batch request support to fetch
        group settings in chunks, reducing HTTP round-trips from N
        serial calls to ceil(N / batch_size) batch calls.

        Parameters
        ----------
        group_emails:
            A list of group email addresses to fetch settings for.
        batch_size:
            Maximum number of requests per batch (Google API limit is
            1000; default 100 is conservative).

        Returns
        -------
        A dict mapping group email → settings dict.  Groups that fail
        are omitted and recorded via :meth:`record_error`.
        """
        results: dict[str, dict[str, Any]] = {}

        for i in range(0, len(group_emails), batch_size):
            chunk = group_emails[i : i + batch_size]
            batch = self.service.new_batch_http_request()

            for email in chunk:
                request = self.service.groups().get(
                    groupUniqueId=email, alt="json"
                )

                def _callback(request_id, response, exception, _email=email):
                    if exception is not None:
                        self.record_error(
                            f"batch_get_group_settings({_email})", exception
                        )
                    elif response is not None:
                        results[_email] = response

                batch.add(request, callback=_callback)

            try:
                self._bucket.consume()
                batch.execute()
            except Exception as exc:
                self.record_error(
                    f"batch_get_group_settings(chunk {i}–{i + len(chunk)})",
                    exc,
                )

        logger.info(
            "Batch-retrieved settings for %d / %d groups",
            len(results),
            len(group_emails),
        )
        return results

    def list_all_group_settings(
        self, groups_list: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Retrieve settings for all provided groups.

        Uses :meth:`batch_get_group_settings` to fetch settings in
        batched HTTP requests for efficiency.

        Parameters
        ----------
        groups_list:
            A list of group resource dicts; each must contain an
            ``"email"`` key.

        Returns
        -------
        A list of group-settings resource dicts (one per group that was
        successfully queried).  Groups that cannot be queried are silently
        skipped and recorded via :meth:`record_error`.
        """
        emails = [g["email"] for g in groups_list if g.get("email")]
        settings_map = self.batch_get_group_settings(emails)

        all_settings: list[dict[str, Any]] = []
        for email in emails:
            settings = settings_map.get(email)
            if settings is not None:
                settings["groupEmail"] = email
                all_settings.append(settings)

        logger.info(
            "Retrieved settings for %d / %d groups",
            len(all_settings),
            len(groups_list),
        )
        return all_settings
