# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Google Chat Admin API client for listing Chat spaces.

Wraps the ``chat`` / ``v1`` service and provides a method for listing
all Chat spaces with admin access via the ``spaces.search()`` endpoint.

Note: ``spaces.list()`` only returns spaces the caller is a member of
and does **not** support admin scopes.  ``spaces.search()`` with
``useAdminAccess=True`` is the correct endpoint for admin-level
enumeration of all spaces in the organisation.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class ChatSpacesClient(BaseAPIClient):
    """Client for the Google Chat API (``chat v1``) with admin access."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    @property
    def service(self):
        """Lazily build and cache the Chat API service."""
        if self._service is None:
            logger.debug("Building Google Chat service")
            self._service = self.auth_manager.build_service("chat", "v1")
        return self._service

    def list_spaces(self) -> list[dict[str, Any]]:
        """List all Chat spaces using admin access.

        Uses the ``spaces.search()`` endpoint with ``useAdminAccess=True``
        to enumerate all spaces in the organisation.  Requires the
        ``chat.admin.spaces.readonly`` scope and the "manage chat and
        spaces conversations" admin privilege.

        Returns
        -------
        A list of space resource dicts.  Key fields include:
        ``name``, ``displayName``, ``spaceType``, ``createTime``,
        ``lastActiveTime``.
        """
        try:
            spaces = self.paginate(
                self.service.spaces().search,
                items_key="spaces",
                useAdminAccess=True,
                query='customer = "customers/my_customer" AND spaceType = "SPACE"',
                pageSize=100,
            )
            logger.info("Retrieved %d Chat spaces", len(spaces))
            return spaces
        except Exception as exc:
            self.record_error("list_spaces", exc)
            return []

    def list_space_owners(self, space_name: str) -> list[dict[str, Any]]:
        """List members with ROLE_MANAGER (owner) role for a space.

        Parameters
        ----------
        space_name:
            The resource name of the space (e.g. ``spaces/abc123``).

        Returns
        -------
        A list of membership resource dicts for owners.  Each has a
        ``member`` sub-dict with ``name`` (``users/{id}``) and
        ``type`` fields.
        """
        try:
            members = self.paginate(
                self.service.spaces().members().list,
                items_key="memberships",
                parent=space_name,
                useAdminAccess=True,
                filter='member.type = "HUMAN" AND role = "ROLE_MANAGER"',
                pageSize=100,
            )
            return members
        except Exception as exc:
            self.record_error(f"list_space_owners({space_name})", exc)
            return []
