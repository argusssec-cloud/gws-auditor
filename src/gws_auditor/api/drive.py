# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Drive API client.

Wraps the ``drive`` / ``v3`` service and provides methods for listing
shared drives and their permissions.
"""

import logging
from typing import Any

from googleapiclient.errors import HttpError

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class DriveClient(BaseAPIClient):
    """Client for the Google Drive API (``v3``)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    # ------------------------------------------------------------------
    # Service (lazy build)
    # ------------------------------------------------------------------

    @property
    def service(self):
        """Lazily build and cache the Drive API service."""
        if self._service is None:
            logger.debug("Building Drive API service")
            self._service = self.auth_manager.build_service("drive", "v3")
        return self._service

    # ------------------------------------------------------------------
    # Shared Drives
    # ------------------------------------------------------------------

    def list_shared_drives(self, customer_id: str) -> list[dict[str, Any]]:
        """List all shared drives in the domain.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.  Note: the Drive API
            ``drives.list`` endpoint does not directly accept a customer
            ID but uses the admin credentials to scope the request.

        Returns
        -------
        A list of shared-drive resource dicts.
        """
        try:
            drives = self.paginate(
                self.service.drives().list,
                items_key="drives",
                pageSize=100,
                useDomainAdminAccess=True,
            )
            logger.info("Retrieved %d shared drives", len(drives))
            return drives
        except Exception as exc:
            err_str = str(exc)
            if "domainPolicy" in err_str or "disabled Drive apps" in err_str:
                logger.info(
                    "Drive SDK is disabled by domain policy — "
                    "skipping shared drives enumeration"
                )
            else:
                self.record_error("list_shared_drives", exc)
            return []

    # ------------------------------------------------------------------
    # Permissions
    # ------------------------------------------------------------------

    def get_drive_permissions(
        self, drive_id: str
    ) -> list[dict[str, Any]]:
        """Get the permissions for a specific shared drive.

        Parameters
        ----------
        drive_id:
            The shared-drive identifier.

        Returns
        -------
        A list of permission resource dicts.
        """
        try:
            permissions = self.paginate(
                self.service.permissions().list,
                items_key="permissions",
                fileId=drive_id,
                supportsAllDrives=True,
                useDomainAdminAccess=True,
                fields="permissions(id,type,role,emailAddress,domain,displayName),nextPageToken",
                pageSize=100,
            )
            logger.debug(
                "Shared drive %s has %d permissions",
                drive_id,
                len(permissions),
            )
            return permissions
        except Exception as exc:
            self.record_error(
                f"get_drive_permissions({drive_id})", exc
            )
            return []

    # ------------------------------------------------------------------
    # Drive SDK detection
    # ------------------------------------------------------------------

    def is_drive_sdk_enabled(self) -> bool | None:
        """Detect whether Drive SDK is enabled by probing the Drive API.

        When Drive SDK is disabled by the domain administrator, **all**
        Drive API calls from third-party apps return HTTP 403 with
        reason ``domainPolicy`` and message *"The domain administrators
        have disabled Drive apps."*

        Uses a dedicated Drive service built with delegated credentials
        to ensure the probe runs as the domain user, not the service
        account itself (which is unaffected by the domain setting).

        Returns
        -------
        ``False`` if Drive SDK is disabled (403 domainPolicy),
        ``True`` if the API responds successfully (SDK enabled),
        ``None`` if the result is indeterminate (other errors).
        """
        try:
            from googleapiclient.discovery import build as api_build

            creds = self.auth_manager.credentials
            if hasattr(creds, "with_subject") and not getattr(creds, "_subject", None):
                # Service account without delegation — cannot detect
                logger.debug("Drive SDK detection requires delegated credentials")
                return None
            authed_http = self.auth_manager.build_authorized_http(creds)
            probe_service = api_build(
                "drive", "v3", http=authed_http, cache_discovery=False,
            )
            probe_service.about().get(fields="user").execute()
            # API responded successfully — Drive SDK is enabled
            return True
        except HttpError as exc:
            status = exc.resp.status if exc.resp else 0
            reason = ""
            if exc.error_details:
                for detail in exc.error_details:
                    if isinstance(detail, dict):
                        reason = detail.get("reason", "")
                        if reason:
                            break
            if status == 403 and reason == "domainPolicy":
                logger.info("Drive SDK is disabled (domainPolicy)")
                return False
            logger.debug("Drive SDK detection inconclusive: %s", exc)
            return None
        except Exception as exc:
            logger.debug("Drive SDK detection failed: %s", exc)
            return None
