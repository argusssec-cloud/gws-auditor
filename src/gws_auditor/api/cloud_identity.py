# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Cloud Identity API client for endpoint verification devices.

Wraps the ``cloudidentity`` / ``v1`` service and provides a method for
listing all endpoint verification devices (Windows, Mac, Linux) managed
via endpoint verification or company-owned device policies.

This covers devices that are **not** returned by the Admin SDK
``mobiledevices`` or ``chromeosdevices`` endpoints.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class CloudIdentityClient(BaseAPIClient):
    """Client for the Cloud Identity API (``cloudidentity v1``)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    @property
    def service(self):
        """Lazily build and cache the Cloud Identity service."""
        if self._service is None:
            logger.debug("Building Cloud Identity service")
            self._service = self.auth_manager.build_service("cloudidentity", "v1")
        return self._service

    def list_endpoint_devices(self, customer_id: str) -> list[dict[str, Any]]:
        """List all endpoint verification devices.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.  Note: the Cloud Identity
            Devices API only accepts the literal ``customers/my_customer``
            — real customer IDs return 400.  The *customer_id* parameter
            is accepted for interface consistency but always overridden.

        Returns
        -------
        A list of device resource dicts.  Key fields include:
        ``name``, ``deviceId``, ``serialNumber``, ``hostname``,
        ``deviceType``, ``osVersion``, ``managementState``,
        ``lastSyncTime``, ``createTime``, ``owner``.
        """
        try:
            # The Cloud Identity Devices API only accepts the literal
            # "customers/my_customer" — real customer IDs (e.g.
            # "customers/C0xxxxx") return HTTP 400.
            devices = self.paginate(
                self.service.devices().list,
                items_key="devices",
                customer="customers/my_customer",
                pageSize=100,
            )
            logger.info("Retrieved %d endpoint devices", len(devices))
            return devices
        except Exception as exc:
            self.record_error("list_endpoint_devices", exc)
            return []
