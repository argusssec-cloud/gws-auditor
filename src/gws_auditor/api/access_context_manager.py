# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Access Context Manager API client (Context-Aware Access access levels).

Context-Aware Access levels created in the Admin console are Access Context
Manager (ACM) resources of the Cloud organisation that every Workspace customer
owns. This client reads them with the service account's **own** identity and the
``cloud-platform`` scope (not through domain-wide delegation); the account needs
``roles/accesscontextmanager.policyReader`` on the organisation and the Access
Context Manager API enabled in the auditor's project. Optional:
``roles/resourcemanager.organizationViewer`` to discover the organisation by
domain, ``roles/accesscontextmanager.gcpAccessReader`` for the Google Cloud
access bindings.

Verified live 2026-11-06: ``accessPolicies.list`` returns the policy created by
the Admin console ("Access policy created in Cloud Identity Console") and
``accessLevels.list`` returns each level with ``basic.conditions[]``
(``regions``, ``ipSubnetworks``, ``devicePolicy``, ``members``,
``requiredAccessLevels``, ``negate``) or ``custom.expr``.
"""

import logging
from typing import Any

from googleapiclient.discovery import build

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class AccessContextManagerClient(BaseAPIClient):
    """Client for ``accesscontextmanager`` v1 and ``cloudresourcemanager`` v1 (organisation search)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._acm = None
        self._crm = None

    def _cloud_http(self):
        creds = self.auth_manager.cloud_credentials()
        if creds is None:
            raise RuntimeError(
                "Access Context Manager needs the service account's own cloud-platform "
                "credentials; not available with the configured auth method"
            )
        return self.auth_manager.build_authorized_http(creds)

    @property
    def service(self):
        """Lazily build the Access Context Manager service."""
        if self._acm is None:
            logger.debug("Building Access Context Manager service")
            self._acm = build("accesscontextmanager", "v1", http=self._cloud_http(), cache_discovery=False)
        return self._acm

    @property
    def resource_manager(self):
        """Lazily build the Cloud Resource Manager service (organisation search)."""
        if self._crm is None:
            logger.debug("Building Cloud Resource Manager service")
            self._crm = build("cloudresourcemanager", "v1", http=self._cloud_http(), cache_discovery=False)
        return self._crm

    @staticmethod
    def organization_name(value: str) -> str:
        value = str(value or "").strip()
        return value if not value or value.startswith("organizations/") else f"organizations/{value}"

    @staticmethod
    def policy_name(value: str) -> str:
        value = str(value or "").strip()
        return value if not value or value.startswith("accessPolicies/") else f"accessPolicies/{value}"

    def search_organization(self, domain: str = "", customer_id: str = "") -> str:
        """Return the organisation resource name for *domain* or *customer_id*, or ``""``.

        ``organizations.search`` needs ``resourcemanager.organizations.get`` on the
        organisation; without it the call succeeds with an empty result.
        """
        filters = []
        if domain:
            filters.append(f"domain:{domain}")
        if customer_id and customer_id != "my_customer":
            filters.append(f"owner.directoryCustomerId:{customer_id}")
        for flt in filters or [""]:
            body: dict[str, Any] = {"filter": flt} if flt else {}
            response = self.execute_with_retry(self.resource_manager.organizations().search(body=body))
            orgs = response.get("organizations", [])
            if orgs:
                return orgs[0].get("name", "")
        return ""

    def list_access_policies(self, organization: str) -> list[dict]:
        """List the organisation's access policies (normally exactly one)."""
        return self.paginate(
            self.service.accessPolicies().list, items_key="accessPolicies",
            parent=self.organization_name(organization),
        )

    def list_access_levels(self, access_policy: str) -> list[dict]:
        """List every access level of *access_policy* as defined (basic or custom)."""
        return self.paginate(
            self.service.accessPolicies().accessLevels().list, items_key="accessLevels",
            parent=self.policy_name(access_policy), accessLevelFormat="AS_DEFINED",
        )

    def list_user_access_bindings(self, organization: str) -> list[dict]:
        """List the Google Cloud console/API access bindings (group -> access levels)."""
        return self.paginate(
            self.service.organizations().gcpUserAccessBindings().list, items_key="gcpUserAccessBindings",
            parent=self.organization_name(organization),
        )
