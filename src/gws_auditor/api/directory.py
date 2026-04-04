# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Admin SDK Directory API client.

Wraps the ``admin`` / ``directory_v1`` service and provides convenience
methods for listing users, domains, org units, and admin roles.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class DirectoryClient(BaseAPIClient):
    """Client for the Admin SDK Directory API (``directory_v1``)."""

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    # ------------------------------------------------------------------
    # Service (lazy build)
    # ------------------------------------------------------------------

    @property
    def service(self):
        """Lazily build and cache the Directory API service."""
        if self._service is None:
            logger.debug("Building Admin SDK Directory service")
            self._service = self.auth_manager.build_service(
                "admin", "directory_v1"
            )
        return self._service

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self, customer_id: str) -> list[dict[str, Any]]:
        """List all users in the domain.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID (or ``"my_customer"``).

        Returns
        -------
        A list of user resource dicts.  Key fields include:
        ``primaryEmail``, ``isAdmin``, ``isDelegatedAdmin``,
        ``suspended``, ``isEnrolledIn2Sv``, ``isEnforcedIn2Sv``,
        ``creationTime``, ``lastLoginTime``, ``orgUnitPath``.
        """
        try:
            users = self.paginate(
                self.service.users().list,
                items_key="users",
                customer=customer_id,
                maxResults=500,
                projection="full",
                orderBy="email",
            )
            logger.info("Retrieved %d users", len(users))
            return users
        except Exception as exc:
            self.record_error("list_users", exc)
            return []

    def list_super_admins(self, customer_id: str) -> list[dict[str, Any]]:
        """Return only the super-admin users.

        A super admin has ``isAdmin`` set to ``True``.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A filtered list of user resource dicts.
        """
        users = self.list_users(customer_id)
        admins = [u for u in users if u.get("isAdmin", False)]
        logger.info("Found %d super admins out of %d users", len(admins), len(users))
        return admins

    def get_user(self, user_key: str) -> dict[str, Any] | None:
        """Get details for a single user.

        Parameters
        ----------
        user_key:
            The user's primary email address, alias, or unique ID.

        Returns
        -------
        A user resource dict, or ``None`` on failure.
        """
        try:
            request = self.service.users().get(
                userKey=user_key, projection="full"
            )
            user = self.execute_with_retry(request)
            logger.debug("Retrieved user %s", user_key)
            return user
        except Exception as exc:
            self.record_error(f"get_user({user_key})", exc)
            return None

    # ------------------------------------------------------------------
    # Domains
    # ------------------------------------------------------------------

    def list_domains(self, customer_id: str) -> list[dict[str, Any]]:
        """List all domains registered for the customer.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A list of domain resource dicts.
        """
        try:
            request = self.service.domains().list(customer=customer_id)
            response = self.execute_with_retry(request)
            domains = response.get("domains", [])
            logger.info("Retrieved %d domains", len(domains))
            return domains
        except Exception as exc:
            self.record_error("list_domains", exc)
            return []

    # ------------------------------------------------------------------
    # Org Units
    # ------------------------------------------------------------------

    def list_org_units(self, customer_id: str) -> list[dict[str, Any]]:
        """List all organizational units.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A list of org-unit resource dicts.
        """
        try:
            request = self.service.orgunits().list(
                customerId=customer_id, type="all"
            )
            response = self.execute_with_retry(request)
            org_units = response.get("organizationUnits", [])
            logger.info("Retrieved %d org units", len(org_units))
            return org_units
        except Exception as exc:
            self.record_error("list_org_units", exc)
            return []

    def get_org_unit(
        self, customer_id: str, org_unit_id: str
    ) -> dict[str, Any] | None:
        """Fetch a single organizational unit by its unique ID.

        The Admin SDK ``orgunits.get()`` ``orgUnitPath`` parameter
        accepts either a path (``Engineering``) or a unique ID with the
        ``id:`` prefix (``id:03ph8a2z1rlsact``).  This method accepts
        a bare ID and prepends ``id:`` automatically.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.
        org_unit_id:
            The bare org-unit ID (e.g. ``"03ph8a2z1rlsact"``), without
            any ``id:`` or ``orgUnits/`` prefix.

        Returns
        -------
        An org-unit resource dict, or ``None`` on failure.
        """
        # The Admin SDK expects the "id:" prefix for ID-based lookups.
        lookup_id = org_unit_id if org_unit_id.startswith("id:") else f"id:{org_unit_id}"
        try:
            request = self.service.orgunits().get(
                customerId=customer_id, orgUnitPath=lookup_id,
            )
            ou = self.execute_with_retry(request)
            logger.debug(
                "Retrieved org unit %s -> %s",
                org_unit_id,
                ou.get("orgUnitPath", ""),
            )
            return ou
        except Exception as exc:
            logger.debug("get_org_unit(%s) failed: %s", lookup_id, exc)
            return None

    # ------------------------------------------------------------------
    # App-Specific Passwords (ASPs)
    # ------------------------------------------------------------------

    def list_user_asps(self, user_key: str) -> list[dict[str, Any]]:
        """List App-Specific Passwords for a user.

        Parameters
        ----------
        user_key:
            The user's primary email address or unique ID.

        Returns
        -------
        A list of ASP resource dicts.  Returns an empty list if the
        user has no ASPs or the API call fails.
        """
        try:
            result = self.execute_with_retry(
                self.service.asps().list(userKey=user_key)
            )
            return result.get("items", [])
        except Exception:
            return []

    # ------------------------------------------------------------------
    # OAuth Tokens
    # ------------------------------------------------------------------

    def list_user_tokens(self, user_key: str) -> list[dict[str, Any]]:
        """List OAuth tokens (third-party app grants) for a user.

        Uses the ``tokens.list()`` endpoint from the Admin SDK Directory
        API to enumerate currently active OAuth token grants.

        Parameters
        ----------
        user_key:
            The user's primary email address or unique ID.

        Returns
        -------
        A list of token resource dicts.  Key fields include:
        ``clientId``, ``displayText``, ``anonymous``, ``nativeApp``,
        ``scopes``, ``userKey``.  Returns an empty list if the user has
        no tokens or the API call fails.
        """
        try:
            result = self.execute_with_retry(
                self.service.tokens().list(userKey=user_key)
            )
            return result.get("items", [])
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    def list_group_members(self, group_key: str) -> list[dict[str, Any]]:
        """List all members of a group.

        Parameters
        ----------
        group_key:
            The group's email address or unique ID.

        Returns
        -------
        A list of member resource dicts with keys including
        ``email``, ``role``, ``type``, ``status``.
        """
        try:
            members = self.paginate(
                self.service.members().list,
                items_key="members",
                groupKey=group_key,
                maxResults=200,
            )
            logger.debug("Retrieved %d members for group %s", len(members), group_key)
            return members
        except Exception as exc:
            self.record_error(f"list_group_members({group_key})", exc)
            return []

    def list_groups(self, customer_id: str) -> list[dict[str, Any]]:
        """List all groups in the domain.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A list of group resource dicts.
        """
        try:
            groups = self.paginate(
                self.service.groups().list,
                items_key="groups",
                customer=customer_id,
                maxResults=200,
            )
            logger.info("Retrieved %d groups", len(groups))
            return groups
        except Exception as exc:
            self.record_error("list_groups", exc)
            return []

    # ------------------------------------------------------------------
    # Roles & Role Assignments
    # ------------------------------------------------------------------

    def list_roles(self, customer_id: str) -> dict[str, Any]:
        """List admin roles and their assignments.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A dict with keys ``"roles"`` and ``"assignments"``, each
        containing a list of resource dicts.
        """
        roles: list[dict[str, Any]] = []
        assignments: list[dict[str, Any]] = []

        # Fetch roles
        try:
            roles = self.paginate(
                self.service.roles().list,
                items_key="items",
                customer=customer_id,
            )
            logger.info("Retrieved %d admin roles", len(roles))
        except Exception as exc:
            self.record_error("list_roles", exc)

        # Fetch role assignments
        try:
            assignments = self.paginate(
                self.service.roleAssignments().list,
                items_key="items",
                customer=customer_id,
            )
            logger.info("Retrieved %d role assignments", len(assignments))
        except Exception as exc:
            self.record_error("list_role_assignments", exc)

        return {"roles": roles, "assignments": assignments}

    # ------------------------------------------------------------------
    # Mobile Devices
    # ------------------------------------------------------------------

    def list_mobile_devices(self, customer_id: str) -> list[dict[str, Any]]:
        """List all mobile devices managed by the domain.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A list of mobile device resource dicts.  Key fields include:
        ``resourceId``, ``email``, ``model``, ``os``, ``type``,
        ``status``, ``lastSync``.
        """
        try:
            devices = self.paginate(
                self.service.mobiledevices().list,
                items_key="mobiledevices",
                customerId=customer_id,
                maxResults=100,
            )
            logger.info("Retrieved %d mobile devices", len(devices))
            return devices
        except Exception as exc:
            self.record_error("list_mobile_devices", exc)
            return []

    # ------------------------------------------------------------------
    # ChromeOS Devices
    # ------------------------------------------------------------------

    def list_chromeos_devices(self, customer_id: str) -> list[dict[str, Any]]:
        """List all ChromeOS devices managed by the domain.

        Parameters
        ----------
        customer_id:
            The Google Workspace customer ID.

        Returns
        -------
        A list of ChromeOS device resource dicts.  Key fields include:
        ``deviceId``, ``serialNumber``, ``annotatedUser``, ``model``,
        ``status``, ``lastSync``.
        """
        try:
            devices = self.paginate(
                self.service.chromeosdevices().list,
                items_key="chromeosdevices",
                customerId=customer_id,
                maxResults=100,
                projection="FULL",
            )
            logger.info("Retrieved %d ChromeOS devices", len(devices))
            return devices
        except Exception as exc:
            self.record_error("list_chromeos_devices", exc)
            return []
