# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Chrome Policy API client.

Resolves Chrome browser policies via the Chrome Policy API (``chromepolicy``
``v1``).  Used to check Gemini-in-Chrome and Device Bound Session Credentials
(DBSC) settings that are managed through Chrome device policies rather than
Cloud Identity.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class ChromePolicyClient(BaseAPIClient):
    """Client for the Chrome Policy API (``chromepolicy`` ``v1``).

    Resolves Chrome browser policies for a given customer using the
    ``customers().policies().resolve()`` endpoint.
    """

    def __init__(self, auth_manager, **kwargs):
        super().__init__(auth_manager, **kwargs)
        self._service = None

    @property
    def service(self):
        """Lazily build and cache the Chrome Policy service."""
        if self._service is None:
            logger.debug("Building Chrome Policy service")
            self._service = self.auth_manager.build_service(
                "chromepolicy", "v1"
            )
        return self._service

    def _get_root_org_unit_id(self, customer_id: str) -> str:
        """Look up the root Org Unit ID via the Admin SDK Directory API.

        The Chrome Policy API requires an explicit org-unit ID — it does
        not accept an empty or bare ``orgunits/`` path.  This method
        fetches the root OU path (``/``) and returns its ``orgUnitId``.

        Returns the ID string (e.g. ``"03ph8a2z1234abc"``) or empty
        string on failure.
        """
        if hasattr(self, "_root_ou_id"):
            return self._root_ou_id

        # Strategy 1: list OUs including the root parent using
        # type=all_including_parent (works even when no sub-OUs exist).
        try:
            dir_service = self.auth_manager.build_service(
                "admin", "directory_v1"
            )
            result = self.execute_with_retry(
                dir_service.orgunits().list(
                    customerId=customer_id, type="allIncludingParent"
                )
            )
            for ou in result.get("organizationUnits", []):
                if ou.get("orgUnitPath") == "/":
                    raw_id = ou.get("orgUnitId", "")
                    if raw_id:
                        self._root_ou_id = raw_id.removeprefix("id:")
                        logger.debug("Root Org Unit ID (from list): %s", self._root_ou_id)
                        return self._root_ou_id
                # Fallback: derive root from parentOrgUnitId of top-level OUs
                if ou.get("parentOrgUnitPath") == "/":
                    root_id = ou.get("parentOrgUnitId", "")
                    if root_id:
                        self._root_ou_id = root_id.removeprefix("id:")
                        logger.debug("Root Org Unit ID (from parent): %s", self._root_ou_id)
                        return self._root_ou_id
        except Exception as exc:
            logger.debug("orgunits().list() failed: %s", exc)

        # Strategy 2: direct get of root OU
        try:
            dir_service = self.auth_manager.build_service(
                "admin", "directory_v1"
            )
            root = self.execute_with_retry(
                dir_service.orgunits().get(
                    customerId=customer_id, orgUnitPath="/"
                )
            )
            raw_id = root.get("orgUnitId", "")
            self._root_ou_id = raw_id.removeprefix("id:")
            logger.debug("Root Org Unit ID (from get): %s", self._root_ou_id)
            return self._root_ou_id
        except Exception as exc:
            logger.warning("Failed to look up root OU ID: %s", exc)
            self._root_ou_id = ""
            return ""

    def resolve_policy(
        self,
        customer_id: str,
        schema_filter: str,
        org_unit_id: str = "",
    ) -> list[dict[str, Any]]:
        """Resolve policies matching a schema filter.

        Parameters
        ----------
        customer_id:
            The customer ID (e.g. ``"my_customer"``).
        schema_filter:
            The policy schema filter (e.g.
            ``"chrome.users.GeminiSettings"``).
        org_unit_id:
            The org-unit ID to resolve for.  If empty, resolves for the
            root org unit (looked up automatically).

        Returns
        -------
        A list of resolved policy dicts.
        """
        if not org_unit_id:
            org_unit_id = self._get_root_org_unit_id(customer_id)
            if not org_unit_id:
                logger.warning(
                    "Cannot resolve Chrome policy %s: root OU ID unavailable",
                    schema_filter,
                )
                return []
        body = {
            "policySchemaFilter": schema_filter,
            "policyTargetKey": {
                "targetResource": f"orgunits/{org_unit_id}",
            },
        }
        try:
            request = (
                self.service.customers()
                .policies()
                .resolve(
                    customer=f"customers/{customer_id}",
                    body=body,
                )
            )
            response = self.execute_with_retry(request)
            policies = response.get("resolvedPolicies", [])
            logger.debug(
                "Resolved %d policies for schema %s",
                len(policies),
                schema_filter,
            )
            return policies
        except Exception as exc:
            # 404 = schema not available for this tenant (e.g. Chrome
            # Browser Cloud Management not enabled, or edition doesn't
            # support this policy).  This is expected — don't surface
            # it as a user-visible API error.
            from googleapiclient.errors import HttpError
            if isinstance(exc, HttpError) and exc.resp.status == 404:
                logger.debug(
                    "Chrome policy schema %s not found (404) — "
                    "not available for this tenant",
                    schema_filter,
                )
                return []
            logger.warning(
                "Chrome Policy resolve failed for %s: %s",
                schema_filter,
                exc,
            )
            self.record_error(f"resolve_policy({schema_filter})", exc)
            return []

    def get_chrome_policies(self, customer_id: str) -> dict[str, Any]:
        """Resolve key Chrome policies for security checks.

        Returns a dict with:
        - ``gemini_in_chrome_disabled``: Whether Gemini in Chrome is disabled.
        - ``dbsc_enabled``: Whether Device Bound Session Credentials are enabled.

        Parameters
        ----------
        customer_id:
            The customer ID (e.g. ``"my_customer"``).
        """
        result: dict[str, Any] = {}

        # --- Gemini in Chrome ---
        gemini_policies = self.resolve_policy(
            customer_id, "chrome.users.GeminiSettings"
        )
        for policy in gemini_policies:
            value = policy.get("value", {}).get("value", {})
            # The API returns an integer enum: 0 = allow, 1 = disable
            gemini_setting = value.get("geminiSetting")
            if gemini_setting is not None:
                result["gemini_in_chrome_disabled"] = gemini_setting == 1
                break

        # --- Device Bound Session Credentials ---
        dbsc_policies = self.resolve_policy(
            customer_id, "chrome.users.BoundSessionCredentialsEnabled"
        )
        for policy in dbsc_policies:
            value = policy.get("value", {}).get("value", {})
            dbsc_enabled = value.get("boundSessionCredentialsEnabled")
            if dbsc_enabled is not None:
                result["dbsc_enabled"] = bool(dbsc_enabled)
                break

        # --- Password Protection Warning ---
        pw_policies = self.resolve_policy(
            customer_id, "chrome.users.PasswordProtectionWarningTrigger"
        )
        for policy in pw_policies:
            value = policy.get("value", {}).get("value", {})
            # passwordProtectionWarningTrigger enum:
            # 0 = PASSWORD_PROTECTION_WARNING_OFF
            # 1 = PASSWORD_REUSE_WARNING (warn on reuse)
            # 2 = PHISHING_REUSE_WARNING (warn on reuse + phishing)
            trigger = value.get("passwordProtectionWarningTrigger")
            if trigger is not None:
                result["password_protection_warning_trigger"] = trigger
                break

        logger.info("Chrome policies resolved: %s", result)
        return result
