# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Chrome Policy API client.

Resolves Chrome browser and ChromeOS policies via the Chrome Policy API (``chromepolicy``
``v1``): Gemini in Chrome, Device Bound Session Credentials, Password Alert, Safe Browsing,
the password manager, download restrictions, site isolation and update policies. These are
managed through Chrome policies rather than the Cloud Identity Policy API.
"""

import logging
from typing import Any

from .base import BaseAPIClient

logger = logging.getLogger(__name__)

# Chrome Policy API schema -> (field read from the resolved value, key in data["chrome_policies"]).
# Confirmed live against policySchemas.list / .get on 2026-11-15; see tests/fixtures/chrome_policy_schemas.json.
CHROME_POLICY_FIELDS: dict[str, tuple[str, str]] = {
    "chrome.users.GeminiSettings": ("geminiSettings", "gemini_settings"),
    "chrome.users.GenAiDefaultSettings": ("genAiDefaultSettings", "gen_ai_default_settings"),
    "chrome.users.BoundSessionCredentialsEnabled": ("boundSessionCredentialsEnabled", "bound_session_credentials"),
    "chrome.users.PasswordAlert": ("passwordProtectionWarningTrigger", "password_protection_warning_trigger"),
    "chrome.users.SafeBrowsingProtectionLevel": ("safeBrowsingProtectionLevel", "safe_browsing_protection_level"),
    "chrome.users.DisableSafeBrowsingProceedAnyway": ("disableSafeBrowsingProceedAnyway", "disable_safe_browsing_proceed_anyway"),
    "chrome.users.PasswordManager": ("passwordManagerEnabled", "password_manager_enabled"),
    "chrome.users.DownloadRestrictions": ("safeBrowsingDownloadRestrictions", "download_restrictions"),
    "chrome.users.SiteIsolationBrowser": ("sitePerProcess", "site_per_process"),
    "chrome.users.ComponentUpdates": ("componentUpdatesEnabled", "component_updates_enabled"),
    "chrome.users.AutoUpdateCheckPeriodNewV2": ("autoUpdateCheckPeriodMinutesNew", "auto_update_check_period_minutes"),
    "chrome.users.RelaunchNotificationWithDurationV2": ("relaunchNotificationEnum", "relaunch_notification"),
    "chrome.devices.AutoUpdateSettings": ("updateDisabled", "chromeos_update_disabled"),
}

# Schema namespaces resolved with one wildcard call each per child OU.
CHROME_POLICY_PREFIXES: tuple[str, ...] = ("chrome.users", "chrome.devices")

# Derived result keys -> the raw keys they are computed from (a derived key counts as set on an
# OU when one of its inputs is set there).
DERIVED_KEYS: dict[str, tuple[str, ...]] = {
    "gemini_in_chrome_disabled": ("gemini_settings", "gen_ai_default_settings"),
    "dbsc_enabled": ("bound_session_credentials",),
}


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
            # A 404 means the schema name does not exist for this tenant (a wrong name,
            # or a policy Chrome has withdrawn). It is recorded like any other failure so
            # the check reports MANUAL instead of mistaking the silence for "Chrome default".
            logger.warning(
                "Chrome Policy resolve failed for %s: %s",
                schema_filter,
                exc,
            )
            self.record_error(f"resolve_policy({schema_filter})", exc)
            return []

    def resolve_all(self, customer_id: str, org_unit_id: str, schema_filter: str) -> list[dict[str, Any]]:
        """Resolve every set policy under a wildcard filter (``chrome.users.*``) at one OU, paginated.

        The response holds the *effective* value of each set policy for that OU: a value inherited
        from an ancestor comes back with ``sourceKey.targetResource`` naming the ancestor, a value
        set on the OU itself with the OU as source (confirmed live 2026-11-16). Unset policies are
        not returned. Raises on failure so the caller can record the error per schema.
        """
        body: dict[str, Any] = {
            "policySchemaFilter": schema_filter,
            "policyTargetKey": {"targetResource": f"orgunits/{org_unit_id}"},
            "pageSize": 1000,
        }
        policies: list[dict[str, Any]] = []
        page_token = None
        while True:
            if page_token:
                body["pageToken"] = page_token
            request = self.service.customers().policies().resolve(customer=f"customers/{customer_id}", body=body)
            response = self.execute_with_retry(request)
            policies.extend(response.get("resolvedPolicies", []))
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        return policies

    @staticmethod
    def _derive(values: dict[str, Any]) -> None:
        """Add the derived booleans the older checks read (in place)."""
        gemini = values.get("gemini_settings")
        genai_default = values.get("gen_ai_default_settings")
        if gemini == "GEMINI_SETTINGS_ENUM_DISABLED":
            values["gemini_in_chrome_disabled"] = True
        elif gemini == "GEMINI_SETTINGS_ENUM_ENABLED":
            values["gemini_in_chrome_disabled"] = False
        elif genai_default is not None:
            # UNSET or absent: Chrome falls back to the Generative AI policy default.
            values["gemini_in_chrome_disabled"] = genai_default == "GEN_AI_DEFAULT_SETTINGS_ENUM_DISABLED"

        dbsc = values.get("bound_session_credentials")
        if dbsc in ("TRUE", "FALSE"):
            values["dbsc_enabled"] = dbsc == "TRUE"
        elif isinstance(dbsc, bool):
            values["dbsc_enabled"] = dbsc

    def _resolve_org_unit(self, customer_id: str, org_unit_id: str, org_unit_path: str) -> dict[str, Any]:
        """``{"values": {key: effective value}, "explicit": [keys set on this OU]}`` for one child OU.

        Two wildcard calls (``chrome.users.*``, ``chrome.devices.*``) replace the thirteen
        per-schema calls used at the root. When one fails, an error is recorded for every schema
        under that prefix as ``resolve_policy(<schema>)[<ou path>]`` so ``chrome_policy_unset``
        stops treating the OU's silence as "Chrome default".
        """
        values: dict[str, Any] = {}
        sources: dict[str, str] = {}
        for prefix in CHROME_POLICY_PREFIXES:
            try:
                policies = self.resolve_all(customer_id, org_unit_id, f"{prefix}.*")
            except Exception as exc:
                logger.warning("Chrome Policy resolve failed for %s.* at %s: %s", prefix, org_unit_path, exc)
                for schema in CHROME_POLICY_FIELDS:
                    if schema.startswith(prefix + "."):
                        self.record_error(f"resolve_policy({schema})[{org_unit_path}]", exc)
                continue
            for policy in policies:
                wrapper = policy.get("value") or {}
                schema = wrapper.get("policySchema")
                if schema not in CHROME_POLICY_FIELDS:
                    continue
                field, key = CHROME_POLICY_FIELDS[schema]
                value = wrapper.get("value") or {}
                if isinstance(value, dict) and value.get(field) is not None:
                    values[key] = value[field]
                    sources[key] = str((policy.get("sourceKey") or {}).get("targetResource", ""))
        self._derive(values)
        own = f"orgunits/{org_unit_id}"
        explicit = {key for key, source in sources.items() if source == own}
        for derived, inputs in DERIVED_KEYS.items():
            if derived in values and explicit.intersection(inputs):
                explicit.add(derived)
        return {"values": values, "explicit": sorted(explicit)}

    def get_chrome_policies(self, customer_id: str, org_units: list[dict] | None = None) -> dict[str, Any]:
        """Resolve the Chrome user and device policies the checks read, at the root OU and per OU.

        Every schema name and field below was confirmed against the live
        ``policySchemas`` catalogue on 2026-11-15 (``tests/fixtures/chrome_policy_schemas.json``).
        Enum fields come back as the enum member name (for example
        ``SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION``), booleans as JSON booleans
        and counts as integers. An unset policy resolves to nothing and leaves its key absent,
        which the checks read as "Chrome default" only when no resolve error was recorded.

        The top-level keys are the root OU's values (raw values under ``CHROME_POLICY_FIELDS``
        result keys) plus the derived booleans kept for the existing checks:

        - ``gemini_in_chrome_disabled``: GeminiSettings DISABLED, or UNSET/absent while
          GenAiDefaultSettings is DISABLED.
        - ``dbsc_enabled``: BoundSessionCredentialsEnabled TRUE/FALSE (absent when UNSET).
        - ``password_protection_warning_trigger``: the PasswordAlert enum member.

        ``_ou_policies`` maps every OU path (root included) to its effective values and the keys
        it sets itself (``explicit``); ``checks.base.chrome_ou_rows`` turns that into per-OU rows.
        *org_units* is the Directory ``orgunits.list`` output (``orgUnitPath``, ``orgUnitId``).
        """
        result: dict[str, Any] = {}
        for schema, (field, key) in CHROME_POLICY_FIELDS.items():
            for policy in self.resolve_policy(customer_id, schema):
                value = (policy.get("value") or {}).get("value") or {}
                if isinstance(value, dict) and field in value and value[field] is not None:
                    result[key] = value[field]
                    break
        self._derive(result)

        ou_policies: dict[str, dict[str, Any]] = {
            "/": {"values": dict(result), "explicit": sorted(result)},
        }
        for ou in org_units or []:
            if not isinstance(ou, dict):
                continue
            path = str(ou.get("orgUnitPath") or ou.get("org_unit_path") or "")
            ou_id = str(ou.get("orgUnitId") or ou.get("org_unit_id") or "").removeprefix("id:")
            if not path or path == "/" or not ou_id:
                continue
            ou_policies[path] = self._resolve_org_unit(customer_id, ou_id, path)
        result["_ou_policies"] = ou_policies

        logger.info("Chrome policies resolved for %d OU(s); root: %s", len(ou_policies),
                    {k: v for k, v in result.items() if k != "_ou_policies"})
        return result
