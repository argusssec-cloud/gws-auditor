# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Cloud Identity Policy API client.

This is the most important API client in the auditor -- it accesses the
GWS admin console settings via the Cloud Identity ``v1`` Policies API.
Policies are organized into categories (gmail, drive, calendar, etc.) and
each category contains a set of typed policy resources.

The Cloud Identity Policies API uses
``cloudidentity.googleapis.com/v1/policies`` with query filters to
retrieve policies for specific service areas.
"""

import logging
from typing import Any

from .base import BaseAPIClient
from ..constants import POLICY_API_RATE_LIMIT_QPS

logger = logging.getLogger(__name__)

# Maps our internal category names to the setting type prefix used in the
# Cloud Identity Policy API's CEL filter expressions.  The API's setting
# types follow the pattern ``settings/<prefix>.<setting_name>`` where
# ``<prefix>`` is the value below.
#
# Reference: https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings
POLICY_CATEGORIES = {
    "gmail": "gmail",
    "drive": "drive_and_docs",
    "calendar": "calendar",
    "chat": "chat",
    "meet": "meet",
    "sites": "sites",
    "marketplace": "workspace_marketplace",
    "security": "security",
    "directory": "directory",
    "groups": "groups_for_business",
    "api_controls": "api_controls",
    "classroom": "classroom",
    "rules": "rule",
    "data_regions": "data_regions",
    "multi_party_approval": "multi_party_approval",
    "access_management": "access_management",
    "access_approval": "access_approval",
}


# Setting types required by security checks, grouped by our internal
# category names.  When ``policies.list`` (broad regex filter) does not
# return a setting, ``get_policies()`` issues a narrow
# ``policies.list`` call per missing setting type to fetch its effective
# value — including Google-applied defaults.
REQUIRED_SETTINGS: dict[str, list[str]] = {
    "gmail": [
        "gmail.email_attachment_safety",
        "gmail.links_and_external_images",
        "gmail.spoofing_and_authentication",
        "gmail.enhanced_pre_delivery_message_scanning",
        "gmail.confidential_mode",
        "gmail.user_email_uploads",
        "gmail.mail_delegation",
        "gmail.pop_access",
        "gmail.imap_access",
        "gmail.auto_forwarding",
        "gmail.per_user_outbound_gateway",
        "gmail.comprehensive_mail_storage",
        "gmail.workspace_sync_for_outlook",
        "gmail.spam_override_lists",
        "gmail.email_spam_filter_ip_allowlist",
    ],
    "drive": [
        "drive_and_docs.shared_drive_creation",
        "drive_and_docs.external_sharing",
        "drive_and_docs.general_access_default",
        "drive_and_docs.drive_for_desktop",
        "drive_and_docs.drive_sdk",
        "drive_and_docs.file_security_update",
    ],
    "calendar": [
        "calendar.primary_calendar_max_allowed_external_sharing",
        "calendar.primary_calendar_max_allowed_internal_sharing",
        "calendar.secondary_calendar_max_allowed_external_sharing",
        "calendar.secondary_calendar_max_allowed_internal_sharing",
        "calendar.external_invitations",
        "calendar.interoperability",
        "calendar.appointment_schedules",
        "calendar.calendar_offline_access",
    ],
    "chat": [
        "chat.chat_file_sharing",
        "chat.chat_external_spaces",
        "chat.chat_apps_access",
        "chat.space_history",
        "chat.chat_reporting",
    ],
    "meet": [
        "meet.meet_joining",
        "meet.safety_domain",
        "meet.safety_host_management",
        "meet.safety_external_participants",
        "meet.safety_access",
        "meet.video_recording",
    ],
    "security": [
        "security.advanced_protection_program",
        "security.login_challenges",
        "security.super_admin_account_recovery",
        "security.session_controls",
        "security.password",
        "security.passkeys_restriction",
        "security.user_account_recovery",
        "security.less_secure_apps",
        "security.two_step_verification_enrollment",
        "security.two_step_verification_enforcement",
        "security.two_step_verification_enforcement_factor",
        "security.two_step_verification_device_trust",
    ],
    "groups": [
        "groups_for_business.groups_sharing",
    ],
    "directory": [
        "directory.external_directory_sharing",
    ],
    "sites": [
        "sites.sites_creation_and_modification",
        "service_status.sites",
    ],
    "marketplace": [
        "workspace_marketplace.apps_access_options",
    ],
    "api_controls": [
        "api_controls.unconfigured_third_party_apps",
        "api_controls.internal_apps",
    ],
}


# Factory-default values for settings that the Cloud Identity Policy API
# does not expose.  When a required setting is absent from both the broad
# regex query *and* the narrow per-setting backfill call, these values are
# injected as synthetic "DEFAULT" policies so that downstream checks can
# evaluate them instead of falling back to ERROR / MANUAL.
#
# Values are sourced from Google Workspace admin-console defaults for new
# tenants (as of 2026-02) and the official GWS admin help documentation.
GOOGLE_DEFAULTS: dict[str, dict] = {
    # ── Gmail ──────────────────────────────────────────────────────────
    "gmail.mail_delegation": {
        "enableMailDelegation": False,
    },
    "gmail.pop_access": {
        "enablePopAccess": False,
    },
    "gmail.imap_access": {
        "enableImapAccess": True,
    },
    "gmail.auto_forwarding": {
        "enableAutoForwarding": True,
    },
    "gmail.per_user_outbound_gateway": {
        "allowUsersToUseExternalSmtpServers": False,
    },
    "gmail.comprehensive_mail_storage": {
        "enableComprehensiveMailStorage": False,
    },
    "gmail.workspace_sync_for_outlook": {
        "enableGoogleWorkspaceSyncForMicrosoftOutlook": True,
    },
    "gmail.spam_override_lists": {},
    "gmail.email_spam_filter_ip_allowlist": {
        "allowedIpAddresses": [],
    },
    # ── Calendar ───────────────────────────────────────────────────────
    "calendar.primary_calendar_max_allowed_external_sharing": {
        "maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY",
    },
    "calendar.secondary_calendar_max_allowed_external_sharing": {
        "maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY",
    },
    "calendar.external_invitations": {
        "warnOnInvite": True,
    },
    "calendar.interoperability": {
        "enableInteroperability": False,
    },
    "calendar.calendar_offline_access": {
        "enableOfflineAccess": True,
    },
    # ── Drive & Docs ───────────────────────────────────────────────────
    # The external_sharing setting is not reliably returned by the Policy
    # API for all tenants.  The default below reflects the factory state
    # for new Google Workspace tenants (warning enabled).
    "drive_and_docs.external_sharing": {
        "warnForExternalSharing": True,
    },
    "drive_and_docs.general_access_default": {
        "defaultFileAccess": "LINK_SHARING_PRIVATE",
    },
    "drive_and_docs.drive_sdk": {
        "enableDriveSdkApiAccess": True,
    },
    "drive_and_docs.file_security_update": {
        "securityUpdate": "APPLY_TO_IMPACTED_FILES",
    },
    # ── Security ───────────────────────────────────────────────────────
    "security.two_step_verification_enrollment": {
        "allowEnrollment": True,
    },
    "security.two_step_verification_enforcement": {
        "enforcedFrom": "",
    },
    "security.two_step_verification_enforcement_factor": {
        "allowedSignInFactorSet": "ANY_VERIFICATION_METHOD",
    },
    "security.two_step_verification_device_trust": {
        "allowTrustingDevice": True,
    },
    "security.user_account_recovery": {
        "enableAccountRecovery": False,
    },
    "security.less_secure_apps": {
        "allowLessSecureApps": False,
    },
    # ── Directory ──────────────────────────────────────────────────────
    # Default: external directory sharing restricted to basic profile only.
    # Google Workspace admin help: "Authenticated user basic profile fields"
    # is the default for new tenants.
    "directory.external_directory_sharing": {
        "sharing_option": "REQUESTER_BASIC_PROFILE_ONLY",
    },
    # ── Sites ─────────────────────────────────────────────────────────
    "sites.sites_creation_and_modification": {
        "allowSitesCreation": True,
    },
    # ── Groups for Business ────────────────────────────────────────────
    "groups_for_business.groups_sharing": {
        "collaborationCapability": "FULL_COLLABORATION",
        "whoCanCreateGroups": "ALL_USERS_CAN_CREATE",
    },
    # ── Workspace Marketplace ──────────────────────────────────────────
    "workspace_marketplace.apps_access_options": {
        "accessLevel": "ALLOW_ALL",
    },
}


class PolicyClient(BaseAPIClient):
    """Client for the Cloud Identity Policy API (``cloudidentity`` ``v1``).

    The Policies API exposes the administrative settings of the Google
    Workspace admin console through a machine-readable interface.
    Settings are grouped by product/service area (Gmail, Drive, etc.)
    and can be queried individually or all at once.
    """

    def __init__(self, auth_manager, customer_id: str = "", **kwargs):
        # The Cloud Identity Policy API has a tight per-minute quota
        # (30 read requests/min/project).  Default to a conservative QPS
        # unless the caller explicitly overrides it.
        kwargs.setdefault("rate_limit_qps", POLICY_API_RATE_LIMIT_QPS)
        super().__init__(auth_manager, **kwargs)
        self._service = None
        self.customer_id = customer_id

    # ------------------------------------------------------------------
    # Service (lazy build)
    # ------------------------------------------------------------------

    @property
    def service(self):
        """Lazily build and cache the Cloud Identity service."""
        if self._service is None:
            logger.debug("Building Cloud Identity service")
            self._service = self.auth_manager.build_service(
                "cloudidentity", "v1"
            )
        return self._service

    # ------------------------------------------------------------------
    # Core policy retrieval
    # ------------------------------------------------------------------

    def get_policy_by_type(self, setting_type: str) -> dict[str, Any] | None:
        """Fetch a single policy by its setting type via ``policies.list``.

        The Cloud Identity Policy API uses opaque resource names
        (``policies/<id>``) that cannot be derived from the setting type.
        This method issues a narrow ``policies.list`` call filtered to
        the exact setting type and returns the first matching policy,
        which includes the effective value (with Google-applied defaults).

        Returns ``None`` if the setting is not found or the call fails.
        """
        cel_filter = f'setting.type == "settings/{setting_type}"'
        if self.customer_id:
            cel_filter += f' && customer == "customers/{self.customer_id}"'
        try:
            results = self.paginate(
                self.service.policies().list,
                items_key="policies",
                filter=cel_filter,
                pageSize=1,
            )
            if results:
                return results[0]
            return None
        except Exception as exc:
            logger.debug(
                "policies.list failed for setting type %s: %s",
                setting_type, exc,
            )
            return None

    def get_policies(self, policy_type: str) -> list[dict[str, Any]]:
        """Retrieve policies for a specific service area.

        First fetches all policies via a broad ``policies.list`` regex
        filter, then backfills any required settings that were not
        returned by issuing narrow per-setting ``policies.list`` calls.

        Parameters
        ----------
        policy_type:
            A policy category key such as ``"gmail"``, ``"drive"``, etc.
            The key is mapped to the setting type prefix used in the
            Cloud Identity Policies API's CEL filter expression.

        Returns
        -------
        A list of policy resource dicts.
        """
        setting_prefix = POLICY_CATEGORIES.get(
            policy_type.lower(), policy_type.lower()
        )
        # The Policy API uses CEL (Common Expression Language) filters.
        # Setting types follow the pattern: settings/<prefix>.<setting>
        # Reference: https://docs.cloud.google.com/identity/docs/reference/rest/v1/policies/list
        cel_filter = (
            f"setting.type.matches('^settings/{setting_prefix}\\\\..*$')"
        )
        if self.customer_id:
            cel_filter += f' && customer == "customers/{self.customer_id}"'
        try:
            logger.debug(
                "Querying Policy API for %s with filter: %s",
                policy_type, cel_filter,
            )
            policies = self.paginate(
                self.service.policies().list,
                items_key="policies",
                filter=cel_filter,
                pageSize=100,
            )
            logger.info(
                "Retrieved %d policies for %s", len(policies), policy_type
            )

            # Backfill missing required settings with individual list calls
            required = REQUIRED_SETTINGS.get(policy_type.lower(), [])
            if required:
                returned_types = {
                    p.get("setting", {}).get("type", "")
                    for p in policies
                }
                logger.debug(
                    "Broad query for %s returned %d types: %s",
                    policy_type,
                    len(returned_types),
                    sorted(returned_types),
                )
                for setting_type in required:
                    full_type = f"settings/{setting_type}"
                    if full_type not in returned_types:
                        logger.debug(
                            "Backfilling missing setting %s for %s",
                            setting_type, policy_type,
                        )
                        policy = self.get_policy_by_type(setting_type)
                        if policy:
                            policies.append(policy)
                            logger.debug(
                                "Backfilled %s for %s",
                                setting_type, policy_type,
                            )
                        elif setting_type in GOOGLE_DEFAULTS:
                            policies.append({
                                "name": f"policies/_default/{setting_type}",
                                "setting": {
                                    "type": full_type,
                                    "value": GOOGLE_DEFAULTS[setting_type],
                                },
                                "type": "DEFAULT",
                            })
                            logger.debug(
                                "Applied Google default for %s in %s",
                                setting_type, policy_type,
                            )

            return self._normalise_policies(policies, policy_type)
        except Exception as exc:
            logger.warning(
                "Policy API query failed for %s (filter: %s): %s",
                policy_type, cel_filter, exc,
            )
            self.record_error(f"get_policies({policy_type})", exc)
            return []

    # ------------------------------------------------------------------
    # Convenience per-category methods
    # ------------------------------------------------------------------

    def get_gmail_policies(self) -> list[dict[str, Any]]:
        """Retrieve Gmail-related admin policies."""
        return self.get_policies("gmail")

    def get_drive_policies(self) -> list[dict[str, Any]]:
        """Retrieve Drive-related admin policies."""
        return self.get_policies("drive")

    def get_calendar_policies(self) -> list[dict[str, Any]]:
        """Retrieve Calendar-related admin policies."""
        return self.get_policies("calendar")

    def get_chat_policies(self) -> list[dict[str, Any]]:
        """Retrieve Chat-related admin policies."""
        return self.get_policies("chat")

    def get_meet_policies(self) -> list[dict[str, Any]]:
        """Retrieve Meet-related admin policies."""
        return self.get_policies("meet")

    def get_sites_policies(self) -> list[dict[str, Any]]:
        """Retrieve Sites-related admin policies."""
        return self.get_policies("sites")

    def get_marketplace_policies(self) -> list[dict[str, Any]]:
        """Retrieve Marketplace-related admin policies."""
        return self.get_policies("marketplace")

    def get_security_policies(self) -> list[dict[str, Any]]:
        """Retrieve security-related admin policies."""
        return self.get_policies("security")

    def get_directory_policies(self) -> list[dict[str, Any]]:
        """Retrieve Directory-related admin policies."""
        return self.get_policies("directory")

    def get_groups_policies(self) -> list[dict[str, Any]]:
        """Retrieve Groups-related admin policies."""
        return self.get_policies("groups")

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def get_all_policies(self) -> dict[str, list[dict[str, Any]]]:
        """Collect all policy categories into a single dict.

        Returns
        -------
        A dict keyed by category name (``"gmail"``, ``"drive"``, etc.)
        with each value being the list of policy resource dicts
        returned by :meth:`get_policies`.
        """
        all_policies: dict[str, list[dict[str, Any]]] = {}

        for category in POLICY_CATEGORIES:
            logger.info("Fetching %s policies …", category)
            policies = self.get_policies(category)
            all_policies[category] = policies

        total = sum(len(v) for v in all_policies.values())
        logger.info(
            "Collected %d total policies across %d categories",
            total,
            len(all_policies),
        )
        return all_policies

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_policies(
        raw_policies: list[dict[str, Any]], category: str
    ) -> list[dict[str, Any]]:
        """Normalise raw policy resources into a consistent shape.

        Each normalised policy dict contains:
        * ``category`` -- the service area (e.g. ``"gmail"``).
        * ``name`` -- the policy resource name.
        * ``setting`` -- the setting payload.
        * ``orgUnit`` -- the org-unit path the setting applies to, if
          present.

        Parameters
        ----------
        raw_policies:
            The list of policy dicts as returned by the API.
        category:
            The policy category label.

        Returns
        -------
        A list of normalised policy dicts.
        """
        normalised: list[dict[str, Any]] = []

        for policy in raw_policies:
            entry: dict[str, Any] = {
                "category": category,
                "name": policy.get("name", ""),
                "setting": policy.get("setting", {}),
                "orgUnit": (
                    policy.get("policyQuery", {}).get("orgUnit")
                    or policy.get("orgUnit", "/")
                ),
            }

            # Preserve the full raw payload under a private key so that
            # individual checks can drill into API-specific fields.
            entry["_raw"] = policy
            normalised.append(entry)

        return normalised
