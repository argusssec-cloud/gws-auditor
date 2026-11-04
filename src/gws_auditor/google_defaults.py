# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Google's documented default values for Cloud Identity Policy API settings.

The Policy API concepts page states: "When a field is not present on the Reduced
Setting, its default value is as follows", followed by a table of defaults
(``DOCUMENTED_DEFAULTS`` below, keys converted to the camelCase the JSON API
returns, device settings omitted). The supported-settings page adds: "If the
supported settings are missing from the Cloud Identity Policy API response, see
Default field values." These values are therefore what Google tells consumers
to assume for an absent field; they are *not* admin-configured values and every
verdict that relies on them says so in its details.

A handful of settings outside that table have a default stated in Admin Help;
they live in ``ADMIN_HELP_DEFAULTS`` with their citation. Settings whose default
Google documents nowhere (POP, IMAP, comprehensive mail storage, ...) are
deliberately absent: an absent field there is unknown and a check reports MANUAL.
"""

from __future__ import annotations

SOURCE_URL = "https://docs.cloud.google.com/identity/docs/concepts/policy-api-concepts#default-field-values"
SOURCE_DATE = "2026-11-01"

DOCUMENTED_DEFAULTS: dict[str, dict] = {
    "api_controls.google_services": {"services": []},
    "calendar.external_invitations": {"warnOnInvite": True},
    "calendar.interoperability": {"enableInteroperability": False},
    "calendar.primary_calendar_max_allowed_external_sharing": {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"},
    "calendar.secondary_calendar_max_allowed_external_sharing": {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"},
    "chat.chat_history": {"historyOnByDefault": False, "allowUserModification": True},  # enable_chat_history is documented too but never returned by the API
    "chat.external_chat_restriction": {"allowExternalChat": False, "externalChatRestriction": "NO_RESTRICTION"},
    "chat.chat_and_space_restrictions": {"restrictionLevel": "UNRESTRICTED"},
    "directory.external_directory_sharing": {"sharingOption": "ORGANIZATION_DIRECTORY_DATA"},
    "drive_and_docs.drive_sdk": {"enableDriveSdkApiAccess": True},
    "drive_and_docs.external_sharing": {
        "externalSharingMode": "ALLOWED",
        "allowReceivingExternalFiles": True,
        "warnForSharingOutsideAllowlistedDomains": True,
        "allowNonGoogleInvitesInAllowlistedDomains": False,
        "allowReceivingFilesOutsideAllowlistedDomains": True,
        "warnForExternalSharing": True,
        "allowNonGoogleInvites": True,
        "allowPublishingFiles": True,
        "accessCheckerSuggestions": "RECIPIENTS_OR_AUDIENCE_OR_PUBLIC",
        "allowedPartiesForDistributingContent": "ALL_ELIGIBLE_USERS",
    },
    "drive_and_docs.general_access_default": {"defaultFileAccess": "LINK_SHARING_PRIVATE"},
    "gmail.auto_forwarding": {"enableAutoForwarding": True},
    "gmail.email_image_proxy_bypass": {"imageProxyBypassPattern": [], "enableImageProxy": True},
    "gmail.email_spam_filter_ip_allowlist": {"allowedIpAddresses": []},
    "gmail.links_and_external_images": {"applyFutureSettingsAutomatically": True, "enableAggressiveWarningsOnUntrustedLinks": False},
    "gmail.mail_delegation": {"enableMailDelegation": False},
    "gmail.smime_encryption": {"enableSmimeEncryption": "STATUS_DISABLED", "allowSha1GloballyInSmimeSignature": False},
    "gmail.spoofing_and_authentication": {"applyFutureSettingsAutomatically": True},
    "gmail.user_email_uploads": {"enableMailAndContactsImport": False},
    "gmail.workspace_sync_for_outlook": {"enableGoogleWorkspaceSyncForMicrosoftOutlook": True},
    "gmail.external_recipient_warning": {"enabled": True},
    "groups_for_business.groups_sharing": {
        "collaborationCapability": "DOMAIN_USERS_ONLY",
        "createGroupsAccessLevel": "USERS_IN_DOMAIN",
        "viewTopicsDefaultAccessLevel": "DOMAIN_USERS",
        "ownersCanAllowExternalMembers": False,
        "ownersCanAllowIncomingMailFromPublic": True,
        "ownersCanHideGroups": False,
        "newGroupsAreHidden": False,
    },
    "security.less_secure_apps": {"allowLessSecureApps": False},
    "security.password": {
        "allowedStrength": "STRONG", "minimumLength": 8, "maximumLength": 100,
        "enforceRequirementsAtLogin": False, "allowReuse": False, "expirationDuration": "0s",
    },
    "security.super_admin_account_recovery": {"enableAccountRecovery": False},
    "security.two_step_verification_device_trust": {"allowTrustingDevice": True},
    # Google documents enforcedFrom as "Unset": no enforcement. Represented as an explicit
    # None so an absent enforcement policy still yields an entry that says "not enforced".
    "security.two_step_verification_enforcement": {"enforcedFrom": None},
    "security.two_step_verification_enforcement_factor": {"allowedSignInFactorSet": "ALL"},
    "security.two_step_verification_enrollment": {"allowEnrollment": True},
    "security.two_step_verification_grace_period": {"enrollmentGracePeriod": "0s"},
    "security.user_account_recovery": {"enableAccountRecovery": False},
    "workspace_marketplace.apps_access_options": {"allowAllInternalApps": False},
    "workspace_marketplace.apps_allowlist": {"apps": []},
}

# Fields whose documented default depends on the edition. They are not injected
# unless the edition is known; an absent field is otherwise unknown.
EDITION_DEPENDENT_DEFAULTS: dict[str, dict[str, dict[str, object]]] = {
    "chat.chat_apps_access": {
        "enableApps": {"education": True, "default": False},
        "enableWebhooks": {"education": True, "default": False},
    },
    "workspace_marketplace.apps_access_options": {
        "accessLevel": {"k12": "ALLOW_NONE", "default": "ALLOW_ALL"},
    },
}

# Defaults stated in Google Workspace Admin Help rather than in the Policy API table.
ADMIN_HELP_DEFAULTS: dict[str, dict] = {
    # "By default, users cannot use an outbound gateway."
    # https://knowledge.workspace.google.com/admin/gmail/advanced/allow-per-user-outbound-gateways
    "gmail.per_user_outbound_gateway": {"allowUsersToUseExternalSmtpServers": False},
    # No approved-sender list exists until an admin creates one.
    "gmail.spam_override_lists": {"spamOverride": []},
    # "By default, user can use Calendar even when offline."
    # https://knowledge.workspace.google.com/admin/security/monitor-the-health-of-your-calendar-settings
    "calendar.calendar_offline_access": {"enableOfflineAccess": True},
    # "By default, Users can edit sites and Allow users to create new sites are enabled."
    # https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off (API also returns a SYSTEM policy)
    "sites.sites_creation_and_modification": {"allowSitesCreation": True, "allowSitesModification": True},
    # The API returns a SYSTEM policy with these values; kept for caches that predate it.
    "drive_and_docs.file_security_update": {"securityUpdate": "APPLY_TO_IMPACTED_FILES", "allowUsersToManageUpdate": True},
}

ALL_DEFAULTS: dict[str, dict] = {**ADMIN_HELP_DEFAULTS, **DOCUMENTED_DEFAULTS}


def defaults_for_setting(setting_key: str) -> dict:
    """Documented default fields for a setting key such as ``mail_delegation`` or ``gmail.mail_delegation``."""
    if setting_key in ALL_DEFAULTS:
        return ALL_DEFAULTS[setting_key]
    for setting_type, fields in ALL_DEFAULTS.items():
        if setting_type.split(".", 1)[1] == setting_key:
            return fields
    return {}
