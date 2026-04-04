# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Pydantic validation contracts for GWS Security Auditor data.

These models define the structural contract between Provider output and
Check input.  They are used for:

1. **Test factories** — ``tests/factories.py`` uses models to produce
   structurally correct fixture dicts via ``.model_dump()``.
2. **Provider validation** — ``provider.normalize_data()`` optionally
   validates output through ``AuditData`` to catch structural drift.
3. **Documentation** — the models serve as living documentation of
   expected data shapes.

Checks continue receiving plain ``dict`` — no check code changes needed.

All models use ``model_config = ConfigDict(extra="allow")`` so that
dynamically-added keys (dual-case normalization, etc.) are tolerated.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator


# ---------------------------------------------------------------------------
# Base configuration shared by all models
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    """Base model allowing extra fields and optional construction."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)


# ---------------------------------------------------------------------------
# User records
# ---------------------------------------------------------------------------

class UserRecord(_Base):
    """Normalized user record with both camelCase and snake_case fields.

    The Admin SDK Directory API returns camelCase fields; the provider
    normalizer adds snake_case aliases.  Both must be present for checks
    to work regardless of which convention they use.
    """
    # camelCase (original API)
    primaryEmail: str = ""
    isAdmin: bool = False
    isDelegatedAdmin: bool = False
    isEnrolledIn2Sv: bool = False
    isEnforcedIn2Sv: bool = False
    lastLoginTime: str = ""
    creationTime: str = ""
    orgUnitPath: str = "/"
    suspended: bool = False
    recoveryEmail: str = ""
    recoveryPhone: str = ""

    # snake_case (normalized aliases)
    primary_email: str = ""
    is_super_admin: bool = False
    is_admin: bool = False
    is_delegated_admin: bool = False
    is_enrolled_in_2sv: bool = False
    is_enforced_in_2sv: bool = False
    last_login_time: str = ""
    creation_time: str = ""
    org_unit_path: str = "/"
    recovery_email: str = ""
    recovery_phone: str = ""

    name: dict[str, Any] = {}

    @model_validator(mode="after")
    def _sync_fields(self) -> "UserRecord":
        """Sync camelCase ↔ snake_case so both are always consistent."""
        # primaryEmail ↔ primary_email
        if self.primaryEmail and not self.primary_email:
            self.primary_email = self.primaryEmail
        elif self.primary_email and not self.primaryEmail:
            self.primaryEmail = self.primary_email

        # isAdmin ↔ is_super_admin / is_admin
        if self.isAdmin and not self.is_super_admin:
            self.is_super_admin = self.isAdmin
            self.is_admin = self.isAdmin
        elif self.is_super_admin and not self.isAdmin:
            self.isAdmin = self.is_super_admin
            self.is_admin = self.is_super_admin

        # isDelegatedAdmin ↔ is_delegated_admin
        if self.isDelegatedAdmin and not self.is_delegated_admin:
            self.is_delegated_admin = self.isDelegatedAdmin
        elif self.is_delegated_admin and not self.isDelegatedAdmin:
            self.isDelegatedAdmin = self.is_delegated_admin

        # 2SV enrollment
        if self.isEnrolledIn2Sv and not self.is_enrolled_in_2sv:
            self.is_enrolled_in_2sv = self.isEnrolledIn2Sv
        elif self.is_enrolled_in_2sv and not self.isEnrolledIn2Sv:
            self.isEnrolledIn2Sv = self.is_enrolled_in_2sv

        # 2SV enforcement
        if self.isEnforcedIn2Sv and not self.is_enforced_in_2sv:
            self.is_enforced_in_2sv = self.isEnforcedIn2Sv
        elif self.is_enforced_in_2sv and not self.isEnforcedIn2Sv:
            self.isEnforcedIn2Sv = self.is_enforced_in_2sv

        # Timestamps
        if self.lastLoginTime and not self.last_login_time:
            self.last_login_time = self.lastLoginTime
        elif self.last_login_time and not self.lastLoginTime:
            self.lastLoginTime = self.last_login_time

        if self.creationTime and not self.creation_time:
            self.creation_time = self.creationTime
        elif self.creation_time and not self.creationTime:
            self.creationTime = self.creation_time

        # OU path
        if self.orgUnitPath != "/" and self.org_unit_path == "/":
            self.org_unit_path = self.orgUnitPath
        elif self.org_unit_path != "/" and self.orgUnitPath == "/":
            self.orgUnitPath = self.org_unit_path

        # Recovery
        if self.recoveryEmail and not self.recovery_email:
            self.recovery_email = self.recoveryEmail
        elif self.recovery_email and not self.recoveryEmail:
            self.recoveryEmail = self.recovery_email

        if self.recoveryPhone and not self.recovery_phone:
            self.recovery_phone = self.recoveryPhone
        elif self.recovery_phone and not self.recoveryPhone:
            self.recoveryPhone = self.recovery_phone

        return self


# ---------------------------------------------------------------------------
# Domain & OU records
# ---------------------------------------------------------------------------

class DomainRecord(_Base):
    """Domain metadata from Admin SDK Directory API."""
    domainName: str = ""
    isPrimary: bool = False
    verified: bool = True


class OrgUnitRecord(_Base):
    """Organizational unit from Admin SDK Directory API."""
    orgUnitPath: str = "/"
    orgUnitId: str = ""
    name: str = ""
    parentOrgUnitPath: str = "/"
    parentOrgUnitId: str = ""


# ---------------------------------------------------------------------------
# Group records
# ---------------------------------------------------------------------------

class GroupSettings(_Base):
    """Group settings from Groups Settings API."""
    whoCanViewGroup: str = ""
    whoCanViewMembership: str = ""
    whoCanPostMessage: str = ""
    allowExternalMembers: str = "false"
    whoCanJoin: str = ""


class GroupRecord(_Base):
    """Group with nested settings."""
    email: str = ""
    name: str = ""
    settings: GroupSettings = GroupSettings()


# ---------------------------------------------------------------------------
# OU-aware policy entries (used by get_ou_values() in checks/base.py)
# ---------------------------------------------------------------------------

class OUPolicySetting(_Base):
    """The ``setting`` sub-dict of an OU policy entry.

    ``type`` is the full setting type path, e.g.
    ``"settings/gmail.mail_delegation"``.
    ``value`` is the raw API payload dict.
    """
    type: str = ""
    value: dict[str, Any] = {}


class OUPolicyEntry(_Base):
    """A single ``_ou_policies`` entry.

    Used by ``get_ou_values()`` to iterate per-OU policy settings.
    """
    setting: OUPolicySetting = OUPolicySetting()
    orgUnit: str = "/"


# ---------------------------------------------------------------------------
# DNS records
# ---------------------------------------------------------------------------

class SpfRecord(_Base):
    """SPF DNS record with synced ``exists``/``record_found`` fields."""
    exists: bool = False
    record_found: bool = False
    record: str = ""
    valid: bool = False

    @model_validator(mode="after")
    def _sync_exists(self) -> "SpfRecord":
        """Ensure both ``exists`` and ``record_found`` are consistent."""
        if self.exists and not self.record_found:
            self.record_found = self.exists
        elif self.record_found and not self.exists:
            self.exists = self.record_found
        return self


class DkimRecord(_Base):
    """DKIM DNS record with synced ``exists``/``record_found`` fields."""
    exists: bool = False
    record_found: bool = False
    record: str = ""
    valid: bool = False
    enabled: bool = False

    @model_validator(mode="after")
    def _sync_exists(self) -> "DkimRecord":
        if self.exists and not self.record_found:
            self.record_found = self.exists
        elif self.record_found and not self.exists:
            self.exists = self.record_found
        # Sync enabled ↔ valid when one is set
        if self.enabled and not self.valid:
            self.valid = self.enabled
        return self


class DmarcRecord(_Base):
    """DMARC DNS record with synced ``exists``/``record_found`` fields."""
    exists: bool = False
    record_found: bool = False
    record: str = ""
    policy: str = "none"

    @model_validator(mode="after")
    def _sync_exists(self) -> "DmarcRecord":
        if self.exists and not self.record_found:
            self.record_found = self.exists
        elif self.record_found and not self.exists:
            self.exists = self.record_found
        return self


class MxRecord(_Base):
    """Single MX record entry."""
    priority: int = 0
    exchange: str = ""
    host: str = ""


class DnsDomainRecords(_Base):
    """Per-domain DNS records container.

    After normalization, ``mx`` is a flat list of record dicts (not
    a wrapper dict with ``records`` key).
    """
    spf: SpfRecord = SpfRecord()
    dkim: DkimRecord = DkimRecord()
    dmarc: DmarcRecord = DmarcRecord()
    mx: list[dict[str, Any]] = []
    mx_uses_google: bool = False


# ---------------------------------------------------------------------------
# Activity log entries
# ---------------------------------------------------------------------------

class LogEntry(_Base):
    """Flattened activity log entry (admin, login, or token)."""
    actor_email: str = ""
    event_name: str = ""
    event_type: str = ""
    time: str = ""
    ip_address: str = ""
    parameters: dict[str, Any] = {}
    # Promoted parameter fields
    app_name: str = ""
    client_id: str = ""


# ---------------------------------------------------------------------------
# Alert center rules
# ---------------------------------------------------------------------------

class AlertRule(_Base):
    """Alert Center rule entry."""
    name: str = ""
    enabled: bool = True
    source: str = ""


# ---------------------------------------------------------------------------
# Chrome policies
# ---------------------------------------------------------------------------

class ChromePolicies(_Base):
    """Chrome Policy API resolved settings."""
    gemini_in_chrome_disabled: bool = False
    dbsc_enabled: bool = False


# ---------------------------------------------------------------------------
# Service policy models (post-normalization nested structures)
# ---------------------------------------------------------------------------

class _ServicePolicies(_Base):
    """Base for all service policy containers.

    Includes ``_ou_policies`` for OU-aware checks and ``_ou_id_map``
    for secondary ID resolution.
    """
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Gmail ---

class GmailAttachmentSafety(_Base):
    encrypted_attachment_protection: bool | None = None
    script_attachment_protection: bool | None = None
    anomalous_attachment_protection: bool | None = None


class GmailLinkSafety(_Base):
    scan_shortened_urls: bool | None = None
    scan_linked_images: bool | None = None
    show_warning_for_untrusted_links: bool | None = None


class GmailSpoofingSafety(_Base):
    domain_spoofing_protection: bool | None = None
    employee_name_spoofing_protection: bool | None = None
    inbound_domain_spoofing_protection: bool | None = None
    unauthenticated_email_protection: bool | None = None
    groups_spoofing_protection: bool | None = None


class GmailSafety(_Base):
    attachments: GmailAttachmentSafety = GmailAttachmentSafety()
    links: GmailLinkSafety = GmailLinkSafety()
    spoofing: GmailSpoofingSafety = GmailSpoofingSafety()
    enhanced_predelivery_scanning: bool | None = None


class GmailUserSettings(_Base):
    mail_delegation_enabled: bool | None = None
    mail_import_enabled: bool | None = None
    email_uploads_enabled: bool | None = None


class GmailEndUserAccess(_Base):
    pop_enabled: bool | None = None
    imap_enabled: bool | None = None
    workspace_sync_enabled: bool | None = None


class GmailRouting(_Base):
    auto_forwarding_enabled: bool | None = None
    per_user_outbound_gateway_enabled: bool | None = None


class GmailCompliance(_Base):
    tls_required: bool | None = None
    comprehensive_mail_storage: bool | None = None
    comprehensive_mail_storage_enabled: bool | None = None
    content_compliance_configured: bool | None = None


class GmailEncryption(_Base):
    smime_user_upload: bool | None = None


class GmailConfidentialMode(_Base):
    enabled: bool | None = None


class GmailSpamSettings(_Base):
    approved_senders_domains: list[str] = []
    domains_bypass_and_hide_warnings: list[str] = []


class GmailInboundGateway(_Base):
    configured: bool | None = None


class GmailPolicies(_Base):
    """Post-normalization Gmail policy structure."""
    safety: GmailSafety = GmailSafety()
    user_settings: GmailUserSettings = GmailUserSettings()
    end_user_access: GmailEndUserAccess = GmailEndUserAccess()
    routing: GmailRouting = GmailRouting()
    compliance: GmailCompliance = GmailCompliance()
    encryption: GmailEncryption = GmailEncryption()
    confidential_mode_settings: GmailConfidentialMode = GmailConfidentialMode()
    spam_settings: GmailSpamSettings = GmailSpamSettings()
    inbound_gateway: GmailInboundGateway = GmailInboundGateway()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Drive ---

class DriveSharingSettings(_Base):
    warn_on_external_sharing: bool | None = None
    warn_for_external_sharing: bool | None = None
    allow_public_publishing: bool | None = None
    allowlisted_domains_enabled: bool | None = None
    warn_on_allowlisted_domain_sharing: bool | None = None
    access_checker_suggestion: str = ""
    access_checker_suggestions: str = ""
    external_distribution_allowed_for: str = ""
    receive_files_from_non_allowlisted: bool | None = None
    allow_non_google_account_sharing: bool | None = None
    anyone_with_link_enabled: bool | None = None
    allow_upload_to_external_drives: bool | None = None
    out_of_domain_warning_enabled: bool | None = None
    default_link_sharing_access: str = ""


class DriveSharedDriveSettings(_Base):
    creation_restricted: bool | None = None
    manager_can_override: bool | None = None
    allow_manager_override: bool | None = None
    access_restricted_to_members: bool | None = None
    allow_non_member_access: bool | None = None
    viewer_download_print_copy_disabled: bool | None = None
    allow_external_user_access: bool | None = None


class DriveFeatures(_Base):
    desktop_access_enabled: bool | None = None
    desktop_allowed: bool | None = None
    security_update_for_files: bool | None = None
    drive_sdk_enabled: bool | None = None


class DrivePolicies(_Base):
    """Post-normalization Drive policy structure."""
    sharing_settings: DriveSharingSettings = DriveSharingSettings()
    shared_drive_settings: DriveSharedDriveSettings = DriveSharedDriveSettings()
    features: DriveFeatures = DriveFeatures()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Calendar ---

class CalendarPrimarySettings(_Base):
    external_sharing: str = ""
    internal_sharing: str = ""


class CalendarSecondarySettings(_Base):
    external_sharing: str = ""
    internal_sharing: str = ""


class CalendarInterop(_Base):
    exchange_interop_enabled: bool | None = None
    auth_method: str = ""


class CalendarAppointments(_Base):
    paid_appointments_enabled: bool | None = None


class CalendarPolicies(_Base):
    """Post-normalization Calendar policy structure."""
    primary_calendar: CalendarPrimarySettings = CalendarPrimarySettings()
    secondary_calendar: CalendarSecondarySettings = CalendarSecondarySettings()
    external_invitation_warning: bool | None = None
    interop: CalendarInterop = CalendarInterop()
    appointments: CalendarAppointments = CalendarAppointments()
    offline_access_enabled: bool | None = None
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Chat ---

class ChatFileSharing(_Base):
    external_file_sharing_enabled: bool | None = None
    internal_file_sharing_enabled: bool | None = None


class ChatSpaces(_Base):
    external_spaces_enabled: bool | None = None


class ChatExternalChat(_Base):
    restriction_mode: str = ""


class ChatApps(_Base):
    chat_apps_enabled: bool | None = None
    incoming_webhooks_enabled: bool | None = None


class ChatHistory(_Base):
    history_on_by_default: bool | None = None
    history_enabled: bool | None = None
    space_history_enabled: bool | None = None
    history_state: str = ""
    allow_user_modification: bool | None = None


class ChatContentReporting(_Base):
    enabled: bool | None = None
    all_categories_selected: bool | None = None


class ChatPolicies(_Base):
    """Post-normalization Chat policy structure."""
    file_sharing: ChatFileSharing = ChatFileSharing()
    spaces: ChatSpaces = ChatSpaces()
    external_chat: ChatExternalChat = ChatExternalChat()
    apps: ChatApps = ChatApps()
    history: ChatHistory = ChatHistory()
    content_reporting: ChatContentReporting = ChatContentReporting()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Meet ---

class MeetJoiningControls(_Base):
    knock_to_join_required: bool | None = None


class MeetSafety(_Base):
    external_users_must_ask_to_join: bool | None = None
    domain_restriction: str = ""
    host_management_enabled: bool | None = None
    warn_for_external_participants: bool | None = None
    non_workspace_meetings_allowed: bool | None = None


class MeetCalling(_Base):
    incoming_calls_restricted: bool | None = None


class MeetRecording(_Base):
    enabled: bool | None = None
    auto_recording_enabled: bool | None = None


class MeetPolicies(_Base):
    """Post-normalization Meet policy structure."""
    joining_controls: MeetJoiningControls = MeetJoiningControls()
    safety: MeetSafety = MeetSafety()
    calling: MeetCalling = MeetCalling()
    recording: MeetRecording = MeetRecording()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Sites ---

class SitesPolicies(_Base):
    """Post-normalization Sites policy structure."""
    sites_creation_enabled: bool | None = None
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Marketplace ---

class MarketplacePolicies(_Base):
    """Post-normalization Marketplace policy structure."""
    app_install_policy: str = ""
    restrict_to_approved_apps: bool | None = None
    allowlisted_apps: list[dict[str, Any]] = []
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Groups ---

class GroupsSharingPolicy(_Base):
    allow_external_members: bool | None = None
    external_access_default: str = ""


class GroupsCreationPolicy(_Base):
    who_can_create: str = ""


class GroupsVisibilityPolicy(_Base):
    default_conversation_visibility: str = ""


class GroupsPolicies(_Base):
    """Post-normalization Groups policy structure."""
    external_members_allowed: bool | None = None
    who_can_create_groups: str = ""
    default_message_visibility: str = ""
    allow_external_posting: bool | None = None
    external_groups_access_enabled: bool | None = None
    allow_hiding_from_directory: bool | None = None
    sharing: GroupsSharingPolicy = GroupsSharingPolicy()
    creation: GroupsCreationPolicy = GroupsCreationPolicy()
    visibility: GroupsVisibilityPolicy = GroupsVisibilityPolicy()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Directory ---

class DirectorySharingSettings(_Base):
    external_sharing_restricted: bool | None = None


class DirectoryPolicies(_Base):
    """Post-normalization Directory policy structure."""
    sharing_settings: DirectorySharingSettings = DirectorySharingSettings()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Security ---

class TwoStepVerification(_Base):
    enrollment_enabled: bool | None = None
    enforcement: bool | None = None
    admin_enforcement: bool | None = None
    admin_allowed_methods: str = ""
    device_trust_enabled: bool | None = None
    new_user_enrollment_period_days: int | None = None


class AdvancedProtection(_Base):
    enrollment_available: bool | None = None


class AccountRecovery(_Base):
    super_admin_recovery_enabled: bool | None = None
    user_recovery_enabled: bool | None = None
    allow_recovery_info: bool | None = None


class SessionManagement(_Base):
    web_session_duration_hours: float | None = None
    session_duration_hours: float | None = None
    dbsc_enabled: bool | None = None


class PasswordManagement(_Base):
    minimum_length: int | None = None
    enforce_strong_password: bool | None = None
    strength: str = ""
    expiration_days: int | None = None


class LessSecureApps(_Base):
    allowed: bool | None = None


class LoginChallenges(_Base):
    enabled: bool | None = None
    enableEmployeeIdChallenge: bool | None = None


class Passkeys(_Base):
    allowed_type: str = ""


class Authentication(_Base):
    passkeys_enforced: bool | None = None


class ApiAccess(_Base):
    third_party_apps_restricted: bool | None = None
    trust_policy: str = ""
    internal_apps_controlled: bool | None = None


class AppAccess(_Base):
    third_party_api_access_restricted: bool | None = None
    allow_unconfigured_third_party_apps: bool | None = None
    trust_unconfigured_internal_apps: bool | None = None


class MultiPartyApproval(_Base):
    enabled: bool | None = None
    vault_exports_covered: bool | None = None


class DlpSettings(_Base):
    calendar_dlp_rules: list[dict[str, Any]] = []
    calendar_dlp_enabled: bool | None = None


class SecurityPolicies(_Base):
    """Post-normalization Security policy structure."""
    two_step_verification: TwoStepVerification = TwoStepVerification()
    advanced_protection: AdvancedProtection = AdvancedProtection()
    account_recovery: AccountRecovery = AccountRecovery()
    session_management: SessionManagement = SessionManagement()
    password_management: PasswordManagement = PasswordManagement()
    less_secure_apps: LessSecureApps = LessSecureApps()
    login_challenges: LoginChallenges = LoginChallenges()
    passkeys: Passkeys = Passkeys()
    authentication: Authentication = Authentication()
    api_access: ApiAccess = ApiAccess()
    app_access: AppAccess = AppAccess()
    multi_party_approval: MultiPartyApproval = MultiPartyApproval()
    dlp: DlpSettings = DlpSettings()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Gemini ---

class GeminiChrome(_Base):
    enabled: bool | None = None


class GeminiPolicies(_Base):
    """Post-normalization Gemini policy structure."""
    chrome: GeminiChrome = GeminiChrome()
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# --- Classroom ---

class ClassroomApiAccess(_Base):
    enabled: bool | None = None


class ClassroomSharing(_Base):
    class_membership: str = ""
    classes_to_join: str = ""


class ClassroomClassSettings(_Base):
    who_can_unenroll_students: str = ""
    who_can_create_classes: str = ""


class ClassroomPolicies(_Base):
    """Post-normalization Classroom policy structure."""
    api_access: ClassroomApiAccess = ClassroomApiAccess()
    sharing: ClassroomSharing = ClassroomSharing()
    class_settings: ClassroomClassSettings = ClassroomClassSettings()
    service_status: str = ""
    _ou_policies: list[dict[str, Any]] = []
    _ou_id_map: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Policies container
# ---------------------------------------------------------------------------

class PoliciesContainer(_Base):
    """Top-level policies dict containing all service policy containers."""
    gmail: GmailPolicies | dict[str, Any] = {}
    drive: DrivePolicies | dict[str, Any] = {}
    calendar: CalendarPolicies | dict[str, Any] = {}
    chat: ChatPolicies | dict[str, Any] = {}
    meet: MeetPolicies | dict[str, Any] = {}
    sites: SitesPolicies | dict[str, Any] = {}
    marketplace: MarketplacePolicies | dict[str, Any] = {}
    security: SecurityPolicies | dict[str, Any] = {}
    groups: GroupsPolicies | dict[str, Any] = {}
    directory: DirectoryPolicies | dict[str, Any] = {}
    gemini: GeminiPolicies | dict[str, Any] = {}
    classroom: ClassroomPolicies | dict[str, Any] = {}
    access_control: dict[str, Any] = {}
    api_controls: dict[str, Any] = {}
    multi_party_approval: dict[str, Any] = {}
    rules: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Top-level audit data
# ---------------------------------------------------------------------------

class AuditData(_Base):
    """Top-level data dict that checks receive.

    This is the structural contract for the ``data`` argument passed
    to every check function.
    """
    users: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    org_units: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    policies: dict[str, Any] = {}
    chrome_policies: dict[str, Any] = {}
    admin_logs: list[dict[str, Any]] = []
    login_logs: list[dict[str, Any]] = []
    token_logs: list[dict[str, Any]] = []
    usage_reports: list[dict[str, Any]] | dict[str, Any] = []
    dns_records: dict[str, Any] = {}
    alert_center_rules: list[dict[str, Any]] = []
    calendar_acls: dict[str, Any] = {}
    api_errors: list[dict[str, Any]] = []
