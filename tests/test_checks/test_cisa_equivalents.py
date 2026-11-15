"""Tests for checks/cisa_equivalents.py: SCuBA v1 policies that re-label a CIS/ADD twin's verdict,
plus the SCuBA controls with their own thresholds (6.2, 11.1, GMAIL.3.1) and the CIS 4.3 reviews."""

import pytest

from gws_auditor.checks import cisa_equivalents as eq
from gws_auditor.checks.registry import CheckRegistry
from gws_auditor.models import Status
from tests.factories import make_dns_domain, make_ou_policy


def _ou(category, key, value, org_unit="/"):
    return {"_ou_policies": [make_ou_policy(category, key, value, org_unit)]}


# (function, pass payload, fail payload) — payloads are policies-dict fragments keyed by category.
_POLICY_CASES = [
    (eq.check_scuba_primary_calendar_sharing, "GWS.CALENDAR.1.1",
     {"calendar": _ou("calendar", "primary_calendar_max_allowed_external_sharing", {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"})},
     {"calendar": _ou("calendar", "primary_calendar_max_allowed_external_sharing", {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_ONLY"})}),
    (eq.check_scuba_secondary_calendar_sharing, "GWS.CALENDAR.1.2",
     {"calendar": _ou("calendar", "secondary_calendar_max_allowed_external_sharing", {"maxAllowedExternalSharing": "EXTERNAL_FREE_BUSY_ONLY"})},
     {"calendar": _ou("calendar", "secondary_calendar_max_allowed_external_sharing", {"maxAllowedExternalSharing": "EXTERNAL_ALL_INFO_READ_WRITE"})}),
    (eq.check_scuba_external_invitation_warning, "GWS.CALENDAR.2.1",
     {"calendar": _ou("calendar", "external_invitations", {"warnOnInvite": True})},
     {"calendar": _ou("calendar", "external_invitations", {"warnOnInvite": False})}),
    (eq.check_scuba_external_chat_restriction, "GWS.CHAT.4.1",
     {"chat": _ou("chat", "external_chat_restriction", {"allowExternalChat": True, "externalChatRestriction": "TRUSTED_DOMAINS"})},
     {"chat": _ou("chat", "external_chat_restriction", {"allowExternalChat": True, "externalChatRestriction": "NO_RESTRICTION"})}),
    (eq.check_chat_external_file_sharing_cis, "CIS-3.1.4.1.1",
     {"chat": _ou("chat", "chat_file_sharing", {"externalFileSharing": "NO_FILES"})},
     {"chat": _ou("chat", "chat_file_sharing", {"externalFileSharing": "ALL_FILES"})}),
    (eq.check_scuba_mfa_all_users, "GWS.COMMONCONTROLS.1.2",
     {"security": _ou("security", "two_step_verification_enforcement", {"enforcedFrom": "2020-01-01T00:00:00Z"})},
     {"security": _ou("security", "two_step_verification_enforcement", {"enforcedFrom": "2099-01-01T00:00:00Z"})}),
    (eq.check_scuba_less_secure_apps, "GWS.COMMONCONTROLS.10.5",
     {"security": _ou("security", "less_secure_apps", {"allowLessSecureApps": False})},
     {"security": _ou("security", "less_secure_apps", {"allowLessSecureApps": True})}),
    (eq.check_scuba_takeout_disabled, "GWS.COMMONCONTROLS.12.1",
     {"takeout": _ou("maps", "user_takeout", {"takeoutStatus": "DISABLED"})},
     {"takeout": _ou("youtube", "user_takeout", {"takeoutStatus": "ENABLED"})}),
    (eq.check_scuba_drive_external_sharing, "GWS.DRIVEDOCS.1.1",
     {"drive": _ou("drive", "external_sharing", {"externalSharingMode": "ALLOWLISTED_DOMAINS"})},
     {"drive": _ou("drive", "external_sharing", {"externalSharingMode": "ALLOWED"})}),
    (eq.check_scuba_drive_sdk, "GWS.DRIVEDOCS.4.1",
     {"drive": _ou("drive", "drive_sdk", {"enableDriveSdkApiAccess": False})},
     {"drive": _ou("drive", "drive_sdk", {"enableDriveSdkApiAccess": True})}),
    (eq.check_scuba_1_1_mail_delegation, "GWS.GMAIL.1.1",
     {"gmail": _ou("gmail", "mail_delegation", {"enableMailDelegation": False})},
     {"gmail": _ou("gmail", "mail_delegation", {"enableMailDelegation": True})}),
    (eq.check_scuba_5_1_encrypted_attachment, "GWS.GMAIL.5.1",
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableEncryptedAttachmentProtection": True})},
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableEncryptedAttachmentProtection": False})}),
    (eq.check_scuba_5_2_script_attachment, "GWS.GMAIL.5.2",
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableAttachmentWithScriptsProtection": True})},
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableAttachmentWithScriptsProtection": False})}),
    (eq.check_scuba_5_3_anomalous_attachment, "GWS.GMAIL.5.3",
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableAnomalousAttachmentProtection": True})},
     {"gmail": _ou("gmail", "email_attachment_safety", {"enableAnomalousAttachmentProtection": False})}),
    (eq.check_scuba_6_1_shortened_urls, "GWS.GMAIL.6.1",
     {"gmail": _ou("gmail", "links_and_external_images", {"enableShortenerScanning": True})},
     {"gmail": _ou("gmail", "links_and_external_images", {"enableShortenerScanning": False})}),
    (eq.check_scuba_6_2_linked_image_scanning, "GWS.GMAIL.6.2",
     {"gmail": _ou("gmail", "links_and_external_images", {"enableExternalImageScanning": True})},
     {"gmail": _ou("gmail", "links_and_external_images", {"enableExternalImageScanning": False})}),
    (eq.check_scuba_6_3_untrusted_link_warning, "GWS.GMAIL.6.3",
     {"gmail": _ou("gmail", "links_and_external_images", {"enableAggressiveWarningsOnUntrustedLinks": True})},
     {"gmail": _ou("gmail", "links_and_external_images", {"enableAggressiveWarningsOnUntrustedLinks": False})}),
    (eq.check_scuba_7_1_domain_spoofing, "GWS.GMAIL.7.1",
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectDomainNameSpoofing": True})},
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectDomainNameSpoofing": False})}),
    (eq.check_scuba_7_2_employee_spoofing, "GWS.GMAIL.7.2",
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectEmployeeNameSpoofing": True})},
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectEmployeeNameSpoofing": False})}),
    (eq.check_scuba_7_3_inbound_spoofing, "GWS.GMAIL.7.3",
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectDomainSpoofingFromUnauthenticatedSenders": True})},
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectDomainSpoofingFromUnauthenticatedSenders": False})}),
    (eq.check_scuba_7_4_unauthenticated_email, "GWS.GMAIL.7.4",
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectUnauthenticatedEmails": True})},
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectUnauthenticatedEmails": False})}),
    (eq.check_scuba_7_5_groups_spoofing, "GWS.GMAIL.7.5",
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectGroupsSpoofing": True})},
     {"gmail": _ou("gmail", "spoofing_and_authentication", {"detectGroupsSpoofing": False})}),
    (eq.check_scuba_9_1_pop_imap, "GWS.GMAIL.9.1",
     {"gmail": {"_ou_policies": [make_ou_policy("gmail", "pop_access", {"enablePopAccess": False}),
                                 make_ou_policy("gmail", "imap_access", {"enableImapAccess": False})]}},
     {"gmail": {"_ou_policies": [make_ou_policy("gmail", "pop_access", {"enablePopAccess": False}),
                                 make_ou_policy("gmail", "imap_access", {"enableImapAccess": True})]}}),
    (eq.check_scuba_11_1_auto_forwarding, "GWS.GMAIL.11.1",
     {"gmail": _ou("gmail", "auto_forwarding", {"enableAutoForwarding": False})},
     {"gmail": _ou("gmail", "auto_forwarding", {"enableAutoForwarding": True})}),
    (eq.check_scuba_12_1_outbound_gateway, "GWS.GMAIL.12.1",
     {"gmail": _ou("gmail", "per_user_outbound_gateway", {"allowUsersToUseExternalSmtpServers": False})},
     {"gmail": _ou("gmail", "per_user_outbound_gateway", {"allowUsersToUseExternalSmtpServers": True})}),
    (eq.check_scuba_13_1_external_recipient_warning, "GWS.GMAIL.13.1",
     {"gmail": _ou("gmail", "external_recipient_warning", {"enabled": True})},
     {"gmail": _ou("gmail", "external_recipient_warning", {"enabled": False})}),
    (eq.check_scuba_15_1_predelivery_scanning, "GWS.GMAIL.15.1",
     {"gmail": _ou("gmail", "enhanced_pre_delivery_message_scanning", {"enableImprovedSuspiciousContentDetection": True})},
     {"gmail": _ou("gmail", "enhanced_pre_delivery_message_scanning", {"enableImprovedSuspiciousContentDetection": False})}),
    (eq.check_scuba_16_1_security_sandbox, "GWS.GMAIL.16.1",
     {"gmail": {"safety": {"security_sandbox_enabled": True}}},
     {"gmail": {"safety": {"security_sandbox_enabled": False}}}),
    (eq.check_scuba_17_1_comprehensive_storage, "GWS.GMAIL.17.1",
     {"gmail": _ou("gmail", "comprehensive_mail_storage", {"enableComprehensiveMailStorage": True})},
     {"gmail": _ou("gmail", "comprehensive_mail_storage", {"enableComprehensiveMailStorage": False})}),
    (eq.check_scuba_group_creation, "GWS.GROUPS.2.1",
     {"groups": _ou("groups", "groups_sharing", {"createGroupsAccessLevel": "ADMIN_ONLY"})},
     {"groups": _ou("groups", "groups_sharing", {"createGroupsAccessLevel": "ALL_USERS_CAN_CREATE"})}),
]


def _apply(data, fragment):
    data["users"] = [{"primary_email": "user@example.com", "is_enrolled_in_2sv": True, "is_super_admin": False}]
    data["user_usage"] = []
    data["admin_logs"] = []
    for category, value in fragment.items():
        data["policies"][category] = value


def _by_id():
    return {m.check_id: m for m in CheckRegistry().get_all_checks()}


class TestRelabelledTwins:
    @pytest.mark.parametrize("func, check_id, ok, bad", _POLICY_CASES, ids=[c[1] for c in _POLICY_CASES])
    def test_pass_payload(self, full_audit_data, func, check_id, ok, bad):
        _apply(full_audit_data, ok)
        result = func(full_audit_data)
        assert result.status == Status.PASS, result.details
        assert result.check_id == check_id
        assert "Same setting as " in result.details
        assert result.remediation

    @pytest.mark.parametrize("func, check_id, ok, bad", _POLICY_CASES, ids=[c[1] for c in _POLICY_CASES])
    def test_fail_payload(self, full_audit_data, func, check_id, ok, bad):
        _apply(full_audit_data, bad)
        result = func(full_audit_data)
        assert result.status == Status.FAIL, result.details
        assert result.check_id == check_id
        assert result.remediation

    def test_twin_verdicts_agree(self, full_audit_data):
        """A twin and its original judge the same data the same way."""
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        _apply(full_audit_data, _POLICY_CASES[22][3])
        twin = eq.check_scuba_9_1_pop_imap(full_audit_data)
        original = check_gmail_pop_imap(full_audit_data)
        assert (twin.status, twin.actual_value) == (original.status, original.actual_value)
        assert twin.source == "CISA" and original.source == "CIS"

    def test_unknown_passes_through(self, full_audit_data):
        _apply(full_audit_data, {"gmail": _ou("gmail", "mail_delegation", {})})
        full_audit_data["policies"]["gmail"]["_ou_policies"] = []
        result = eq.check_scuba_1_1_mail_delegation(full_audit_data)
        assert result.status in (Status.MANUAL, Status.ERROR)

    def test_standards_and_levels(self):
        meta = _by_id()
        for check_id in ("GWS.CALENDAR.1.1", "GWS.CHAT.4.1", "GWS.COMMONCONTROLS.1.2", "GWS.GMAIL.5.1", "GWS.GMAIL.9.1"):
            assert meta[check_id].bod_25_01 is True, check_id
            assert meta[check_id].level == "L1", check_id
            assert meta[check_id].nist_sp800_53, check_id
        for check_id in ("GWS.GMAIL.1.1", "GWS.GMAIL.2.1", "GWS.GMAIL.11.1", "GWS.GROUPS.2.1", "GWS.DRIVEDOCS.4.1"):
            assert meta[check_id].level == "L2" and meta[check_id].bod_25_01 is False, check_id
        cis = meta["CIS-3.1.4.1.1"]
        assert cis.source == "CIS" and cis.nist_csf and cis.bod_25_01 is False
        assert meta["GWS.CHAT.4.1"].requires_license == meta["CIS-3.1.4.2.1"].requires_license
        assert meta["GWS.GMAIL.16.1"].requires_license == meta["ADD-02"].requires_license

    def test_every_scuba_v1_gmail_safety_policy_is_present(self):
        meta = _by_id()
        for n in ("5.1", "5.2", "5.3", "6.1", "6.2", "6.3", "7.1", "7.2", "7.3", "7.4", "7.5"):
            assert f"GWS.GMAIL.{n}" in meta


class TestDkimTwin:
    def test_pass_and_fail(self, full_audit_data):
        full_audit_data["dns_records"] = {"example.com": make_dns_domain(), "example.org": make_dns_domain()}
        assert eq.check_scuba_2_1_dkim(full_audit_data).status == Status.PASS
        full_audit_data["dns_records"]["example.org"] = make_dns_domain(dkim_found=False, dkim_enabled=False)
        result = eq.check_scuba_2_1_dkim(full_audit_data)
        assert result.status == Status.FAIL and result.check_id == "GWS.GMAIL.2.1"


class TestSpfPolicy:
    """GWS.GMAIL.3.1: one record per domain ending in -all or ~all (or redirect=)."""

    def _dns(self, full_audit_data, record, **kw):
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(spf_record=record, **kw),
            "example.org": make_dns_domain(),
        }

    @pytest.mark.parametrize("record", [
        "v=spf1 include:_spf.google.com -all",
        "v=spf1 include:_spf.google.com ~all",
        "v=spf1 redirect=_spf.example.net",
    ])
    def test_pass(self, full_audit_data, record):
        self._dns(full_audit_data, record)
        result = eq.check_scuba_spf_policy(full_audit_data)
        assert result.status == Status.PASS, result.details

    @pytest.mark.parametrize("record, word", [
        ("v=spf1 include:_spf.google.com ?all", "?all"),
        ("v=spf1 include:_spf.google.com +all", "+all"),
        ("v=spf1 include:_spf.google.com", "no 'all' mechanism"),
    ])
    def test_fail(self, full_audit_data, record, word):
        self._dns(full_audit_data, record)
        result = eq.check_scuba_spf_policy(full_audit_data)
        assert result.status == Status.FAIL
        assert word in result.details and "example.com" in result.details

    def test_missing_and_duplicate(self, full_audit_data):
        self._dns(full_audit_data, "v=spf1 -all", spf_found=False)
        assert "no SPF record" in eq.check_scuba_spf_policy(full_audit_data).details
        self._dns(full_audit_data, "v=spf1 -all")
        full_audit_data["dns_records"]["example.com"]["spf"]["record_count"] = 2
        assert "more than one SPF record" in eq.check_scuba_spf_policy(full_audit_data).details

    def test_cis_twin_is_looser(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_spf
        self._dns(full_audit_data, "v=spf1 include:_spf.google.com")
        assert check_gmail_spf(full_audit_data).status == Status.PASS
        assert eq.check_scuba_spf_policy(full_audit_data).status == Status.FAIL

    def test_no_domains(self, full_audit_data):
        full_audit_data["domains"] = []
        assert eq.check_scuba_spf_policy(full_audit_data).status == Status.ERROR


class TestSuperAdminBand:
    """GWS.COMMONCONTROLS.6.2: 2 to 8 super admins, break-glass accounts excluded; CIS-1.1.1 keeps 2 to 4."""

    @staticmethod
    def _admins(n, suspended=0):
        return [{"primary_email": f"admin{i}@example.com", "is_super_admin": True, "suspended": i < suspended}
                for i in range(n)]

    def test_six_passes_scuba_but_fails_cis(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_count
        full_audit_data["users"] = self._admins(6)
        assert eq.check_scuba_super_admin_count(full_audit_data).status == Status.PASS
        assert check_super_admin_count(full_audit_data).status == Status.FAIL

    def test_nine_fails(self, full_audit_data):
        full_audit_data["users"] = self._admins(9)
        result = eq.check_scuba_super_admin_count(full_audit_data)
        assert result.status == Status.FAIL and "maximum of eight" in result.details

    def test_one_active_fails(self, full_audit_data):
        full_audit_data["users"] = self._admins(2, suspended=1)
        result = eq.check_scuba_super_admin_count(full_audit_data)
        assert result.status == Status.FAIL and "Only 1 active" in result.details

    def test_break_glass_excluded(self, full_audit_data):
        full_audit_data["users"] = self._admins(9)
        full_audit_data["_options"] = {"break_glass_accounts": ["Admin8@example.com"]}
        result = eq.check_scuba_super_admin_count(full_audit_data)
        assert result.status == Status.PASS
        assert "break-glass account(s) excluded" in result.details and result.actual_value == 8


class TestMarketplaceAllowlist:
    """GWS.COMMONCONTROLS.11.1 also requires allowAllInternalApps off."""

    def _mk(self, full_audit_data, value):
        full_audit_data["policies"]["marketplace"] = _ou("workspace_marketplace", "apps_access_options", value)

    def test_allowlist_and_no_internal_bypass_passes(self, full_audit_data):
        self._mk(full_audit_data, {"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": False})
        assert eq.check_scuba_marketplace_allowlist(full_audit_data).status == Status.PASS
        self._mk(full_audit_data, {"accessLevel": "ALLOW_NONE", "allowAllInternalApps": False})
        assert eq.check_scuba_marketplace_allowlist(full_audit_data).status == Status.PASS

    def test_allow_all_fails(self, full_audit_data):
        self._mk(full_audit_data, {"accessLevel": "ALLOW_ALL", "allowAllInternalApps": False})
        assert eq.check_scuba_marketplace_allowlist(full_audit_data).status == Status.FAIL

    def test_internal_bypass_fails_where_cis_passes(self, full_audit_data):
        from gws_auditor.checks.apps_marketplace import check_marketplace_restriction
        self._mk(full_audit_data, {"accessLevel": "ALLOW_LISTED_APPS", "allowAllInternalApps": True})
        result = eq.check_scuba_marketplace_allowlist(full_audit_data)
        assert result.status == Status.FAIL and "allowAllInternalApps=True" in str(result.actual_value)
        assert check_marketplace_restriction(full_audit_data).status == Status.PASS

    def test_absent_internal_flag_uses_documented_default(self, full_audit_data):
        # Google documents allowAllInternalApps as false by default (google_defaults.py), so an
        # allowlist entry without the flag passes with the provenance note.
        self._mk(full_audit_data, {"accessLevel": "ALLOW_LISTED_APPS"})
        result = eq.check_scuba_marketplace_allowlist(full_audit_data)
        assert result.status == Status.PASS and "Google default" in result.details

    def test_unspecified_access_level_is_manual(self, full_audit_data):
        self._mk(full_audit_data, {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED", "allowAllInternalApps": False})
        assert eq.check_scuba_marketplace_allowlist(full_audit_data).status == Status.MANUAL

    def test_not_returned_is_manual(self, full_audit_data):
        full_audit_data["policies"]["marketplace"] = {}
        assert eq.check_scuba_marketplace_allowlist(full_audit_data).status == Status.MANUAL


class TestPasswordSubControls:
    def _pw(self, full_audit_data, value):
        full_audit_data["policies"]["security"] = _ou("security", "password", value)

    def test_length_12(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_password_length_12
        self._pw(full_audit_data, {"minimumLength": 12})
        assert check_password_length_12(full_audit_data).status == Status.PASS
        self._pw(full_audit_data, {"minimumLength": 8})
        assert check_password_length_12(full_audit_data).status == Status.FAIL

    def test_enforce_at_login(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_password_enforce_at_login
        self._pw(full_audit_data, {"enforceRequirementsAtLogin": True})
        assert check_password_enforce_at_login(full_audit_data).status == Status.PASS
        self._pw(full_audit_data, {"enforceRequirementsAtLogin": False})
        assert check_password_enforce_at_login(full_audit_data).status == Status.FAIL

    def test_length_ok_but_weak_strength_passes_52_and_fails_cis(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_password_length_12
        from gws_auditor.checks.security_auth import check_password_policy
        self._pw(full_audit_data, {"minimumLength": 12, "allowedStrength": "WEAK", "enforceRequirementsAtLogin": True})
        assert check_password_length_12(full_audit_data).status == Status.PASS
        assert check_password_policy(full_audit_data).status == Status.FAIL


class TestCisReviewControls:
    def test_dashboard_and_health_are_manual_and_unscored(self, full_audit_data):
        from gws_auditor.checks.reporting import check_security_dashboard_reviewed, check_security_health_reviewed
        meta = _by_id()
        for func, check_id in ((check_security_dashboard_reviewed, "CIS-4.3.1"), (check_security_health_reviewed, "CIS-4.3.2")):
            result = func(full_audit_data)
            assert result.status == Status.MANUAL and result.check_id == check_id
            assert meta[check_id].scored is False and meta[check_id].nist_sp800_53
