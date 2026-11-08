"""Tests for Gmail security checks."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_dns_domain, make_ou_policy


class TestDNSChecks:
    """Tests for CIS-3.1.3.2.x DNS-based checks."""

    def test_spf_pass_all_domains(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_spf
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(),
        }
        result = check_gmail_spf(full_audit_data)
        assert result.status == Status.PASS

    def test_spf_fail_missing_domain(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_spf
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(spf_found=False, dkim_found=False, dmarc_found=False, dmarc_policy="none", mx_uses_google=False),
        }
        result = check_gmail_spf(full_audit_data)
        assert result.status == Status.FAIL

    def test_dkim_pass_all_domains(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_dkim
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(),
        }
        result = check_gmail_dkim(full_audit_data)
        assert result.status == Status.PASS

    def test_dkim_fail_missing(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_dkim
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(spf_found=False, dkim_found=False, dmarc_found=False, dmarc_policy="none", mx_uses_google=False),
        }
        result = check_gmail_dkim(full_audit_data)
        assert result.status == Status.FAIL

    def test_dmarc_pass_all_domains(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_dmarc
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(),
        }
        result = check_gmail_dmarc(full_audit_data)
        assert result.status == Status.PASS

    def test_dmarc_fail_missing(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_dmarc
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(),
            "example.org": make_dns_domain(spf_found=False, dkim_found=False, dmarc_found=False, dmarc_policy="none", mx_uses_google=False),
        }
        result = check_gmail_dmarc(full_audit_data)
        assert result.status == Status.FAIL


class TestGmailPolicies:
    """Tests for Gmail policy-based checks."""

    def test_delegation_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"mail_delegation_enabled": False},
        }
        result = check_gmail_mail_delegation(full_audit_data)
        assert result.status == Status.PASS

    def test_delegation_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"mail_delegation_enabled": True},
        }
        result = check_gmail_mail_delegation(full_audit_data)
        assert result.status == Status.FAIL

    def test_auto_forwarding_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        full_audit_data["policies"]["gmail"] = {
            "routing": {"auto_forwarding_enabled": False},
        }
        result = check_gmail_auto_forwarding(full_audit_data)
        assert result.status == Status.PASS

    def test_pop_imap_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "end_user_access": {"pop_enabled": False, "imap_enabled": False},
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.PASS

    def test_tls_required_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_tls_enforcement
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"tls_required": True},
        }
        result = check_gmail_tls_enforcement(full_audit_data)
        assert result.status == Status.PASS


class TestGmailOffline:
    """Tests for CIS-3.1.3.1.2 offline Gmail check."""

    def test_offline_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_offline
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"offline_access_enabled": False},
        }
        result = check_gmail_offline(full_audit_data)
        assert result.status == Status.PASS

    def test_offline_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_offline
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"offline_access_enabled": True},
        }
        result = check_gmail_offline(full_audit_data)
        assert result.status == Status.FAIL


class TestQuarantineNotifications:
    """Tests for CIS-3.1.3.3.1 quarantine admin notifications check."""

    def test_quarantine_notifications_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_quarantine_notifications
        full_audit_data["policies"]["gmail"] = {
            "quarantine": {"admin_notifications_enabled": True},
        }
        result = check_gmail_quarantine_notifications(full_audit_data)
        assert result.status == Status.PASS

    def test_quarantine_notifications_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_quarantine_notifications
        full_audit_data["policies"]["gmail"] = {
            "quarantine": {"admin_notifications_enabled": False},
        }
        result = check_gmail_quarantine_notifications(full_audit_data)
        assert result.status == Status.FAIL


class TestEncryptedAttachment:
    """Tests for CIS-3.1.3.4.1.1 encrypted attachment protection check."""

    def test_encrypted_attachment_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"encrypted_attachment_protection": True}},
        }
        result = check_gmail_encrypted_attachment(full_audit_data)
        assert result.status == Status.PASS

    def test_encrypted_attachment_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"encrypted_attachment_protection": False}},
        }
        result = check_gmail_encrypted_attachment(full_audit_data)
        assert result.status == Status.FAIL


class TestScriptAttachment:
    """Tests for CIS-3.1.3.4.1.2 script attachment protection check."""

    def test_script_attachment_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_script_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"script_attachment_protection": True}},
        }
        result = check_gmail_script_attachment(full_audit_data)
        assert result.status == Status.PASS

    def test_script_attachment_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_script_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"script_attachment_protection": False}},
        }
        result = check_gmail_script_attachment(full_audit_data)
        assert result.status == Status.FAIL


class TestAnomalousAttachment:
    """Tests for CIS-3.1.3.4.1.3 anomalous attachment protection check."""

    def test_anomalous_attachment_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_anomalous_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"anomalous_attachment_protection": True}},
        }
        result = check_gmail_anomalous_attachment(full_audit_data)
        assert result.status == Status.PASS

    def test_anomalous_attachment_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_anomalous_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"anomalous_attachment_protection": False}},
        }
        result = check_gmail_anomalous_attachment(full_audit_data)
        assert result.status == Status.FAIL


class TestShortenedUrls:
    """Tests for CIS-3.1.3.4.2.1 shortened URL scanning check."""

    def test_shortened_urls_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_shortened_urls
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"scan_shortened_urls": True}},
        }
        result = check_gmail_shortened_urls(full_audit_data)
        assert result.status == Status.PASS

    def test_shortened_urls_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_shortened_urls
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"scan_shortened_urls": False}},
        }
        result = check_gmail_shortened_urls(full_audit_data)
        assert result.status == Status.FAIL


class TestLinkedImageScanning:
    """Tests for CIS-3.1.3.4.2.2 linked image scanning check."""

    def test_linked_image_scanning_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_linked_image_scanning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"scan_linked_images": True}},
        }
        result = check_gmail_linked_image_scanning(full_audit_data)
        assert result.status == Status.PASS

    def test_linked_image_scanning_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_linked_image_scanning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"scan_linked_images": False}},
        }
        result = check_gmail_linked_image_scanning(full_audit_data)
        assert result.status == Status.FAIL


class TestUntrustedLinkWarning:
    """Tests for CIS-3.1.3.4.2.3 untrusted link warning check."""

    def test_untrusted_link_warning_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_untrusted_link_warning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"show_warning_for_untrusted_links": True}},
        }
        result = check_gmail_untrusted_link_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_untrusted_link_warning_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_untrusted_link_warning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"links": {"show_warning_for_untrusted_links": False}},
        }
        result = check_gmail_untrusted_link_warning(full_audit_data)
        assert result.status == Status.FAIL


class TestDomainSpoofing:
    """Tests for CIS-3.1.3.4.3.1 domain spoofing protection check."""

    def test_domain_spoofing_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_domain_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"domain_spoofing_protection": True}},
        }
        result = check_gmail_domain_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_domain_spoofing_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_domain_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"domain_spoofing_protection": False}},
        }
        result = check_gmail_domain_spoofing(full_audit_data)
        assert result.status == Status.FAIL


class TestEmployeeSpoofing:
    """Tests for CIS-3.1.3.4.3.2 employee name spoofing protection check."""

    def test_employee_spoofing_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_employee_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"employee_name_spoofing_protection": True}},
        }
        result = check_gmail_employee_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_employee_spoofing_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_employee_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"employee_name_spoofing_protection": False}},
        }
        result = check_gmail_employee_spoofing(full_audit_data)
        assert result.status == Status.FAIL


class TestInboundSpoofing:
    """Tests for CIS-3.1.3.4.3.3 inbound domain spoofing protection check."""

    def test_inbound_spoofing_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_inbound_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"inbound_domain_spoofing_protection": True}},
        }
        result = check_gmail_inbound_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_inbound_spoofing_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_inbound_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"inbound_domain_spoofing_protection": False}},
        }
        result = check_gmail_inbound_spoofing(full_audit_data)
        assert result.status == Status.FAIL


class TestUnauthenticatedEmail:
    """Tests for CIS-3.1.3.4.3.4 unauthenticated email protection check."""

    def test_unauthenticated_email_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_unauthenticated_email
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"unauthenticated_email_protection": True}},
        }
        result = check_gmail_unauthenticated_email(full_audit_data)
        assert result.status == Status.PASS

    def test_unauthenticated_email_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_unauthenticated_email
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"unauthenticated_email_protection": False}},
        }
        result = check_gmail_unauthenticated_email(full_audit_data)
        assert result.status == Status.FAIL


class TestGroupsSpoofing:
    """Tests for CIS-3.1.3.4.3.5 Groups inbound spoofing protection check."""

    def test_groups_spoofing_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_groups_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"groups_spoofing_protection": True}},
        }
        result = check_gmail_groups_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_groups_spoofing_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_groups_spoofing
        full_audit_data["policies"]["gmail"] = {
            "safety": {"spoofing": {"groups_spoofing_protection": False}},
        }
        result = check_gmail_groups_spoofing(full_audit_data)
        assert result.status == Status.FAIL


class TestOutboundGateway:
    """Tests for CIS-3.1.3.5.3 per-user outbound gateway check."""

    def test_outbound_gateway_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_outbound_gateway
        full_audit_data["policies"]["gmail"] = {
            "routing": {"per_user_outbound_gateway_enabled": False},
        }
        result = check_gmail_outbound_gateway(full_audit_data)
        assert result.status == Status.PASS

    def test_outbound_gateway_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_outbound_gateway
        full_audit_data["policies"]["gmail"] = {
            "routing": {"per_user_outbound_gateway_enabled": True},
        }
        result = check_gmail_outbound_gateway(full_audit_data)
        assert result.status == Status.FAIL


class TestExternalRecipientWarning:
    """Tests for CIS-3.1.3.5.4 external recipient warning check."""

    def test_external_recipient_warning_from_policy_api(self, full_audit_data):
        """gmail.external_recipient_warning.enabled, seen live 2026-11-07; documented default enabled=true."""
        from gws_auditor.checks.apps_gmail import check_gmail_external_recipient_warning
        from tests.factories import make_ou_policy
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "external_recipient_warning", {"enabled": True})]}
        assert check_gmail_external_recipient_warning(full_audit_data).status == Status.PASS
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "external_recipient_warning", {"enabled": False})]}
        assert check_gmail_external_recipient_warning(full_audit_data).status == Status.FAIL
        # absent with other gmail settings present -> Google's documented default (enabled) is injected
        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "mail_delegation", {"enableMailDelegation": False})]}
        result = check_gmail_external_recipient_warning(full_audit_data)
        assert result.status == Status.PASS and "default" in result.details.lower()

    def test_external_recipient_warning_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_external_recipient_warning
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"external_recipient_warning_enabled": True},
        }
        result = check_gmail_external_recipient_warning(full_audit_data)
        assert result.status == Status.PASS

    def test_external_recipient_warning_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_external_recipient_warning
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"external_recipient_warning_enabled": False},
        }
        result = check_gmail_external_recipient_warning(full_audit_data)
        assert result.status == Status.FAIL


class TestPredeliveryScanning:
    """Tests for CIS-3.1.3.6.1 enhanced pre-delivery scanning check."""

    def test_predelivery_scanning_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_predelivery_scanning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"enhanced_predelivery_scanning": True},
        }
        result = check_gmail_predelivery_scanning(full_audit_data)
        assert result.status == Status.PASS

    def test_predelivery_scanning_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_predelivery_scanning
        full_audit_data["policies"]["gmail"] = {
            "safety": {"enhanced_predelivery_scanning": False},
        }
        result = check_gmail_predelivery_scanning(full_audit_data)
        assert result.status == Status.FAIL


# ---------------------------------------------------------------------------
# OU-aware tests
# ---------------------------------------------------------------------------


class TestGmailEncryptedAttachmentOU:
    """OU-aware tests for CIS-3.1.3.4.1.1 encrypted attachment protection."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_attachment_safety",
                                {"enableEncryptedAttachmentProtection": True}, "/"),
                make_ou_policy("gmail", "email_attachment_safety",
                                {"enableEncryptedAttachmentProtection": True}, "/Engineering"),
            ],
        }
        result = check_gmail_encrypted_attachment(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "email_attachment_safety",
                                {"enableEncryptedAttachmentProtection": True}, "/"),
                make_ou_policy("gmail", "email_attachment_safety",
                                {"enableEncryptedAttachmentProtection": False}, "/Sales"),
            ],
        }
        result = check_gmail_encrypted_attachment(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sales" in result.details

    def test_fallback_when_no_ou_data(self, full_audit_data):
        """Without _ou_policies the check uses the mapped fallback path."""
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        full_audit_data["policies"]["gmail"] = {
            "safety": {"attachments": {"encrypted_attachment_protection": True}},
        }
        result = check_gmail_encrypted_attachment(full_audit_data)
        assert result.status == Status.PASS


class TestGmailMailDelegationOU:
    """OU-aware tests for CIS-3.1.3.1.1 mail delegation."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "mail_delegation",
                                {"enableMailDelegation": False}, "/"),
                make_ou_policy("gmail", "mail_delegation",
                                {"enableMailDelegation": False}, "/Finance"),
            ],
        }
        result = check_gmail_mail_delegation(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "mail_delegation",
                                {"enableMailDelegation": False}, "/"),
                make_ou_policy("gmail", "mail_delegation",
                                {"enableMailDelegation": True}, "/Contractors"),
            ],
        }
        result = check_gmail_mail_delegation(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Contractors" in result.details

    def test_fallback_when_no_ou_data(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        full_audit_data["policies"]["gmail"] = {
            "user_settings": {"mail_delegation_enabled": False},
        }
        result = check_gmail_mail_delegation(full_audit_data)
        assert result.status == Status.PASS


class TestGmailAutoForwardingOU:
    """OU-aware tests for CIS-3.1.3.5.2 auto-forwarding."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "auto_forwarding",
                                {"enableAutoForwarding": False}, "/"),
                make_ou_policy("gmail", "auto_forwarding",
                                {"enableAutoForwarding": False}, "/HR"),
            ],
        }
        result = check_gmail_auto_forwarding(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "auto_forwarding",
                                {"enableAutoForwarding": False}, "/"),
                make_ou_policy("gmail", "auto_forwarding",
                                {"enableAutoForwarding": True}, "/Temp"),
            ],
        }
        result = check_gmail_auto_forwarding(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Temp" in result.details


class TestGmailPopImapOU:
    """OU-aware tests for CIS-3.1.3.5.1 POP/IMAP access."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "pop_access",
                                {"enablePop3Access": False}, "/"),
                make_ou_policy("gmail", "pop_access",
                                {"enablePop3Access": False}, "/Dev"),
                make_ou_policy("gmail", "imap_access",
                                {"enableImapAccess": False}, "/"),
                make_ou_policy("gmail", "imap_access",
                                {"enableImapAccess": False}, "/Dev"),
            ],
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_imap_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "pop_access",
                                {"enablePop3Access": False}, "/"),
                make_ou_policy("gmail", "pop_access",
                                {"enablePop3Access": False}, "/Legacy"),
                make_ou_policy("gmail", "imap_access",
                                {"enableImapAccess": False}, "/"),
                make_ou_policy("gmail", "imap_access",
                                {"enableImapAccess": True}, "/Legacy"),
            ],
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details

    def test_child_ou_pop_enabled(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "pop_access",
                                {"enablePop3Access": True}, "/OldDept"),
                make_ou_policy("gmail", "imap_access",
                                {"enableImapAccess": False}, "/OldDept"),
            ],
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.FAIL
        assert "/OldDept" in result.details


class TestGmailPredeliveryScanningOU:
    """OU-aware tests for CIS-3.1.3.6.1 enhanced pre-delivery scanning."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_predelivery_scanning
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "enhanced_pre_delivery_message_scanning",
                                {"enableImprovedSuspiciousContentDetection": True}, "/"),
                make_ou_policy("gmail", "enhanced_pre_delivery_message_scanning",
                                {"enableImprovedSuspiciousContentDetection": True}, "/Marketing"),
            ],
        }
        result = check_gmail_predelivery_scanning(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_predelivery_scanning
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "enhanced_pre_delivery_message_scanning",
                                {"enableImprovedSuspiciousContentDetection": True}, "/"),
                make_ou_policy("gmail", "enhanced_pre_delivery_message_scanning",
                                {"enableImprovedSuspiciousContentDetection": False}, "/External"),
            ],
        }
        result = check_gmail_predelivery_scanning(full_audit_data)
        assert result.status == Status.FAIL
        assert "/External" in result.details


class TestGmailComprehensiveStorageOU:
    """OU-aware tests for CIS-3.1.3.7.1 comprehensive mail storage.

    The real API shape carries only ruleId (see TestGmailUnknownValues); these
    tests exercise the legacy enableComprehensiveMailStorage alias, the only
    way a PASS/FAIL verdict can be reached.
    """

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "comprehensive_mail_storage",
                                {"enableComprehensiveMailStorage": True}, "/"),
            ],
        }
        result = check_gmail_comprehensive_storage(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "comprehensive_mail_storage",
                                {"enableComprehensiveMailStorage": True}, "/"),
                make_ou_policy("gmail", "comprehensive_mail_storage",
                                {"enableComprehensiveMailStorage": False}, "/Sandbox"),
            ],
        }
        result = check_gmail_comprehensive_storage(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Sandbox" in result.details


class TestGmailOutboundGatewayOU:
    """OU-aware tests for CIS-3.1.3.5.3 per-user outbound gateways."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_outbound_gateway
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "per_user_outbound_gateway",
                                {"allowUsersToUseExternalSmtpServers": False}, "/"),
                make_ou_policy("gmail", "per_user_outbound_gateway",
                                {"allowUsersToUseExternalSmtpServers": False}, "/Ops"),
            ],
        }
        result = check_gmail_outbound_gateway(full_audit_data)
        assert result.status == Status.PASS

    def test_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_outbound_gateway
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "per_user_outbound_gateway",
                                {"allowUsersToUseExternalSmtpServers": False}, "/"),
                make_ou_policy("gmail", "per_user_outbound_gateway",
                                {"allowUsersToUseExternalSmtpServers": True}, "/SpecialTeam"),
            ],
        }
        result = check_gmail_outbound_gateway(full_audit_data)
        assert result.status == Status.FAIL
        assert "/SpecialTeam" in result.details


class TestGmailSpoofingOU:
    """OU-aware tests for CIS-3.1.3.4.3.x spoofing protection checks."""

    def test_domain_spoofing_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_domain_spoofing
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spoofing_and_authentication",
                                {"detectDomainNameSpoofing": True}, "/"),
                make_ou_policy("gmail", "spoofing_and_authentication",
                                {"detectDomainNameSpoofing": True}, "/Research"),
            ],
        }
        result = check_gmail_domain_spoofing(full_audit_data)
        assert result.status == Status.PASS

    def test_domain_spoofing_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_domain_spoofing
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "spoofing_and_authentication",
                                {"detectDomainNameSpoofing": True}, "/"),
                make_ou_policy("gmail", "spoofing_and_authentication",
                                {"detectDomainNameSpoofing": False}, "/TestLab"),
            ],
        }
        result = check_gmail_domain_spoofing(full_audit_data)
        assert result.status == Status.FAIL
        assert "/TestLab" in result.details


class TestGmailLinksOU:
    """OU-aware tests for CIS-3.1.3.4.2.x links and external images checks."""

    def test_shortened_urls_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_shortened_urls
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "links_and_external_images",
                                {"enableShortenerScanning": True}, "/"),
            ],
        }
        result = check_gmail_shortened_urls(full_audit_data)
        assert result.status == Status.PASS

    def test_shortened_urls_child_ou_unsafe(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_shortened_urls
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "links_and_external_images",
                                {"enableShortenerScanning": True}, "/"),
                make_ou_policy("gmail", "links_and_external_images",
                                {"enableShortenerScanning": False}, "/Partners"),
            ],
        }
        result = check_gmail_shortened_urls(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Partners" in result.details


# -----------------------------------------------------------------------
# Unknown-aware OU verdicts (real Policy API field names only)
# -----------------------------------------------------------------------


def _gmail_ou(full_audit_data, key, *entries):
    """Install ADMIN per-OU entries for one gmail setting key."""
    full_audit_data["policies"]["gmail"] = {
        "_ou_policies": [make_ou_policy("gmail", key, value, ou) for value, ou in entries],
    }
    return full_audit_data


class TestGmailUnknownValues:
    """Absent fields without a documented default and *_UNSPECIFIED are MANUAL, not PASS/FAIL."""

    def test_attachment_empty_value_is_manual(self, full_audit_data):
        # Was FAIL: an empty ADMIN value says nothing about the setting.
        from gws_auditor.checks.apps_gmail import check_gmail_encrypted_attachment
        result = check_gmail_encrypted_attachment(_gmail_ou(full_audit_data, "email_attachment_safety", ({}, "/")))
        assert result.status == Status.MANUAL
        assert "/" in result.details

    def test_attachment_unknown_plus_unsafe_is_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_script_attachment
        result = check_gmail_script_attachment(_gmail_ou(
            full_audit_data, "email_attachment_safety",
            ({}, "/"), ({"enableAttachmentWithScriptsProtection": False}, "/Sales")))
        assert result.status == Status.FAIL
        assert "/Sales" in result.details
        assert "Undetermined" in result.details

    def test_spoofing_empty_value_is_manual(self, full_audit_data):
        # Was FAIL: detectDomainNameSpoofing has no documented default.
        from gws_auditor.checks.apps_gmail import check_gmail_domain_spoofing
        result = check_gmail_domain_spoofing(_gmail_ou(
            full_audit_data, "spoofing_and_authentication", ({"applyFutureSettingsAutomatically": True}, "/")))
        assert result.status == Status.MANUAL

    def test_shortener_empty_value_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_shortened_urls
        result = check_gmail_shortened_urls(_gmail_ou(full_audit_data, "links_and_external_images", ({}, "/")))
        assert result.status == Status.MANUAL

    def test_untrusted_links_documented_default_is_fail(self, full_audit_data):
        # Google documents enableAggressiveWarningsOnUntrustedLinks=false, so absent -> FAIL.
        from gws_auditor.checks.apps_gmail import check_gmail_untrusted_link_warning
        result = check_gmail_untrusted_link_warning(_gmail_ou(full_audit_data, "links_and_external_images", ({}, "/")))
        assert result.status == Status.FAIL

    def test_mail_delegation_documented_default_is_pass(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_mail_delegation
        result = check_gmail_mail_delegation(_gmail_ou(full_audit_data, "mail_delegation", ({}, "/")))
        assert result.status == Status.PASS

    def test_auto_forwarding_documented_default_is_fail(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_auto_forwarding
        result = check_gmail_auto_forwarding(_gmail_ou(full_audit_data, "auto_forwarding", ({}, "/")))
        assert result.status == Status.FAIL

    def test_outbound_gateway_documented_default_is_pass(self, full_audit_data):
        # Admin Help: "By default, users cannot use an outbound gateway."
        from gws_auditor.checks.apps_gmail import check_gmail_outbound_gateway
        result = check_gmail_outbound_gateway(_gmail_ou(full_audit_data, "per_user_outbound_gateway", ({}, "/")))
        assert result.status == Status.PASS

    def test_predelivery_empty_value_is_manual(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_predelivery_scanning
        result = check_gmail_predelivery_scanning(_gmail_ou(
            full_audit_data, "enhanced_pre_delivery_message_scanning", ({}, "/")))
        assert result.status == Status.MANUAL

    def test_pop_imap_one_protocol_unknown_is_manual(self, full_audit_data):
        # Was PASS: IMAP state unknown for "/" must not be read as disabled.
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "pop_access", {"enablePopAccess": False}, "/"),
                make_ou_policy("gmail", "imap_access", {"imapAccessRestriction": "ANY_CLIENT"}, "/"),
            ],
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.MANUAL

    def test_pop_enabled_wins_over_unknown_imap(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_pop_imap
        full_audit_data["policies"]["gmail"] = {
            "_ou_policies": [
                make_ou_policy("gmail", "pop_access", {"enablePopAccess": True}, "/Legacy"),
            ],
        }
        result = check_gmail_pop_imap(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Legacy" in result.details
        assert "POP=True" in result.actual_value

    def test_comprehensive_storage_real_shape_is_manual(self, full_audit_data):
        # The API returns only ruleId for this setting: no enabled flag -> MANUAL with guidance.
        from gws_auditor.checks.apps_gmail import check_gmail_comprehensive_storage
        result = check_gmail_comprehensive_storage(_gmail_ou(
            full_audit_data, "comprehensive_mail_storage", ({"ruleId": "rule-1"}, "/")))
        assert result.status == Status.MANUAL
        assert "does not expose whether it is enabled" in result.details
