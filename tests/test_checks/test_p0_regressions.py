"""Regression tests for wrong-status bugs reproduced during the check-correctness review.

Each test pins a verdict that was wrong before the fix. See docs/check-correctness-test-plan.md
section 1 and docs/check-test-matrix.md for the per-check context.
"""

import pytest

from gws_auditor.models import Status
from tests.factories import make_dns_domain, make_log_entry, make_ou_policy, make_user


def _ou(data, category, setting_key, value, org_unit="/"):
    data["policies"][category] = {"_ou_policies": [make_ou_policy(category, setting_key, value, org_unit)]}


class TestSuperAdminUsage:
    """CIS-1.1.3 read actor.email but normalized login_logs carry actor_email."""

    def test_heavy_super_admin_login_warns(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_usage

        full_audit_data["login_logs"] = [
            make_log_entry(event_name="login_success", event_type="login", actor_email="admin1@example.com")
            for _ in range(11)
        ]
        result = check_super_admin_usage(full_audit_data)
        assert result.status == Status.WARN
        assert "admin1@example.com (11 logins)" in result.actual_value

    def test_ten_logins_is_the_boundary(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_usage

        full_audit_data["login_logs"] = [
            make_log_entry(event_name="login_success", event_type="login", actor_email="admin1@example.com")
            for _ in range(10)
        ]
        assert check_super_admin_usage(full_audit_data).status == Status.MANUAL

    def test_failed_logins_do_not_count(self, full_audit_data):
        from gws_auditor.checks.directory import check_super_admin_usage

        full_audit_data["login_logs"] = [
            make_log_entry(event_name="login_failure", event_type="login", actor_email="admin1@example.com")
            for _ in range(30)
        ]
        assert check_super_admin_usage(full_audit_data).status == Status.MANUAL


class TestDmarcWithoutRecord:
    """GWS.GMAIL.4.3 / 4.4 passed a tenant that has no DMARC record at all."""

    def test_no_dmarc_is_not_strict(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_strict_alignment

        full_audit_data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        full_audit_data["dns_records"] = {"example.com": make_dns_domain(dmarc_found=False, dmarc_policy="none")}
        result = check_dmarc_strict_alignment(full_audit_data)
        assert result.status == Status.WARN
        assert "no DMARC record" in result.details

    def test_no_dmarc_is_not_reporting(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_reporting

        full_audit_data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        full_audit_data["dns_records"] = {"example.com": make_dns_domain(dmarc_found=False, dmarc_policy="none")}
        assert check_dmarc_reporting(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("record", ["v=DMARC1; p=reject; ASPF=R", "v=DMARC1; p=reject; aspf = r"])
    def test_relaxed_tag_is_case_and_space_insensitive(self, full_audit_data, record):
        from gws_auditor.checks.cisa_scuba import check_dmarc_strict_alignment

        full_audit_data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        full_audit_data["dns_records"] = {"example.com": make_dns_domain(dmarc_record=record)}
        assert check_dmarc_strict_alignment(full_audit_data).status == Status.WARN

    def test_uppercase_rua_is_reporting(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_dmarc_reporting

        full_audit_data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        full_audit_data["dns_records"] = {
            "example.com": make_dns_domain(dmarc_record="v=DMARC1; p=reject; RUA=mailto:d@example.com")}
        assert check_dmarc_reporting(full_audit_data).status == Status.PASS


class TestPasswordStrength:
    """CIS-4.1.5.1 never read allowedStrength, so WEAK passed."""

    _BASE = {"minimumLength": 12, "maximumLength": 100, "enforceRequirementsAtLogin": True,
             "allowReuse": False, "expirationDuration": "0s"}

    def test_weak_strength_fails(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy

        _ou(full_audit_data, "security", "password", {**self._BASE, "allowedStrength": "WEAK"})
        result = check_password_policy(full_audit_data)
        assert result.status == Status.FAIL
        assert "strength=WEAK" in result.actual_value

    def test_strong_passes(self, full_audit_data):
        from gws_auditor.checks.security_auth import check_password_policy

        _ou(full_audit_data, "security", "password", {**self._BASE, "allowedStrength": "STRONG"})
        assert check_password_policy(full_audit_data).status == Status.PASS

    @pytest.mark.parametrize("length, status", [("11", Status.FAIL), ("12", Status.PASS), (11, Status.FAIL)])
    def test_minimum_length_boundary_and_string_values(self, full_audit_data, length, status):
        from gws_auditor.checks.security_auth import check_password_policy

        _ou(full_audit_data, "security", "password",
            {**self._BASE, "allowedStrength": "STRONG", "minimumLength": length})
        assert check_password_policy(full_audit_data).status == status


class TestSessionDurationBoundary:
    """GWS.COMMONCONTROLS.4.1 floored 12.5 h to 12 h and passed it."""

    @pytest.mark.parametrize("duration, status", [
        ("43200s", Status.PASS),   # exactly 12 h
        ("45000s", Status.FAIL),   # 12.5 h
        ("43201s", Status.FAIL),
        ("1209600s", Status.FAIL),
    ])
    def test_web_session_duration(self, full_audit_data, duration, status):
        from gws_auditor.checks.cisa_commoncontrols import check_session_duration

        full_audit_data["subscription_type"] = "Enterprise Standard"
        _ou(full_audit_data, "security", "session_controls", {"webSessionDuration": duration})
        assert check_session_duration(full_audit_data).status == status


class TestAdminPrivilegeAlertRule:
    """CIS-6.4 matched the unrelated 'Admin privilege revoked' rule by substring."""

    def _rules(self, data, *entries):
        data["policies"]["rules"] = {"_ou_policies": [
            make_ou_policy("rule", "system_defined_alerts", {"displayName": name, "state": state})
            for name, state in entries]}

    def test_granted_active_revoked_inactive_passes(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        self._rules(full_audit_data, ("User granted Admin privilege", "ACTIVE"),
                    ("User's Admin privilege revoked", "INACTIVE"))
        assert check_alert_admin_privilege(full_audit_data).status == Status.PASS

    def test_granted_inactive_fails(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        self._rules(full_audit_data, ("User granted Admin privilege", "INACTIVE"),
                    ("User's Admin privilege revoked", "ACTIVE"))
        assert check_alert_admin_privilege(full_audit_data).status == Status.FAIL

    def test_only_revoked_rule_is_unknown(self, full_audit_data):
        from gws_auditor.checks.rules import check_alert_admin_privilege

        self._rules(full_audit_data, ("User's Admin privilege revoked", "ACTIVE"))
        assert check_alert_admin_privilege(full_audit_data).status == Status.MANUAL


class TestDriveReceiveInAllowlistMode:
    """GWS.DRIVEDOCS.1.2 read allowReceivingExternalFiles even in allowlist mode."""

    def test_allowlist_mode_blocking_outside_allowlist_passes(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        _ou(full_audit_data, "drive", "external_sharing", {
            "externalSharingMode": "ALLOWLISTED_DOMAINS",
            "allowReceivingExternalFiles": True,
            "allowReceivingFilesOutsideAllowlistedDomains": False})
        assert check_drive_receive_non_allowlisted(full_audit_data).status == Status.PASS

    def test_allowlist_mode_allowing_outside_allowlist_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        _ou(full_audit_data, "drive", "external_sharing", {
            "externalSharingMode": "ALLOWLISTED_DOMAINS",
            "allowReceivingExternalFiles": True,
            "allowReceivingFilesOutsideAllowlistedDomains": True})
        assert check_drive_receive_non_allowlisted(full_audit_data).status == Status.FAIL

    def test_open_mode_receiving_external_fails(self, full_audit_data):
        from gws_auditor.checks.cisa_scuba import check_drive_receive_non_allowlisted

        _ou(full_audit_data, "drive", "external_sharing", {
            "externalSharingMode": "ALLOWED", "allowReceivingExternalFiles": True})
        assert check_drive_receive_non_allowlisted(full_audit_data).status == Status.FAIL


class TestFlaggedEmailActionUnknown:
    """GWS.GMAIL.5.5 failed any tenant with admin spam-override rules but default attachment safety."""

    def test_spam_override_only_is_unknown(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []})]}
        result = check_flagged_email_action(full_audit_data)
        assert result.status in (Status.MANUAL, Status.ERROR)

    def test_consequence_fields_still_decide(self, full_audit_data):
        from gws_auditor.checks.cisa_services import check_flagged_email_action

        full_audit_data["policies"]["gmail"] = {"_ou_policies": [
            make_ou_policy("gmail", "spam_override_lists", {"spamOverride": []}),
            make_ou_policy("gmail", "email_attachment_safety", {
                "encryptedAttachmentProtectionConsequence": "WARNING",
                "attachmentWithScriptsProtectionConsequence": "SPAM_FOLDER",
                "anomalousAttachmentProtectionConsequence": "QUARANTINE"})]}
        result = check_flagged_email_action(full_audit_data)
        assert result.status == Status.FAIL
        assert "encryptedAttachmentProtectionConsequence=WARNING" in result.actual_value


class TestMxHostMatching:
    """ADD-05 matched 'google.com' as a substring, so mx.notgoogle.com passed."""

    def _dns(self, data, host):
        data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        data["dns_records"] = {"example.com": {"mx": {"records": [{"host": host}], "uses_google": None}}}

    @pytest.mark.parametrize("host", ["mx.notgoogle.com", "aspmx.l.google.com.attacker.io", "mail.example.com"])
    def test_non_google_host_fails(self, full_audit_data, host):
        from gws_auditor.checks.additional import check_mx_records

        self._dns(full_audit_data, host)
        assert check_mx_records(full_audit_data).status == Status.FAIL

    @pytest.mark.parametrize("host", ["aspmx.l.google.com", "ASPMX.L.GOOGLE.COM.", "smtp.google.com",
                                      "alt1.aspmx.l.googlemail.com"])
    def test_google_host_passes(self, full_audit_data, host):
        from gws_auditor.checks.additional import check_mx_records

        self._dns(full_audit_data, host)
        assert check_mx_records(full_audit_data).status == Status.PASS

    def test_factory_default_dns_fixture_passes(self, full_audit_data):
        """tests/factories.make_dns_domain used an 'exchange' key the check never read."""
        from gws_auditor.checks.additional import check_mx_records

        full_audit_data["domains"] = [{"domainName": "example.com", "isPrimary": True}]
        full_audit_data["dns_records"] = {"example.com": make_dns_domain(mx_uses_google=True)}
        assert check_mx_records(full_audit_data).status == Status.PASS


class TestThirdPartyAppAccessEnums:
    """Flip test on the live tenant (2026-11-01): setting the console to "Don't allow users to access
    any third-party apps" made the API return the documented ``BLOCK_ALL``; the checks only knew the
    older ``BLOCK_ALL_SCOPES`` and reported FAIL on a securely configured tenant. The console labels the
    permissive option "(Default) ..." and the ADMIN policy then carries ``ACCESS_LEVEL_UNSPECIFIED``."""

    def _data(self, full_audit_data, admin_level, with_system=True):
        entries = []
        if with_system:
            sysp = make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                  {"accessLevel": "ACCESS_LEVEL_UNSPECIFIED",
                                   "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"})
            sysp["_raw"] = {"type": "SYSTEM", "policyQuery": {"sortOrder": 100.00001}}
            entries.append(sysp)
        if admin_level is not None:
            adm = make_ou_policy("api_controls", "unconfigured_third_party_apps",
                                 {"accessLevel": admin_level,
                                  "accessLevelUnder18": "ACCESS_LEVEL_UNDER18_UNSPECIFIED"})
            adm["_raw"] = {"type": "ADMIN", "policyQuery": {"sortOrder": 201.00336}}
            entries.append(adm)
        full_audit_data["policies"]["security"] = {}
        full_audit_data["policies"]["access_control"] = {}
        full_audit_data["policies"]["api_controls"] = {"_ou_policies": entries}
        full_audit_data["token_logs"] = [{"app_name": "Some App", "client_id": "1"}]
        return full_audit_data

    @pytest.mark.parametrize("level", ["BLOCK_ALL", "BLOCK_ALL_SCOPES"])
    def test_block_all_passes_everywhere(self, full_audit_data, level):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_third_party_api_restricted, check_unconfigured_third_party_apps)
        from gws_auditor.checks.security_access import check_third_party_app_access

        d = self._data(full_audit_data, level)
        assert check_third_party_app_access(d).status == Status.PASS
        assert check_third_party_api_restricted(d).status == Status.PASS
        assert check_unconfigured_third_party_apps(d).status == Status.PASS

    def test_sign_in_only_still_allows_unconfigured_apps(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import check_unconfigured_third_party_apps
        from gws_auditor.checks.security_access import check_third_party_app_access

        d = self._data(full_audit_data, "ALLOW_SIGN_IN_ONLY")
        assert check_third_party_app_access(d).status == Status.PASS
        assert check_unconfigured_third_party_apps(d).status == Status.FAIL

    def test_admin_unspecified_is_the_permissive_default(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_third_party_api_restricted, check_unconfigured_third_party_apps)
        from gws_auditor.checks.security_access import check_third_party_app_access, check_third_party_app_review

        d = self._data(full_audit_data, "ACCESS_LEVEL_UNSPECIFIED")
        for fn in (check_third_party_app_access, check_third_party_api_restricted, check_unconfigured_third_party_apps):
            result = fn(d)
            assert result.status == Status.FAIL, fn.__name__
            assert "console default" in str(result.actual_value)
        assert check_third_party_app_review(d).status == Status.FAIL

    def test_system_only_unspecified_stays_unknown(self, full_audit_data):
        from gws_auditor.checks.cisa_commoncontrols import (
            check_third_party_api_restricted, check_unconfigured_third_party_apps)
        from gws_auditor.checks.security_access import check_third_party_app_access

        d = self._data(full_audit_data, None)
        for fn in (check_third_party_app_access, check_third_party_api_restricted, check_unconfigured_third_party_apps):
            assert fn(d).status == Status.MANUAL, fn.__name__


class TestMeetStrictestOptionsPass:
    """The strictest documented Meet options were judged non-compliant."""

    @pytest.mark.parametrize("audience, status", [("RESTRICTED", Status.PASS), ("TRUSTED", Status.PASS), ("OPEN", Status.FAIL)])
    def test_meet_joining_audience(self, full_audit_data, audience, status):
        from gws_auditor.checks.cisa_scuba import check_meet_external_join

        _ou(full_audit_data, "meet", "meet_joining", {"allowedAudience": audience})
        assert check_meet_external_join(full_audit_data).status == status

    @pytest.mark.parametrize("callers, status", [("NONE", Status.PASS), ("CONTACTS_AND_ORGANIZATION_ONLY", Status.PASS), ("ALL", Status.FAIL)])
    def test_meet_incoming_callers(self, full_audit_data, callers, status):
        from gws_auditor.checks.cisa_scuba import check_meet_incoming_calls

        _ou(full_audit_data, "meet", "meet_incoming_call_restrictions", {"allowedCallers": callers})
        assert check_meet_incoming_calls(full_audit_data).status == status
