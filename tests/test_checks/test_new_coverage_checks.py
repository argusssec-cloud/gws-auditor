"""Tests for cisa_additions.py and additional_identity.py (payloads use real Policy API field names)."""

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy


def _set(data, category, setting_key, value, org_unit="/"):
    data["policies"][category] = {"_ou_policies": [make_ou_policy(category, setting_key, value, org_unit)]}


def _user(email, **kw):
    base = {"primary_email": email, "suspended": False, "archived": False, "is_super_admin": False,
            "is_admin": False, "is_delegated_admin": False, "last_login_time": "2026-03-25T10:00:00.000Z"}
    return {**base, **kw}


NOW = "2026-04-01T00:00:00+00:00"


class TestScubaAdditions:
    @pytest.mark.parametrize("value, status", [("NO_FILES", Status.PASS), ("ALL_FILES", Status.FAIL), ("IMAGES_ONLY", Status.FAIL)])
    def test_chat_external_file_sharing(self, full_audit_data, value, status):
        from gws_auditor.checks.cisa_additions import check_chat_external_file_sharing

        _set(full_audit_data, "chat", "chat_file_sharing", {"externalFileSharing": value, "internalFileSharing": "ALL_FILES"})
        assert check_chat_external_file_sharing(full_audit_data).status == status

    def test_setting_not_returned_is_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_chat_external_file_sharing, check_password_reuse

        full_audit_data["policies"]["chat"] = {}
        full_audit_data["policies"]["security"] = {}
        assert check_chat_external_file_sharing(full_audit_data).status == Status.MANUAL
        assert check_password_reuse(full_audit_data).status == Status.MANUAL

    def test_spoofing_consequence(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_gmail_spoofing_consequence

        fields = ("domainSpoofingConsequence", "domainNameSpoofingConsequence", "employeeNameSpoofingConsequence",
                  "groupsSpoofingConsequence", "unauthenticatedEmailConsequence")
        _set(full_audit_data, "gmail", "spoofing_and_authentication", {f: "QUARANTINE" for f in fields})
        assert check_gmail_spoofing_consequence(full_audit_data).status == Status.PASS
        _set(full_audit_data, "gmail", "spoofing_and_authentication",
             {**{f: "SPAM_FOLDER" for f in fields}, "groupsSpoofingConsequence": "WARNING"})
        result = check_gmail_spoofing_consequence(full_audit_data)
        assert result.status == Status.FAIL and "groupsSpoofingConsequence=WARNING" in result.details

    def test_auto_apply_future_settings(self, full_audit_data):
        from gws_auditor.checks import cisa_additions as m

        for func, key, field in [(m.check_gmail_attachment_auto_apply, "email_attachment_safety", "applyFutureRecommendedSettingsAutomatically"),
                                 (m.check_gmail_links_auto_apply, "links_and_external_images", "applyFutureSettingsAutomatically"),
                                 (m.check_gmail_spoofing_auto_apply, "spoofing_and_authentication", "applyFutureSettingsAutomatically")]:
            _set(full_audit_data, "gmail", key, {field: True})
            assert func(full_audit_data).status == Status.PASS
            _set(full_audit_data, "gmail", key, {field: False})
            assert func(full_audit_data).status == Status.FAIL

    def test_phishing_resistant_mfa(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_phishing_resistant_mfa

        def policies(factor, enforced_from):
            full_audit_data["policies"]["security"] = {"_ou_policies": [
                make_ou_policy("security", "two_step_verification_enforcement_factor", {"allowedSignInFactorSet": factor}),
                make_ou_policy("security", "two_step_verification_enforcement", {"enforcedFrom": enforced_from})]}
            return check_phishing_resistant_mfa(full_audit_data).status
        assert policies("PASSKEY_ONLY", "2026-01-01T00:00:00Z") == Status.PASS
        assert policies("NO_TELEPHONY", "2026-01-01T00:00:00Z") == Status.FAIL
        assert policies("PASSKEY_ONLY", "") == Status.FAIL  # right method, but 2SV not enforced

    def test_password_controls(self, full_audit_data):
        from gws_auditor.checks import cisa_additions as m

        good = {"allowedStrength": "STRONG", "minimumLength": 15, "allowReuse": False, "expirationDuration": "0s"}
        checks = (m.check_password_strength, m.check_password_length_15, m.check_password_reuse, m.check_password_no_expiry)
        _set(full_audit_data, "security", "password", good)
        assert all(c(full_audit_data).status == Status.PASS for c in checks)
        _set(full_audit_data, "security", "password",
             {"allowedStrength": "WEAK", "minimumLength": 12, "allowReuse": True, "expirationDuration": "7776000s"})
        assert all(c(full_audit_data).status == Status.FAIL for c in checks)

    def test_forms_controls_are_manual(self, full_audit_data):
        from gws_auditor.checks.cisa_additions import check_forms_external_responses, check_forms_external_submission

        assert check_forms_external_responses(full_audit_data).status == Status.MANUAL
        assert check_forms_external_submission(full_audit_data).status == Status.MANUAL


class TestAccounts:
    def test_stale_super_admin(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_stale_super_admins

        full_audit_data["collection_timestamp"] = NOW
        full_audit_data["users"] = [_user("a@example.com", is_super_admin=True)]
        assert check_stale_super_admins(full_audit_data).status == Status.PASS
        full_audit_data["users"].append(_user("old@example.com", is_super_admin=True, last_login_time="2025-06-01T00:00:00.000Z"))
        full_audit_data["users"].append(_user("never@example.com", is_super_admin=True, last_login_time="1970-01-01T00:00:00.000Z"))
        full_audit_data["users"].append(_user("susp@example.com", is_super_admin=True, suspended=True, last_login_time="2020-01-01T00:00:00.000Z"))
        result = check_stale_super_admins(full_audit_data)
        assert result.status == Status.FAIL
        assert "old@example.com" in result.details and "never signed in" in result.details
        assert "susp@example.com" not in result.details

    def test_suspended_admin(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_suspended_admins

        full_audit_data["users"] = [_user("a@example.com", is_super_admin=True), _user("u@example.com", suspended=True)]
        assert check_suspended_admins(full_audit_data).status == Status.PASS
        full_audit_data["users"].append(_user("x@example.com", suspended=True, is_delegated_admin=True))
        assert check_suspended_admins(full_audit_data).status == Status.FAIL

    def test_stale_users_inventory_warns(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_stale_users

        full_audit_data["collection_timestamp"] = NOW
        full_audit_data["users"] = [_user("a@example.com"), _user("b@example.com", last_login_time="2025-01-01T00:00:00.000Z")]
        result = check_stale_users(full_audit_data)
        assert result.status == Status.WARN and result.scored is False

    def test_unlicensed_users(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_unlicensed_users

        full_audit_data["users"] = [_user("a@example.com"), _user("b@example.com")]
        full_audit_data["subscription_info"] = {}
        assert check_unlicensed_users(full_audit_data).status == Status.MANUAL
        full_audit_data["subscription_info"] = {"licensed_users": ["A@example.com"]}
        result = check_unlicensed_users(full_audit_data)
        assert result.status == Status.WARN and "b@example.com" in result.details and "a@example.com" not in result.details


class TestChatGroupsDevices:
    @pytest.mark.parametrize("value, status", [({"enabled": False}, Status.PASS),
                                               ({"enabled": True, "domainAllowlistMode": "ALL_DOMAINS"}, Status.FAIL),
                                               ({"enabled": True, "domainAllowlistMode": "TRUSTED_DOMAINS"}, Status.PASS)])
    def test_chat_external_spaces(self, full_audit_data, value, status):
        from gws_auditor.checks.additional_identity import check_chat_external_spaces

        _set(full_audit_data, "chat", "chat_external_spaces", value)
        assert check_chat_external_spaces(full_audit_data).status == status

    def test_open_groups(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_open_groups

        full_audit_data["groups"] = [{"email": "team@example.com", "settings": {"whoCanJoin": "INVITED_CAN_JOIN", "allowExternalMembers": "false"}}]
        assert check_open_groups(full_audit_data).status == Status.PASS
        full_audit_data["groups"].append({"email": "partners@example.com", "settings": {"whoCanJoin": "INVITED_CAN_JOIN", "allowExternalMembers": "true"}})
        assert check_open_groups(full_audit_data).status == Status.WARN
        full_audit_data["groups"].append({"email": "open@example.com", "settings": {"whoCanJoin": "ANYONE_CAN_JOIN"}})
        assert check_open_groups(full_audit_data).status == Status.FAIL
        full_audit_data["groups"] = [{"email": "nosettings@example.com"}]
        assert check_open_groups(full_audit_data).status == Status.ERROR

    def test_device_posture(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_device_posture

        full_audit_data["mobile_devices"] = []
        full_audit_data["endpoint_devices"] = [{"deviceId": "d1", "model": "Pixel"}]
        assert check_device_posture(full_audit_data).status == Status.MANUAL  # no posture attributes reported
        full_audit_data["endpoint_devices"] = [{"model": "Pixel", "compromisedState": "UNCOMPROMISED", "encryptionState": "ENCRYPTED", "managementState": "APPROVED"}]
        assert check_device_posture(full_audit_data).status == Status.PASS
        full_audit_data["endpoint_devices"].append({"model": "Rooted", "compromisedState": "COMPROMISED", "managementState": "APPROVED"})
        assert check_device_posture(full_audit_data).status == Status.FAIL
        full_audit_data["endpoint_devices"][-1]["managementState"] = "BLOCKED"
        assert check_device_posture(full_audit_data).status == Status.PASS


class TestRoles:
    def _roles(self, data, privileges, system=False, assigned=True):
        data["api_errors"] = []
        data["roles"] = {"roles": [{"roleId": "r1", "roleName": "Helpdesk", "isSystemRole": system,
                                    "rolePrivileges": [{"privilegeName": p} for p in privileges]}],
                         "assignments": [{"roleId": "r1", "assignedTo": "u1", "assigneeType": "user"}] if assigned else []}
        return data

    def test_powerful_custom_role(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_powerful_custom_roles as c

        assert c(self._roles(full_audit_data, ["USERS_UPDATE", "REPORTS_ACCESS"])).status == Status.WARN
        assert c(self._roles(full_audit_data, ["REPORTS_ACCESS", "USERS_RETRIEVE"])).status == Status.PASS
        assert c(self._roles(full_audit_data, ["USERS_UPDATE"], system=True)).status == Status.PASS
        assert c(self._roles(full_audit_data, ["USERS_UPDATE"], assigned=False)).status == Status.PASS

    def test_vault_holders_and_not_collected(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_vault_privilege_holders as c

        assert c(self._roles(full_audit_data, ["MANAGE_HOLDS", "MANAGE_EXPORTS"])).status == Status.WARN
        assert c(self._roles(full_audit_data, ["REPORTS_ACCESS", "THRESHOLDS_VIEW"])).status == Status.PASS
        full_audit_data.pop("roles")
        assert c(full_audit_data).status == Status.ERROR


class TestMailTransportAndForwarding:
    def test_mta_sts(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_mta_sts

        def dns(sts, rpt):
            full_audit_data["dns_records"] = {"example.com": {"mx": [{"host": "aspmx.l.google.com"}],
                                                              "mta_sts": {"record_found": sts}, "tls_rpt": {"record_found": rpt}}}
            return check_mta_sts(full_audit_data).status
        assert dns(True, True) == Status.PASS
        assert dns(True, False) == Status.WARN
        assert dns(False, False) == Status.FAIL
        full_audit_data["dns_records"] = {"example.com": {"spf": {"record_found": True}}}
        assert check_mta_sts(full_audit_data).status == Status.MANUAL  # older cache without the lookup

    def test_duplicate_spf_fails(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_spf

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["dns_records"] = {"example.com": {"spf": {"record_found": True, "record": "v=spf1 -all", "record_count": 2}}}
        assert check_gmail_spf(full_audit_data).status == Status.FAIL

    def test_mailbox_forwarding(self, full_audit_data):
        from gws_auditor.checks.additional_identity import check_mailbox_external_forwarding as c

        full_audit_data["domains"] = [{"domainName": "example.com"}]
        full_audit_data["mailbox_forwarding"] = {"collected": False}
        assert c(full_audit_data).status == Status.MANUAL
        full_audit_data["mailbox_forwarding"] = {"collected": True, "users_checked": 2,
                                                 "forwarding": {"a@example.com": ["archive@example.com"]}}
        assert c(full_audit_data).status == Status.PASS  # internal forward only
        full_audit_data["mailbox_forwarding"]["forwarding"]["b@example.com"] = ["me@gmail.com"]
        result = c(full_audit_data)
        assert result.status == Status.FAIL and "me@gmail.com" in result.details and "archive@example.com" not in result.details

    def test_external_recipient_warning_from_admin_log(self, full_audit_data):
        from gws_auditor.checks.apps_gmail import check_gmail_external_recipient_warning as c

        full_audit_data["policies"]["gmail"] = {}
        name = "OutOfDomainWarningProto disable_untrusted_recipient_warning"
        ev = lambda v: [{"event_name": "CHANGE_APPLICATION_SETTING", "time": "2026-03-01T00:00:00Z",
                         "parameters": {"SETTING_NAME": name, "NEW_VALUE": v, "ORG_UNIT_NAME": "/"}}]
        full_audit_data["admin_logs"] = ev("true")
        assert c(full_audit_data).status == Status.FAIL
        full_audit_data["admin_logs"] = ev("false")
        assert c(full_audit_data).status == Status.PASS


class TestCollectors:
    def test_dns_counts_spf_records_and_reads_mta_sts(self):
        from types import SimpleNamespace
        from gws_auditor.api.dns import DNSClient

        client = DNSClient()
        txt = lambda *v: [SimpleNamespace(to_text=lambda s=s: f'"{s}"') for s in v]
        answers = {"example.com": txt("v=spf1 include:a -all", "v=spf1 include:b ~all", "unrelated"),
                   "_mta-sts.example.com": txt("v=STSv1; id=20260101"), "_smtp._tls.example.com": txt("other")}
        client._resolver = SimpleNamespace(resolve=lambda name, rtype: answers[name])
        spf = client.check_spf("example.com")
        assert spf["record_count"] == 2 and spf["record"] == "v=spf1 include:a -all"
        assert client.check_mta_sts("example.com")["exists"] is True
        assert client.check_tls_rpt("example.com")["exists"] is False


class TestSuperAdminRecovery:
    @pytest.mark.parametrize("enabled, status", [(False, Status.PASS), (True, Status.FAIL)])
    def test_super_admin_recovery(self, full_audit_data, enabled, status):
        from gws_auditor.checks.cisa_additions import check_super_admin_recovery_disabled

        _set(full_audit_data, "security", "super_admin_account_recovery", {"enableAccountRecovery": enabled})
        result = check_super_admin_recovery_disabled(full_audit_data)
        assert result.status == status
        assert result.severity.value == "CRITICAL"  # resolved from CRITICAL_CHECKS
