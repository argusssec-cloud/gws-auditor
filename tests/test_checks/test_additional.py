"""Tests for additional (non-CIS) security checks."""

from datetime import datetime, timedelta, timezone

import pytest

from gws_auditor.models import Status
from tests.factories import make_ou_policy, make_user



def _caa_event(name, app, applied=("Geo restriction",), satisfied=None, unsatisfied=(), time="2026-11-06T18:33:34.387Z"):
    """A normalized context_aware_access entry in the live shape observed 2026-11-06."""
    applied = list(applied)
    satisfied = applied if satisfied is None and not unsatisfied else list(satisfied or [])
    params = {"CAA_ACCESS_LEVEL_APPLIED": applied, "CAA_APPLICATION": app,
              "CAA_DEVICE_ID": "UNKNOWN", "CAA_DEVICE_STATE": "No Device Signals"}
    if satisfied:
        params["CAA_ACCESS_LEVEL_SATISFIED"] = satisfied
        params["PROTECTED_API_ACCESS"] = [app]
    if unsatisfied:
        params["CAA_ACCESS_LEVEL_UNSATISFIED"] = list(unsatisfied)
        params["BLOCKED_API_ACCESS"] = [app]
    return {"actor_email": "user@example.com", "event_name": name, "event_type": "CONTEXT_AWARE_ACCESS_USER_EVENT",
            "time": time, "ip_address": "203.0.113.5", "parameters": params}


class TestAdditionalChecks:
    """Tests for Other + Google best practice checks."""

    def test_mx_records_google_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_mx_records
        # Fix all domains to have Google MX
        for domain in full_audit_data["dns_records"]:
            full_audit_data["dns_records"][domain]["mx"] = [
                {"host": "aspmx.l.google.com.", "priority": 1},
            ]
        result = check_mx_records(full_audit_data)
        assert result.status == Status.PASS

    def test_takeout_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_takeout_restriction
        full_audit_data["policies"]["security"]["data_export"] = {
            "takeout_enabled": False,
        }
        result = check_takeout_restriction(full_audit_data)
        assert result.status == Status.PASS


class TestSecuritySandbox:
    """Tests for ADD-02 security sandbox check."""

    def test_security_sandbox_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["policies"]["gmail"] = {
            "safety": {"security_sandbox_enabled": True},
        }
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.PASS

    def test_security_sandbox_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["policies"]["gmail"] = {
            "safety": {"security_sandbox_enabled": False},
        }
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.FAIL


class TestInboundGatewaySpf:
    """Tests for ADD-06 inbound gateway SPF configuration check."""

    def test_no_gateway_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": False},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.PASS

    def test_gateway_with_spf_reject_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": True, "reject_if_spf_fail": True},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.PASS

    def test_gateway_without_spf_reject_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_inbound_gateway_spf
        full_audit_data["policies"]["gmail"] = {
            "inbound_gateway": {"configured": True, "reject_if_spf_fail": False},
        }
        result = check_inbound_gateway_spf(full_audit_data)
        assert result.status == Status.FAIL


class TestPartnerTls:
    """Tests for ADD-07 partner domain TLS enforcement check."""

    def test_partner_tls_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_partner_tls
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "partner_domain_tls_rules": [{"domain": "partner.com"}],
            },
        }
        result = check_partner_tls(full_audit_data)
        assert result.status == Status.PASS

    def test_partner_tls_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_partner_tls
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "partner_domain_tls_rules": [],
                "tls_required": False,
            },
        }
        result = check_partner_tls(full_audit_data)
        assert result.status == Status.FAIL


class TestPasswordAlert:
    """Tests for ADD-08 Password Alert deployment check."""

    def test_password_alert_deployed_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        full_audit_data["policies"]["security"]["password_alert"] = {
            "deployed": True,
        }
        result = check_password_alert(full_audit_data)
        assert result.status == Status.PASS

    def test_password_alert_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_password_alert
        full_audit_data["policies"]["security"]["password_alert"] = {
            "deployed": None,
        }
        result = check_password_alert(full_audit_data)
        assert result.status == Status.MANUAL


class TestClientSideEncryption:
    """Tests for ADD-11 client-side encryption check."""

    def test_cse_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_client_side_encryption
        full_audit_data["policies"]["security"]["client_side_encryption"] = {
            "enabled": True,
        }
        result = check_client_side_encryption(full_audit_data)
        assert result.status == Status.PASS

    def test_cse_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_client_side_encryption
        full_audit_data["policies"]["security"]["client_side_encryption"] = {
            "enabled": False,
        }
        result = check_client_side_encryption(full_audit_data)
        assert result.status == Status.FAIL


class TestGmailDlp:
    """Tests for ADD-12 Gmail DLP rules check."""

    def test_gmail_dlp_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_dlp
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "dlp_rules": [{"name": "PII detection"}],
                "content_compliance_rules": [],
            },
        }
        full_audit_data["policies"]["security"]["dlp"] = {
            "gmail_dlp_enabled": None,
        }
        result = check_gmail_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_gmail_dlp_empty_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_dlp
        full_audit_data["policies"]["gmail"] = {
            "compliance": {
                "dlp_rules": [],
                "content_compliance_rules": [],
            },
        }
        full_audit_data["policies"]["security"]["dlp"] = {
            "gmail_dlp_enabled": False,
        }
        result = check_gmail_dlp(full_audit_data)
        assert result.status == Status.FAIL


# ---------------------------------------------------------------------------
# ADD-13 to ADD-27: New 2025-2026 checks
# ---------------------------------------------------------------------------


class TestGeminiWorkspaceFeatures:
    """Tests for ADD-13 Gemini features in Workspace apps."""

    def test_gemini_workspace_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {
            "workspace_features": {"enabled": False},
        }
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_workspace_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {
            "workspace_features": {"enabled": True},
        }
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_workspace_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_workspace_features
        full_audit_data["policies"]["gemini"] = {}
        result = check_gemini_workspace_features(full_audit_data)
        assert result.status == Status.MANUAL


class TestGeminiChrome:
    """Tests for ADD-14 Gemini in Chrome."""

    def test_gemini_chrome_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": False},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.PASS

    def test_gemini_chrome_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": True},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_not_configured_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {}
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_none_value_fail(self, full_audit_data):
        """None value for enabled should be treated as not-disabled (FAIL)."""
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"]["gemini"] = {
            "chrome": {"enabled": None},
        }
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL

    def test_gemini_chrome_missing_policies_key(self, full_audit_data):
        """Missing gemini key in policies should FAIL."""
        from gws_auditor.checks.additional import check_gemini_chrome
        full_audit_data["policies"].pop("gemini", None)
        result = check_gemini_chrome(full_audit_data)
        assert result.status == Status.FAIL


class TestWorkspaceStudio:
    """Tests for ADD-15 Workspace Studio access."""

    def test_studio_disabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {
            "workspace_studio": {"enabled": False},
        }
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.PASS

    def test_studio_enabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {
            "workspace_studio": {"enabled": True},
        }
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.FAIL

    def test_studio_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_workspace_studio
        full_audit_data["policies"]["gemini"] = {}
        result = check_workspace_studio(full_audit_data)
        assert result.status == Status.MANUAL


class TestAppleWritingTools:
    """Tests for ADD-16 Apple Intelligence Writing Tools."""

    def test_apple_writing_tools_always_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_apple_writing_tools
        result = check_apple_writing_tools(full_audit_data)
        assert result.status == Status.MANUAL


class TestPasskeysEnforced:
    """Tests for ADD-18 passkey enforcement."""

    def test_passkeys_always_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_passkeys_enforced
        result = check_passkeys_enforced(full_audit_data)
        assert result.status == Status.MANUAL


class TestCaaOidc:
    """Tests for ADD-20 Context-Aware Access for OIDC apps.

    The check is log-driven (no policy API exposes the toggle).
      - No third-party OIDC apps in token_logs → NOT_APPLICABLE
      - OIDC apps present + CAA ACCESS_DENY_EVENT in caa_events → PASS
      - OIDC apps present + no denial events → MANUAL (REVIEW)
    """

    def test_caa_oidc_no_apps_not_applicable(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["token_logs"] = []
        full_audit_data["caa_events"] = []
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE

    def test_caa_oidc_only_google_first_party_not_applicable(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        # Google first-party apps don't count as "third-party OIDC"
        full_audit_data["token_logs"] = [
            {
                "event_name": "activity",
                "client_id": "77185425430.apps.googleusercontent.com",
                "app_name": "Google Chrome",
                "parameters": {
                    "client_id": "77185425430.apps.googleusercontent.com",
                    "app_name": "Google Chrome",
                },
            },
        ]
        full_audit_data["caa_events"] = []
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE

    def test_caa_oidc_apps_with_denials_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["token_logs"] = [
            {
                "event_name": "activity",
                "client_id": "990339570472-abc.apps.googleusercontent.com",
                "app_name": "LinkedIn",
                "parameters": {
                    "client_id": "990339570472-abc.apps.googleusercontent.com",
                    "app_name": "LinkedIn",
                },
            },
        ]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_DENY_EVENT", "LinkedIn", unsatisfied=["Corp devices"])]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.PASS
        assert "1 active-mode evaluation(s) (1 denied)" in result.details

    def test_caa_oidc_allowed_evaluation_for_the_app_passes(self, full_audit_data):
        """ACCESS_LEVELS_EVALUATED (allowed, live shape 2026-11-06) naming the app is enforcement too."""
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion")
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "Notion")]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.PASS
        assert "(0 denied)" in result.details

    def test_caa_oidc_fails_when_access_context_manager_has_no_levels(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        from tests.test_checks.test_security_access import TestGeoBlocking as G
        self._oidc(full_audit_data, "Notion")
        full_audit_data["access_context"] = G._acm()
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL
        assert "no access level" in result.details
        full_audit_data["access_context"] = G._acm(G._DEVICE)  # levels exist, assignment unknown -> MANUAL
        assert check_caa_oidc(full_audit_data).status == Status.MANUAL

    def test_caa_oidc_evaluation_for_workspace_app_or_monitor_mode_is_not_evidence(self, full_audit_data):
        """A Gmail evaluation says nothing about OIDC coverage; monitor-mode names never count."""
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion")
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL"),
                                         _caa_event("ACCESS_DENY_EVENT", "DRIVE", unsatisfied=["Geo restriction"]),
                                         _caa_event("MONITOR_MODE_ACCESS_DENY_EVENT", "Notion", unsatisfied=["Geo restriction"])]
        assert check_caa_oidc(full_audit_data).status == Status.MANUAL

    def test_caa_oidc_apps_without_denials_review(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        full_audit_data["token_logs"] = [
            {
                "event_name": "activity",
                "client_id": "990339570472-abc.apps.googleusercontent.com",
                "app_name": "Notion",
                "parameters": {
                    "client_id": "990339570472-abc.apps.googleusercontent.com",
                    "app_name": "Notion",
                },
            },
        ]
        full_audit_data["caa_events"] = []
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Notion" in result.details

    def _oidc(self, data, *names):
        data["token_logs"] = [{"event_name": "activity", "client_id": f"{i}-abc.apps.googleusercontent.com", "app_name": n,
                               "parameters": {"client_id": f"{i}-abc.apps.googleusercontent.com", "app_name": n}}
                              for i, n in enumerate(names)]
        data["caa_events"] = []

    def test_caa_toggled_off_fails(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        from tests.factories import make_admin_event
        self._oidc(full_audit_data, "Notion")
        full_audit_data["admin_logs"] = [
            make_admin_event("TOGGLE_CAA_ENABLEMENT", {"NEW_VALUE": "ENABLED"}, "2026-01-01T00:00:00Z"),
            make_admin_event("TOGGLE_CAA_ENABLEMENT", {"NEW_VALUE": "DISABLED"}, "2026-02-01T00:00:00Z")]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL and "turned off" in result.details

    # Event shape below is the one observed live (flip test 2026-11-06, Tasks app): one event per app
    # and mode, APPLICATION_NAME upper-case, MODE MONITOR|BLOCK, CAA_ACCESS_ASSIGNMENTS_NEW a list of
    # level names, or CAA_ACCESS_ASSIGNMENTS_OLD alone when that mode's assignment is removed.
    @staticmethod
    def _assign(app, mode, levels, time="2026-10-01T10:00:00.000Z", removed=False):
        from tests.factories import make_admin_event
        key = "CAA_ACCESS_ASSIGNMENTS_OLD" if removed else "CAA_ACCESS_ASSIGNMENTS_NEW"
        return make_admin_event("CHANGE_CAA_APP_ASSIGNMENTS", {
            "APPLICATION_NAME": app.upper(), "CAA_ENFORCEMENT_ENDPOINTS_OLD": "CAA_WEB_VERSION",
            "CAA_ENFORCEMENT_ENDPOINTS_NEW": "CAA_WEB_VERSION_AND_1P_OAUTH_CLIENTS",
            "TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "example.com",
            "MODE": mode, key: list(levels)}, time)

    def test_access_levels_assigned_to_every_app_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion", "LinkedIn")
        full_audit_data["admin_logs"] = [self._assign("notion", "BLOCK", ["Corp devices"]),
                                         self._assign("LinkedIn", "WARN", ["Corp devices"])]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.PASS
        assert sorted(result.actual_value["covered"]) == ["LinkedIn", "Notion"]

    def test_levels_removed_or_monitor_mode_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion", "LinkedIn")
        full_audit_data["admin_logs"] = [
            self._assign("Notion", "BLOCK", ["Corp devices"], "2026-01-01T00:00:00Z"),
            self._assign("Notion", "BLOCK", ["Corp devices"], "2026-02-01T00:00:00Z", removed=True),
            self._assign("LinkedIn", "MONITOR", ["Corp devices"])]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL
        assert "removed from Notion" in result.details and "monitor mode only" in result.details and "LinkedIn" in result.details

    def test_live_sequence_monitor_then_block_then_removed(self, full_audit_data):
        """The exact event sequence recorded on 2026-11-06: assign in monitor mode, switch to block
        (block NEW + monitor OLD at the same instant), then remove (block OLD)."""
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Tasks")
        t1, t2, t3 = "2026-11-06T08:23:11.500Z", "2026-11-06T08:26:27.197Z", "2026-11-06T08:28:07.000Z"
        monitor_on = [self._assign("TASKS", "MONITOR", ["Audit flip test (temporary)"], t1)]
        full_audit_data["admin_logs"] = list(monitor_on)
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL and "monitor mode only" in result.details
        switched = monitor_on + [self._assign("TASKS", "BLOCK", ["Audit flip test (temporary)"], t2),
                                 self._assign("TASKS", "MONITOR", ["Audit flip test (temporary)"], t2, removed=True)]
        full_audit_data["admin_logs"] = list(switched)
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.PASS and result.actual_value["covered"] == ["Tasks"]
        full_audit_data["admin_logs"] = switched + [self._assign("TASKS", "BLOCK", ["Audit flip test (temporary)"], t3, removed=True)]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.FAIL and result.actual_value["levels_removed"] == ["Tasks"]

    def test_partial_assignment_stays_review(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion", "LinkedIn")
        full_audit_data["admin_logs"] = [self._assign("Notion", "BLOCK", ["Corp devices"])]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["covered"] == ["Notion"] and result.actual_value["no_assignment_event"] == ["LinkedIn"]

    def test_unrecognised_mode_is_review_not_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion")
        full_audit_data["admin_logs"] = [self._assign("Notion", "ENFORCE", ["Corp devices"])]
        result = check_caa_oidc(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["unrecognised_mode"] == ["Notion (mode ENFORCE)"]

    def test_documented_active_mode_and_parameter_aliases(self, full_audit_data):
        """The Reports API appendix documents MODE ACTIVE and CAA_ACCESS_LEVELS_NEW / CAA_ASSIGNMENTS_NEW."""
        from tests.factories import make_admin_event
        from gws_auditor.checks.additional import check_caa_oidc
        self._oidc(full_audit_data, "Notion")
        full_audit_data["admin_logs"] = [self._assign("Notion", "ACTIVE", ["Corp devices"])]
        assert check_caa_oidc(full_audit_data).status == Status.PASS
        full_audit_data["admin_logs"] = [make_admin_event("CHANGE_CAA_APP_ASSIGNMENTS", {
            "APPLICATION_NAME": "NOTION", "MODE": "ACTIVE", "CAA_ASSIGNMENTS_NEW": ["Corp devices"]})]
        assert check_caa_oidc(full_audit_data).status == Status.PASS

    def test_legacy_levels_parameter_still_read(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        from tests.factories import make_admin_event
        self._oidc(full_audit_data, "Notion")
        full_audit_data["admin_logs"] = [make_admin_event("CHANGE_CAA_APP_ASSIGNMENTS", {
            "APPLICATION_NAME": "NOTION", "CAA_ACCESS_LEVELS_NEW": "[Corp devices]", "MODE": "BLOCK"})]
        assert check_caa_oidc(full_audit_data).status == Status.PASS

    def test_denial_evidence_still_wins(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_oidc
        from tests.factories import make_admin_event
        self._oidc(full_audit_data, "Notion")
        full_audit_data["caa_events"] = [_caa_event("ACCESS_DENY_EVENT", "Notion", unsatisfied=["Corp devices"])]
        full_audit_data["admin_logs"] = [make_admin_event("TOGGLE_CAA_ENABLEMENT", {"NEW_VALUE": "DISABLED"})]
        assert check_caa_oidc(full_audit_data).status == Status.PASS


class TestCaaSamlDefault:
    """Tests for ADD-40 default Context-Aware Access policy for SAML apps.

    Parallel structure to ADD-20:
      - No SAML logins in login_logs → NOT_APPLICABLE
      - SAML apps present + CAA ACCESS_DENY_EVENT in caa_events → PASS
      - SAML apps present + no denial events → MANUAL (REVIEW)
    """

    def test_caa_saml_no_apps_not_applicable(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_saml_default
        # Only google_password / reauth logins, no SAML
        full_audit_data["login_logs"] = [
            {
                "event_name": "login_success",
                "parameters": {"login_type": "google_password"},
            },
        ]
        full_audit_data["caa_events"] = []
        result = check_caa_saml_default(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE

    def test_caa_saml_apps_with_denials_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_saml_default
        full_audit_data["login_logs"] = [
            {
                "event_name": "login_success",
                "parameters": {
                    "login_type": "saml",
                    "application_name": "Workday",
                },
            },
        ]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_DENY_EVENT", "Workday", unsatisfied=["Corp devices"])]
        result = check_caa_saml_default(full_audit_data)
        assert result.status == Status.PASS

    def test_caa_saml_fails_when_access_context_manager_has_no_levels(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_saml_default
        from tests.test_checks.test_security_access import TestGeoBlocking as G
        full_audit_data["login_logs"] = [{"event_name": "login_success",
                                          "parameters": {"login_type": "saml", "application_name": "Workday"}}]
        full_audit_data["access_context"] = G._acm()
        assert check_caa_saml_default(full_audit_data).status == Status.FAIL
        full_audit_data["access_context"] = G._acm(G._DEVICE)
        assert check_caa_saml_default(full_audit_data).status == Status.MANUAL

    def test_caa_saml_evaluation_for_other_app_is_not_evidence(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_saml_default
        full_audit_data["login_logs"] = [{"event_name": "login_success",
                                          "parameters": {"login_type": "saml", "application_name": "Workday"}}]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")]
        assert check_caa_saml_default(full_audit_data).status == Status.MANUAL

    def test_caa_saml_apps_without_denials_review(self, full_audit_data):
        from gws_auditor.checks.additional import check_caa_saml_default
        full_audit_data["login_logs"] = [
            {
                "event_name": "login_success",
                "parameters": {
                    "login_type": "saml",
                    "application_name": "Salesforce",
                },
            },
        ]
        full_audit_data["caa_events"] = []
        result = check_caa_saml_default(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Salesforce" in result.details


class TestMpaVaultExports:
    """Tests for ADD-21 Multi-Party Approval for Vault exports."""

    def test_mpa_vault_covered_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_mpa_vault_exports
        full_audit_data["policies"]["security"]["multi_party_approval"] = {
            "vault_exports_covered": True,
        }
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.PASS

    def test_mpa_vault_not_covered_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_mpa_vault_exports
        full_audit_data["policies"]["security"]["multi_party_approval"] = {
            "vault_exports_covered": False,
        }
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.FAIL

    def test_mpa_vault_not_exposed_is_review(self, full_audit_data):
        """P3: the Policy API has no Vault multi-party-approval setting; unknown is MANUAL, not FAIL."""
        from gws_auditor.checks.additional import check_mpa_vault_exports
        result = check_mpa_vault_exports(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.scored is False


class TestGmailClassificationLabels:
    """Tests for ADD-22 Gmail data classification labels."""

    def test_classification_labels_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"classification_labels_enabled": True},
        }
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.PASS

    def test_classification_labels_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"classification_labels_enabled": False},
        }
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.FAIL

    def test_classification_labels_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_classification_labels
        full_audit_data["policies"]["gmail"] = {}
        result = check_gmail_classification_labels(full_audit_data)
        assert result.status == Status.MANUAL


class TestCalendarDlp:
    """Tests for ADD-23 Calendar DLP rules."""

    def test_calendar_dlp_rules_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["calendar"]["dlp_rules"] = [
            {"name": "PII in events"},
        ]
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_dlp_security_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["security"]["dlp"] = {
            "calendar_dlp_enabled": True,
        }
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.PASS

    def test_calendar_dlp_empty_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_calendar_dlp
        full_audit_data["policies"]["calendar"]["dlp_rules"] = []
        full_audit_data["policies"]["security"]["dlp"] = {
            "calendar_dlp_enabled": False,
        }
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.FAIL

    def test_calendar_dlp_rules_not_collected_is_review(self, full_audit_data):
        """No rules category at all: unknown, not FAIL (P3)."""
        from gws_auditor.checks.additional import check_calendar_dlp
        result = check_calendar_dlp(full_audit_data)
        assert result.status == Status.MANUAL


class TestGmailCse:
    """Tests for ADD-26 Gmail client-side encryption."""

    def test_gmail_cse_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"cse_enabled": True},
        }
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.PASS

    def test_gmail_cse_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {
            "compliance": {"cse_enabled": False},
        }
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.FAIL

    def test_gmail_cse_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_gmail_cse
        full_audit_data["policies"]["gmail"] = {}
        result = check_gmail_cse(full_audit_data)
        assert result.status == Status.MANUAL


class TestMeetComplianceRecording:
    """Tests for ADD-27 Meet compliance recording."""

    def test_compliance_recording_enabled_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": True},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS

    def test_compliance_recording_disabled_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": False},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.FAIL

    def test_compliance_recording_unknown_manual(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {}
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.MANUAL


# ---------------------------------------------------------------------------
# OU-aware tests
# ---------------------------------------------------------------------------


class TestMeetComplianceRecordingOU:
    """OU-aware tests for ADD-27 Meet compliance recording."""

    def test_all_ous_safe(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/"),
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/Compliance"),
            ],
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS
        assert "2 OU(s)" in result.details

    def test_child_ou_recording_disabled(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "_ou_policies": [
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": True}, "/"),
                make_ou_policy("meet", "video_recording",
                                {"enableRecording": False}, "/Interns"),
            ],
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.FAIL
        assert "/Interns" in result.details

    def test_fallback_when_no_ou_policies(self, full_audit_data):
        from gws_auditor.checks.additional import check_meet_compliance_recording
        full_audit_data["policies"]["meet"] = {
            "compliance": {"recording_enabled": True},
        }
        result = check_meet_compliance_recording(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-28: Groups with no active members
# -----------------------------------------------------------------------

class TestGroupsNoActiveUsers:
    """Tests for ADD-28 groups with no active members check."""

    def test_pass_all_groups_have_active_members(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = [
            {"email": "team@example.com", "directMembersCount": 2},
        ]
        full_audit_data["group_members"] = {
            "team@example.com": [
                {"email": "admin1@example.com", "role": "MEMBER"},
                {"email": "user1@example.com", "role": "MEMBER"},
            ],
        }
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_empty_group(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = [
            {"email": "empty@example.com", "directMembersCount": 0},
        ]
        full_audit_data["group_members"] = {}
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.WARN
        assert "empty@example.com" in result.actual_value["empty_groups"]

    def test_warn_all_inactive_members(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        suspended_user = make_user(email="suspended@example.com", suspended=True)
        full_audit_data["users"].append(suspended_user)
        full_audit_data["groups"] = [
            {"email": "dead@example.com", "directMembersCount": 1},
        ]
        full_audit_data["group_members"] = {
            "dead@example.com": [
                {"email": "suspended@example.com", "role": "MEMBER"},
            ],
        }
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.WARN
        assert "dead@example.com" in result.actual_value["all_inactive_groups"]

    def test_pass_no_groups(self, full_audit_data):
        from gws_auditor.checks.additional import check_groups_no_active_users
        full_audit_data["groups"] = []
        result = check_groups_no_active_users(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-29: Chat spaces with no recent activity
# -----------------------------------------------------------------------

class TestChatSpacesInactive:
    """Tests for ADD-29 inactive Chat spaces check."""

    def test_pass_all_active(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/abc", "displayName": "Active Space", "lastActiveTime": recent},
        ]
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_inactive_space(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/old", "displayName": "Old Space", "lastActiveTime": old},
        ]
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["inactive_spaces"][0]["name"] == "Old Space"

    def test_manual_no_data(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        full_audit_data["chat_spaces"] = []
        result = check_chat_spaces_inactive(full_audit_data)
        # make_review returns MANUAL status
        assert result.status == Status.MANUAL

    def test_custom_threshold(self, full_audit_data):
        from gws_auditor.checks.additional import check_chat_spaces_inactive
        # 50 days ago - should pass with default 90 but fail with 30-day threshold
        ts = (datetime.now(timezone.utc) - timedelta(days=50)).isoformat() + "Z"
        full_audit_data["chat_spaces"] = [
            {"name": "spaces/mid", "displayName": "Mid Space", "lastActiveTime": ts},
        ]
        full_audit_data["_options"] = {"chat_inactive_days": 30}
        result = check_chat_spaces_inactive(full_audit_data)
        assert result.status == Status.WARN


# -----------------------------------------------------------------------
# ADD-30: Mobile devices not synced recently
# -----------------------------------------------------------------------

class TestMobileDevicesStale:
    """Tests for ADD-30 stale mobile devices check."""

    def test_pass_all_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel 8", "email": ["user@example.com"], "lastSync": recent, "status": "APPROVED"},
        ]
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "iPhone 12", "email": ["user@example.com"], "lastSync": old, "status": "APPROVED"},
        ]
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_mobile_devices_stale
        full_audit_data["mobile_devices"] = []
        result = check_mobile_devices_stale(full_audit_data)
        assert result.status == Status.PASS
        assert "No mobile devices enrolled" in result.details


# -----------------------------------------------------------------------
# ADD-31: ChromeOS devices not active recently
# -----------------------------------------------------------------------

class TestChromeosDevicesStale:
    """Tests for ADD-31 stale ChromeOS devices check."""

    def test_pass_all_active(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["chromeos_devices"] = [
            {"model": "Chromebook", "serialNumber": "SN123", "lastSync": recent, "status": "ACTIVE"},
        ]
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["chromeos_devices"] = [
            {"model": "Chromebook", "serialNumber": "SN456", "annotatedUser": "user@example.com",
             "lastSync": old, "status": "ACTIVE"},
        ]
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_chromeos_devices_stale
        full_audit_data["chromeos_devices"] = []
        result = check_chromeos_devices_stale(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-38: Endpoint verification devices stale
# -----------------------------------------------------------------------

class TestEndpointDevicesStale:
    """Tests for ADD-38 stale endpoint verification devices check."""

    def test_pass_all_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "laptop1", "deviceType": "WINDOWS", "lastSyncTime": recent,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_stale_device(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "old-laptop", "deviceType": "MAC_OS", "lastSyncTime": old,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["stale_devices"]) == 1

    def test_warn_never_synced(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        old_create = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat() + "Z"
        full_audit_data["endpoint_devices"] = [
            {"hostname": "never-synced", "deviceType": "LINUX", "createTime": old_create,
             "managementState": "APPROVED"},
        ]
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["stale_devices"][0]["last_sync"] == "never"

    def test_pass_no_devices(self, full_audit_data):
        from gws_auditor.checks.additional import check_endpoint_devices_stale
        full_audit_data["endpoint_devices"] = []
        result = check_endpoint_devices_stale(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-39: Devices pending approval too long
# -----------------------------------------------------------------------

class TestDevicesPending:
    """Tests for ADD-39 devices pending approval check."""

    def test_pass_no_pending(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel", "email": "u@example.com", "status": "APPROVED", "firstSync": recent},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.PASS

    def test_warn_mobile_pending_too_long(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "iPhone", "email": "u@example.com", "status": "PENDING", "firstSync": old},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.WARN
        assert len(result.actual_value["pending_devices"]) == 1
        assert result.actual_value["pending_devices"][0]["device_type"] == "Mobile"

    def test_warn_endpoint_pending_too_long(self, full_audit_data):
        from gws_auditor.checks.additional import check_devices_pending
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = []
        full_audit_data["endpoint_devices"] = [
            {"hostname": "laptop1", "managementState": "PENDING",
             "createTime": old, "owner": {"userResourceName": "users/123"}},
        ]
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.WARN
        assert result.actual_value["pending_devices"][0]["device_type"] == "Endpoint"

    def test_pass_pending_recent(self, full_audit_data):
        """Pending devices that were enrolled recently should not trigger a warning."""
        from gws_auditor.checks.additional import check_devices_pending
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat() + "Z"
        full_audit_data["mobile_devices"] = [
            {"model": "Pixel", "email": "u@example.com", "status": "PENDING", "firstSync": recent},
        ]
        full_audit_data["endpoint_devices"] = []
        result = check_devices_pending(full_audit_data)
        assert result.status == Status.PASS


# -----------------------------------------------------------------------
# ADD-32: Users without 2SV by OU inventory
# -----------------------------------------------------------------------

class TestTwoSvInventory:
    """Tests for ADD-32 2SV inventory check."""

    def test_pass_all_enrolled(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="a@example.com", is_enrolled_in_2sv=True),
            make_user(email="b@example.com", is_enrolled_in_2sv=True),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["summary"]["not_enrolled"] == 0

    def test_fail_some_not_enrolled(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="a@example.com", is_enrolled_in_2sv=True),
            make_user(email="b@example.com", is_enrolled_in_2sv=False),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["summary"]["not_enrolled"] == 1
        # Check per-OU breakdown
        root_ou = next(ou for ou in result.actual_value["per_ou"] if ou["org_unit"] == "/")
        assert "b@example.com" in root_ou["users_without_2sv"]

    def test_excludes_suspended_users(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="active@example.com", is_enrolled_in_2sv=True),
            make_user(email="suspended@example.com", is_enrolled_in_2sv=False, suspended=True),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["summary"]["total_users"] == 1

    def test_multi_ou_breakdown(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = [
            make_user(email="eng@example.com", is_enrolled_in_2sv=True, org_unit_path="/Engineering"),
            make_user(email="sales@example.com", is_enrolled_in_2sv=False, org_unit_path="/Sales"),
        ]
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.FAIL
        assert len(result.actual_value["per_ou"]) == 2

    def test_error_no_users(self, full_audit_data):
        from gws_auditor.checks.additional import check_2sv_inventory
        full_audit_data["users"] = []
        result = check_2sv_inventory(full_audit_data)
        assert result.status == Status.ERROR


# -----------------------------------------------------------------------
# ADD-33: OAuth apps with dangerous privileges
# -----------------------------------------------------------------------

class TestOauthDangerousApps:
    """Tests for ADD-33 OAuth dangerous apps check."""

    def test_pass_no_dangerous_apps(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Safe App",
                    "client_id": "safe-123",
                    "scope": "https://www.googleapis.com/auth/userinfo.email",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_grants"] == 1

    def test_fail_dangerous_scopes(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Risky App",
                    "client_id": "risky-456",
                    "scope": "https://mail.google.com/ https://www.googleapis.com/auth/drive",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.FAIL
        assert "Risky App" in result.actual_value["dangerous_apps"]
        app = result.actual_value["dangerous_apps"]["Risky App"]
        assert app["risk_level"] == "CRITICAL"
        assert "user@example.com" in app["granted_by"]

    def test_warn_no_token_logs(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = []
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.WARN

    def test_ignores_non_authorize_events(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "revoke",
                "actor_email": "user@example.com",
                "parameters": {
                    "app_name": "Some App",
                    "scope": "https://mail.google.com/",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        # No authorize events processed, but token_logs is non-empty
        assert result.status == Status.PASS
        assert result.actual_value["total_grants"] == 0

    def test_multiple_apps_aggregation(self, full_audit_data):
        from gws_auditor.checks.additional import check_oauth_dangerous_apps
        full_audit_data["token_logs"] = [
            {
                "event_name": "authorize",
                "actor_email": "user1@example.com",
                "parameters": {
                    "app_name": "App A",
                    "scope": "https://www.googleapis.com/auth/admin.directory.user",
                },
            },
            {
                "event_name": "authorize",
                "actor_email": "user2@example.com",
                "parameters": {
                    "app_name": "App A",
                    "scope": "https://www.googleapis.com/auth/admin.directory.group",
                },
            },
        ]
        result = check_oauth_dangerous_apps(full_audit_data)
        assert result.status == Status.FAIL
        app = result.actual_value["dangerous_apps"]["App A"]
        assert app["grant_count"] == 2
        assert len(app["granted_by"]) == 2


# -----------------------------------------------------------------------
# ADD-34: App-Specific Passwords
# -----------------------------------------------------------------------

class TestAppPasswords:
    """Tests for ADD-34 App-Specific Passwords check."""

    def test_no_asps_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = []
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_asps"] == 0

    def test_asps_found_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = [
            {
                "userEmail": "user1@example.com",
                "codeId": 1,
                "name": "Thunderbird",
                "creationTime": "1700000000",
                "lastTimeUsed": "1700100000",
            },
            {
                "userEmail": "user2@example.com",
                "codeId": 2,
                "name": "IMAP client",
                "creationTime": "1700000000",
                "lastTimeUsed": 0,
            },
        ]
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["total_asps"] == 2
        assert result.actual_value["users_with_asps"] == 2
        assert result.actual_value["never_used_asps"] == 1

    def test_never_used_asps(self, full_audit_data):
        from gws_auditor.checks.additional import check_app_passwords
        full_audit_data["app_passwords"] = [
            {
                "userEmail": "user1@example.com",
                "codeId": 1,
                "name": "Old app",
                "creationTime": "1600000000",
                "lastTimeUsed": 0,
            },
        ]
        result = check_app_passwords(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["never_used_asps"] == 1
        asps = result.actual_value["asps_by_user"][0]["asps"]
        assert asps[0]["last_used"] == "Never"


# -----------------------------------------------------------------------
# ADD-35: Shared Drives security settings
# -----------------------------------------------------------------------

class TestSharedDriveRestrictions:
    """Tests for ADD-35 Shared Drives restrictions check."""

    def test_no_drives_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = []
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_drives"] == 0

    def test_all_secure_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = [
            {
                "id": "drive-1",
                "name": "Secure Drive",
                "restrictions": {
                    "domainUsersOnly": True,
                    "driveMembersOnly": True,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": True,
                },
            },
        ]
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["insecure_drives"] == 0

    def test_insecure_drive_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_shared_drive_restrictions
        full_audit_data["shared_drives"] = [
            {
                "id": "drive-1",
                "name": "Open Drive",
                "restrictions": {
                    "domainUsersOnly": False,
                    "driveMembersOnly": False,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": False,
                },
            },
            {
                "id": "drive-2",
                "name": "Locked Drive",
                "restrictions": {
                    "domainUsersOnly": True,
                    "driveMembersOnly": True,
                    "adminManagedRestrictions": True,
                    "sharingFoldersRequiresOrganizerPermission": True,
                },
            },
        ]
        result = check_shared_drive_restrictions(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["insecure_drives"] == 1
        assert result.actual_value["total_drives"] == 2
        # Verify the insecure drive has issues listed
        open_drive = result.actual_value["drives"][0]
        assert len(open_drive["issues"]) == 3


# -----------------------------------------------------------------------
# ADD-37: Group discoverability
# -----------------------------------------------------------------------

class TestGroupDiscoverability:
    """Tests for ADD-37 group discoverability check."""

    def test_restricted_pass(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = [
            {
                "email": "team@example.com",
                "settings": {"whoCanDiscoverGroup": "ALL_MEMBERS_CAN_DISCOVER"},
            },
        ]
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.PASS

    def test_public_group_fail(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = [
            {
                "email": "public@example.com",
                "settings": {"whoCanDiscoverGroup": "ANYONE_CAN_DISCOVER"},
            },
            {
                "email": "private@example.com",
                "settings": {"whoCanDiscoverGroup": "ALL_MEMBERS_CAN_DISCOVER"},
            },
        ]
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.FAIL
        assert result.actual_value["public_groups_count"] == 1
        assert "public@example.com" in result.actual_value["public_groups"]

    def test_no_groups_manual(self, full_audit_data):
        from gws_auditor.checks.apps_groups import check_groups_discoverability
        full_audit_data["groups"] = []
        result = check_groups_discoverability(full_audit_data)
        assert result.status == Status.ERROR


class TestLicenseGating:
    """Tests for license-aware ERROR → NOT_APPLICABLE reclassification."""

    def test_error_reclassified_on_business_starter(self, full_audit_data):
        """ERROR results should become NOT_APPLICABLE on Business Starter."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE
        assert "Business Standard" in result.details

    def test_manual_on_enterprise_plus(self, full_audit_data):
        """When the tier supports the feature but the Policy API does not
        expose it (e.g. Security Sandbox), the check returns MANUAL so an
        admin can verify in the console rather than ERROR."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Enterprise Plus"
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.MANUAL

    def test_manual_when_license_unknown(self, full_audit_data):
        """When the license is unknown, the check still runs and returns
        MANUAL (verifiable in console) rather than ERROR."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = ""
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.MANUAL

    def test_pass_not_reclassified(self, full_audit_data):
        """PASS results should not be affected by license gating."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_type"] = "Business Starter"
        full_audit_data["policies"]["gmail"]["safety"] = {
            "security_sandbox_enabled": True,
        }
        result = check_security_sandbox(full_audit_data)
        # Even on Business Starter, a PASS should stay PASS (or NA if gated)
        assert result.status in (Status.PASS, Status.MANUAL, Status.NOT_APPLICABLE)

    def test_subscription_info_fallback(self, full_audit_data):
        """subscription_info.edition should work as fallback."""
        from gws_auditor.checks.additional import check_security_sandbox
        full_audit_data["subscription_info"] = {"edition": "Business Starter"}
        full_audit_data.pop("subscription_type", None)
        result = check_security_sandbox(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE

    def test_rules_check_runs_on_all_editions(self, full_audit_data):
        """Alert rule checks should run on all editions (no license gate)."""
        from gws_auditor.checks.rules import check_alert_password_change
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_alert_password_change(full_audit_data)
        # System-defined alerts are available on all editions
        assert result.status != Status.NOT_APPLICABLE

    def test_dlp_check_reclassified(self, full_audit_data):
        """DLP checks should be reclassified on Business Starter."""
        from gws_auditor.checks.security_access import check_drive_dlp
        full_audit_data["subscription_type"] = "Business Starter"
        result = check_drive_dlp(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE


class TestActiveOAuthTokens:
    """Tests for ADD-36: Active OAuth tokens with dangerous scopes."""

    def test_no_tokens_warns(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = []
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.WARN

    def test_safe_tokens_pass(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "safe-app.apps.googleusercontent.com",
                "displayText": "Safe App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["openid", "profile", "email"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS

    def test_native_apps_skipped(self, full_audit_data):
        """Native apps (Google's own) should be skipped entirely."""
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "google-native",
                "displayText": "Google Native",
                "anonymous": False,
                "nativeApp": True,
                "scopes": ["https://mail.google.com/"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["total_tokens"] == 0

    def test_dangerous_scopes_fail(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "evil-app.example.com",
                "displayText": "Evil App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": [
                    "https://mail.google.com/",
                    "https://www.googleapis.com/auth/drive",
                ],
                "userEmail": "admin@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        assert "CRITICAL" in result.details
        apps = result.actual_value["dangerous_apps"]
        assert "Evil App" in apps
        assert apps["Evil App"]["risk_level"] == "CRITICAL"

    def test_anonymous_app_flagged(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "anon-client-id",
                "displayText": "Anon App",
                "anonymous": True,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/drive"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["Anon App"]["anonymous"] is True
        assert "anonymous" in result.details.lower()

    def test_multiple_users_aggregated(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "shared-app",
                "displayText": "Shared App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "userEmail": "user1@example.com",
            },
            {
                "clientId": "shared-app",
                "displayText": "Shared App",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
                "userEmail": "user2@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["Shared App"]["install_count"] == 2
        assert len(apps["Shared App"]["users"]) == 2

    def test_ediscovery_scope_critical(self, full_audit_data):
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "ediscovery-app",
                "displayText": "eDiscovery Tool",
                "anonymous": False,
                "nativeApp": False,
                "scopes": ["https://www.googleapis.com/auth/ediscovery"],
                "userEmail": "admin@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.FAIL
        apps = result.actual_value["dangerous_apps"]
        assert apps["eDiscovery Tool"]["risk_level"] == "CRITICAL"

    def test_safe_tokens_with_anonymous_pass(self, full_audit_data):
        """Anonymous apps with no dangerous scopes should pass."""
        from gws_auditor.checks.additional import check_active_oauth_tokens
        full_audit_data["user_tokens"] = [
            {
                "clientId": "anon-safe",
                "displayText": "Anon Safe",
                "anonymous": True,
                "nativeApp": False,
                "scopes": ["openid", "profile"],
                "userEmail": "user@example.com",
            },
        ]
        result = check_active_oauth_tokens(full_audit_data)
        assert result.status == Status.PASS
        assert result.actual_value["anonymous_apps"] == 1


# ---------------------------------------------------------------------------
# ADD-53 .. ADD-56: Context-Aware Access posture from the access-level inventory
# ---------------------------------------------------------------------------

_LEVEL_NAME = "accessPolicies/134654395911/accessLevels/geo_restriction_fttlt6s2"
_GEO_LEVEL = {"name": _LEVEL_NAME, "title": "Geo restriction",
              "basic": {"conditions": [{"negate": True, "regions": ["AQ"]}]}}  # live ACM shape 2026-11-06
# Live ACM shape 2026-11-06 23:30Z (flip: level with the "Screen password protected" device condition):
# {"name": ".../accessLevels/device_posture_test_b6fwshm4", "title": "Device posture test", "description": ...,
#  "basic": {"conditions": [{"devicePolicy": {"requireScreenlock": true}}]}}
_DEVICE_LEVEL = {"name": "accessPolicies/134654395911/accessLevels/managed_device",
                 "title": "Managed device",
                 "basic": {"conditions": [{"devicePolicy": {"requireScreenlock": True,
                                                             "allowedEncryptionStatuses": ["ENCRYPTED"]}}]}}
# Admin log 2026-11-06 23:31Z, UPDATE_ACCESS_LEVEL_V2 after editing the description: CURR_STATE drops the
# description, PREV_STATE keeps it; both carry basic.conditions. Exact live text.
_UPDATE_CURR_STATE = ('{\n  "basic": {\n    "conditions": [{\n      "devicePolicy": {\n        "requireScreenlock": true\n      }\n    }]\n  },\n'
                      '  "name": "accessPolicies/134654395911/accessLevels/device_posture_test_b6fwshm4",\n  "title": "Device posture test"\n}')
_UPDATE_PREV_STATE = ('{\n  "name": "accessPolicies/134654395911/accessLevels/device_posture_test_b6fwshm4",\n  "title": "Device posture test",\n'
                      '  "description": "GWS auditor flip test: screen lock required (temporary)",\n  "basic": {\n    "conditions": [{\n'
                      '      "devicePolicy": {\n        "requireScreenlock": true\n      }\n    }]\n  }\n}')
# Admin console app code observed live 2026-11-06 23:23Z (flip: geo level assigned to the Admin console in
# Block mode): CHANGE_CAA_APP_ASSIGNMENTS APPLICATION_NAME and ACCESS_LEVELS_EVALUATED CAA_APPLICATION both
# "ADMIN_CONSOLE" (PROTECTED_API_ACCESS ["ADMIN_CONSOLE"], CAA_DEVICE_ID = the Endpoint Verification device id).
_ADMIN_APP = "ADMIN_CONSOLE"


def _acm(*levels):
    return {"collected": True, "source": "access_context_manager", "organization": "organizations/18479643020",
            "access_policy": "accessPolicies/134654395911", "access_levels": list(levels), "bindings": [],
            "bindings_collected": False, "reason": ""}


def _assign(app, mode, levels, time="2026-11-06T18:26:28.786Z", removed=False):
    from tests.factories import make_admin_event
    key = "CAA_ACCESS_ASSIGNMENTS_OLD" if removed else "CAA_ACCESS_ASSIGNMENTS_NEW"
    return make_admin_event("CHANGE_CAA_APP_ASSIGNMENTS", {
        "APPLICATION_NAME": app, "CAA_ENFORCEMENT_ENDPOINTS_OLD": "CAA_WEB_VERSION",
        "CAA_ENFORCEMENT_ENDPOINTS_NEW": "CAA_WEB_VERSION_AND_1P_OAUTH_CLIENTS",
        "TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "example.com", "MODE": mode, key: list(levels)}, time)


def _toggle(value, time="2026-11-06T18:00:00.000Z"):
    from tests.factories import make_admin_event
    return make_admin_event("TOGGLE_CAA_ENABLEMENT", {"NEW_VALUE": value, "OLD_VALUE": "ENABLED" if value == "DISABLED" else "DISABLED"}, time)


class TestCaaAdminConsole:
    """ADD-53."""

    def _run(self, data):
        from gws_auditor.checks.additional import check_caa_admin_console
        return check_caa_admin_console(data)

    def test_evaluation_for_admin_console_passes(self, full_audit_data):
        full_audit_data["admin_logs"] = []
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", _ADMIN_APP),
                                         _caa_event("ACCESS_DENY_EVENT", _ADMIN_APP, satisfied=(), unsatisfied=("Geo restriction",))]
        result = self._run(full_audit_data)
        assert result.status == Status.PASS
        assert "2 Admin console access(es) (1 denied)" in result.details
        assert result.actual_value["access_levels"] == ["Geo restriction"]

    def test_evaluation_for_other_apps_is_not_admin_console_evidence(self, full_audit_data):
        full_audit_data["admin_logs"] = []
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL"), _caa_event("ACCESS_LEVELS_EVALUATED", "DRIVE")]
        full_audit_data["access_context"] = _acm(_GEO_LEVEL)
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert "Geo restriction" in result.details and "no Admin console assignment change" in result.details
        assert result.actual_value["evaluated_apps"] == ["DRIVE", "GMAIL"]

    def test_active_assignment_passes_monitor_or_removal_fails(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["admin_logs"] = [_assign(_ADMIN_APP, "BLOCK", ["Geo restriction"])]
        assert self._run(full_audit_data).status == Status.PASS
        full_audit_data["admin_logs"] = [_assign(_ADMIN_APP, "MONITOR", ["Geo restriction"])]
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL and "monitor mode only" in result.details
        full_audit_data["admin_logs"] = [_assign(_ADMIN_APP, "BLOCK", ["Geo restriction"]),
                                         _assign(_ADMIN_APP, "BLOCK", ["Geo restriction"], time="2026-11-06T19:00:00.000Z", removed=True)]
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL and "removed" in result.details

    def test_caa_disabled_fails_unless_newer_evaluation(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["admin_logs"] = [_assign(_ADMIN_APP, "BLOCK", ["Geo restriction"]), _toggle("DISABLED", "2026-11-06T19:00:00.000Z")]
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL and "turned off" in result.details
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", _ADMIN_APP, time="2026-11-06T20:00:00.000Z")]
        assert self._run(full_audit_data).status == Status.PASS

    def test_acm_without_levels_fails(self, full_audit_data):
        full_audit_data["caa_events"], full_audit_data["admin_logs"] = [], []
        full_audit_data["access_context"] = _acm()
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL
        assert "lists no access level" in result.details

    def test_unrecognised_mode_and_no_evidence_are_review(self, full_audit_data):
        full_audit_data["caa_events"], full_audit_data["admin_logs"] = [], []
        assert self._run(full_audit_data).status == Status.MANUAL
        full_audit_data["admin_logs"] = [_assign(_ADMIN_APP, "ENFORCE", ["Geo restriction"])]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "unrecognised mode" in result.details

    def test_lower_edition_not_applicable(self, full_audit_data):
        full_audit_data["subscription_type"] = "business_starter"
        assert self._run(full_audit_data).status == Status.NOT_APPLICABLE


class TestCaaDeviceLevel:
    """ADD-54."""

    def _run(self, data):
        from gws_auditor.checks.additional import check_caa_device_level
        return check_caa_device_level(data)

    def test_device_level_evaluated_passes_with_signal_count(self, full_audit_data):
        full_audit_data["admin_logs"] = []
        full_audit_data["access_context"] = _acm(_GEO_LEVEL, _DEVICE_LEVEL)
        allowed = _caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL", applied=("Managed device", "Geo restriction"))
        allowed["parameters"]["CAA_DEVICE_STATE"] = "Managed"
        full_audit_data["caa_events"] = [allowed, _caa_event("ACCESS_LEVELS_EVALUATED", "DRIVE")]
        result = self._run(full_audit_data)
        assert result.status == Status.PASS
        assert "Managed device" in result.details and "applied on GMAIL" in result.details
        assert result.actual_value["device_signals"] == {"evaluations": 2, "with_device_signals": 1}

    def test_device_level_assigned_in_block_mode_passes(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["access_context"] = _acm(_DEVICE_LEVEL)
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Managed device"])]
        result = self._run(full_audit_data)
        assert result.status == Status.PASS and "active mode" in result.details

    def test_device_level_unassigned_or_monitor_is_review(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["access_context"] = _acm(_DEVICE_LEVEL)
        full_audit_data["admin_logs"] = []
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "no active-mode assignment" in result.details
        full_audit_data["admin_logs"] = [_assign("GMAIL", "MONITOR", ["Managed device"])]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "monitor mode only" in result.details

    def test_acm_with_only_geo_level_fails(self, full_audit_data):
        """Live tenant 2026-11-06: one geographic level, seven evaluations without device signals."""
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Geo restriction"])]
        full_audit_data["access_context"] = _acm(_GEO_LEVEL)
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")] * 3
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL
        assert "none of which requires device posture" in result.details
        assert "0 of 3 evaluation(s) carried device signals; deploy Endpoint Verification" in result.details
        full_audit_data["access_context"] = _acm()
        assert "no access level for the organisation" in self._run(full_audit_data).details

    def test_device_policy_without_requirements_is_not_device_based(self, full_audit_data):
        from gws_auditor.checks.additional import _access_level_requires_device
        assert not _access_level_requires_device({"basic": {"conditions": [{"devicePolicy": {}}]}})
        assert not _access_level_requires_device({"basic": {"conditions": [{"devicePolicy": {"requireScreenlock": False}}]}})
        assert _access_level_requires_device({"basic": {"conditions": [{"devicePolicy": {"requireCorpOwned": True}}]}})
        assert _access_level_requires_device({"basic": {"conditions": [{"devicePolicy": {"osConstraints": [{"osType": "DESKTOP_MAC"}]}}]}})
        assert _access_level_requires_device({"custom": {"expr": "device.encryption_status == DeviceEncryptionStatus.ENCRYPTED"}})
        assert not _access_level_requires_device({"custom": {"expr": "origin.region_code in ['AQ']"}})

    def test_nested_required_level_counts_as_device_based(self, full_audit_data):
        full_audit_data["caa_events"], full_audit_data["admin_logs"] = [], []
        wrapper = {"name": "accessPolicies/134654395911/accessLevels/wrapper", "title": "Wrapper",
                   "basic": {"conditions": [{"requiredAccessLevels": [_DEVICE_LEVEL["name"]]}]}}
        full_audit_data["access_context"] = _acm(_DEVICE_LEVEL, wrapper)
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["device_access_levels"] == ["Managed device", "Wrapper"]

    def test_live_update_event_feeds_the_admin_log_inventory(self, full_audit_data):
        """UPDATE_ACCESS_LEVEL_V2 as logged live 2026-11-06 23:31Z, with a MONITOR assignment -> MANUAL (monitor only)."""
        from tests.factories import make_admin_event
        full_audit_data["caa_events"] = []
        full_audit_data["admin_logs"] = [
            make_admin_event("UPDATE_ACCESS_LEVEL_V2", {
                "ACCESS_LEVEL_TITLE": "Device posture test",
                "ACCESS_LEVEL_NAME": "accessPolicies/134654395911/accessLevels/device_posture_test_b6fwshm4",
                "ACCESS_LEVEL_CURR_STATE": _UPDATE_CURR_STATE, "ACCESS_LEVEL_PREV_STATE": _UPDATE_PREV_STATE,
                "AUTH_PRINCIPLE_EMAIL": "admin@example.com"}, "2026-11-06T23:31:11.676Z"),
            _assign("TASKS", "MONITOR", ["Device posture test"], time="2026-11-06T23:32:54.501Z"),
        ]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["device_access_levels"] == ["Device posture test"]
        assert result.actual_value["inventory_source"] == "admin_log"
        assert "monitor mode only" in result.details
        full_audit_data["admin_logs"].append(_assign("TASKS", "BLOCK", ["Device posture test"], time="2026-11-06T23:40:00.000Z"))
        assert self._run(full_audit_data).status == Status.PASS

    def test_live_ou_scoped_sequence_and_monitor_evaluations(self, full_audit_data):
        """Flip 2026-11-06 23:32-23:35Z: device level MONITOR on the root OU, then WARN (geo level) + MONITOR
        (device level) on the Workspace Guests sub-OU; Tasks loads wrote MONITOR_MODE_ACCESS_EVALUATED_EVENT
        for the device level (CAA_DEVICE_STATE 'Normal') and ACCESS_LEVELS_EVALUATED for the geo level."""
        from tests.factories import make_admin_event
        full_audit_data["access_context"] = _acm(_GEO_LEVEL, {**_DEVICE_LEVEL, "title": "Device posture test"})
        guests = {"TARGET_ENTITY_TYPE": "ORG_UNIT", "TARGET_ENTITY_NAME": "Workspace Guests"}
        root_monitor = _assign("TASKS", "MONITOR", ["Device posture test"], time="2026-11-06T23:32:54.501Z")
        guests_warn = _assign("TASKS", "WARN", ["Geo restriction"], time="2026-11-06T23:35:26.577Z"); guests_warn["parameters"].update(guests)
        guests_monitor = _assign("TASKS", "MONITOR", ["Device posture test"], time="2026-11-06T23:35:26.577Z"); guests_monitor["parameters"].update(guests)
        full_audit_data["admin_logs"] = [root_monitor, guests_warn, guests_monitor]
        monitor_eval = _caa_event("MONITOR_MODE_ACCESS_EVALUATED_EVENT", "TASKS", applied=("Device posture test",), time="2026-11-06T23:33:12.328Z")
        monitor_eval["parameters"]["CAA_DEVICE_STATE"] = "Normal"
        full_audit_data["caa_events"] = [monitor_eval, _caa_event("ACCESS_LEVELS_EVALUATED", "TASKS", time="2026-11-06T23:33:12.328Z")]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert "monitor mode only" in result.details
        # the monitor-mode evaluation is not an evaluation of the device level, and its device signal is not counted
        assert result.actual_value["device_signals"] == {"evaluations": 1, "with_device_signals": 0}

    def test_sub_ou_removal_does_not_mask_root_assignment(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["access_context"] = _acm(_DEVICE_LEVEL)
        guests_block = _assign("GMAIL", "BLOCK", ["Managed device"], time="2026-11-06T23:35:00.000Z")
        guests_block["parameters"]["TARGET_ENTITY_NAME"] = "Workspace Guests"
        guests_removed = _assign("GMAIL", "BLOCK", ["Managed device"], time="2026-11-06T23:40:00.000Z", removed=True)
        guests_removed["parameters"]["TARGET_ENTITY_NAME"] = "Workspace Guests"
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Managed device"]), guests_block, guests_removed]
        assert self._run(full_audit_data).status == Status.PASS
        # the root removal, even if older than a sub-OU assignment, leaves only the sub-OU covered
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Managed device"]),
                                         _assign("GMAIL", "BLOCK", ["Managed device"], time="2026-11-06T23:30:00.000Z", removed=True), guests_block]
        assert self._run(full_audit_data).status == Status.PASS

    def test_caa_disabled_fails(self, full_audit_data):
        full_audit_data["caa_events"] = []
        full_audit_data["access_context"] = _acm(_DEVICE_LEVEL)
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Managed device"]), _toggle("DISABLED", "2026-11-06T19:00:00.000Z")]
        result = self._run(full_audit_data)
        assert result.status == Status.FAIL and "turned off" in result.details

    def test_without_acm_evaluations_of_unknown_levels_or_nothing_are_review(self, full_audit_data):
        full_audit_data["admin_logs"] = []
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL", applied=("Old level",))]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "Old level" in result.details
        full_audit_data["caa_events"] = []
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "not readable" in result.details


class TestCaaUnassignedLevels:
    """ADD-55 (unscored review)."""

    def _run(self, data):
        from gws_auditor.checks.additional import check_caa_unassigned_levels
        return check_caa_unassigned_levels(data)

    def test_all_levels_seen_passes(self, full_audit_data):
        full_audit_data["access_context"] = _acm(_GEO_LEVEL, _DEVICE_LEVEL)
        full_audit_data["admin_logs"] = [_assign("GMAIL", "MONITOR", ["Managed device"])]
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")]
        result = self._run(full_audit_data)
        assert result.status == Status.PASS and "All 2 access level(s)" in result.details

    def test_unseen_and_empty_levels_are_listed(self, full_audit_data):
        empty = {"name": "accessPolicies/134654395911/accessLevels/empty", "title": "Empty", "basic": {"conditions": []}}
        full_audit_data["access_context"] = _acm(_GEO_LEVEL, _DEVICE_LEVEL, empty)
        full_audit_data["admin_logs"] = [_assign("GMAIL", "BLOCK", ["Geo restriction"])]
        full_audit_data["caa_events"] = []
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["unassigned"] == ["Empty", "Managed device"]
        assert result.actual_value["without_condition"] == ["Empty"]
        assert "2 of 3 access level(s)" in result.details and "always satisfied" in result.details

    def test_admin_log_inventory_is_used_when_acm_not_collected(self, full_audit_data):
        from tests.factories import make_admin_event
        full_audit_data["caa_events"] = []
        full_audit_data["admin_logs"] = [make_admin_event("CREATE_ACCESS_LEVEL_V2", {
            "ACCESS_LEVEL_TITLE": "Geo restriction", "ACCESS_LEVEL_NAME": _LEVEL_NAME,
            "ACCESS_LEVEL_CURR_STATE": '{"basic": {"conditions": [{"regions": ["AQ"], "negate": true}]}, "title": "Geo restriction"}'},
            "2026-11-06T18:23:52.947Z")]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL and "admin-log window" in result.details
        assert result.actual_value["inventory_source"] == "admin_log"

    def test_no_level_known_is_not_applicable(self, full_audit_data):
        full_audit_data["caa_events"], full_audit_data["admin_logs"] = [], []
        assert self._run(full_audit_data).status == Status.NOT_APPLICABLE
        full_audit_data["access_context"] = _acm()
        result = self._run(full_audit_data)
        assert result.status == Status.NOT_APPLICABLE and "GWS.COMMONCONTROLS.2.1" in result.details


class TestCaaDenials:
    """ADD-56 (unscored review)."""

    def _run(self, data):
        from gws_auditor.checks.additional import check_caa_denials
        return check_caa_denials(data)

    def test_no_events_not_applicable_no_denials_pass(self, full_audit_data):
        full_audit_data["caa_events"] = []
        assert self._run(full_audit_data).status == Status.NOT_APPLICABLE
        full_audit_data["caa_events"] = [_caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")] * 2
        result = self._run(full_audit_data)
        assert result.status == Status.PASS and "No denial among 2" in result.details

    def test_denials_summarised_per_app_actor_region_and_level(self, full_audit_data):
        from tests.factories import make_user
        full_audit_data["users"] = [make_user("admin@example.com", is_admin=True), make_user("user@example.com")]
        denied = _caa_event("ACCESS_DENY_EVENT", "GMAIL", satisfied=(), unsatisfied=("Geo restriction",))
        denied["region_code"] = "AQ"
        admin_denied = _caa_event("ACCESS_DENY_EVENT", "DRIVE", satisfied=(), unsatisfied=("Geo restriction",))
        admin_denied["actor_email"], admin_denied["region_code"] = "admin@example.com", "BV"
        full_audit_data["caa_events"] = [denied, denied, admin_denied, _caa_event("ACCESS_LEVELS_EVALUATED", "GMAIL")]
        result = self._run(full_audit_data)
        assert result.status == Status.MANUAL
        assert result.actual_value["by_app"] == {"GMAIL": 2, "DRIVE": 1}
        assert result.actual_value["by_region"] == {"AQ": 2, "BV": 1}
        assert result.actual_value["by_unsatisfied_level"] == {"Geo restriction": 3}
        assert result.actual_value["super_admins_denied"] == ["admin@example.com"]
        assert "3 of 4" in result.details and "Super admin(s) denied: admin@example.com" in result.details

    def test_monitor_mode_events_are_ignored(self, full_audit_data):
        full_audit_data["caa_events"] = [_caa_event("MONITOR_MODE_ACCESS_DENY_EVENT", "GMAIL", satisfied=(), unsatisfied=("Geo restriction",))]
        assert self._run(full_audit_data).status == Status.NOT_APPLICABLE
