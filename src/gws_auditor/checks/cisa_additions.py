# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CISA SCuBA baseline controls not covered by another check id.

Every check here reads a Cloud Identity Policy API field listed in
``tests/fixtures/policy_api_shapes.json``; pass/fail semantics follow the CISA
ScubaGoggles reference implementation. When the API does not return the setting
the result is MANUAL, never a guessed PASS or FAIL.
"""

from collections.abc import Callable

from .base import check, make_pass, make_fail, make_review, get_ou_values, format_ou_values_readable
from ..models import CheckResult


def _evaluate_setting(data: dict, category: str, setting_key: str, fields: tuple[str, ...],
                      unsafe_value: Callable[[dict], object | None], *,
                      check_id: str, title: str, level: str, section: str,
                      ok: str, bad: str, expected: str, remediation: str) -> CheckResult:
    """Judge one Policy API setting per OU.

    *unsafe_value* gets the setting's value dict and returns the offending value (shown in
    the report) or ``None`` when that OU is compliant. OUs where none of *fields* is present
    are undetermined; if that is every OU the result is MANUAL.
    """
    common = dict(check_id=check_id, title=title, level=level, source="CISA", section=section)
    entries = [e for e in get_ou_values(data.get("policies", {}).get(category, {}), setting_key)
               if any(f in e["value"] for f in fields)]
    if not entries:
        return make_review(
            **common, remediation=remediation,
            details=f"'{category}.{setting_key}' was not returned by the Cloud Identity Policy API — verify in Admin console.",
        )
    unsafe = [{"org_unit": e["org_unit"], "value": v}
              for e in entries if (v := unsafe_value(e["value"])) is not None]
    if unsafe:
        return make_fail(
            **common, remediation=remediation,
            details=f"{len(unsafe)} OU(s) {bad}: " + ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe),
            actual_value=format_ou_values_readable(unsafe), expected_value=expected,
        )
    return make_pass(
        **common, details=f"All {len(entries)} OU(s) {ok}.",
        actual_value=f"{len(entries)} OU(s) safe", expected_value=expected,
    )


# ── Chat ─────────────────────────────────────────────────────────────────

_CHAT_2_1_REMED = (
    "Admin console > Apps > Google Workspace > Google Chat > Chat File Sharing. "
    "Set External filesharing to 'No files'. https://knowledge.workspace.google.com/admin/chat/allow-users-to-share-files-in-chat"
)


@check(
    check_id="GWS.CHAT.2.1",
    title="Ensure external file sharing in Chat is disabled",
    level="L1", source="CISA", section="Google Chat", severity="HIGH",
    remediation=_CHAT_2_1_REMED,
)
def check_chat_external_file_sharing(data: dict) -> CheckResult:
    """External file sharing in Chat should be set to 'No files'."""
    return _evaluate_setting(
        data, "chat", "chat_file_sharing", ("externalFileSharing",),
        lambda v: None if v.get("externalFileSharing") == "NO_FILES" else v.get("externalFileSharing"),
        check_id="GWS.CHAT.2.1", title="Ensure external file sharing in Chat is disabled",
        level="L1", section="Google Chat",
        ok="block external file sharing in Chat", bad="allow files to be shared externally in Chat",
        expected="NO_FILES for all OUs", remediation=_CHAT_2_1_REMED,
    )


# ── Gmail ────────────────────────────────────────────────────────────────

_SPOOFING_CONSEQUENCES = (
    "domainSpoofingConsequence", "domainNameSpoofingConsequence", "employeeNameSpoofingConsequence",
    "groupsSpoofingConsequence", "unauthenticatedEmailConsequence",
)
_GMAIL_SAFETY_REMED = "Admin console > Apps > Google Workspace > Gmail > Safety. "


def _left_in_inbox(value: dict) -> str | None:
    kept = sorted(f"{f}={value[f]}" for f in _SPOOFING_CONSEQUENCES
                  if f in value and value[f] not in ("SPAM_FOLDER", "QUARANTINE"))
    return ", ".join(kept) or None


@check(
    check_id="GWS.GMAIL.7.6",
    title="Ensure spoofed and unauthenticated email is not kept in the inbox",
    level="L1", source="CISA", section="Gmail", severity="HIGH",
    remediation=_GMAIL_SAFETY_REMED + "Under Spoofing and authentication, set every action to 'Move email to spam' or 'Quarantine'.",
)
def check_gmail_spoofing_consequence(data: dict) -> CheckResult:
    """Mail flagged by the spoofing protections must be moved to spam or quarantined, not just warned about."""
    return _evaluate_setting(
        data, "gmail", "spoofing_and_authentication", _SPOOFING_CONSEQUENCES, _left_in_inbox,
        check_id="GWS.GMAIL.7.6", title="Ensure spoofed and unauthenticated email is not kept in the inbox",
        level="L1", section="Gmail",
        ok="move spoofed or unauthenticated email out of the inbox", bad="leave flagged email in the inbox",
        expected="SPAM_FOLDER or QUARANTINE for every spoofing protection",
        remediation=_GMAIL_SAFETY_REMED + "Under Spoofing and authentication, set every action to 'Move email to spam' or 'Quarantine'.",
    )


def _auto_apply_check(data: dict, check_id: str, title: str, setting_key: str, field: str, area: str) -> CheckResult:
    remediation = _GMAIL_SAFETY_REMED + f"Under {area}, enable 'Apply future recommended settings automatically'."
    return _evaluate_setting(
        data, "gmail", setting_key, (field,),
        lambda v: None if v.get(field) is True else v.get(field),
        check_id=check_id, title=title, level="L1", section="Gmail",
        ok="apply future recommended settings automatically",
        bad="do not apply future recommended settings automatically",
        expected="Enabled for all OUs", remediation=remediation,
    )


@check(
    check_id="GWS.GMAIL.5.4",
    title="Ensure future recommended attachment protections are applied automatically",
    level="L1", source="CISA", section="Gmail", severity="LOW",
    remediation=_GMAIL_SAFETY_REMED + "Under Attachments, enable 'Apply future recommended settings automatically'.",
)
def check_gmail_attachment_auto_apply(data: dict) -> CheckResult:
    """Google should be allowed to apply future recommended attachment settings automatically."""
    return _auto_apply_check(
        data, "GWS.GMAIL.5.4", "Ensure future recommended attachment protections are applied automatically",
        "email_attachment_safety", "applyFutureRecommendedSettingsAutomatically", "Attachments")


@check(
    check_id="GWS.GMAIL.6.4",
    title="Ensure future recommended link and image protections are applied automatically",
    level="L1", source="CISA", section="Gmail", severity="LOW",
    remediation=_GMAIL_SAFETY_REMED + "Under Links and external images, enable 'Apply future recommended settings automatically'.",
)
def check_gmail_links_auto_apply(data: dict) -> CheckResult:
    """Google should be allowed to apply future recommended link/image settings automatically."""
    return _auto_apply_check(
        data, "GWS.GMAIL.6.4", "Ensure future recommended link and image protections are applied automatically",
        "links_and_external_images", "applyFutureSettingsAutomatically", "Links and external images")


@check(
    check_id="GWS.GMAIL.7.7",
    title="Ensure future recommended spoofing protections are applied automatically",
    level="L1", source="CISA", section="Gmail", severity="LOW",
    remediation=_GMAIL_SAFETY_REMED + "Under Spoofing and authentication, enable 'Apply future recommended settings automatically'.",
)
def check_gmail_spoofing_auto_apply(data: dict) -> CheckResult:
    """Google should be allowed to apply future recommended spoofing settings automatically."""
    return _auto_apply_check(
        data, "GWS.GMAIL.7.7", "Ensure future recommended spoofing protections are applied automatically",
        "spoofing_and_authentication", "applyFutureSettingsAutomatically", "Spoofing and authentication")


# ── Common Controls: MFA and passwords ───────────────────────────────────

_MFA_REMED = (
    "Admin console > Security > Authentication > 2-step verification. Turn on enforcement and set "
    "Methods to 'Only security key'. https://knowledge.workspace.google.com/admin/security/deploy-2-step-verification"
)


@check(
    check_id="GWS.COMMONCONTROLS.1.1",
    title="Ensure phishing-resistant MFA is required for all users",
    level="L2", source="CISA", section="Security", severity="HIGH",
    remediation=_MFA_REMED,
)
def check_phishing_resistant_mfa(data: dict) -> CheckResult:
    """2SV should be enforced with passkeys/security keys only (no codes, prompts or telephony)."""
    common = dict(check_id="GWS.COMMONCONTROLS.1.1", title="Ensure phishing-resistant MFA is required for all users",
                  level="L2", source="CISA", section="Security")
    security = data.get("policies", {}).get("security", {})
    factors = {e["org_unit"]: e["value"].get("allowedSignInFactorSet")
               for e in get_ou_values(security, "two_step_verification_enforcement_factor")
               if e["value"].get("allowedSignInFactorSet") is not None}
    enforced = {e["org_unit"]: bool(e["value"].get("enforcedFrom"))
                for e in get_ou_values(security, "two_step_verification_enforcement")}
    if not factors:
        return make_review(**common, remediation=_MFA_REMED,
                           details="2-step verification method policy was not returned by the Policy API — verify in Admin console.")
    unsafe = []
    for ou, factor in factors.items():
        if factor != "PASSKEY_ONLY":
            unsafe.append({"org_unit": ou, "value": factor})
        elif not enforced.get(ou, enforced.get("/", False)):
            unsafe.append({"org_unit": ou, "value": "PASSKEY_ONLY but 2SV not enforced"})
    if unsafe:
        return make_fail(
            **common, remediation=_MFA_REMED,
            details=f"{len(unsafe)} OU(s) do not require phishing-resistant MFA: "
                    + ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe),
            actual_value=format_ou_values_readable(unsafe), expected_value="PASSKEY_ONLY with 2SV enforced",
        )
    return make_pass(**common, details=f"All {len(factors)} OU(s) enforce 2SV with security keys/passkeys only.",
                     actual_value=f"{len(factors)} OU(s) safe", expected_value="PASSKEY_ONLY with 2SV enforced")


_SA_RECOVERY_REMED = (
    "Admin console > Security > Authentication > Account recovery > Super admin account recovery. "
    "Turn off 'Allow super admins to recover their account'. "
    "https://knowledge.workspace.google.com/admin/security/set-up-password-recovery-for-users"
)


@check(
    check_id="GWS.COMMONCONTROLS.8.1",
    title="Ensure super admin account self-recovery is disabled",
    level="L1", source="CISA", section="Security",
    remediation=_SA_RECOVERY_REMED,
)
def check_super_admin_recovery_disabled(data: dict) -> CheckResult:
    """Self-service recovery lets an attacker who controls a recovery email/phone take over a super admin."""
    return _evaluate_setting(
        data, "security", "super_admin_account_recovery", ("enableAccountRecovery",),
        lambda v: None if v.get("enableAccountRecovery") is False else v.get("enableAccountRecovery"),
        check_id="GWS.COMMONCONTROLS.8.1", title="Ensure super admin account self-recovery is disabled",
        level="L1", section="Security",
        ok="disable super admin self-recovery", bad="allow super admins to recover their own account",
        expected="Disabled for all OUs", remediation=_SA_RECOVERY_REMED,
    )


_PW_REMED = "Admin console > Security > Authentication > Password management. "


def _password_check(data, check_id, title, level, field, unsafe_value, ok, bad, expected, how) -> CheckResult:
    return _evaluate_setting(
        data, "security", "password", (field,), unsafe_value,
        check_id=check_id, title=title, level=level, section="Security",
        ok=ok, bad=bad, expected=expected, remediation=_PW_REMED + how,
    )


@check(
    check_id="GWS.COMMONCONTROLS.5.1",
    title="Ensure strong password strength is enforced",
    level="L1", source="CISA", section="Security",
    remediation=_PW_REMED + "Select 'Enforce strong password'.",
)
def check_password_strength(data: dict) -> CheckResult:
    """Password strength enforcement should be STRONG."""
    return _password_check(
        data, "GWS.COMMONCONTROLS.5.1", "Ensure strong password strength is enforced", "L1", "allowedStrength",
        lambda v: None if str(v.get("allowedStrength", "")).upper() == "STRONG" else v.get("allowedStrength"),
        "enforce strong passwords", "do not enforce strong passwords", "STRONG for all OUs",
        "Select 'Enforce strong password'.")


@check(
    check_id="GWS.COMMONCONTROLS.5.3",
    title="Ensure minimum password length is at least 15 characters",
    level="L2", source="CISA", section="Security", severity="LOW",
    remediation=_PW_REMED + "Set the minimum length to 15 or more.",
)
def check_password_length_15(data: dict) -> CheckResult:
    """SCuBA recommends (SHOULD) a 15-character minimum; CIS-4.1.5.1 covers the 12-character SHALL."""
    return _password_check(
        data, "GWS.COMMONCONTROLS.5.3", "Ensure minimum password length is at least 15 characters", "L2", "minimumLength",
        lambda v: None if int(v.get("minimumLength") or 0) >= 15 else v.get("minimumLength"),
        "require passwords of 15+ characters", "allow passwords shorter than 15 characters", ">= 15 for all OUs",
        "Set the minimum length to 15 or more.")


@check(
    check_id="GWS.COMMONCONTROLS.5.5",
    title="Ensure password reuse is not allowed",
    level="L1", source="CISA", section="Security",
    remediation=_PW_REMED + "Clear 'Allow password reuse'.",
)
def check_password_reuse(data: dict) -> CheckResult:
    """Users should not be able to reuse a previous password."""
    return _password_check(
        data, "GWS.COMMONCONTROLS.5.5", "Ensure password reuse is not allowed", "L1", "allowReuse",
        lambda v: None if v.get("allowReuse") is False else v.get("allowReuse"),
        "disallow password reuse", "allow password reuse", "Disabled for all OUs",
        "Clear 'Allow password reuse'.")


@check(
    check_id="GWS.COMMONCONTROLS.5.6",
    title="Ensure passwords are not set to expire",
    level="L1", source="CISA", section="Security", severity="LOW",
    remediation=_PW_REMED + "Set Expiration to 'Never expires' (NIST SP 800-63B: rotate on compromise, not on a schedule).",
)
def check_password_no_expiry(data: dict) -> CheckResult:
    """Forced periodic expiry leads to weaker passwords; SCuBA requires 'never expires'."""
    def _expires(v: dict):
        duration = str(v.get("expirationDuration") or "0s")
        return None if duration.rstrip("s") in ("0", "0.0", "") else duration
    return _password_check(
        data, "GWS.COMMONCONTROLS.5.6", "Ensure passwords are not set to expire", "L1", "expirationDuration",
        _expires, "never expire passwords", "force periodic password expiry", "Never expires (0s) for all OUs",
        "Set Expiration to 'Never expires'.")


# ── Drive: Forms (SCuBA classifies both as manual; the API does not expose them) ──

def _forms_manual(check_id: str, title: str, guidance: str) -> CheckResult:
    return make_review(
        check_id=check_id, title=title, level="L2", source="CISA", section="Drive and Docs",
        details="Google Forms response settings are not exposed by the Cloud Identity Policy API or the admin "
                "audit log; CISA SCuBA also lists this control as a manual check. " + guidance,
        remediation=guidance,
    )


@check(
    check_id="GWS.DRIVEDOCS.1.10",
    title="Ensure forms cannot accept external responses when external sharing is off",
    level="L2", source="CISA", section="Drive and Docs", severity="LOW",
    remediation="Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings > Sharing options.",
)
def check_forms_external_responses(data: dict) -> CheckResult:
    """Manual: forms owned by the organization should not accept responses from outside it."""
    return _forms_manual(
        "GWS.DRIVEDOCS.1.10", "Ensure forms cannot accept external responses when external sharing is off",
        "Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings > Sharing options: if sharing "
        "outside the organization is OFF, confirm forms cannot accept external responses.")


@check(
    check_id="GWS.DRIVEDOCS.1.11",
    title="Ensure users cannot respond to external forms when receiving files is off",
    level="L2", source="CISA", section="Drive and Docs", severity="LOW",
    remediation="Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings > Sharing options.",
)
def check_forms_external_submission(data: dict) -> CheckResult:
    """Manual: users should not submit responses to forms owned outside the organization."""
    return _forms_manual(
        "GWS.DRIVEDOCS.1.11", "Ensure users cannot respond to external forms when receiving files is off",
        "Admin console > Apps > Google Workspace > Drive and Docs > Sharing settings > Sharing options: if receiving "
        "files from outside the organization is OFF, confirm users cannot submit responses to external forms.")
