# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""SCuBA v1 policies whose control is also a CIS Benchmark recommendation (and the one CIS
recommendation whose control is a SCuBA policy).

Each check here is the SCuBA (or CIS) face of a setting another check already judges: the
verdict comes from the twin's logic, re-labelled with this id, title, level, standards mapping
and BOD 25-01 flag, so both frameworks report every policy they contain. Where the two
standards set different thresholds the check has its own judge (GWS.COMMONCONTROLS.6.2
allows up to eight super admins, GWS.COMMONCONTROLS.11.1 also requires
``allowAllInternalApps`` off, GWS.GMAIL.3.1 requires an SPF ``all`` mechanism or redirect).
GWS.COMMONCONTROLS.5.2 and 5.4 live in ``cisa_additions.py`` next to the other password controls.
"""

from collections.abc import Callable

from .additional import check_security_sandbox, check_takeout_restriction
from .apps_calendar import (
    check_cal_external_invitation_warning,
    check_primary_cal_external_sharing,
    check_secondary_cal_external_sharing,
)
from .apps_chat import check_chat_external_restriction
from .apps_drive import check_drive_domain_allowlist, check_drive_sdk
from .apps_gmail import (
    check_gmail_anomalous_attachment,
    check_gmail_auto_forwarding,
    check_gmail_comprehensive_storage,
    check_gmail_dkim,
    check_gmail_domain_spoofing,
    check_gmail_employee_spoofing,
    check_gmail_encrypted_attachment,
    check_gmail_external_recipient_warning,
    check_gmail_groups_spoofing,
    check_gmail_inbound_spoofing,
    check_gmail_linked_image_scanning,
    check_gmail_mail_delegation,
    check_gmail_outbound_gateway,
    check_gmail_pop_imap,
    check_gmail_predelivery_scanning,
    check_gmail_script_attachment,
    check_gmail_shortened_urls,
    check_gmail_unauthenticated_email,
    check_gmail_untrusted_link_warning,
    spf_findings,
)
from .apps_groups import check_groups_creation_restriction
from .base import check, field_value, get_ou_values, make_fail, make_manual, make_pass, make_review, ou_verdict
from .cisa_additions import check_chat_external_file_sharing
from .directory import super_admin_count_result
from .security_auth import check_2sv_all_users, check_less_secure_apps
from ..models import CheckResult


def _twin(func):
    return func._check_metadata


def same_as(data: dict, twin: Callable, *, check_id: str, title: str, level: str, source: str,
            section: str) -> CheckResult:
    """Run the twin check's own logic (not its decorator) and re-label the result.

    The twin's remediation is kept, its id is named in the details, and the surrounding
    ``@check`` decorator of the caller then applies this check's severity, scoring, licence gate,
    standards mapping and provenance note.
    """
    meta = _twin(twin)
    inner = twin.__wrapped__(data)
    details = (inner.details or "").rstrip()
    sep = "" if not details or details.endswith((".", "!", "?")) else "."
    return CheckResult(
        check_id=check_id, title=title, status=inner.status, level=level, source=source, section=section,
        details=f"{details}{sep} Same setting as {meta.check_id}.".strip(),
        actual_value=inner.actual_value, expected_value=inner.expected_value,
        remediation=inner.remediation or meta.remediation, org_unit=inner.org_unit,
    )


# ===========================================================================
# Calendar
# ===========================================================================

@check(
    check_id="GWS.CALENDAR.1.1",
    title="Ensure external sharing of primary calendars is limited to free/busy information",
    level="L1", source="CISA", section="Calendar",
    remediation=_twin(check_primary_cal_external_sharing).remediation,
)
def check_scuba_primary_calendar_sharing(data: dict) -> CheckResult:
    """SCuBA v1 GWS.CALENDAR.1.1 (SHALL, BOD 25-01) = CIS-3.1.1.1.1."""
    return same_as(data, check_primary_cal_external_sharing, check_id="GWS.CALENDAR.1.1",
                   title="Ensure external sharing of primary calendars is limited to free/busy information",
                   level="L1", source="CISA", section="Calendar")


@check(
    check_id="GWS.CALENDAR.1.2",
    title="Ensure external sharing of secondary calendars is limited to free/busy information",
    level="L1", source="CISA", section="Calendar",
    remediation=_twin(check_secondary_cal_external_sharing).remediation,
)
def check_scuba_secondary_calendar_sharing(data: dict) -> CheckResult:
    """SCuBA v1 GWS.CALENDAR.1.2 (SHALL, BOD 25-01) = CIS-3.1.1.2.1."""
    return same_as(data, check_secondary_cal_external_sharing, check_id="GWS.CALENDAR.1.2",
                   title="Ensure external sharing of secondary calendars is limited to free/busy information",
                   level="L1", source="CISA", section="Calendar")


@check(
    check_id="GWS.CALENDAR.2.1",
    title="Ensure external invitation warnings are enabled",
    level="L1", source="CISA", section="Calendar",
    remediation=_twin(check_cal_external_invitation_warning).remediation,
)
def check_scuba_external_invitation_warning(data: dict) -> CheckResult:
    """SCuBA v1 GWS.CALENDAR.2.1 (SHALL, BOD 25-01) = CIS-3.1.1.1.3."""
    return same_as(data, check_cal_external_invitation_warning, check_id="GWS.CALENDAR.2.1",
                   title="Ensure external invitation warnings are enabled",
                   level="L1", source="CISA", section="Calendar")


# ===========================================================================
# Chat
# ===========================================================================

@check(
    check_id="GWS.CHAT.4.1",
    title="Ensure external chat is restricted to allowlisted domains",
    level="L1", source="CISA", section="Google Chat", severity="HIGH",
    requires_license=_twin(check_chat_external_restriction).requires_license,
    remediation=_twin(check_chat_external_restriction).remediation,
)
def check_scuba_external_chat_restriction(data: dict) -> CheckResult:
    """SCuBA v1 GWS.CHAT.4.1 (SHALL, BOD 25-01) = CIS-3.1.4.2.1: external chat off, or
    ``externalChatRestriction`` = TRUSTED_DOMAINS."""
    return same_as(data, check_chat_external_restriction, check_id="GWS.CHAT.4.1",
                   title="Ensure external chat is restricted to allowlisted domains",
                   level="L1", source="CISA", section="Google Chat")


@check(
    check_id="CIS-3.1.4.1.1",
    title="Ensure external file sharing in Google Chat is disabled",
    level="L1", source="CIS", section="Google Chat", severity="HIGH",
    requires_license=_twin(check_chat_external_file_sharing).requires_license,
    remediation=_twin(check_chat_external_file_sharing).remediation,
)
def check_chat_external_file_sharing_cis(data: dict) -> CheckResult:
    """CIS 3.1.4.1.1 (L1): 'External filesharing' set to 'No files' = GWS.CHAT.2.1."""
    return same_as(data, check_chat_external_file_sharing, check_id="CIS-3.1.4.1.1",
                   title="Ensure external file sharing in Google Chat is disabled",
                   level="L1", source="CIS", section="Google Chat")


# ===========================================================================
# Common Controls
# ===========================================================================

@check(
    check_id="GWS.COMMONCONTROLS.1.2",
    title="Ensure an MFA method is enforced for all users",
    level="L1", source="CISA", section="Security", severity="HIGH",
    remediation=_twin(check_2sv_all_users).remediation,
)
def check_scuba_mfa_all_users(data: dict) -> CheckResult:
    """SCuBA v1 GWS.COMMONCONTROLS.1.2 (SHALL, BOD 25-01) = CIS-4.1.1.3: 2-Step Verification
    enforced for every user (GWS.COMMONCONTROLS.1.1 covers the phishing-resistant method)."""
    return same_as(data, check_2sv_all_users, check_id="GWS.COMMONCONTROLS.1.2",
                   title="Ensure an MFA method is enforced for all users",
                   level="L1", source="CISA", section="Security")


_SA_SCUBA_REMED = (
    "Admin console > Directory > Users, filter Admin role = Super admin. Keep between two and "
    "eight Super Admin accounts; list dedicated break-glass accounts in options.break_glass_accounts "
    "so they are reported but not counted. "
    "https://knowledge.workspace.google.com/admin/users/make-a-user-an-admin"
)


@check(
    check_id="GWS.COMMONCONTROLS.6.2",
    title="Ensure between two and eight super admin accounts are configured",
    level="L1", source="CISA", section="Directory", severity="HIGH",
    remediation=_SA_SCUBA_REMED,
)
def check_scuba_super_admin_count(data: dict) -> CheckResult:
    """SCuBA v1 GWS.COMMONCONTROLS.6.2 (SHALL, BOD 25-01): 2 to 8 super admins, break-glass
    accounts excluded. CIS-1.1.1 applies the benchmark's stricter 2-to-4 band."""
    excluded = tuple(str(e) for e in ((data.get("_options") or {}).get("break_glass_accounts") or []))
    return super_admin_count_result(
        data, check_id="GWS.COMMONCONTROLS.6.2",
        title="Ensure between two and eight super admin accounts are configured",
        level="L1", source="CISA", section="Directory", maximum=8, remediation=_SA_SCUBA_REMED,
        excluded=excluded,
    )


@check(
    check_id="GWS.COMMONCONTROLS.10.5",
    title="Ensure less secure app access is disabled",
    level="L1", source="CISA", section="Security", severity="HIGH",
    remediation=_twin(check_less_secure_apps).remediation,
)
def check_scuba_less_secure_apps(data: dict) -> CheckResult:
    """SCuBA v1 GWS.COMMONCONTROLS.10.5 (SHALL, BOD 25-01) = ADD-58 (the former CIS-4.2.6.1)."""
    return same_as(data, check_less_secure_apps, check_id="GWS.COMMONCONTROLS.10.5",
                   title="Ensure less secure app access is disabled",
                   level="L1", source="CISA", section="Security")


_MARKETPLACE_REMED = (
    "Admin console > Apps > Google Workspace Marketplace apps > Settings. Select 'Allow users to "
    "install and run allowlisted apps from the Marketplace' (or 'Don't allow users to install and "
    "run apps') and clear 'Allow users to install and run any internal app, even if it's not "
    "allowlisted'. https://knowledge.workspace.google.com/admin/apps/set-whether-users-can-install-marketplace-apps"
)
_MARKETPLACE_RESTRICTED = ("ALLOW_LISTED_APPS", "ALLOW_NONE")


@check(
    check_id="GWS.COMMONCONTROLS.11.1",
    title="Ensure only allowlisted Marketplace apps can be installed, including internal apps",
    level="L1", source="CISA", section="Marketplace", severity="HIGH",
    remediation=_MARKETPLACE_REMED,
)
def check_scuba_marketplace_allowlist(data: dict) -> CheckResult:
    """SCuBA v1 GWS.COMMONCONTROLS.11.1 (SHALL, BOD 25-01): ``accessLevel`` ALLOW_LISTED_APPS or
    ALLOW_NONE **and** ``allowAllInternalApps`` false. CIS-3.1.9.1.1 judges the access level only."""
    _ID = "GWS.COMMONCONTROLS.11.1"
    _TITLE = "Ensure only allowlisted Marketplace apps can be installed, including internal apps"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Marketplace")
    marketplace = data.get("policies", {}).get("marketplace", {})
    ou_values = get_ou_values(marketplace, "apps_access_options")
    if not ou_values:
        return make_review(
            **common, remediation=_MARKETPLACE_REMED,
            details="'workspace_marketplace.apps_access_options' was not returned by the Cloud Identity "
                    "Policy API — verify in Admin console.",
        )

    def judge(entry):
        level = field_value(entry, "accessLevel")
        allow_internal = field_value(entry, "allowAllInternalApps")
        if level is None:
            return None
        if str(level).upper() not in _MARKETPLACE_RESTRICTED:
            return False, level
        if allow_internal is True:
            return False, f"{level} but any internal app may be installed (allowAllInternalApps=True)"
        if allow_internal is None:
            return None
        return True, level

    return ou_verdict(
        ou_values, judge, **common,
        fail_text="allow Marketplace apps outside the allowlist",
        pass_text="restrict Marketplace installs to allowlisted apps, internal apps included",
        expected_value="ALLOW_LISTED_APPS or ALLOW_NONE with allowAllInternalApps=False for all OUs",
        remediation=_MARKETPLACE_REMED,
    )


@check(
    check_id="GWS.COMMONCONTROLS.12.1",
    title="Ensure Google Takeout is disabled",
    level="L1", source="CISA", section="Security",
    remediation=_twin(check_takeout_restriction).remediation,
)
def check_scuba_takeout_disabled(data: dict) -> CheckResult:
    """SCuBA v1 GWS.COMMONCONTROLS.12.1 (SHALL, BOD 25-01) = ADD-09: the Takeout service and
    every per-service user export off."""
    return same_as(data, check_takeout_restriction, check_id="GWS.COMMONCONTROLS.12.1",
                   title="Ensure Google Takeout is disabled",
                   level="L1", source="CISA", section="Security")


# ===========================================================================
# Drive and Docs
# ===========================================================================

@check(
    check_id="GWS.DRIVEDOCS.1.1",
    title="Ensure external Drive sharing is restricted to allowlisted domains",
    level="L1", source="CISA", section="Drive and Docs", severity="HIGH",
    remediation=_twin(check_drive_domain_allowlist).remediation,
)
def check_scuba_drive_external_sharing(data: dict) -> CheckResult:
    """SCuBA v1 GWS.DRIVEDOCS.1.1 (SHALL, BOD 25-01) = CIS-3.1.2.1.1.3: ``externalSharingMode``
    ALLOWLISTED_DOMAINS (or DISALLOWED, which the baseline text accepts as stricter)."""
    return same_as(data, check_drive_domain_allowlist, check_id="GWS.DRIVEDOCS.1.1",
                   title="Ensure external Drive sharing is restricted to allowlisted domains",
                   level="L1", source="CISA", section="Drive and Docs")


@check(
    check_id="GWS.DRIVEDOCS.4.1",
    title="Ensure Google Drive SDK access is disabled",
    level="L2", source="CISA", section="Drive and Docs",
    remediation=_twin(check_drive_sdk).remediation,
)
def check_scuba_drive_sdk(data: dict) -> CheckResult:
    """SCuBA v1 GWS.DRIVEDOCS.4.1 (SHOULD) = ADD-57 (the former CIS-3.1.2.2.3)."""
    return same_as(data, check_drive_sdk, check_id="GWS.DRIVEDOCS.4.1",
                   title="Ensure Google Drive SDK access is disabled",
                   level="L2", source="CISA", section="Drive and Docs")


# ===========================================================================
# Gmail
# ===========================================================================

def _gmail_twin(check_id: str, title: str, level: str, twin: Callable, severity: str = "",
                scored: bool = True, requires_license=""):
    """Register a Gmail SCuBA policy that re-labels its CIS twin's verdict."""
    meta = _twin(twin)

    def func(data: dict) -> CheckResult:
        return same_as(data, twin, check_id=check_id, title=title, level=level, source="CISA", section="Gmail")

    func.__name__ = f"check_scuba_{check_id.rsplit('.', 2)[-2]}_{check_id.rsplit('.', 1)[-1]}_" + twin.__name__.removeprefix("check_gmail_").removeprefix("check_")
    func.__doc__ = f"SCuBA v1 {check_id} = {meta.check_id}: {meta.title}."
    return check(check_id=check_id, title=title, level=level, source="CISA", section="Gmail",
                 severity=severity, scored=scored, requires_license=requires_license or meta.requires_license,
                 remediation=meta.remediation)(func)


check_scuba_1_1_mail_delegation = _gmail_twin(
    "GWS.GMAIL.1.1", "Ensure mail delegation is disabled", "L2", check_gmail_mail_delegation, severity="HIGH")
check_scuba_2_1_dkim = _gmail_twin(
    "GWS.GMAIL.2.1", "Ensure DKIM is enabled for all domains", "L2", check_gmail_dkim, severity="HIGH")
check_scuba_5_1_encrypted_attachment = _gmail_twin(
    "GWS.GMAIL.5.1", "Ensure protection against encrypted attachments from untrusted senders is enabled", "L1",
    check_gmail_encrypted_attachment, severity="HIGH")
check_scuba_5_2_script_attachment = _gmail_twin(
    "GWS.GMAIL.5.2", "Ensure protection against attachments with scripts from untrusted senders is enabled", "L1",
    check_gmail_script_attachment, severity="HIGH")
check_scuba_5_3_anomalous_attachment = _gmail_twin(
    "GWS.GMAIL.5.3", "Ensure protection against anomalous attachment types is enabled", "L1",
    check_gmail_anomalous_attachment, severity="HIGH")
check_scuba_6_1_shortened_urls = _gmail_twin(
    "GWS.GMAIL.6.1", "Ensure links behind shortened URLs are identified", "L1",
    check_gmail_shortened_urls, severity="HIGH")
check_scuba_6_2_linked_image_scanning = _gmail_twin(
    "GWS.GMAIL.6.2", "Ensure linked images are scanned", "L1",
    check_gmail_linked_image_scanning, severity="HIGH")
check_scuba_6_3_untrusted_link_warning = _gmail_twin(
    "GWS.GMAIL.6.3", "Ensure a warning prompt is shown for clicks on links to untrusted domains", "L1",
    check_gmail_untrusted_link_warning, severity="HIGH")
check_scuba_7_1_domain_spoofing = _gmail_twin(
    "GWS.GMAIL.7.1", "Ensure protection against domain spoofing based on similar domain names is enabled", "L1",
    check_gmail_domain_spoofing, severity="HIGH")
check_scuba_7_2_employee_spoofing = _gmail_twin(
    "GWS.GMAIL.7.2", "Ensure protection against spoofing of employee names is enabled", "L1",
    check_gmail_employee_spoofing, severity="HIGH")
check_scuba_7_3_inbound_spoofing = _gmail_twin(
    "GWS.GMAIL.7.3", "Ensure protection against inbound emails spoofing your domain is enabled", "L1",
    check_gmail_inbound_spoofing, severity="HIGH")
check_scuba_7_4_unauthenticated_email = _gmail_twin(
    "GWS.GMAIL.7.4", "Ensure protection against any unauthenticated emails is enabled", "L1",
    check_gmail_unauthenticated_email, severity="HIGH")
check_scuba_7_5_groups_spoofing = _gmail_twin(
    "GWS.GMAIL.7.5", "Ensure Groups are protected from inbound emails spoofing your domain", "L1",
    check_gmail_groups_spoofing, severity="HIGH")
check_scuba_9_1_pop_imap = _gmail_twin(
    "GWS.GMAIL.9.1", "Ensure POP and IMAP access are disabled", "L1", check_gmail_pop_imap, severity="HIGH")
check_scuba_11_1_auto_forwarding = _gmail_twin(
    "GWS.GMAIL.11.1", "Ensure automatic forwarding is disabled", "L2", check_gmail_auto_forwarding, severity="HIGH")
check_scuba_12_1_outbound_gateway = _gmail_twin(
    "GWS.GMAIL.12.1", "Ensure per-user outbound gateways are disabled", "L1", check_gmail_outbound_gateway)
check_scuba_13_1_external_recipient_warning = _gmail_twin(
    "GWS.GMAIL.13.1", "Ensure unintended external reply warnings are enabled", "L1",
    check_gmail_external_recipient_warning)
check_scuba_15_1_predelivery_scanning = _gmail_twin(
    "GWS.GMAIL.15.1", "Ensure enhanced pre-delivery message scanning is enabled", "L1",
    check_gmail_predelivery_scanning, severity="HIGH")
check_scuba_16_1_security_sandbox = _gmail_twin(
    "GWS.GMAIL.16.1", "Ensure the Security sandbox is enabled", "L2", check_security_sandbox, severity="HIGH")
check_scuba_17_1_comprehensive_storage = _gmail_twin(
    "GWS.GMAIL.17.1", "Ensure comprehensive mail storage is enabled", "L2", check_gmail_comprehensive_storage)


_SPF_REMED = (
    "Publish one 'v=spf1 ...' TXT record per domain that lists only the approved senders and ends in "
    "'-all' (or '~all'); a record with no 'all' mechanism or redirect fails no sender. "
    "https://knowledge.workspace.google.com/admin/security/set-up-spf"
)


@check(
    check_id="GWS.GMAIL.3.1",
    title="Ensure every domain publishes an SPF policy that fails non-approved senders",
    level="L1", source="CISA", section="Gmail", severity="HIGH",
    remediation=_SPF_REMED,
)
def check_scuba_spf_policy(data: dict) -> CheckResult:
    """SCuBA v1 GWS.GMAIL.3.1 (SHALL, BOD 25-01): one SPF record per domain ending in ``-all`` or
    ``~all`` (or delegating with ``redirect=``). Stricter than CIS-3.1.3.2.2, which accepts a record
    without an ``all`` mechanism and only warns on ``?all``."""
    _ID = "GWS.GMAIL.3.1"
    _TITLE = "Ensure every domain publishes an SPF policy that fails non-approved senders"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CISA", section="Gmail")
    domains = data.get("domains", [])
    if not domains:
        return make_manual(**common, details="No domains were collected, so no SPF record can be judged.",
                           remediation=_SPF_REMED)
    f = spf_findings(domains, data.get("dns_records", {}))
    problems = []
    if f["missing"]:
        problems.append(f"no SPF record: {', '.join(f['missing'])}")
    if f["duplicate"]:
        problems.append(f"more than one SPF record (permanent error for receivers): {', '.join(f['duplicate'])}")
    if f["permissive"]:
        problems.append(f"'+all' authorises every sender: {', '.join(f['permissive'])}")
    if f["neutral"]:
        problems.append(f"'?all' fails no sender: {', '.join(f['neutral'])}")
    if f["no_all"]:
        problems.append(f"no 'all' mechanism or redirect: {', '.join(f['no_all'])}")
    if problems:
        return make_fail(**common, details="SPF does not fail non-approved senders — " + "; ".join(problems) + ".",
                         actual_value={k: v for k, v in f.items() if v},
                         expected_value="One SPF record per domain ending in -all or ~all", remediation=_SPF_REMED)
    return make_pass(**common,
                     details=f"All {len(domains)} domain(s) publish a single SPF record ending in -all or ~all.",
                     actual_value={"domains_checked": len(domains)},
                     expected_value="One SPF record per domain ending in -all or ~all")


# ===========================================================================
# Groups
# ===========================================================================

@check(
    check_id="GWS.GROUPS.2.1",
    title="Ensure group creation is restricted to administrators",
    level="L2", source="CISA", section="Groups",
    remediation=_twin(check_groups_creation_restriction).remediation,
)
def check_scuba_group_creation(data: dict) -> CheckResult:
    """SCuBA v1 GWS.GROUPS.2.1 (SHOULD) = CIS-3.1.6.2: ``createGroupsAccessLevel`` ADMIN_ONLY."""
    return same_as(data, check_groups_creation_restriction, check_id="GWS.GROUPS.2.1",
                   title="Ensure group creation is restricted to administrators",
                   level="L2", source="CISA", section="Groups")
