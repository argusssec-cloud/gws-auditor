# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Additional checks on accounts, groups, devices, admin roles, mail transport and licensing.

These evaluate collected inventory (users, groups, devices, roles, DNS, licences) rather than
tenant policy settings. When the data needed was not collected the result is ERROR/MANUAL,
never a PASS.
"""

import re
from datetime import datetime, timedelta, timezone

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   field_value, ou_verdict, user_usage_by_email)
from ..constants import EDITIONS_ADMIN_ROLE_CONDITIONS
from ..models import CheckResult

_NEVER = datetime(1971, 1, 1, tzinfo=timezone.utc)  # Directory API reports "never" as 1970-01-01


def _parse(ts) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).rstrip("Z").split(".")[0]).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _now(data: dict) -> datetime:
    """Audit time: the collection timestamp when re-running on a cache, else the current time."""
    collected = data.get("collection_timestamp")
    try:
        parsed = datetime.fromisoformat(str(collected)) if collected else None
    except ValueError:
        parsed = None
    if parsed is None:
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _inactive_since(user: dict, cutoff: datetime) -> str | None:
    """Return a label when *user* has not signed in since *cutoff* (or ever), else None."""
    last = _parse(user.get("last_login_time"))
    if last is None or last < _NEVER:
        return "never signed in"
    return f"last sign-in {last.date()}" if last < cutoff else None


def _has_api_error(data: dict, *operations: str) -> bool:
    return any(isinstance(e, dict) and e.get("operation") in operations for e in data.get("api_errors", []))


# ── Accounts ─────────────────────────────────────────────────────────────

@check(
    check_id="ADD-42",
    title="Ensure super admin accounts are actively used or removed",
    level="L1", source="OTHER", section="Directory", severity="HIGH",
    remediation=(
        "Admin console > Directory > Users. Remove the super admin role from accounts that are no longer "
        "used, or delete them: a dormant super admin is a standing takeover target that nobody is watching."
    ),
)
def check_stale_super_admins(data: dict) -> CheckResult:
    """Active super admins that have not signed in recently (or ever)."""
    common = dict(check_id="ADD-42", title="Ensure super admin accounts are actively used or removed",
                  level="L1", source="OTHER", section="Directory")
    admins = [u for u in data.get("users", []) if u.get("is_super_admin") and not u.get("suspended")]
    if not admins:
        return make_manual(**common, details="No active super admin accounts were found in the collected users.")
    days = data.get("_options", {}).get("user_inactive_days", 90)
    cutoff = _now(data) - timedelta(days=days)
    stale = sorted(f"{u.get('primary_email', 'unknown')} ({why})"
                   for u in admins if (why := _inactive_since(u, cutoff)))
    if stale:
        return make_fail(
            **common,
            details=f"{len(stale)} of {len(admins)} super admin(s) have not signed in for {days}+ days: {', '.join(stale)}",
            actual_value={"stale_super_admins": stale}, expected_value=f"All super admins active within {days} days",
        )
    return make_pass(**common, details=f"All {len(admins)} super admin(s) signed in within the last {days} days.",
                     actual_value={"stale_super_admins": []}, expected_value=f"All super admins active within {days} days")


@check(
    check_id="ADD-43",
    title="Ensure suspended users do not hold admin roles",
    level="L1", source="OTHER", section="Directory",
    remediation=(
        "Admin console > Directory > Users. Revoke admin roles from suspended accounts: un-suspending the "
        "account (for example through a compromised helpdesk admin) restores the privileges immediately."
    ),
)
def check_suspended_admins(data: dict) -> CheckResult:
    """Suspended accounts that still carry super admin or delegated admin privileges."""
    common = dict(check_id="ADD-43", title="Ensure suspended users do not hold admin roles",
                  level="L1", source="OTHER", section="Directory")
    users = data.get("users", [])
    if not users:
        return make_manual(**common, details="No user data was collected.")
    flagged = sorted(
        f"{u.get('primary_email', 'unknown')} ({'super admin' if u.get('is_super_admin') else 'delegated admin'})"
        for u in users
        if u.get("suspended") and (u.get("is_super_admin") or u.get("is_admin") or u.get("is_delegated_admin")))
    if flagged:
        return make_fail(**common, details=f"{len(flagged)} suspended account(s) still hold admin roles: {', '.join(flagged)}",
                         actual_value={"suspended_admins": flagged}, expected_value="No suspended account holds an admin role")
    return make_pass(**common, details="No suspended account holds an admin role.",
                     actual_value={"suspended_admins": []}, expected_value="No suspended account holds an admin role")


@check(
    check_id="ADD-44",
    title="Review active user accounts with no recent sign-in",
    level="L2", source="OTHER", section="Directory", severity="LOW", scored=False,
    remediation="Admin console > Directory > Users. Suspend or delete accounts that are no longer needed and reclaim their licences.",
)
def check_stale_users(data: dict) -> CheckResult:
    """Inventory of active (non-suspended, non-archived) accounts without a recent sign-in."""
    common = dict(check_id="ADD-44", title="Review active user accounts with no recent sign-in",
                  level="L2", source="OTHER", section="Directory")
    active = [u for u in data.get("users", []) if not u.get("suspended") and not u.get("archived")]
    if not active:
        return make_manual(**common, details="No active user data was collected.")
    days = data.get("_options", {}).get("user_inactive_days", 90)
    cutoff = _now(data) - timedelta(days=days)
    stale = sorted(f"{u.get('primary_email', 'unknown')} ({why})" for u in active if (why := _inactive_since(u, cutoff)))
    if stale:
        return make_warn(
            **common,
            details=f"{len(stale)} of {len(active)} active account(s) have not signed in for {days}+ days: "
                    + ", ".join(stale[:15]) + ("..." if len(stale) > 15 else ""),
            actual_value={"stale_user_count": len(stale), "stale_users": stale},
            expected_value=f"All active accounts used within {days} days",
        )
    return make_pass(**common, details=f"All {len(active)} active account(s) signed in within the last {days} days.",
                     actual_value={"stale_user_count": 0}, expected_value=f"All active accounts used within {days} days")


@check(
    check_id="ADD-52",
    title="Review active users without a Google Workspace licence",
    level="L2", source="OTHER", section="Directory", severity="LOW", scored=False,
    remediation=(
        "Admin console > Billing > Licence settings. Unlicensed accounts fall back to reduced security and audit "
        "coverage (for example shorter log retention and no Vault); assign a licence or remove the account."
    ),
)
def check_unlicensed_users(data: dict) -> CheckResult:
    """Inventory of active accounts that hold no Workspace licence."""
    common = dict(check_id="ADD-52", title="Review active users without a Google Workspace licence",
                  level="L2", source="OTHER", section="Directory")
    licensed = (data.get("subscription_info") or {}).get("licensed_users")
    if not licensed:
        return make_review(**common, details="Per-user licence assignments were not collected (Licensing API unavailable "
                                             "or an older cache) — review in Admin console > Billing.")
    licensed = {str(x).lower() for x in licensed}
    unlicensed = sorted(u.get("primary_email", "unknown") for u in data.get("users", [])
                        if not u.get("suspended") and not u.get("archived")
                        and str(u.get("primary_email", "")).lower() not in licensed)
    if unlicensed:
        return make_warn(**common,
                         details=f"{len(unlicensed)} active account(s) hold no Workspace licence: "
                                 + ", ".join(unlicensed[:15]) + ("..." if len(unlicensed) > 15 else ""),
                         actual_value={"unlicensed_users": unlicensed}, expected_value="Every active account licensed")
    return make_pass(**common, details="Every active account holds a Workspace licence.",
                     actual_value={"unlicensed_users": []}, expected_value="Every active account licensed")


# ── Chat and Groups ──────────────────────────────────────────────────────

@check(
    check_id="ADD-45",
    title="Ensure Chat spaces with external members are restricted",
    level="L2", source="OTHER", section="Google Chat",
    remediation=(
        "Admin console > Apps > Google Workspace > Google Chat > External Spaces & Group Direct Messages. Turn external spaces off, or "
        "limit them to allowlisted domains. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
    ),
)
def check_chat_external_spaces(data: dict) -> CheckResult:
    """Users should not be able to create or join spaces with people from any outside domain."""
    common = dict(check_id="ADD-45", title="Ensure Chat spaces with external members are restricted",
                  level="L2", source="OTHER", section="Google Chat")
    ou_values = get_ou_values(data.get("policies", {}).get("chat", {}), "chat_external_spaces")
    if not ou_values:
        return make_review(**common, details="'chat.chat_external_spaces' was not returned by the Policy API — verify in Admin console.")

    def _judge(entry):
        enabled = field_value(entry, "enabled")
        if enabled is None:
            return None
        if enabled is not True:
            return True, "disabled"
        mode = field_value(entry, "domainAllowlistMode")
        if mode is None:
            return None  # no documented default: cannot tell ALL_DOMAINS from an allowlist
        return mode != "ALL_DOMAINS", f"enabled, {mode}"
    return ou_verdict(
        ou_values, _judge, **common,
        fail_text="allow Chat spaces with members from any domain",
        pass_text="disable external spaces or limit them to allowlisted domains",
        expected_value="External spaces off or limited to allowlisted domains",
        remediation=(
            "Admin console > Apps > Google Workspace > Google Chat > External Spaces & Group Direct Messages. Turn external spaces off, or "
            "limit them to allowlisted domains. https://knowledge.workspace.google.com/admin/chat/control-external-chat-and-spaces-chat-options"
        ),
    )


@check(
    check_id="ADD-46",
    title="Ensure groups cannot be joined by anyone on the internet",
    level="L1", source="GOOGLE", section="Groups",
    remediation=(
        "Google Groups > group > Group settings. Set 'Who can join group' to invited users or organization "
        "members, and turn off 'Allow external members' unless the group exists for outside collaboration. "
        "A group is often an access-control principal for Drive, Calendar and cloud resources."
    ),
)
def check_open_groups(data: dict) -> CheckResult:
    """Per-group join settings: open-to-the-internet groups fail; groups allowing external members are flagged."""
    common = dict(check_id="ADD-46", title="Ensure groups cannot be joined by anyone on the internet",
                  level="L1", source="GOOGLE", section="Groups")
    with_settings = [g for g in data.get("groups", []) if isinstance(g.get("settings"), dict) and g["settings"]]
    if not with_settings:
        return make_manual(**common, details="No per-group settings were collected (Groups Settings API).")
    anyone = sorted(g.get("email", "unknown") for g in with_settings if g["settings"].get("whoCanJoin") == "ANYONE_CAN_JOIN")
    external = sorted(g.get("email", "unknown") for g in with_settings
                      if str(g["settings"].get("allowExternalMembers")).lower() == "true" and g.get("email") not in anyone)
    value = {"anyone_can_join": anyone, "external_members_allowed": external, "groups_checked": len(with_settings)}
    expected = "No group joinable by anyone; external members only where intended"
    if anyone:
        return make_fail(**common, details=f"{len(anyone)} group(s) can be joined by anyone on the internet: {', '.join(anyone[:15])}",
                         actual_value=value, expected_value=expected)
    if external:
        return make_warn(**common, details=f"{len(external)} group(s) allow external members — confirm each is intended: {', '.join(external[:15])}",
                         actual_value=value, expected_value=expected)
    return make_pass(**common, details=f"None of the {len(with_settings)} groups is open to the internet or to external members.",
                     actual_value=value, expected_value=expected)


# ── Devices ──────────────────────────────────────────────────────────────

def _device_problems(device: dict) -> list[str]:
    """Posture problems on a device using the documented Directory / Cloud Identity device fields."""
    problems = []
    if str(device.get("compromisedState", device.get("deviceCompromisedStatus", ""))).upper() == "COMPROMISED":
        problems.append("compromised")
    if str(device.get("encryptionState", "")).upper() == "NOT_ENCRYPTED" or \
            str(device.get("encryptionStatus", "")).lower() in ("not encrypted", "unencrypted"):
        problems.append("not encrypted")
    if str(device.get("devicePasswordStatus", "")).lower() == "off":
        problems.append("no screen lock")
    return problems


_POSTURE_FIELDS = ("compromisedState", "deviceCompromisedStatus", "encryptionState", "encryptionStatus", "devicePasswordStatus")


@check(
    check_id="ADD-47",
    title="Ensure compromised, unencrypted or unlocked devices do not keep access",
    level="L1", source="OTHER", section="Security", severity="HIGH",
    remediation=(
        "Admin console > Devices > Mobile & endpoints. Block or wipe the listed devices, and under Universal "
        "settings require a screen lock and encryption and block compromised devices."
    ),
)
def check_device_posture(data: dict) -> CheckResult:
    """Devices that report a bad posture while still approved for access to company data."""
    common = dict(check_id="ADD-47", title="Ensure compromised, unencrypted or unlocked devices do not keep access",
                  level="L1", source="OTHER", section="Security")
    devices = list(data.get("mobile_devices") or []) + list(data.get("endpoint_devices") or [])
    reporting = [d for d in devices if isinstance(d, dict) and any(f in d for f in _POSTURE_FIELDS)]
    if not reporting:
        return make_review(**common, details=f"{len(devices)} device(s) collected, none reports posture attributes (requires "
                                             "advanced mobile management / endpoint verification) — review in Admin console > Devices.")
    blocked_states = ("BLOCKED", "WIPED", "WIPING", "UNPROVISIONED", "DELETED")
    flagged = []
    for d in reporting:
        state = str(d.get("managementState", d.get("status", ""))).upper()
        problems = _device_problems(d)
        if problems and state not in blocked_states:
            flagged.append(f"{d.get('model', d.get('deviceId', 'device'))} [{', '.join(problems)}]")
    if flagged:
        return make_fail(**common, details=f"{len(flagged)} device(s) with a bad security posture still have access: "
                                           + ", ".join(sorted(flagged)[:15]),
                         actual_value={"devices_at_risk": sorted(flagged), "devices_reporting": len(reporting)},
                         expected_value="No compromised, unencrypted or unlocked device with access")
    return make_pass(**common, details=f"None of the {len(reporting)} device(s) reporting posture is compromised, unencrypted or unlocked.",
                     actual_value={"devices_at_risk": [], "devices_reporting": len(reporting)},
                     expected_value="No compromised, unencrypted or unlocked device with access")


# ── Admin roles ──────────────────────────────────────────────────────────

# Directory API privilege names are service-defined strings; match by pattern, not an exact list.
_POWERFUL_PRIVILEGE = re.compile(r"^(USERS?_(ALL|CREATE|UPDATE|DELETE|SECURITY)|USER_SECURITY|ROLE|ORGANIZATION_UNITS_(ALL|UPDATE)"
                                 r"|GROUPS_(ALL|UPDATE)|DOMAIN_MANAGEMENT|SECURITY_SETTINGS|APP_ADMIN|SERVICES)", re.I)
_VAULT_PRIVILEGE = re.compile(r"VAULT|MATTER|(^|_)HOLDS?($|_)|EXPORT|RETENTION", re.I)


def _roles(data: dict, common: dict):
    roles = data.get("roles")
    if not isinstance(roles, dict) or "roles" not in roles:
        return None, make_manual(**common, details="Admin roles were not collected.")
    if _has_api_error(data, "list_roles", "list_role_assignments"):
        return None, make_manual(**common, details="Admin roles could not be fully enumerated (API error).")
    return roles, None


def _assignee_counts(roles: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in roles.get("assignments", []):
        counts[str(a.get("roleId"))] = counts.get(str(a.get("roleId")), 0) + 1
    return counts


def _privileges(role: dict) -> list[str]:
    return [str(p.get("privilegeName", "")) for p in role.get("rolePrivileges", []) if isinstance(p, dict)]


@check(
    check_id="ADD-48",
    title="Review custom admin roles with account-takeover privileges",
    level="L2", source="OTHER", section="Security",
    remediation=(
        "Admin console > Account > Admin roles. For each listed custom role, remove privileges that allow "
        "resetting passwords, changing security settings, managing roles or editing users unless the role needs "
        "them: those privileges let a holder take over other accounts, including super admins."
    ),
)
def check_powerful_custom_roles(data: dict) -> CheckResult:
    """Custom (non-system) roles that are assigned and carry user/security/role-management privileges."""
    common = dict(check_id="ADD-48", title="Review custom admin roles with account-takeover privileges",
                  level="L2", source="OTHER", section="Security")
    roles, problem = _roles(data, common)
    if problem:
        return problem
    assigned = _assignee_counts(roles)
    flagged = []
    for role in roles["roles"]:
        if role.get("isSystemRole") or role.get("isSuperAdminRole"):
            continue
        powerful = sorted({p for p in _privileges(role) if _POWERFUL_PRIVILEGE.search(p)})
        holders = assigned.get(str(role.get("roleId")), 0)
        if powerful and holders:
            flagged.append(f"{role.get('roleName', role.get('roleId'))} ({holders} assignee(s): {', '.join(powerful[:6])})")
    if flagged:
        return make_warn(**common, details=f"{len(flagged)} custom role(s) grant account-takeover privileges: {'; '.join(sorted(flagged))}",
                         actual_value={"powerful_custom_roles": sorted(flagged)}, expected_value="Custom roles follow least privilege")
    return make_pass(**common, details="No assigned custom role grants user, security or role-management privileges.",
                     actual_value={"powerful_custom_roles": []}, expected_value="Custom roles follow least privilege")


@check(
    check_id="ADD-49",
    title="Review who holds Google Vault privileges",
    level="L2", source="GOOGLE", section="Security", severity="LOW", scored=False,
    remediation=(
        "Admin console > Account > Admin roles. Vault privileges (matters, holds, searches, exports, retention) give "
        "access to every user's mail and files and can destroy data through retention rules — keep holders to the minimum."
    ),
)
def check_vault_privilege_holders(data: dict) -> CheckResult:
    """Inventory of assigned roles that carry Vault privileges."""
    common = dict(check_id="ADD-49", title="Review who holds Google Vault privileges",
                  level="L2", source="GOOGLE", section="Security")
    roles, problem = _roles(data, common)
    if problem:
        return problem
    assigned = _assignee_counts(roles)
    holders = sorted(
        f"{role.get('roleName', role.get('roleId'))} ({assigned[str(role.get('roleId'))]} assignee(s))"
        for role in roles["roles"]
        if not role.get("isSuperAdminRole") and assigned.get(str(role.get("roleId")))
        and any(_VAULT_PRIVILEGE.search(p) for p in _privileges(role)))
    if holders:
        return make_warn(**common, details=f"{len(holders)} assigned role(s) carry Vault privileges — confirm each holder: {'; '.join(holders)}",
                         actual_value={"vault_roles": holders}, expected_value="Vault access limited to named legal/compliance staff")
    return make_pass(**common, details="No assigned role other than super admin carries Vault privileges.",
                     actual_value={"vault_roles": []}, expected_value="Vault access limited to named legal/compliance staff")


# ── Mail transport and forwarding ────────────────────────────────────────

@check(
    check_id="ADD-50",
    title="Ensure MTA-STS is published for all mail domains",
    level="L2", source="OTHER", section="Gmail",
    remediation=(
        "Publish a '_mta-sts.<domain>' TXT record (v=STSv1; id=...) and host the policy at "
        "https://mta-sts.<domain>/.well-known/mta-sts.txt with mode: enforce; add a '_smtp._tls.<domain>' TLS-RPT "
        "record to receive failure reports. https://knowledge.workspace.google.com/admin/gmail/advanced/turn-on-mta-sts-and-tls-reporting"
    ),
)
def check_mta_sts(data: dict) -> CheckResult:
    """Without MTA-STS, inbound SMTP TLS can be stripped by a network attacker (downgrade)."""
    common = dict(check_id="ADD-50", title="Ensure MTA-STS is published for all mail domains",
                  level="L2", source="OTHER", section="Gmail")
    dns_records = data.get("dns_records") or {}
    checked = {d: r for d, r in dns_records.items() if isinstance(r, dict) and isinstance(r.get("mta_sts"), dict)}
    if not checked:
        return make_review(**common, details="MTA-STS records were not collected (older cache or DNS lookups unavailable).")
    # Only domains that receive mail need a policy
    mail_domains = {d: r for d, r in checked.items() if r.get("mx")} or checked
    missing = sorted(d for d, r in mail_domains.items() if not r["mta_sts"].get("record_found", r["mta_sts"].get("exists")))
    no_rpt = sorted(d for d, r in mail_domains.items() if d not in missing
                    and not (r.get("tls_rpt") or {}).get("record_found", (r.get("tls_rpt") or {}).get("exists")))
    value = {"missing_mta_sts": missing, "missing_tls_rpt": no_rpt, "domains_checked": len(mail_domains)}
    if missing:
        return make_fail(**common, details=f"No MTA-STS record for: {', '.join(missing)}", actual_value=value,
                         expected_value="MTA-STS (and TLS-RPT) published for every mail domain")
    if no_rpt:
        return make_warn(**common, details=f"MTA-STS is published but TLS reporting (TLS-RPT) is missing for: {', '.join(no_rpt)}",
                         actual_value=value, expected_value="MTA-STS (and TLS-RPT) published for every mail domain")
    return make_pass(**common, details=f"MTA-STS and TLS-RPT are published for all {len(mail_domains)} mail domain(s).",
                     actual_value=value, expected_value="MTA-STS (and TLS-RPT) published for every mail domain")


@check(
    check_id="ADD-51",
    title="Ensure mailboxes do not forward to external addresses",
    level="L1", source="OTHER", section="Gmail", severity="HIGH",
    remediation=(
        "Review each listed mailbox with its owner and remove unexpected forwarding addresses (Gmail > Settings > "
        "Forwarding and POP/IMAP). External forwarding is a common persistence and exfiltration technique after an "
        "account compromise. To block it tenant-wide, disable automatic forwarding in Admin console > Gmail > End User Access."
    ),
)
def check_mailbox_external_forwarding(data: dict) -> CheckResult:
    """Per-mailbox forwarding addresses outside the organization's domains (opt-in collection)."""
    common = dict(check_id="ADD-51", title="Ensure mailboxes do not forward to external addresses",
                  level="L1", source="OTHER", section="Gmail")
    collected = data.get("mailbox_forwarding") or {}
    if not collected.get("collected"):
        return make_review(**common, details="Per-mailbox forwarding was not collected. It is opt-in because it reads every "
                                             "mailbox's settings: set options.collect_mailbox_forwarding: true to enable it.")
    own = {str(d.get("domainName", d.get("domain_name", "")) if isinstance(d, dict) else d).lower()
           for d in data.get("domains", [])}
    own.discard("")
    external = {}
    for mailbox, addresses in (collected.get("forwarding") or {}).items():
        outside = sorted(a for a in addresses if a.rsplit("@", 1)[-1].lower() not in own)
        if outside:
            external[mailbox] = outside
    scope = f"{collected.get('users_checked', 0)} mailbox(es)" + (" (capped — raise options.mailbox_forwarding_max_users)"
                                                                 if collected.get("truncated") else "")
    if external:
        listing = "; ".join(f"{m} → {', '.join(a)}" for m, a in sorted(external.items())[:15])
        return make_fail(**common, details=f"{len(external)} of {scope} forward to external addresses: {listing}",
                         actual_value={"external_forwarding": external}, expected_value="No mailbox forwards outside the organization")
    return make_pass(**common, details=f"None of {scope} forwards to an external address.",
                     actual_value={"external_forwarding": {}}, expected_value="No mailbox forwards outside the organization")


# ── Google security checklist: groups and administrator accounts ─────────
# Items of Google's "Security checklist for medium and large businesses" and "Security best
# practices for administrator accounts" that no CIS or SCuBA control covers (analysis 2026-11-15).

_CHECKLIST = "https://knowledge.workspace.google.com/admin/security/security-checklist-for-medium-and-large-businesses-100-users"
_ADMIN_BEST_PRACTICES = "https://knowledge.workspace.google.com/admin/users/security-best-practices-for-administrator-accounts"


def _super_admins(data: dict) -> list[dict]:
    return [u for u in data.get("users", []) or [] if isinstance(u, dict) and u.get("is_super_admin")]


@check(
    check_id="ADD-63",
    title="Ensure spam moderation is enabled for every group",
    level="L1", source="GOOGLE", section="Groups",
    severity="MEDIUM",
    remediation=(
        "Google Groups > group > Group settings > Posting policies > Spam message handling: 'Moderate and notify content "
        "moderators', 'Moderate and silently' or 'Reject', never 'Post suspicious messages to the group'. Google's "
        f"checklist: 'Enable spam moderation for your groups'. {_CHECKLIST}"
    ),
)
def check_group_spam_moderation(data: dict) -> CheckResult:
    """Groups Settings API ``spamModerationLevel``: ``ALLOW`` posts suspected spam straight to the members."""
    common = dict(check_id="ADD-63", title="Ensure spam moderation is enabled for every group",
                  level="L1", source="GOOGLE", section="Groups")
    with_settings = [g for g in data.get("groups", []) or [] if isinstance(g.get("settings"), dict) and g["settings"]]
    if not with_settings:
        return make_manual(**common, details="No per-group settings were collected (Groups Settings API).")
    levels: dict[str, int] = {}
    allow, without_value = [], []
    for g in with_settings:
        email = g.get("email", "unknown")
        level = g["settings"].get("spamModerationLevel")
        if level in (None, ""):
            without_value.append(email)
            continue
        levels[str(level)] = levels.get(str(level), 0) + 1
        if str(level).upper() == "ALLOW":
            allow.append(email)
    expected = "spamModerationLevel MODERATE, SILENTLY_MODERATE or REJECT on every group"
    value = {"allow": sorted(allow), "levels": levels, "without_value": sorted(without_value), "groups_checked": len(with_settings)}
    if allow:
        return make_fail(**common, details=(f"{len(allow)} of {len(with_settings)} group(s) post suspected spam straight to "
                                            f"members (spamModerationLevel ALLOW): {', '.join(sorted(allow)[:15])}"),
                         actual_value=value, expected_value=expected)
    if not levels:
        return make_manual(**common, details="Group settings were collected without spamModerationLevel; cannot judge spam moderation.")
    note = f" {len(without_value)} group(s) returned no spamModerationLevel." if without_value else ""
    return make_pass(**common, details=f"All {sum(levels.values())} group(s) moderate or reject suspected spam ({levels}).{note}",
                     actual_value=value, expected_value=expected)


@check(
    check_id="ADD-64",
    title="Ensure every super admin has a spare security key enrolled",
    level="L2", source="GOOGLE", section="Security",
    severity="HIGH",
    remediation=(
        "Each super admin: Google Account > Security > 2-Step Verification > Security keys: register a second hardware key "
        f"and store it safely. Google: 'Enroll a spare security key' in {_ADMIN_BEST_PRACTICES}"
    ),
)
def check_super_admin_spare_key(data: dict) -> CheckResult:
    """Per-user usage report ``accounts:num_security_keys`` for every super admin: two or more keys."""
    common = dict(check_id="ADD-64", title="Ensure every super admin has a spare security key enrolled",
                  level="L2", source="GOOGLE", section="Security")
    admins = _super_admins(data)
    if not admins:
        return make_manual(**common, details="No super admin account found in the collected users.")
    if not data.get("user_usage"):
        return make_manual(**common, details="The per-user usage report (accounts:num_security_keys) was not collected.")
    usage = user_usage_by_email(data)
    short, enough, unknown = [], [], []
    for u in admins:
        email = str(u.get("primary_email", "")).lower()
        raw = (usage.get(email) or {}).get("accounts:num_security_keys")
        try:
            count = int(raw) if raw is not None else None
        except (TypeError, ValueError):
            count = None
        if count is None:
            unknown.append(email)
        elif count >= 2:
            enough.append(email)
        else:
            short.append(f"{email} ({count} key{'s' if count != 1 else ''})")
    expected = "At least two security keys enrolled per super admin (passkeys are counted separately)"
    actual = {"fewer_than_two": short, "two_or_more": enough, "no_usage_row": unknown}
    if short:
        return make_fail(**common, details=(f"{len(short)} of {len(admins)} super admin(s) have fewer than two security keys, so "
                                            f"a lost key locks the account out: {'; '.join(short)}"),
                         actual_value=actual, expected_value=expected)
    if unknown:
        return make_review(**common, details=(f"{len(unknown)} super admin(s) have no row in the per-user usage report yet "
                                              f"(new account or report lag): {', '.join(unknown)}. The others have two or more keys."),
                           actual_value=actual, expected_value=expected)
    return make_pass(**common, details=f"All {len(admins)} super admin(s) have two or more security keys enrolled.",
                     actual_value=actual, expected_value=expected)


_RECOVERY_CONFLICT = (
    "Standards conflict: GWS.COMMONCONTROLS.8.3 asks that users be prevented from adding recovery information and "
    "CIS-4.1.2.1 / GWS.COMMONCONTROLS.8.1 that super admin self-recovery be off; Google's administrator-account guidance "
    "still wants a recovery phone and email on every super admin so Support can verify the admin when locked out. "
    "Each check follows its own standard."
)


@check(
    check_id="ADD-65",
    title="Ensure super admin accounts have recovery email and phone set",
    level="L2", source="GOOGLE", section="Directory",
    severity="MEDIUM",
    remediation=(
        "Admin console > Directory > Users > the super admin > Security > Recovery information: add a recovery phone and a "
        f"recovery email the admin controls. Google: 'Add recovery options to admin accounts' in {_ADMIN_BEST_PRACTICES}"
    ),
)
def check_super_admin_recovery_info(data: dict) -> CheckResult:
    """Directory API ``recoveryEmail`` / ``recoveryPhone`` (returned only when set) on every super admin."""
    common = dict(check_id="ADD-65", title="Ensure super admin accounts have recovery email and phone set",
                  level="L2", source="GOOGLE", section="Directory")
    admins = _super_admins(data)
    if not admins:
        return make_manual(**common, details="No super admin account found in the collected users.")
    missing, complete = [], []
    for u in admins:
        email = u.get("primary_email", "unknown")
        lacks = [what for what, key in (("email", "recovery_email"), ("phone", "recovery_phone")) if not str(u.get(key) or "").strip()]
        if lacks:
            missing.append(f"{email} (no recovery {' or '.join(lacks)})")
        else:
            complete.append(email)
    expected = "Recovery email and recovery phone on every super admin"
    actual = {"missing": missing, "complete": complete}
    if missing:
        return make_fail(**common, details=(f"{len(missing)} of {len(admins)} super admin(s) lack recovery information: "
                                            f"{'; '.join(missing)}. {_RECOVERY_CONFLICT}"),
                         actual_value=actual, expected_value=expected)
    return make_pass(**common, details=f"All {len(admins)} super admin(s) have a recovery email and phone. {_RECOVERY_CONFLICT}",
                     actual_value=actual, expected_value=expected)


@check(
    check_id="ADD-66",
    title="Ensure delegated Groups admin roles are conditioned on a group type",
    level="L2", source="GOOGLE", section="Security",
    severity="MEDIUM",
    requires_license=EDITIONS_ADMIN_ROLE_CONDITIONS,
    remediation=(
        "Admin console > Account > Admin roles > the role > Admins > the assignment > Set conditions: limit Groups Editor, "
        "Groups Reader and custom roles with Groups privileges to security groups or to non-security groups, so that only a "
        "small set of admins can change the groups that grant access. Google: 'Add security conditions to admin roles'. "
        f"{_CHECKLIST}"
    ),
)
def check_group_admin_role_conditions(data: dict) -> CheckResult:
    """``roleAssignments[].condition`` on every assignment of a non-super-admin role with ``GROUPS_*`` privileges."""
    common = dict(check_id="ADD-66", title="Ensure delegated Groups admin roles are conditioned on a group type",
                  level="L2", source="GOOGLE", section="Security")
    roles_data = data.get("roles")
    if not isinstance(roles_data, dict) or "assignments" not in roles_data or "roles" not in roles_data:
        return make_manual(**common, details="Admin roles and role assignments were not collected.")
    if _has_api_error(data, "list_roles", "list_role_assignments"):
        return make_manual(**common, details="Admin roles could not be fully enumerated (API error).")
    group_roles: dict[str, str] = {}
    for role in roles_data.get("roles", []) or []:
        if role.get("isSuperAdminRole"):
            continue
        privileges = {str(p.get("privilegeName", "")).upper() for p in role.get("rolePrivileges", []) or [] if isinstance(p, dict)}
        if any(p.startswith("GROUPS_") for p in privileges):
            group_roles[str(role.get("roleId"))] = role.get("roleName", str(role.get("roleId")))
    assignments = [a for a in roles_data.get("assignments", []) or [] if str(a.get("roleId")) in group_roles]
    expected = "Every assignment of a role with Groups privileges carries a security-group or non-security-group condition"
    if not assignments:
        return make_pass(**common, details="No delegated role with Groups privileges is assigned; only super admins manage groups.",
                         actual_value={"group_role_assignments": 0}, expected_value=expected)
    users_by_id = {str(u.get("id")): u.get("primary_email") for u in data.get("users", []) or [] if u.get("id")}
    groups_by_id = {str(g.get("id")): g.get("email") for g in data.get("groups", []) or [] if g.get("id")}

    def who(a: dict) -> str:
        key = str(a.get("assignedTo"))
        return users_by_id.get(key) or groups_by_id.get(key) or key

    unconditioned, security_only, non_security_only, other = [], [], [], []
    for a in assignments:
        label = f"{who(a)} ({group_roles[str(a.get('roleId'))]})"
        condition = str(a.get("condition") or "").strip()
        if not condition:
            unconditioned.append(label)
        elif "groups.security" in condition and condition.startswith("!"):
            non_security_only.append(label)
        elif "groups.security" in condition:
            security_only.append(label)
        else:
            other.append(f"{label}: {condition[:80]}")
    actual = {"unconditioned": unconditioned, "security_groups_only": security_only,
              "non_security_groups_only": non_security_only, "other_condition": other}
    if unconditioned:
        return make_fail(**common, details=(f"{len(unconditioned)} of {len(assignments)} Groups-privilege assignment(s) have no "
                                            f"condition, so these admins can change every group including the security groups "
                                            f"that grant access: {'; '.join(unconditioned[:15])}"),
                         actual_value=actual, expected_value=expected)
    return make_pass(**common, details=(f"All {len(assignments)} Groups-privilege assignment(s) are conditioned "
                                        f"({len(security_only)} to security groups, {len(non_security_only)} to non-security groups"
                                        + (f", {len(other)} with another condition" if other else "") + ")."),
                     actual_value=actual, expected_value=expected)
