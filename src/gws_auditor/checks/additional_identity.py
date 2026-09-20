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

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
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
        "Admin console > Apps > Google Workspace > Google Chat > External Spaces. Turn external spaces off, or "
        "limit them to allowlisted domains. https://knowledge.workspace.google.com/admin/chat/chat-with-external-users"
    ),
)
def check_chat_external_spaces(data: dict) -> CheckResult:
    """Users should not be able to create or join spaces with people from any outside domain."""
    common = dict(check_id="ADD-45", title="Ensure Chat spaces with external members are restricted",
                  level="L2", source="OTHER", section="Google Chat")
    entries = [e for e in get_ou_values(data.get("policies", {}).get("chat", {}), "chat_external_spaces")
               if e["value"].get("enabled") is not None]
    if not entries:
        return make_review(**common, details="'chat.chat_external_spaces' was not returned by the Policy API — verify in Admin console.")
    open_ous = sorted(e["org_unit"] for e in entries
                      if e["value"]["enabled"] is True and e["value"].get("domainAllowlistMode", "ALL_DOMAINS") == "ALL_DOMAINS")
    if open_ous:
        return make_fail(**common, details=f"{len(open_ous)} OU(s) allow Chat spaces with members from any domain: {', '.join(open_ous)}",
                         actual_value=", ".join(f"{ou} → enabled, ALL_DOMAINS" for ou in open_ous),
                         expected_value="External spaces off or limited to allowlisted domains")
    return make_pass(**common, details=f"All {len(entries)} OU(s) disable external spaces or limit them to allowlisted domains.",
                     actual_value=f"{len(entries)} OU(s) safe", expected_value="External spaces off or limited to allowlisted domains")


@check(
    check_id="ADD-46",
    title="Ensure groups cannot be joined by anyone on the internet",
    level="L1", source="OTHER", section="Groups",
    remediation=(
        "Google Groups > group > Group settings. Set 'Who can join group' to invited users or organization "
        "members, and turn off 'Allow external members' unless the group exists for outside collaboration. "
        "A group is often an access-control principal for Drive, Calendar and cloud resources."
    ),
)
def check_open_groups(data: dict) -> CheckResult:
    """Per-group join settings: open-to-the-internet groups fail; groups allowing external members are flagged."""
    common = dict(check_id="ADD-46", title="Ensure groups cannot be joined by anyone on the internet",
                  level="L1", source="OTHER", section="Groups")
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
    level="L2", source="OTHER", section="Security", severity="LOW", scored=False,
    remediation=(
        "Admin console > Account > Admin roles. Vault privileges (matters, holds, searches, exports, retention) give "
        "access to every user's mail and files and can destroy data through retention rules — keep holders to the minimum."
    ),
)
def check_vault_privilege_holders(data: dict) -> CheckResult:
    """Inventory of assigned roles that carry Vault privileges."""
    common = dict(check_id="ADD-49", title="Review who holds Google Vault privileges",
                  level="L2", source="OTHER", section="Security")
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
        "record to receive failure reports. https://knowledge.workspace.google.com/admin/security/increase-email-security-with-mta-sts-and-tls-reporting"
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
