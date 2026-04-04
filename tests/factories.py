"""Test data factories for GWS Security Auditor.

Factory functions that instantiate Pydantic schema models and return
plain dicts via ``.model_dump()``.  These replace ad-hoc helpers that
were duplicated across test files (``_make_ou_policy``,
``_dns_with_all_configured``, ``_make_security_data``, etc.).

Usage::

    from tests.factories import make_user, make_ou_policy, make_dns_domain

    user = make_user(email="admin@example.com", is_admin=True)
    policy = make_ou_policy("gmail", "mail_delegation",
                            {"enableMailDelegation": False})
    dns = make_dns_domain(spf_found=True, dkim_found=True,
                          dmarc_found=True, dmarc_policy="reject")
"""

from __future__ import annotations

from typing import Any

from gws_auditor.schemas import (
    DkimRecord,
    DmarcRecord,
    DnsDomainRecords,
    LogEntry,
    OUPolicyEntry,
    OUPolicySetting,
    SpfRecord,
    UserRecord,
)


def make_user(
    email: str = "user@example.com",
    is_admin: bool = False,
    is_delegated_admin: bool = False,
    is_enrolled_in_2sv: bool = False,
    is_enforced_in_2sv: bool = False,
    suspended: bool = False,
    last_login_time: str = "2024-01-15T10:00:00Z",
    creation_time: str = "2020-01-01T00:00:00Z",
    org_unit_path: str = "/",
    full_name: str = "",
    recovery_email: str = "",
    recovery_phone: str = "",
    **extra: Any,
) -> dict:
    """Create a normalized user dict with synced camelCase/snake_case fields.

    Returns a plain dict suitable for use in ``data["users"]``.
    """
    user = UserRecord(
        primaryEmail=email,
        primary_email=email,
        isAdmin=is_admin,
        is_super_admin=is_admin,
        is_admin=is_admin,
        isDelegatedAdmin=is_delegated_admin,
        is_delegated_admin=is_delegated_admin,
        isEnrolledIn2Sv=is_enrolled_in_2sv,
        is_enrolled_in_2sv=is_enrolled_in_2sv,
        isEnforcedIn2Sv=is_enforced_in_2sv,
        is_enforced_in_2sv=is_enforced_in_2sv,
        suspended=suspended,
        lastLoginTime=last_login_time,
        last_login_time=last_login_time,
        creationTime=creation_time,
        creation_time=creation_time,
        orgUnitPath=org_unit_path,
        org_unit_path=org_unit_path,
        name={"fullName": full_name or email.split("@")[0].replace(".", " ").title()},
        recoveryEmail=recovery_email,
        recovery_email=recovery_email,
        recoveryPhone=recovery_phone,
        recovery_phone=recovery_phone,
        **extra,
    )
    return user.model_dump()


def make_ou_policy(
    service: str,
    setting_key: str,
    value_dict: dict[str, Any],
    org_unit: str = "/",
) -> dict:
    """Create a single ``_ou_policies`` entry for testing OU-aware checks.

    Parameters
    ----------
    service:
        The service category, e.g. ``"gmail"``, ``"drive"``, ``"calendar"``.
    setting_key:
        The setting-specific key, e.g. ``"mail_delegation"``,
        ``"email_attachment_safety"``.
    value_dict:
        The raw API value dict, e.g.
        ``{"enableMailDelegation": False}``.
    org_unit:
        The OU path, defaults to ``"/"``.

    Returns
    -------
    A dict matching the ``_ou_policies`` entry structure that
    ``get_ou_values()`` in ``checks/base.py`` expects.
    """
    entry = OUPolicyEntry(
        setting=OUPolicySetting(
            type=f"settings/{service}.{setting_key}",
            value=value_dict,
        ),
        orgUnit=org_unit,
    )
    return entry.model_dump()


def make_dns_domain(
    spf_found: bool = True,
    spf_record: str = "v=spf1 include:_spf.google.com ~all",
    spf_valid: bool = True,
    dkim_found: bool = True,
    dkim_record: str = "v=DKIM1; k=rsa; p=MIGf...",
    dkim_valid: bool = True,
    dkim_enabled: bool = True,
    dmarc_found: bool = True,
    dmarc_record: str = "v=DMARC1; p=reject",
    dmarc_policy: str = "reject",
    mx_records: list[dict] | None = None,
    mx_uses_google: bool = True,
) -> dict:
    """Create a per-domain DNS records dict with synced fields.

    Both ``exists`` and ``record_found`` are always present and
    consistent, resolving the key mismatch between the DNS client
    (which uses ``exists``) and checks (which use ``record_found``).

    Returns
    -------
    A dict suitable for use as ``data["dns_records"]["example.com"]``.
    """
    domain = DnsDomainRecords(
        spf=SpfRecord(
            exists=spf_found,
            record_found=spf_found,
            record=spf_record if spf_found else "",
            valid=spf_valid if spf_found else False,
        ),
        dkim=DkimRecord(
            exists=dkim_found,
            record_found=dkim_found,
            record=dkim_record if dkim_found else "",
            valid=dkim_valid if dkim_found else False,
            enabled=dkim_enabled if dkim_found else False,
        ),
        dmarc=DmarcRecord(
            exists=dmarc_found,
            record_found=dmarc_found,
            record=dmarc_record if dmarc_found else "",
            policy=dmarc_policy,
        ),
        mx=mx_records if mx_records is not None else (
            [
                {"priority": 1, "exchange": "aspmx.l.google.com."},
                {"priority": 5, "exchange": "alt1.aspmx.l.google.com."},
            ] if mx_uses_google else []
        ),
        mx_uses_google=mx_uses_google,
    )
    return domain.model_dump()


def make_log_entry(
    event_name: str = "",
    event_type: str = "",
    actor_email: str = "",
    parameters: dict[str, Any] | None = None,
    time: str = "2024-01-15T10:00:00Z",
    **extra: Any,
) -> dict:
    """Create a flattened activity log entry.

    Returns
    -------
    A dict suitable for ``data["admin_logs"]``, ``data["login_logs"]``,
    or ``data["token_logs"]``.
    """
    entry = LogEntry(
        event_name=event_name,
        event_type=event_type,
        actor_email=actor_email,
        parameters=parameters or {},
        time=time,
        **extra,
    )
    return entry.model_dump()
