# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Base check decorator and utilities for GWS Security Auditor."""

import functools
import logging
from typing import Callable

from ..constants import LICENSE_TIERS, LICENSE_TIER_NAMES, CRITICAL_CHECKS
from ..models import CheckMetadata, CheckResult, Status

logger = logging.getLogger(__name__)

# Global list populated by the @check decorator
_registered_checks: list[CheckMetadata] = []


def _normalize_license(raw: str) -> str:
    """Normalize a license string to a LICENSE_TIERS key.

    Handles forms like "Google Workspace Enterprise Plus",
    "Business Starter (Legacy)", "Google Workspace for Education Plus", etc.
    """
    name = raw.lower().replace(" ", "_")
    # Strip common prefixes
    for prefix in ("google_workspace_", "google_apps_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    # Strip "for_" prefix (e.g. "for_education_plus" → "education_plus")
    if name.startswith("for_"):
        name = name[len("for_"):]
    # Strip legacy/beta suffixes
    name = name.replace("_(legacy)", "").replace("_(beta)", "").rstrip("_")
    return name


def _check_license_sufficient(requires_license: str, data: dict) -> bool:
    """Return True if the tenant license meets the requirement."""
    if not requires_license:
        return True
    # subscription_type may live directly on data (cached reports) or
    # nested under subscription_info.edition (live provider output).
    raw_license = (
        data.get("subscription_type")
        or data.get("subscription_info", {}).get("edition", "")
        or ""
    )
    tenant_license = _normalize_license(raw_license)
    if not tenant_license:
        # Unknown license — cannot determine, let the check run normally
        return True
    required_level = LICENSE_TIERS.get(requires_license, 0)
    tenant_level = LICENSE_TIERS.get(tenant_license, 0)
    return tenant_level >= required_level


def _resolve_severity(check_id: str) -> str:
    """Look up severity from CRITICAL_CHECKS constant mapping."""
    if check_id in CRITICAL_CHECKS:
        return "CRITICAL"
    return "MEDIUM"


def _resolve_critical_reason(check_id: str) -> str:
    """Look up the critical reason from CRITICAL_CHECKS constant mapping."""
    return CRITICAL_CHECKS.get(check_id, "")


def check(check_id: str, title: str, level: str, source: str, section: str,
          remediation: str = "", requires_license: str = "",
          severity: str = "", critical_reason: str = ""):
    """Decorator to register a security check function.

    The decorated function should accept a single `data` dict argument
    and return a CheckResult (or raise an exception, which becomes ERROR).

    Parameters
    ----------
    requires_license:
        Minimum license tier needed (e.g. ``"enterprise_plus"``).
        When the tenant license is below this tier, the check result
        is automatically reclassified to NOT_APPLICABLE.

    Usage:
        @check(
            check_id="CIS-1.1.1",
            title="Ensure more than one Super Admin account exists",
            level="L1",
            source="CIS",
            section="Directory",
            remediation="Create at least 2 super admin accounts.",
        )
        def check_super_admin_count(data: dict) -> CheckResult:
            ...
    """

    resolved_severity = severity or _resolve_severity(check_id)
    resolved_reason = critical_reason or _resolve_critical_reason(check_id)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(data: dict) -> CheckResult:
            try:
                # Short-circuit: skip the check entirely when the tenant
                # license is known and below the required tier.
                if (requires_license
                        and not _check_license_sufficient(requires_license, data)):
                    tier_name = LICENSE_TIER_NAMES.get(
                        requires_license, requires_license)
                    return CheckResult(
                        check_id=check_id, title=title,
                        status=Status.NOT_APPLICABLE,
                        level=level, source=source, section=section,
                        details=(
                            f"Not applicable — this feature requires "
                            f"{tier_name} or higher."
                        ),
                        remediation=remediation,
                        severity=resolved_severity,
                        critical_reason=resolved_reason,
                    )
                result = func(data)
                # Ensure metadata fields are populated on the result
                result.check_id = result.check_id or check_id
                result.title = result.title or title
                result.level = result.level or level
                result.source = result.source or source
                result.section = result.section or section
                if not result.remediation and remediation:
                    result.remediation = remediation
                # Apply severity and critical reason
                result.severity = resolved_severity
                result.critical_reason = resolved_reason
                return result
            except Exception as e:
                logger.error("Check %s raised an exception: %s", check_id, e)
                return CheckResult(
                    check_id=check_id,
                    title=title,
                    status=Status.ERROR,
                    level=level,
                    source=source,
                    section=section,
                    details=f"Check execution error: {e}",
                    severity=resolved_severity,
                    critical_reason=resolved_reason,
                )

        metadata = CheckMetadata(
            check_id=check_id,
            title=title,
            level=level,
            source=source,
            section=section,
            func=wrapper,
            remediation=remediation,
            requires_license=requires_license,
            severity=resolved_severity,
            critical_reason=resolved_reason,
        )
        _registered_checks.append(metadata)

        wrapper._check_metadata = metadata
        return wrapper

    return decorator


def get_registered_checks() -> list[CheckMetadata]:
    """Return all registered check metadata objects."""
    return list(_registered_checks)


def make_pass(check_id: str, title: str, level: str, source: str, section: str,
              details: str = "", actual_value=None, expected_value=None,
              remediation: str = "", org_unit: str = "Global",
              cis_controls: list | None = None) -> CheckResult:
    """Helper to create a PASS result."""
    return CheckResult(
        check_id=check_id, title=title, status=Status.PASS,
        level=level, source=source, section=section,
        details=details, actual_value=actual_value,
        expected_value=expected_value, remediation=remediation,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )


def make_fail(check_id: str, title: str, level: str, source: str, section: str,
              details: str = "", actual_value=None, expected_value=None,
              remediation: str = "", org_unit: str = "Global",
              cis_controls: list | None = None) -> CheckResult:
    """Helper to create a FAIL result."""
    return CheckResult(
        check_id=check_id, title=title, status=Status.FAIL,
        level=level, source=source, section=section,
        details=details, actual_value=actual_value,
        expected_value=expected_value, remediation=remediation,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )


def make_warn(check_id: str, title: str, level: str, source: str, section: str,
              details: str = "", actual_value=None, expected_value=None,
              remediation: str = "", org_unit: str = "Global",
              cis_controls: list | None = None) -> CheckResult:
    """Helper to create a WARN result."""
    return CheckResult(
        check_id=check_id, title=title, status=Status.WARN,
        level=level, source=source, section=section,
        details=details, actual_value=actual_value,
        expected_value=expected_value, remediation=remediation,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )


def make_manual(check_id: str, title: str, level: str, source: str, section: str,
                details: str = "", remediation: str = "",
                actual_value=None, expected_value=None,
                org_unit: str = "Global",
                cis_controls: list | None = None) -> CheckResult:
    """Helper to create an ERROR result for an unverifiable control.

    When a security control cannot be verified (e.g. the required API
    data is unavailable), the result is marked as ERROR to distinguish
    it from a genuine security failure. This prevents inflating the
    failure count when data is simply missing or unavailable.

    See also :func:`make_review` which returns MANUAL for checks that
    have data but inherently require human judgment.
    """
    return CheckResult(
        check_id=check_id, title=title, status=Status.ERROR,
        level=level, source=source, section=section,
        details=details, remediation=remediation,
        actual_value=actual_value, expected_value=expected_value,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )


def is_default_policy(entry: dict) -> bool:
    """Return True if an OU-values entry originates from a non-ADMIN policy.

    DEFAULT and SYSTEM policies are Google system defaults, **not**
    admin-configured values.  Some settings may show as configured in
    the Admin UI but the Cloud Identity Policy API only returns the
    DEFAULT/SYSTEM record.  Checks that see such an entry should treat
    it as *unconfirmed* and avoid reporting FAIL on the basis of the
    default alone.
    """
    raw = entry.get("_raw", {})
    if isinstance(raw, dict) and raw.get("type") in ("DEFAULT", "SYSTEM"):
        return True
    name = entry.get("name", "")
    if isinstance(name, str) and "/_default/" in name:
        return True
    return False


def get_ou_values(category_dict: dict, raw_setting_key: str,
                   admin_only: bool = False) -> list[dict]:
    """Return per-OU entries for a raw API setting across all OUs.

    Searches ``_ou_policies`` (preserved by ``_normalize_policies``) for
    policies whose setting type ends with *raw_setting_key*.

    Parameters
    ----------
    category_dict:
        A category dict from ``data["policies"]`` (e.g. ``data["policies"]["calendar"]``).
    raw_setting_key:
        The setting-specific part of the API setting type, e.g.
        ``"primary_calendar_max_allowed_external_sharing"``.
    admin_only:
        If True, exclude DEFAULT and SYSTEM entries (Google defaults)
        and only return admin-configured values.

    Returns
    -------
    A list of dicts ``[{"org_unit": str, "value": dict, "setting_type": str}, ...]``.
    Returns ``[]`` if ``_ou_policies`` is absent (backward compat with old caches).
    """
    ou_policies = category_dict.get("_ou_policies", [])
    if not ou_policies:
        return []

    # OU ID map for secondary resolution of any orgUnits/<id> values
    # that _normalize_policies could not resolve on first pass.
    ou_id_map = category_dict.get("_ou_id_map", {})

    raw_results = []
    for policy in ou_policies:
        if not isinstance(policy, dict):
            continue
        setting = policy.get("setting", {})
        if not isinstance(setting, dict):
            continue
        setting_type = setting.get("type", "")
        # Extract the setting-specific name from the type.
        # E.g. "settings/calendar.primary_calendar_max_allowed_external_sharing"
        # → strip "settings/" → "calendar.primary_calendar_max_allowed_external_sharing"
        # → split on "." → "primary_calendar_max_allowed_external_sharing"
        bare = setting_type
        if bare.startswith("settings/"):
            bare = bare[len("settings/"):]
        if "." in bare:
            key = bare.split(".", 1)[1]
        else:
            key = bare

        if key.lower() == raw_setting_key.lower():
            # Skip non-admin entries when admin_only is requested
            if admin_only and is_default_policy({"_raw": policy.get("_raw", {}),
                                                  "name": policy.get("name", "")}):
                continue
            value = setting.get("value", setting)
            org_unit = policy.get("orgUnit", "/")
            # Secondary resolution: if the orgUnit is still an
            # unresolved ID like "orgUnits/<id>", try the stored map.
            if org_unit.startswith("orgUnits/") and ou_id_map:
                bare_id = org_unit.split("/", 1)[1]
                org_unit = ou_id_map.get(
                    org_unit,
                    ou_id_map.get(bare_id,
                                  ou_id_map.get(f"id:{bare_id}", org_unit)),
                )
            raw_results.append({
                "org_unit": org_unit,
                "value": value,
                "setting_type": setting_type,
                "_raw": policy.get("_raw", {}),
                "name": policy.get("name", ""),
            })

    # Deduplicate per OU: when multiple entries exist for the same OU,
    # prefer ADMIN entries over SYSTEM/DEFAULT.
    seen_ous: dict[str, dict] = {}
    for entry in raw_results:
        ou = entry["org_unit"]
        entry_is_default = is_default_policy(entry)
        if ou not in seen_ous:
            seen_ous[ou] = entry
        elif entry_is_default:
            # Current entry is SYSTEM/DEFAULT — keep existing (which may be ADMIN)
            pass
        else:
            # Current entry is ADMIN — prefer it over any existing entry
            seen_ous[ou] = entry

    return list(seen_ous.values())


def make_review(check_id: str, title: str, level: str, source: str, section: str,
                details: str = "", remediation: str = "",
                actual_value=None, expected_value=None,
                org_unit: str = "Global",
                cis_controls: list | None = None) -> CheckResult:
    """Helper to create a MANUAL result for checks requiring human review.

    Use when the check has data but the control inherently requires
    human judgment.  Contrast with :func:`make_manual` which returns
    ERROR for controls where API data is unavailable.
    """
    return CheckResult(
        check_id=check_id, title=title, status=Status.MANUAL,
        level=level, source=source, section=section,
        details=details, remediation=remediation,
        actual_value=actual_value, expected_value=expected_value,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )


def make_not_applicable(check_id: str, title: str, level: str, source: str,
                        section: str, details: str = "",
                        remediation: str = "",
                        actual_value=None, expected_value=None,
                        org_unit: str = "Global",
                        cis_controls: list | None = None) -> CheckResult:
    """Helper to create a NOT_APPLICABLE result."""
    return CheckResult(
        check_id=check_id, title=title, status=Status.NOT_APPLICABLE,
        level=level, source=source, section=section,
        details=details, remediation=remediation,
        actual_value=actual_value, expected_value=expected_value,
        org_unit=org_unit, cis_controls=cis_controls or [],
    )
