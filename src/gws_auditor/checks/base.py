# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Base check decorator and utilities for GWS Security Auditor."""

import fnmatch
import functools
import logging
import re
from typing import Callable

from ..constants import (
    LICENSE_TIERS, LICENSE_TIER_NAMES, CRITICAL_CHECKS, HIGH_CHECKS, LOW_CHECKS,
    CONSOLE_SECTION_LINKS,
)
from ..models import CheckMetadata, CheckResult, Severity, Status

logger = logging.getLogger(__name__)

# Global list populated by the @check decorator
_registered_checks: list[CheckMetadata] = []

# Matches Google official documentation URLs we surface as "Learn More".
# Order matters: support.google.com is preferred over admin.google.com.
_DOCS_URL_PATTERNS = (
    re.compile(r"https?://support\.google\.com/[^\s)\"'>]+"),
    re.compile(r"https?://cloud\.google\.com/[^\s)\"'>]+"),
    re.compile(r"https?://developers\.google\.com/[^\s)\"'>]+"),
    re.compile(r"https?://workspace\.google\.com/[^\s)\"'>]+"),
)


def _extract_docs_url(text: str) -> str:
    """Pick the first Google documentation URL out of a remediation string."""
    if not text:
        return ""
    for pat in _DOCS_URL_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0).rstrip(".,)")
    return ""


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
    """Return True if the tenant license meets the requirement.

    Detection is *advisory*: when the answer is uncertain (unknown
    edition, multiple distinct editions in the tenant, or any other
    detection ambiguity) we return True so the check runs and lets the
    underlying API data classify availability via real signals (a 404
    or empty policy beats a SKU-lookup mismatch every time).
    """
    if not requires_license:
        return True

    sub_info = data.get("subscription_info", {}) or {}

    # Mixed-edition tenant: if ANY assigned SKU meets the requirement,
    # the feature is available somewhere in the org. Don't short-circuit.
    tier_keys_present = sub_info.get("tier_keys_present", []) or []
    required_level = LICENSE_TIERS.get(requires_license, 0)
    if tier_keys_present:
        max_present = max(
            (LICENSE_TIERS.get(tk, 0) for tk in tier_keys_present),
            default=0,
        )
        if max_present >= required_level:
            return True
        # All present tiers are below required — but if we saw multiple
        # distinct tiers AND any unknown SKUs, treat as ambiguous.
        if any(s.get("tier_key", "") == "" for s in sub_info.get("skus", [])):
            return True

    # subscription_type may live directly on data (cached reports) or
    # nested under subscription_info.edition (live provider output).
    raw_license = (
        data.get("subscription_type")
        or sub_info.get("edition", "")
        or ""
    )
    tenant_license = _normalize_license(raw_license)
    if not tenant_license:
        # Unknown license — cannot determine, let the check run normally
        return True
    tenant_level = LICENSE_TIERS.get(tenant_license, 0)
    return tenant_level >= required_level


def _resolve_severity(check_id: str) -> Severity:
    """Look up severity from check severity mappings."""
    if check_id in CRITICAL_CHECKS:
        return Severity.CRITICAL
    if check_id in HIGH_CHECKS:
        return Severity.HIGH
    if check_id in LOW_CHECKS:
        return Severity.LOW
    return Severity.MEDIUM


def _resolve_critical_reason(check_id: str) -> str:
    """Look up the critical reason from CRITICAL_CHECKS constant mapping."""
    return CRITICAL_CHECKS.get(check_id, "")


def check(check_id: str, title: str, level: str, source: str, section: str,
          remediation: str = "", requires_license: str = "",
          severity: str = "", critical_reason: str = "",
          scored: bool = True,
          docs_url: str = "", console_link: str = "", gam_command: str = ""):
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

    resolved_severity = (
        Severity(severity) if severity else _resolve_severity(check_id)
    )
    resolved_reason = critical_reason or _resolve_critical_reason(check_id)
    resolved_docs_url = docs_url or _extract_docs_url(remediation)
    resolved_console_link = console_link or CONSOLE_SECTION_LINKS.get(section, "")

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
                        docs_url=resolved_docs_url,
                        console_link=resolved_console_link,
                        gam_command=gam_command,
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
                # Apply severity, critical reason, and scored flag
                result.severity = resolved_severity
                result.critical_reason = resolved_reason
                result.scored = scored
                # Attach action metadata (allow per-result overrides)
                if not result.docs_url:
                    result.docs_url = resolved_docs_url or _extract_docs_url(result.remediation)
                if not result.console_link:
                    result.console_link = resolved_console_link
                if not result.gam_command and gam_command:
                    result.gam_command = gam_command
                return result
            except Exception as e:
                logger.exception("Check %s raised an exception: %s", check_id, e)
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
                    docs_url=resolved_docs_url,
                    console_link=resolved_console_link,
                    gam_command=gam_command,
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
            scored=scored,
            docs_url=resolved_docs_url,
            console_link=resolved_console_link,
            gam_command=gam_command,
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


def make_partial(check_id: str, title: str, level: str, source: str, section: str,
                 details: str = "", actual_value=None, expected_value=None,
                 remediation: str = "", org_unit: str = "Global",
                 cis_controls: list | None = None) -> CheckResult:
    """Helper to create a PARTIAL result.

    Use when a control is satisfied for some scopes (OUs, users, domains)
    but not others — typically because of an intentional exception OU or
    a phased rollout. Contrast with FAIL (no compliance) and PASS (full).
    """
    return CheckResult(
        check_id=check_id, title=title, status=Status.PARTIAL,
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


def is_admin_configured(entry: dict) -> bool:
    """Inverse of :func:`is_default_policy` — True when an admin set the value."""
    return not is_default_policy(entry)


# Default patterns that identify intentional external-sharing OUs. Tenants
# can override or extend this via options.external_sharing_ous in config.yaml.
_DEFAULT_EXTERNAL_SHARING_PATTERNS = (
    "*External*",
    "*Sharing-External*",
    "*Sharing External*",
    "*Contractors*",
    "*Vendors*",
    "*3rd*Part*",
    "*Third*Part*",
)


def is_external_sharing_ou(ou_path: str, data: dict) -> bool:
    """Return True if an OU is intentionally permissive (external-sharing scope).

    Real-world tenants often carve out OUs whose explicit purpose is to
    share with outside parties (e.g. ``/NewDeciphex/Sharing-External``).
    Checks that fail when ANY OU has a permissive value would otherwise
    treat these intentional exceptions as violations.

    The list of exception OUs comes from ``options.external_sharing_ous``
    in config.yaml (a list of paths or fnmatch patterns), which the
    orchestrator injects as ``data["_options"]``. Falls back to a
    built-in pattern set when the tenant configures none.
    """
    if not ou_path:
        return False
    options = data.get("_options") or {}
    if not options:
        # Some callers (tests, cached re-scoring) pass the raw config dict.
        options = (data.get("config", {}) or {}).get("options", {}) or {}
    patterns = options.get("external_sharing_ous")
    if not patterns:
        patterns = _DEFAULT_EXTERNAL_SHARING_PATTERNS
    for pat in patterns:
        if not pat:
            continue
        # Exact path match or glob.
        if pat == ou_path or fnmatch.fnmatch(ou_path, pat):
            return True
    return False


def evaluate_ous(ou_values: list[dict], predicate: Callable,
                 data: dict | None = None) -> dict:
    """Partition per-OU entries into safe / unsafe / exception buckets.

    Parameters
    ----------
    ou_values:
        Output of :func:`get_ou_values`.
    predicate:
        Callable ``(entry) -> bool``. Returns True when the entry's value
        is considered SAFE (compliant). Predicates should not raise — they
        may receive None/missing values.
    data:
        Audit data dict, used to resolve exception OUs via
        :func:`is_external_sharing_ou`. When omitted, no OUs are treated
        as exceptions.

    Returns
    -------
    Dict with keys:
      ``safe_ous``: list of OU paths where predicate returned True.
      ``unsafe_ous``: list of OU paths where predicate returned False
        AND the OU is not an external-sharing exception.
      ``exception_ous``: list of OU paths where predicate returned False
        but the OU is an intentional exception.
      ``default_ous``: list of OU paths where the entry is a SYSTEM/DEFAULT
        policy (admin never configured it). These are excluded from the
        unsafe list — checks should typically downgrade to MANUAL when
        only DEFAULT entries are present.
      ``total``: total number of OU entries evaluated.
    """
    safe: list[str] = []
    unsafe: list[str] = []
    exception: list[str] = []
    default: list[str] = []
    for entry in ou_values:
        ou = entry.get("org_unit", "/")
        if is_default_policy(entry):
            default.append(ou)
            continue
        try:
            ok = bool(predicate(entry))
        except Exception:
            ok = False
        if ok:
            safe.append(ou)
        elif data is not None and is_external_sharing_ou(ou, data):
            exception.append(ou)
        else:
            unsafe.append(ou)
    return {
        "safe_ous": safe,
        "unsafe_ous": unsafe,
        "exception_ous": exception,
        "default_ous": default,
        "total": len(ou_values),
    }


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


def format_ou_values_readable(unsafe_ous: list[dict],
                               value_humanizer: Callable | None = None) -> str:
    """Format a list of OU dicts into a human-readable multi-line string.

    Parameters
    ----------
    unsafe_ous:
        List of dicts with ``org_unit`` and ``value`` keys.
    value_humanizer:
        Optional callable ``(value) -> str``.  When omitted, booleans
        become ``"Enabled"``/``"Disabled"``, ``None`` becomes
        ``"Not set"``, and everything else is ``str()``-ed.
    """
    if not unsafe_ous:
        return ""
    lines = []
    for ou_dict in unsafe_ous:
        ou = ou_dict.get("org_unit", "")
        val = ou_dict.get("value")
        if value_humanizer and callable(value_humanizer):
            val = value_humanizer(val)
        elif isinstance(val, bool):
            val = "Enabled" if val else "Disabled"
        elif val is None:
            val = "Not set"
        else:
            val = str(val)
        lines.append(f"{ou} → {val}")
    return "\n".join(lines)


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
