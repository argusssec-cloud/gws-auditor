# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Base check decorator and utilities for GWS Security Auditor."""

import fnmatch
import functools
import logging
import re
import threading
from typing import Callable

from ..constants import (
    LICENSE_TIERS, LICENSE_TIER_NAMES, CRITICAL_CHECKS, HIGH_CHECKS, LOW_CHECKS, NIST_MAPPINGS,
    CONSOLE_SECTION_LINKS,
)
from ..models import CheckMetadata, CheckResult, Severity, Status
from ..google_defaults import defaults_for_setting

logger = logging.getLogger(__name__)

# Global list populated by the @check decorator
_registered_checks: list[CheckMetadata] = []

# Per-check bookkeeping of the OU entries a check looked at, so the decorator can
# say when a verdict rests on Google defaults rather than admin configuration.
_lookups = threading.local()


def _record_lookup(entries: list[dict]) -> None:
    store = getattr(_lookups, "entries", None)
    if store is not None:
        store.extend(entries)


def _provenance_note(entries: list[dict]) -> str:
    """One sentence naming the OUs whose values are Google defaults, or ''."""
    system_ous: set[str] = set()
    documented: set[str] = set()
    for e in entries:
        ou = e.get("org_unit", "/")
        raw_type = str((e.get("_raw") or {}).get("type", "")).upper()
        if raw_type in ("SYSTEM", "DEFAULT") or "/_default/" in str(e.get("name", "")):
            system_ous.add(ou)
        if e.get("_defaulted_fields"):
            documented.add(ou)
    parts = []
    if system_ous:
        parts.append(f"Google default in force, not admin-configured, for OU(s): {', '.join(sorted(system_ous))}")
    if documented - system_ous:
        parts.append(f"documented Google default used for absent field(s) in OU(s): {', '.join(sorted(documented - system_ous))}")
    return " Note: " + "; ".join(parts) + "." if parts else ""

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


_ADDON_TIER_LEVEL = 99  # LICENSE_TIERS level of add-on SKUs (Assured Controls); never a base edition


def license_requirement_text(requires_license) -> str:
    """Human-readable form of a ``requires_license`` value for NOT_APPLICABLE details and docs."""
    if isinstance(requires_license, (tuple, list, set, frozenset)):
        names = [LICENSE_TIER_NAMES.get(k, k) for k in requires_license]
        return "one of these editions: " + ", ".join(names)
    return f"{LICENSE_TIER_NAMES.get(requires_license, requires_license)} or higher"


def _check_license_sufficient(requires_license, data: dict) -> bool:
    """Return True if the tenant license meets the requirement.

    ``requires_license`` is either a minimum tier key (``"enterprise_standard"``: that tier or any
    higher one in ``LICENSE_TIERS``) or a tuple of tier keys (available on exactly those editions,
    any of them; see the ``EDITIONS_*`` sets in constants.py). Add-on tiers (Assured Controls) never
    satisfy a minimum-tier requirement and are matched only by an explicit set.

    Detection is *advisory*: when the answer is uncertain (unknown
    edition, multiple distinct editions in the tenant, or any other
    detection ambiguity) we return True so the check runs and lets the
    underlying API data classify availability via real signals (a 404
    or empty policy beats a SKU-lookup mismatch every time).
    """
    if not requires_license:
        return True

    sub_info = data.get("subscription_info", {}) or {}
    tier_keys_present = sub_info.get("tier_keys_present", []) or []

    if isinstance(requires_license, (tuple, list, set, frozenset)):
        allowed = set(requires_license)
        if tier_keys_present:
            if allowed & set(tier_keys_present):
                return True
            if any(s.get("tier_key", "") == "" for s in sub_info.get("skus", [])):
                return True  # an unrecognised SKU may be the one that carries the feature
            return False
        raw = data.get("subscription_type") or sub_info.get("edition", "") or ""
        tenant = _normalize_license(raw)
        return not tenant or tenant in allowed

    # Mixed-edition tenant: if ANY assigned SKU meets the requirement,
    # the feature is available somewhere in the org. Don't short-circuit.
    required_level = LICENSE_TIERS.get(requires_license, 0)
    if tier_keys_present:
        max_present = max(
            (LICENSE_TIERS.get(tk, 0) for tk in tier_keys_present
             if LICENSE_TIERS.get(tk, 0) < _ADDON_TIER_LEVEL),
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
          remediation: str = "", requires_license="",
          severity: str = "", critical_reason: str = "",
          scored: bool = True,
          docs_url: str = "", console_link: str = "", gam_command: str = "",
          nist_sp800_53: "tuple[str, ...] | None" = None, nist_csf: "tuple[str, ...] | None" = None):
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
    # Standards: explicit on the decorator, otherwise the CIS v1.4.1 References table.
    _nist = NIST_MAPPINGS.get(check_id, {})
    resolved_sp800_53 = list(nist_sp800_53 if nist_sp800_53 is not None else _nist.get("sp800_53", ()))
    resolved_csf = list(nist_csf if nist_csf is not None else _nist.get("csf", ()))

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(data: dict) -> CheckResult:
            try:
                # Short-circuit: skip the check entirely when the tenant
                # license is known and below the required tier.
                if (requires_license
                        and not _check_license_sufficient(requires_license, data)):
                    return CheckResult(
                        check_id=check_id, title=title,
                        status=Status.NOT_APPLICABLE,
                        level=level, source=source, section=section,
                        details=(
                            f"Not applicable — this feature requires "
                            f"{license_requirement_text(requires_license)}."
                        ),
                        remediation=remediation,
                        severity=resolved_severity,
                        critical_reason=resolved_reason,
                        docs_url=resolved_docs_url,
                        console_link=resolved_console_link,
                        gam_command=gam_command,
                        nist_sp800_53=list(resolved_sp800_53), nist_csf=list(resolved_csf),
                    )
                _lookups.entries = []
                try:
                    result = func(data)
                    looked_at = list(_lookups.entries)
                finally:
                    _lookups.entries = None
                if result.status in (Status.PASS, Status.FAIL, Status.WARN, Status.PARTIAL):
                    note = _provenance_note(looked_at)
                    if note and "Google default" not in (result.details or ""):
                        result.details = (result.details or "").rstrip() + note
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
                result.nist_sp800_53 = list(resolved_sp800_53)
                result.nist_csf = list(resolved_csf)
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
                    nist_sp800_53=list(resolved_sp800_53), nist_csf=list(resolved_csf),
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
            nist_sp800_53=list(resolved_sp800_53), nist_csf=list(resolved_csf),
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
      ``default_ous``: list of OU paths whose entry is a SYSTEM/DEFAULT
        policy (the Google default in force, never changed by an admin).
        They are judged like admin values; the list is informational.
      ``total``: total number of OU entries evaluated.
    """
    safe: list[str] = []
    unsafe: list[str] = []
    exception: list[str] = []
    default: list[str] = []
    for entry in ou_values:
        ou = entry.get("org_unit", "/")
        if is_default_policy(entry):
            # Google default in force (SYSTEM policy or documented default): judged like
            # any other value, listed here so callers can report the provenance.
            default.append(ou)
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


def drop_unspecified(entries: list[dict], field: str) -> list[dict]:
    """Drop per-OU entries whose enum *field* is an ``..._UNSPECIFIED`` placeholder.

    The Policy API returns e.g. ``ACCESS_LEVEL_UNSPECIFIED`` when it does not report the
    configured value. That is "unknown", not "insecure": callers fall through to their
    fallback (usually MANUAL) when nothing determinable is left.
    """
    return [e for e in entries if "UNSPECIFIED" not in str(e["value"].get(field, "")).upper()]


def latest_setting_changes(data: dict, setting_name: str) -> dict[str, str]:
    """Return ``{org_unit: latest NEW_VALUE}`` for an admin audit-log setting name.

    Used for settings the Cloud Identity Policy API does not expose: the most recent
    ``SETTING_NAME`` change event per OU in ``data["admin_logs"]`` gives the current value.
    Returns ``{}`` when no event exists in the log window (state unknown, not "default").
    """
    latest: dict[str, tuple[str, str]] = {}
    for log in data.get("admin_logs", []):
        params = log.get("parameters", {})
        if not isinstance(params, dict) or params.get("SETTING_NAME") != setting_name:
            continue
        if "NEW_VALUE" not in params:
            continue
        ou = params.get("ORG_UNIT_NAME") or "/"
        when = log.get("time", "")
        if ou not in latest or when > latest[ou][0]:
            latest[ou] = (when, str(params["NEW_VALUE"]))
    return {ou: value for ou, (_, value) in latest.items()}


def result_from_setting_changes(data: dict, setting_name: str, unsafe_values: tuple[str, ...], *,
                                check_id: str, title: str, level: str, source: str, section: str,
                                what: str, remediation: str = ""):
    """Judge a setting the Policy API does not expose from its admin audit-log changes.

    Returns a PASS/FAIL ``CheckResult`` when ``data["admin_logs"]`` holds a change event for
    *setting_name*, else ``None`` so the caller can fall back (usually to MANUAL). An OU whose
    latest value is in *unsafe_values* (case-insensitive) is non-compliant.
    """
    changes = {ou: v for ou, v in latest_setting_changes(data, setting_name).items()
               if v.upper() != "INHERIT_FROM_PARENT"}
    if not changes:
        return None
    unsafe = {v.lower() for v in unsafe_values}
    bad = sorted(ou for ou, v in changes.items() if v.lower() in unsafe)
    if bad:
        return make_fail(
            check_id=check_id, title=title, level=level, source=source, section=section,
            details=f"{what}: non-compliant in {len(bad)} OU(s) per the latest admin-log change: {', '.join(bad)}",
            actual_value=", ".join(f"{ou} → {changes[ou]}" for ou in bad),
            expected_value="Compliant for all OUs", remediation=remediation,
        )
    return make_pass(
        check_id=check_id, title=title, level=level, source=source, section=section,
        details=f"{what}: compliant in {len(changes)} OU(s) per the latest admin-log change.",
        actual_value=f"{len(changes)} OU(s) safe", expected_value="Compliant for all OUs",
    )


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
    synthesized = _documented_default_entry(ou_policies, raw_setting_key)

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

    # Reduce per OU the way the API documents it: the policy with the greatest
    # policyQuery.sortOrder wins per field (ADMIN ~201 > SYSTEM ~101 > injected
    # DEFAULT), so an admin override beats Google's default and a SYSTEM-only
    # setting is the value in force. Fields still absent take Google's documented
    # default when one exists.
    # An injected DEFAULT entry (synthetic, from the policy client or an older cache) is only
    # evidence while Google documents that default; a stale one must not be judged.
    raw_results = [e for e in raw_results
                   if not (is_default_policy(e) and str((e.get("_raw") or {}).get("type", "")).upper() != "SYSTEM"
                           and not defaults_for_setting(raw_setting_key))]
    if not raw_results and synthesized is not None:
        # The API was queried for this setting family and returned no policy for the
        # setting: per Google, every field then takes its documented default.
        raw_results = [synthesized]
    reduced = _reduce_entries(raw_results, raw_setting_key)
    if admin_only:
        reduced = [e for e in reduced if is_admin_configured(e)]
    _record_lookup(reduced)
    return reduced


def _documented_default_entry(ou_policies: list, raw_setting_key: str) -> dict | None:
    """A root-OU entry built from Google's documented defaults, or None.

    Only when the category really holds policies of the setting's family (for example
    ``settings/gmail.*`` for ``gmail.mail_delegation``), which proves the API was queried
    for it and returned nothing for this setting. A category used by a check as a first
    guess for a setting that lives elsewhere never triggers it.
    """
    from ..google_defaults import ALL_DEFAULTS
    setting_type = next((t for t in ALL_DEFAULTS if t.split(".", 1)[1].lower() == raw_setting_key.lower()), None)
    if not setting_type or not ALL_DEFAULTS[setting_type]:
        return None
    family = f"settings/{setting_type.split('.', 1)[0]}."
    if not any(isinstance(p, dict) and str(p.get("setting", {}).get("type", "")).startswith(family)
               for p in ou_policies):
        return None
    return {
        "org_unit": "/",
        "value": {},  # _reduce_entries fills the documented defaults and records them
        "setting_type": f"settings/{setting_type}",
        "_raw": {"type": "DEFAULT"},
        "name": f"policies/_default/{setting_type}",
    }


def _sort_order(entry: dict) -> float:
    raw = entry.get("_raw") or {}
    query = raw.get("policyQuery") if isinstance(raw, dict) else None
    try:
        return float((query or {}).get("sortOrder"))
    except (TypeError, ValueError):
        return -1.0  # injected DEFAULT entries carry no sortOrder


def _reduce_entries(entries: list[dict], setting_key: str) -> list[dict]:
    by_ou: dict[str, list[dict]] = {}
    for entry in entries:
        by_ou.setdefault(entry["org_unit"], []).append(entry)
    out = []
    for ou, group in by_ou.items():
        group = sorted(group, key=_sort_order)  # ascending: later entries override
        value: dict = {}
        sources: dict[str, str] = {}
        for e in group:
            kind = str((e.get("_raw") or {}).get("type", "ADMIN")).upper() or "ADMIN"
            v = e.get("value")
            if not isinstance(v, dict):
                continue
            for field, fv in v.items():
                value[field] = fv
                sources[field] = kind
        top = group[-1]
        defaulted = []
        for field, fv in defaults_for_setting(setting_key).items():
            if field in value or _snake(field) in value:
                continue
            value[field] = fv
            sources[field] = "DOCUMENTED_DEFAULT"
            defaulted.append(field)
        unspecified = sorted(f for f, fv in value.items()
                             if isinstance(fv, str) and fv.upper().endswith("_UNSPECIFIED"))
        out.append({
            "org_unit": ou,
            "value": value if isinstance(top.get("value"), dict) else top.get("value"),
            "setting_type": top.get("setting_type", ""),
            "_raw": top.get("_raw", {}),
            "name": top.get("name", ""),
            "_field_sources": sources,
            "_defaulted_fields": defaulted,
            "_unspecified_fields": unspecified,
        })
    return out


def _snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


# ---------------------------------------------------------------------------
# Per-OU verdict helper (plan Decision A)
# ---------------------------------------------------------------------------

def field_value(entry: dict, *names: str):
    """Return the first present field among *names*, or ``None`` when the value is unknown.

    Unknown means the field is absent from the reduced setting (and Google documents no
    default for it, otherwise ``get_ou_values`` already filled it) or carries a
    ``*_UNSPECIFIED`` enum member, which the API uses for "not set". Callers treat ``None``
    as "cannot judge", never as safe or unsafe.
    """
    value = entry.get("value") or {}
    if not isinstance(value, dict):
        return None
    for name in names:
        if name in value:
            v = value[name]
            if isinstance(v, str) and v.upper().endswith("_UNSPECIFIED"):
                return None
            return v
    return None


def ou_verdict(ou_values: list[dict], judge: Callable, *, check_id: str, title: str,
               level: str, source: str, section: str,
               fail_text: str, pass_text: str, expected_value, remediation: str = "",
               data: dict | None = None, humanizer: Callable | None = None,
               unknown_text: str | None = None) -> CheckResult:
    """Turn per-OU entries into PASS / FAIL / PARTIAL / MANUAL under the status rules.

    ``judge(entry)`` returns ``True`` (compliant), ``False`` (non-compliant) or ``None``
    (cannot be determined: field absent without a documented default, or
    ``*_UNSPECIFIED``). ``judge`` may also return a ``(verdict, shown_value)`` tuple to
    control the value printed for the OU.

    * any non-compliant OU outside the external-sharing exception OUs -> FAIL
    * non-compliant only in exception OUs -> PARTIAL
    * no non-compliant OU but at least one undetermined OU -> MANUAL
    * otherwise -> PASS

    ``fail_text`` is phrased for ``"{n} OU(s) {fail_text}: {ous}"`` and ``pass_text`` for
    ``"All {n} OU(s) {pass_text}."`` so existing wording and tests keep working.
    """
    unsafe: list[dict] = []
    exception: list[dict] = []
    unknown: list[str] = []
    safe = 0
    for entry in ou_values:
        ou = entry.get("org_unit", "/")
        try:
            res = judge(entry)
        except Exception:  # a malformed value is unknown, not a verdict
            res = None
        shown = None
        if isinstance(res, tuple):
            res, shown = res
        if res is None:
            unknown.append(ou)
        elif res:
            safe += 1
        else:
            item = {"org_unit": ou, "value": shown if shown is not None else _unsafe_display(entry)}
            if data is not None and is_external_sharing_ou(ou, data):
                exception.append(item)
            else:
                unsafe.append(item)
    common = dict(check_id=check_id, title=title, level=level, source=source, section=section)
    if unsafe:
        ou_list = ", ".join(u["org_unit"] for u in unsafe)
        details = f"{len(unsafe)} OU(s) {fail_text}: {ou_list}"
        if unknown:
            details += f". Undetermined (value absent or unspecified) in OU(s): {', '.join(unknown)}"
        return make_fail(details=details, actual_value=format_ou_values_readable(unsafe, humanizer),
                         expected_value=expected_value, remediation=remediation, **common)
    if exception:
        ou_list = ", ".join(u["org_unit"] for u in exception)
        return make_partial(
            details=f"{len(exception)} intentional external-sharing OU(s) {fail_text}: {ou_list}",
            actual_value=format_ou_values_readable(exception, humanizer),
            expected_value=expected_value, remediation=remediation, **common)
    if unknown:
        return make_review(
            details=(unknown_text or f"Setting could not be determined (value absent or unspecified) for OU(s): "
                     f"{', '.join(unknown)}. Verify in the Admin console."),
            remediation=remediation, expected_value=expected_value, **common)
    return make_pass(details=f"All {len(ou_values)} OU(s) {pass_text}.",
                     actual_value=f"{len(ou_values)} OU(s) safe", expected_value=expected_value, **common)


def _unsafe_display(entry: dict):
    value = entry.get("value")
    if isinstance(value, dict) and len(value) == 1:
        return next(iter(value.values()))
    return value


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


# ---------------------------------------------------------------------------
# Account-level evidence shared by the Security report and Advanced Protection checks
# ---------------------------------------------------------------------------

def admin_emails(data: dict) -> set[str]:
    """Primary emails of active super admins and delegated admins (normalized users)."""
    emails: set[str] = set()
    for u in data.get("users", []) or []:
        if not isinstance(u, dict) or u.get("suspended") or u.get("archived"):
            continue
        if u.get("is_admin") or u.get("isAdmin") or u.get("is_delegated_admin") or u.get("isDelegatedAdmin"):
            email = (u.get("primary_email") or u.get("primaryEmail") or "").lower()
            if email:
                emails.add(email)
    return emails


def _usage_parameter_value(param: dict):
    """Typed value of one Reports API usage parameter (``boolValue``, ``intValue``,
    ``stringValue``, ``datetimeValue``; ``intValue`` arrives as a string)."""
    if "boolValue" in param:
        return bool(param["boolValue"])
    if "intValue" in param:
        try:
            return int(param["intValue"])
        except (TypeError, ValueError):
            return None
    if "stringValue" in param:
        return param["stringValue"]
    if "datetimeValue" in param:
        return param["datetimeValue"]
    return param.get("msgValue")


def user_usage_by_email(data: dict) -> dict[str, dict]:
    """``{email: {parameter name: value}}`` from the per-user usage report rows in
    ``data["user_usage"]`` (Reports API ``userUsageReport.get`` shape: ``entity.userEmail``
    plus a ``parameters`` list). Empty when the report was not collected."""
    out: dict[str, dict] = {}
    for row in data.get("user_usage", []) or []:
        if not isinstance(row, dict):
            continue
        email = str((row.get("entity") or {}).get("userEmail", "")).lower()
        if not email:
            continue
        values = out.setdefault(email, {})
        for param in row.get("parameters", []) or []:
            if isinstance(param, dict) and param.get("name"):
                values[param["name"]] = _usage_parameter_value(param)
    return out


def advanced_protection_enrolment(data: dict) -> dict[str, tuple[str, str]]:
    """``{email: (latest event name, time)}`` from ``titanium_enroll`` / ``titanium_unenroll``
    events in the normalized ``user_accounts`` audit log (``data["user_account_logs"]``).
    The actor is the account whose enrolment changed. Empty when nothing was collected."""
    latest: dict[str, tuple[str, str]] = {}
    for log in data.get("user_account_logs", []) or []:
        if not isinstance(log, dict):
            continue
        event = str(log.get("event_name", "")).lower()
        if event not in ("titanium_enroll", "titanium_unenroll"):
            continue
        email = str(log.get("actor_email", "")).lower()
        when = str(log.get("time", ""))
        if email and (email not in latest or when >= latest[email][1]):
            latest[email] = (event, when)
    return latest


def has_api_error(data: dict, *operation_prefixes: str) -> bool:
    """True when ``data["api_errors"]`` holds an error whose operation starts with any prefix."""
    for err in data.get("api_errors", []) or []:
        op = str(err.get("operation", "")) if isinstance(err, dict) else ""
        if any(op.startswith(prefix) for prefix in operation_prefixes):
            return True
    return False


def chrome_policy_unset(data: dict, schema: str) -> bool:
    """True when Chrome policies were collected without error and *schema* resolved to nothing.

    The Chrome Policy API returns no resolved policy for an unset user policy, so "absent" means
    "Chrome default" only when the collection itself succeeded (``chrome_policies`` present, no
    ``get_chrome_policies`` or ``resolve_policy(<schema>)`` error).
    """
    if not isinstance(data.get("chrome_policies"), dict):
        return False
    return not has_api_error(data, "get_chrome_policies", f"resolve_policy({schema})")


def latest_service_toggles(data: dict, service_name: str) -> dict[str, str]:
    """``{org_unit: latest NEW_VALUE}`` of ``TOGGLE_SERVICE_ENABLED`` events for *service_name*.

    Service on/off switches (Apps > ... > Service status) log as ``TOGGLE_SERVICE_ENABLED`` with
    ``SERVICE_NAME`` (display name, e.g. "Google Takeout", observed live 2026-11-06), ``NEW_VALUE``
    "true"/"false" and ``ORG_UNIT_NAME``. Matching on the name is case-insensitive. Returns ``{}``
    when the window has no event (unknown, not "on").
    """
    wanted = service_name.strip().lower()
    latest: dict[str, tuple[str, str]] = {}
    for log in data.get("admin_logs", []) or []:
        if not isinstance(log, dict) or log.get("event_name") != "TOGGLE_SERVICE_ENABLED":
            continue
        params = log.get("parameters", {}) or {}
        if str(params.get("SERVICE_NAME", "")).strip().lower() != wanted or "NEW_VALUE" not in params:
            continue
        ou = params.get("ORG_UNIT_NAME") or "/"
        when = str(log.get("time", ""))
        if ou not in latest or when > latest[ou][0]:
            latest[ou] = (when, str(params["NEW_VALUE"]).lower())
    return {ou: v for ou, (_, v) in latest.items()}


def gmail_rule_settings(data: dict, setting_name: str) -> dict[str, dict]:
    """Rule-type Gmail settings (TLS compliance, address lists, spam rules...) seen in the admin log.

    They log as ``CREATE_GMAIL_SETTING`` / ``CHANGE_GMAIL_SETTING`` / ``DELETE_GMAIL_SETTING`` with
    ``SETTING_NAME`` (rule family, e.g. "TLS_COMPLIANCE", observed live 2026-11-07),
    ``USER_DEFINED_SETTING_NAME`` (the rule id), ``SETTING_DESCRIPTION`` and ``ORG_UNIT_NAME``.
    Returns ``{rule_id: {"event": latest event name, "time", "org_unit", "description"}}``;
    a rule whose latest event is a delete is gone. ``{}`` when the window holds no event.
    """
    latest: dict[str, dict] = {}
    for log in data.get("admin_logs", []) or []:
        if not isinstance(log, dict):
            continue
        name = str(log.get("event_name", ""))
        if not name.endswith("_GMAIL_SETTING"):
            continue
        params = log.get("parameters", {}) or {}
        if params.get("SETTING_NAME") != setting_name:
            continue
        rule_id = str(params.get("USER_DEFINED_SETTING_NAME") or "")
        when = str(log.get("time", ""))
        if rule_id not in latest or when > latest[rule_id]["time"]:
            latest[rule_id] = {
                "event": name, "time": when,
                "org_unit": params.get("ORG_UNIT_NAME") or "/",
                "description": params.get("SETTING_DESCRIPTION") or "",
            }
    return latest


def latest_setting_changes_by_app(data: dict, setting_suffix: str) -> dict[tuple[str, str], str]:
    """``{(APPLICATION_NAME, org_unit): latest NEW_VALUE}`` for setting names ending in *setting_suffix*.

    For per-service settings that share one proto field across applications, e.g. the Gemini in
    Workspace feature switches, which log as APPLICATION_NAME "calendar_genai" with SETTING_NAME
    "CalendarGenAiEnablementSettingsProto genai_features_enabled" (observed live 2026-11-07).
    """
    latest: dict[tuple[str, str], tuple[str, str]] = {}
    for log in data.get("admin_logs", []) or []:
        if not isinstance(log, dict):
            continue
        params = log.get("parameters", {}) or {}
        name = str(params.get("SETTING_NAME", ""))
        if not name.endswith(setting_suffix) or "NEW_VALUE" not in params:
            continue
        key = (str(params.get("APPLICATION_NAME", "")), params.get("ORG_UNIT_NAME") or "/")
        when = str(log.get("time", ""))
        if key not in latest or when > latest[key][0]:
            latest[key] = (when, str(params["NEW_VALUE"]))
    return {k: v for k, (_, v) in latest.items()}
