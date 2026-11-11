# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.2: Drive and Docs checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Drive and Docs controls.
"""

from .base import (
    check, make_pass, make_fail, make_manual, make_review,
    get_ou_values, format_ou_values_readable, is_external_sharing_ou,
    field_value, ou_verdict,
)
from ..constants import (
    EDITIONS_SHARED_DRIVE_SETTINGS,
)
from ..models import CheckResult, Status


def _build_reverse_ou_map(data: dict) -> dict[str, str]:
    """Build mapping from OU path to OU ID for trust rules lookup."""
    ou_map = {}
    for ou in data.get("org_units", []):
        ou_id = ou.get("orgUnitId", "")
        ou_path = ou.get("orgUnitPath", "")
        if ou_id and ou_path:
            clean_id = ou_id.replace("id:", "")
            ou_map[ou_path] = clean_id
    return ou_map


def _get_active_trust_rules_for_ou(trust_rules: list, ou_path: str,
                                     trigger_type: str,
                                     ou_id_map: dict[str, str]) -> list[dict]:
    """Get active trust rules that apply to a specific OU."""
    if not trust_rules or not ou_id_map.get(ou_path):
        return []
    ou_id = ou_id_map[ou_path]
    matching = []
    for rule in trust_rules:
        if rule.get("status") != "ACTIVE":
            continue
        if trigger_type not in rule.get("trigger", []):
            continue
        for entity in rule.get("targets", {}).get("includedEntity", []):
            rule_ou_id = entity.get("ouId", "")
            if rule_ou_id == ou_id or rule_ou_id == f"id:{ou_id}":
                matching.append(rule)
                break
    return matching


def _has_blocking_trust_rule(trust_rules: list[dict]) -> bool:
    """Return True if any trust rule has a BLOCK_SHARE action."""
    for rule in trust_rules:
        for action in rule.get("action", []):
            if action.get("actionName") == "BLOCK_SHARE":
                return True
    return False


def _external_sharing_verdict(ou_values: list[dict], judge, data: dict,
                              trust_rules: list, ou_id_map: dict[str, str], *,
                              review_text: str, review_expected: str,
                              review_remediation: str, **verdict_kwargs) -> CheckResult:
    """Per-OU verdict for the external-sharing controls, trust-rule aware.

    ``judge(entry)`` follows the :func:`ou_verdict` contract (True / False /
    None or a ``(verdict, shown_value)`` tuple). Precedence for an OU that is
    not compliant (or undetermined): an explicit trust rule wins over the
    external-sharing OU convention, because a rule is a deliberate control
    while the OU name is only a naming heuristic. A ``BLOCK_SHARE`` rule
    clears the OU entirely; any other active rule sends the check to manual
    review. Exception OUs are handled by :func:`ou_verdict` (PARTIAL) and are
    listed alongside a real FAIL so they stay visible.
    """
    trust_rule_ous: list[dict] = []
    exception_ous: list[dict] = []

    def _judge(entry: dict):
        res = judge(entry)
        verdict, shown = res if isinstance(res, tuple) else (res, None)
        if verdict is True:
            return res
        ou_path = entry.get("org_unit", "/")
        applicable_rules = _get_active_trust_rules_for_ou(
            trust_rules, ou_path, "DRIVE_SHARE_TRUST", ou_id_map,
        )
        if applicable_rules:
            if not _has_blocking_trust_rule(applicable_rules):
                trust_rule_ous.append({
                    "org_unit": ou_path,
                    "value": _describe_trust_rule_override(applicable_rules),
                })
            return True
        if verdict is False and is_external_sharing_ou(ou_path, data):
            exception_ous.append({
                "org_unit": ou_path,
                "value": shown if shown is not None else entry.get("value"),
            })
        return res

    result = ou_verdict(ou_values, _judge, data=data, **verdict_kwargs)
    common = {k: verdict_kwargs[k] for k in ("check_id", "title", "level", "source", "section")}
    if result.status == Status.FAIL:
        if not (trust_rule_ous or exception_ous):
            return result
        details = result.details
        if trust_rule_ous:
            details += (f"; {len(trust_rule_ous)} additional OU(s) use trust rules: "
                        f"{', '.join(u['org_unit'] for u in trust_rule_ous)}")
        if exception_ous:
            details += (f"; {len(exception_ous)} external-sharing OU(s) exempt: "
                        f"{', '.join(u['org_unit'] for u in exception_ous)}")
        return make_fail(
            details=details,
            actual_value="\n".join(filter(None, [
                result.actual_value,
                format_ou_values_readable(trust_rule_ous + exception_ous),
            ])),
            expected_value=verdict_kwargs["expected_value"],
            remediation=verdict_kwargs.get("remediation", ""), **common,
        )
    if trust_rule_ous:
        return make_review(
            details=f"{len(trust_rule_ous)} OU(s) {review_text}",
            actual_value=format_ou_values_readable(trust_rule_ous),
            expected_value=review_expected, remediation=review_remediation, **common,
        )
    return result


def _describe_trust_rule_override(trust_rules: list[dict]) -> str:
    """Generate human-readable description of trust rule actions."""
    if not trust_rules:
        return ""
    actions = []
    for rule in trust_rules:
        display_name = rule.get("displayName", "Unnamed rule")
        for action in rule.get("action", []):
            action_name = action.get("actionName", "")
            if action_name == "BLOCK_SHARE":
                actions.append(f"{display_name}: blocks sharing")
            elif action_name == "ALLOW_SHARE":
                actions.append(f"{display_name}: allows with conditions")
            elif action_name == "ALLOW_SHARE_WITH_WARNING":
                actions.append(f"{display_name}: warns but allows")
    return "; ".join(actions) if actions else "Trust rules configured"


@check(
    check_id="CIS-3.1.2.1.1.1",
    title="Ensure users are warned when sharing outside domain",
    level="L1",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable 'Warn when files owned by users in your "
        "organization are shared outside of your organization'. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_external_sharing_warning(data: dict) -> CheckResult:
    """Users should receive a warning when sharing files outside the domain."""
    _ID = "CIS-3.1.2.1.1.1"
    _TITLE = "Ensure users are warned when sharing outside domain"
    _L, _S, _SEC = "L1", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable 'Warn when files owned by users in your "
        "organization are shared outside of your organization'. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # Check for trust rules
    trust_rules = drive.get("trust_rules", [])
    ou_id_map = _build_reverse_ou_map(data) if trust_rules else {}

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            mode = field_value(entry, "externalSharingMode")
            if mode == "DISALLOWED":
                return True  # no external sharing, nothing to warn about
            warn_outside = field_value(entry, "warnForSharingOutsideAllowlistedDomains")
            warn_external = field_value(entry, "warnForExternalSharing", "warnOnExternalSharing")
            if mode == "ALLOWLISTED_DOMAINS" and warn_outside is not None:
                return warn_outside is True, warn_outside
            if mode is None:
                # Sharing mode unknown: the verdict is only determinable when the
                # answer is the same under every mode (both warnings on).
                if warn_outside is True and warn_external is True:
                    return True
                return None
            return None if warn_external is None else (warn_external is True, warn_external)

        return _external_sharing_verdict(
            ou_values, _judge, data, trust_rules, ou_id_map,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not warn on external sharing",
            pass_text="warn on external sharing",
            expected_value="Enabled for all OUs", remediation=_REMED,
            review_text="use trust rules for external sharing control. Manual review required.",
            review_expected="Warning enabled or trust rules block sharing",
            review_remediation=f"Review trust rules. {_REMED}",
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    warn_external = sharing.get("warn_on_external_sharing", None)

    if warn_external is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Users are warned when sharing files outside the domain.",
            actual_value=warn_external,
            expected_value="Enabled for all OUs",
        )

    if warn_external is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine external sharing warning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Users are not warned when sharing files outside the domain.",
        actual_value=warn_external,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.1.2",
    title="Ensure users cannot publish files publicly",
    level="L1",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable 'Allow users to publish files on the web'. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_public_publishing(data: dict) -> CheckResult:
    """Users should not be able to publish files on the web."""
    _ID = "CIS-3.1.2.1.1.2"
    _TITLE = "Ensure users cannot publish files publicly"
    _L, _S, _SEC = "L1", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Disable 'Allow users to publish files on the web'. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # Check for trust rules
    trust_rules = drive.get("trust_rules", [])
    ou_id_map = _build_reverse_ou_map(data) if trust_rules else {}

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowPublishingFiles", "allowPublicPublishing")
            return None if value is None else (value is False, value)

        return _external_sharing_verdict(
            ou_values, _judge, data, trust_rules, ou_id_map,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow public publishing",
            pass_text="disallow public publishing",
            expected_value="Disabled for all OUs", remediation=_REMED,
            review_text="use trust rules to control public publishing. Manual review required.",
            review_expected="Public publishing disabled or blocked by trust rules",
            review_remediation=f"Review trust rules for adequacy. {_REMED}",
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    public_publish = sharing.get("allow_public_publishing", None)

    if public_publish is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Public file publishing is disabled.",
            actual_value=public_publish,
            expected_value="Disabled for all OUs",
        )

    if public_publish is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine public publishing setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Users can publish files publicly on the web.",
        actual_value=public_publish,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.1.3",
    title="Ensure sharing is controlled by domain allowlists",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable domain allowlist and configure trusted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_domain_allowlist(data: dict) -> CheckResult:
    """External sharing should be limited to allowlisted domains."""
    _ID = "CIS-3.1.2.1.1.3"
    _TITLE = "Ensure sharing is controlled by domain allowlists"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable domain allowlist and configure trusted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            # Policy API field is externalSharingMode; DISALLOWED is stricter than an allowlist
            mode = field_value(entry, "externalSharingMode")
            if mode is not None:
                return mode in ("ALLOWLISTED_DOMAINS", "DISALLOWED"), mode
            val = field_value(entry, "allowlistedDomainsEnabled")
            return None if val is None else (val is True, val)

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not have domain allowlist enabled",
            pass_text="have domain allowlist enabled",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic (includes domain count check)
    sharing = drive.get("sharing_settings", {})
    allowlist_enabled = sharing.get("allowlisted_domains_enabled", None)
    allowlist = sharing.get("allowlisted_domains", [])

    if allowlist_enabled is True and len(allowlist) > 0:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Domain allowlist is enabled with {len(allowlist)} domain(s) configured.",
            actual_value={"enabled": True, "domain_count": len(allowlist)},
            expected_value="Allowlist enabled with domains configured",
        )

    if allowlist_enabled is None:
        # If allowlisted_domains_enabled is not set but domains exist,
        # the allowlist is likely active — treat as PASS.
        if len(allowlist) > 0:
            return make_pass(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"Domain allowlist has {len(allowlist)} domain(s) configured (enabled flag not explicit).",
                actual_value={"enabled": None, "domain_count": len(allowlist)},
                expected_value="Allowlist enabled with domains configured",
            )
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine domain allowlist configuration.",
            remediation=(
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Sharing settings. Configure allowlisted domains for external sharing. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
            ),
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Domain allowlist is not enabled or has no domains configured.",
        actual_value={"enabled": allowlist_enabled, "domain_count": len(allowlist)},
        expected_value="Allowlist enabled with domains configured",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.1.4",
    title="Ensure users are warned when sharing with allowlisted domains",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable warnings for sharing with allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_allowlist_warning(data: dict) -> CheckResult:
    """Users should be warned even when sharing with allowlisted domains."""
    _ID = "CIS-3.1.2.1.1.4"
    _TITLE = "Ensure users are warned when sharing with allowlisted domains"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Enable warnings for sharing with allowlisted domains. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            mode = field_value(entry, "externalSharingMode")
            if mode == "DISALLOWED":
                return True  # no external sharing, nothing to warn about
            val = field_value(entry, "warnForSharingOutsideAllowlistedDomains",
                              "warnOnAllowlistedDomainSharing")
            if val is None:
                return None
            if val is True:
                return True  # warned under every sharing mode
            # Not warned: only a verdict when the sharing mode is known (DISALLOWED
            # would make the control moot).
            return None if mode is None else (False, val)

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not warn on allowlisted domain sharing",
            pass_text="warn on allowlisted domain sharing",
            expected_value="Enabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    warn_allowlisted = sharing.get("warn_on_allowlisted_domain_sharing", None)

    if warn_allowlisted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Users are warned when sharing with allowlisted domains.",
            actual_value=warn_allowlisted,
            expected_value="Enabled for all OUs",
        )

    if warn_allowlisted is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine allowlisted domain sharing warning setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Users are not warned when sharing with allowlisted domains.",
        actual_value=warn_allowlisted,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.1.5",
    title="Ensure Access Checker limits file access",
    level="L1",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set Access Checker to 'Recipients only' or "
        "'Your organization'. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
    ),
)
def check_drive_access_checker(data: dict) -> CheckResult:
    """Access Checker should limit file access to recipients only or the domain."""
    _ID = "CIS-3.1.2.1.1.5"
    _TITLE = "Ensure Access Checker limits file access"
    _L, _S, _SEC = "L1", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Set Access Checker to 'Recipients only' or "
        "'Your organization'. https://knowledge.workspace.google.com/admin/drive/restrict-the-access-users-can-give-to-files"
    )
    _SAFE_OU = ("RECIPIENTS_ONLY", "DOMAIN_ONLY")

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            val = field_value(entry, "accessCheckerSuggestions", "accessCheckerSuggestion")
            return None if val is None else (str(val).upper() in _SAFE_OU, val)

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have unsafe Access Checker setting",
            pass_text="have Access Checker properly configured",
            expected_value="RECIPIENTS_ONLY or DOMAIN_ONLY", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    access_checker = sharing.get("access_checker_suggestion", "")

    # Expected values: "recipients_only" or "domain_only" (case-insensitive)
    acceptable = ("recipients_only", "domain_only")

    if access_checker.lower() in acceptable:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"Access Checker is set to '{access_checker}'.",
            actual_value=access_checker,
            expected_value="recipients_only or domain_only",
        )

    if not access_checker:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Access Checker setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Access Checker is set to '{access_checker}', which may allow broader access than intended.",
        actual_value=access_checker,
        expected_value="recipients_only or domain_only",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.1.6",
    title="Ensure only internal users can distribute content externally",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Restrict external content distribution to internal users only. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    ),
)
def check_drive_external_distribution(data: dict) -> CheckResult:
    """Only internal users should be able to distribute content outside the org."""
    _ID = "CIS-3.1.2.1.1.6"
    _TITLE = "Ensure only internal users can distribute content externally"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings. Restrict external content distribution to internal users only. https://knowledge.workspace.google.com/admin/drive/manage-external-sharing-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        def _judge(entry: dict):
            val = field_value(entry, "allowedPartiesForDistributingContent",
                              "externalDistributionAllowedFor")
            if val is None:
                return None
            # NONE ("No one") is stricter than internal-only
            text = str(val)
            return ("internal" in text.lower() or text.upper() == "NONE"), val

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow non-internal external distribution",
            pass_text="restrict external distribution to internal users",
            expected_value="INTERNAL_USERS_ONLY", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    external_dist = sharing.get("external_distribution_allowed_for", "")

    expected = "internal_users_only"

    if external_dist == expected:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Only internal users can distribute content externally.",
            actual_value=external_dist,
            expected_value=expected,
        )

    if not external_dist:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine external distribution setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"External distribution is allowed for '{external_dist}' instead of internal users only.",
        actual_value=external_dist,
        expected_value=expected,
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.2.1",
    title="Ensure Shared Drive creation is controlled",
    level="L1",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Restrict who can create shared drives. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
)
def check_shared_drive_creation(data: dict) -> CheckResult:
    """Shared Drive creation should be restricted to admins or specific groups."""
    _ID = "CIS-3.1.2.1.2.1"
    _TITLE = "Ensure Shared Drive creation is controlled"
    _L, _S, _SEC = "L1", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Restrict who can create shared drives. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowSharedDriveCreation")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow unrestricted shared drive creation",
            pass_text="restrict shared drive creation",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    creation_restricted = shared_drive.get("creation_restricted", None)

    if creation_restricted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shared Drive creation is restricted.",
            actual_value=creation_restricted,
            expected_value="Enabled for all OUs",
        )

    if creation_restricted is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Shared Drive creation setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Shared Drive creation is not restricted. Any user can create shared drives.",
        actual_value=creation_restricted,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.2.2",
    title="Ensure manager cannot override shared drive settings",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Disable 'Allow managers to override settings below'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
    requires_license=EDITIONS_SHARED_DRIVE_SETTINGS,
)
def check_shared_drive_manager_override(data: dict) -> CheckResult:
    """Shared Drive managers should not be able to override sharing settings."""
    _ID = "CIS-3.1.2.1.2.2"
    _TITLE = "Ensure manager cannot override shared drive settings"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Disable 'Allow managers to override settings below'. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowManagersToOverrideSettings")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow managers to override settings",
            pass_text="prevent manager overrides",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    manager_override = shared_drive.get("manager_can_override", None)

    if manager_override is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Managers cannot override shared drive sharing settings.",
            actual_value=manager_override,
            expected_value="Disabled for all OUs",
        )

    if manager_override is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine manager override setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Managers can override shared drive sharing settings.",
        actual_value=manager_override,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.2.3",
    title="Ensure shared drive access is restricted to members",
    level="L1",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Restrict access to shared drive members only. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
    requires_license=EDITIONS_SHARED_DRIVE_SETTINGS,
)
def check_shared_drive_member_access(data: dict) -> CheckResult:
    """Shared drive content should only be accessible to members."""
    _ID = "CIS-3.1.2.1.2.3"
    _TITLE = "Ensure shared drive access is restricted to members"
    _L, _S, _SEC = "L1", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Restrict access to shared drive members only. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowNonMemberAccess")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow non-member access to shared drives",
            pass_text="restrict shared drive access to members",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    member_only = shared_drive.get("access_restricted_to_members", None)

    if member_only is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shared drive access is restricted to members only.",
            actual_value=member_only,
            expected_value="Enabled for all OUs",
        )

    if member_only is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine shared drive member access setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Shared drive content may be accessible to non-members.",
        actual_value=member_only,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.1.2.4",
    title="Ensure viewers cannot download, print, or copy files",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Disable download, print, and copy for viewers and commenters. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    ),
    requires_license=EDITIONS_SHARED_DRIVE_SETTINGS,
)
def check_shared_drive_viewer_restrictions(data: dict) -> CheckResult:
    """Viewers and commenters should be prevented from downloading, printing, or copying."""
    _ID = "CIS-3.1.2.1.2.4"
    _TITLE = "Ensure viewers cannot download, print, or copy files"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Sharing settings > Shared drive creation. "
        "Disable download, print, and copy for viewers and commenters. https://knowledge.workspace.google.com/admin/drive/set-up-shared-drives-for-your-organization"
    )
    _UNSAFE = ("ALL", "EDITORS_AND_ABOVE")

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "shared_drive_creation")
    if ou_values:
        def _judge(entry: dict):
            val = field_value(entry, "allowedPartiesForDownloadPrintCopy")
            return None if val is None else (str(val).upper() not in _UNSAFE, val)

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="allow viewers to download/print/copy",
            pass_text="restrict viewer download/print/copy",
            expected_value="Not ALL or EDITORS_AND_ABOVE", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    viewer_restricted = shared_drive.get("viewer_download_print_copy_disabled", None)

    if viewer_restricted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Viewers and commenters cannot download, print, or copy files.",
            actual_value=viewer_restricted,
            expected_value="Enabled for all OUs",
        )

    if viewer_restricted is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine viewer restriction setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Viewers and commenters can download, print, or copy shared drive files.",
        actual_value=viewer_restricted,
        expected_value="Enabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.2.1",
    scored=False,  # P3: Drive offline access is not exposed by the Policy API; MANUAL by design
    title="Ensure offline access to Drive is disabled",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable 'Allow users to enable offline access'. https://knowledge.workspace.google.com/admin/drive/set-up-offline-access-to-docs-sheets-and-slides"
    ),
)
def check_drive_offline_access(data: dict) -> CheckResult:
    """Offline access to Google Drive should be disabled."""
    _ID = "CIS-3.1.2.2.1"
    _TITLE = "Ensure offline access to Drive is disabled"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable 'Allow users to enable offline access'. https://knowledge.workspace.google.com/admin/drive/set-up-offline-access-to-docs-sheets-and-slides"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = []  # P3: "drive_and_docs.drive_offline" is not a Cloud Identity Policy API setting type; nothing to look up
    if ou_values:
        def _judge(entry: dict):
            val = field_value(entry, "enableOfflineAccess", "enabled")
            return None if val is None else val is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Drive offline access enabled",
            pass_text="have Drive offline access disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    features = drive.get("features", {})
    offline_enabled = features.get("offline_access_enabled", None)

    if offline_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Drive offline access is disabled.",
            actual_value=offline_enabled,
            expected_value="Disabled for all OUs",
        )

    if offline_enabled is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine Drive offline access setting. "
                "The Policy API does not expose this setting. Verify manually in "
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Features and Applications."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Drive offline access is enabled, increasing data leakage risk.",
        actual_value=offline_enabled,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.2.2",
    title="Ensure Desktop access to Drive is disabled",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Google Drive for desktop. Disable 'Allow Google Drive for Desktop'. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    ),
)
def check_drive_desktop_access(data: dict) -> CheckResult:
    """Google Drive for Desktop should be disabled to prevent local syncing."""
    _ID = "CIS-3.1.2.2.2"
    _TITLE = "Ensure Desktop access to Drive is disabled"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Google Drive for desktop. Disable 'Allow Google Drive for Desktop'. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "drive_for_desktop")
    if ou_values:
        def _judge(entry: dict):
            value = field_value(entry, "allowDriveForDesktop")
            return None if value is None else value is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Drive for Desktop enabled",
            pass_text="have Drive for Desktop disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: existing mapped value logic
    features = drive.get("features", {})
    desktop_enabled = features.get("desktop_access_enabled", None)

    if desktop_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Drive for Desktop is disabled.",
            actual_value=desktop_enabled,
            expected_value="Disabled for all OUs",
        )

    if desktop_enabled is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Drive for Desktop setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Drive for Desktop is enabled, allowing local file syncing.",
        actual_value=desktop_enabled,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.2.3",
    title="Ensure Drive SDK is disabled",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications > Drive SDK. Disable the Drive SDK "
        "to prevent third-party application integration. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
    ),
)
def check_drive_sdk(data: dict) -> CheckResult:
    """Drive SDK should be disabled to prevent third-party API access to Drive files."""
    _ID = "CIS-3.1.2.2.3"
    _TITLE = "Ensure Drive SDK is disabled"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications > Drive SDK. Disable the Drive SDK "
        "to prevent third-party application integration. https://knowledge.workspace.google.com/admin/drive/allow-third-party-apps-for-drive-files"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "drive_sdk")
    if ou_values:
        def _judge(entry: dict):
            enabled = field_value(entry, "enableDriveSdkApiAccess", "driveSdkEnabled", "enabled")
            return None if enabled is None else enabled is False

        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have Drive SDK enabled",
            pass_text="have Drive SDK disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value from Policy API normalization
    features = drive.get("features", {})
    sdk_enabled = features.get("drive_sdk_enabled", None)

    # Second fallback: Drive API probe (domainPolicy detection)
    if sdk_enabled is None:
        sdk_enabled = data.get("drive_sdk_enabled", None)

    if sdk_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Drive SDK is disabled.",
            actual_value=sdk_enabled,
            expected_value="Disabled for all OUs",
        )

    if sdk_enabled is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine Drive SDK setting. Verify manually in "
                "Admin console > Apps > Google Workspace > Drive and Docs > "
                "Features and Applications > Drive SDK."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Drive SDK is enabled, allowing third-party API access to Drive files.",
        actual_value=sdk_enabled,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )
