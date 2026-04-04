# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.2: Drive and Docs checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Drive and Docs controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values
from ..models import CheckResult, Status


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

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("warnForExternalSharing",
                        entry["value"].get("warnOnExternalSharing", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not warn on external sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) warn on external sharing.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    warn_external = sharing.get("warn_on_external_sharing", None)

    if warn_external is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Users are warned when sharing files outside the domain.",
            actual_value=warn_external,
            expected_value=True,
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
        expected_value=True,
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

    # OU-aware path
    ou_values = get_ou_values(drive, "external_sharing")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowPublishingFiles",
                        entry["value"].get("allowPublicPublishing", None))
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow public publishing: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) disallow public publishing.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    public_publish = sharing.get("allow_public_publishing", None)

    if public_publish is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Public file publishing is disabled.",
            actual_value=public_publish,
            expected_value=False,
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
        expected_value=False,
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowlistedDomainsEnabled", None)
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not have domain allowlist enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have domain allowlist enabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("warnForSharingOutsideAllowlistedDomains",
                        entry["value"].get("warnOnAllowlistedDomainSharing", None))
            if val is not True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) do not warn on allowlisted domain sharing: {ou_list}",
                actual_value=unsafe_ous, expected_value=True,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) warn on allowlisted domain sharing.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=True,
        )

    # Fallback: existing mapped value logic
    sharing = drive.get("sharing_settings", {})
    warn_allowlisted = sharing.get("warn_on_allowlisted_domain_sharing", None)

    if warn_allowlisted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Users are warned when sharing with allowlisted domains.",
            actual_value=warn_allowlisted,
            expected_value=True,
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
        expected_value=True,
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("accessCheckerSuggestions",
                        entry["value"].get("accessCheckerSuggestion", ""))
            if val.upper() not in _SAFE_OU:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have unsafe Access Checker setting: {ou_list}",
                actual_value=unsafe_ous, expected_value="RECIPIENTS_ONLY or DOMAIN_ONLY",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Access Checker properly configured.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="RECIPIENTS_ONLY or DOMAIN_ONLY",
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowedPartiesForDistributingContent",
                        entry["value"].get("externalDistributionAllowedFor", ""))
            if "internal" not in val.lower():
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow non-internal external distribution: {ou_list}",
                actual_value=unsafe_ous, expected_value="INTERNAL_USERS_ONLY",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict external distribution to internal users.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="INTERNAL_USERS_ONLY",
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowSharedDriveCreation", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow unrestricted shared drive creation: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict shared drive creation.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    creation_restricted = shared_drive.get("creation_restricted", None)

    if creation_restricted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shared Drive creation is restricted.",
            actual_value=creation_restricted,
            expected_value=True,
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
        expected_value=True,
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
    requires_license="business_starter",
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowManagersToOverrideSettings", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow managers to override settings: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) prevent manager overrides.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    manager_override = shared_drive.get("manager_can_override", None)

    if manager_override is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Managers cannot override shared drive sharing settings.",
            actual_value=manager_override,
            expected_value=False,
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
        expected_value=False,
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
    requires_license="business_starter",
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowNonMemberAccess", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow non-member access to shared drives: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict shared drive access to members.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    member_only = shared_drive.get("access_restricted_to_members", None)

    if member_only is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Shared drive access is restricted to members only.",
            actual_value=member_only,
            expected_value=True,
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
        expected_value=True,
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
    requires_license="business_starter",
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
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowedPartiesForDownloadPrintCopy", "")
            if val.upper() in _UNSAFE:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(f"{u['org_unit']} ({u['value']})" for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) allow viewers to download/print/copy: {ou_list}",
                actual_value=unsafe_ous, expected_value="Not ALL or EDITORS_AND_ABOVE",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) restrict viewer download/print/copy.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Not ALL or EDITORS_AND_ABOVE",
        )

    # Fallback: existing mapped value logic
    shared_drive = drive.get("shared_drive_settings", {})
    viewer_restricted = shared_drive.get("viewer_download_print_copy_disabled", None)

    if viewer_restricted is True:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Viewers and commenters cannot download, print, or copy files.",
            actual_value=viewer_restricted,
            expected_value=True,
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
        expected_value=True,
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.2.2.1",
    title="Ensure offline access to Drive is disabled",
    level="L2",
    source="CIS",
    section="Drive and Docs",
    remediation=(
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable 'Allow users to enable offline access'. https://knowledge.workspace.google.com/admin/drive/set-up-offline-access-to-docs-sheets-and-slides"
    ),
    requires_license="enterprise_plus",
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
    ou_values = get_ou_values(drive, "drive_offline")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("enableOfflineAccess", entry["value"].get("enabled", None))
            if val is True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Drive offline access enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Drive offline access disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    features = drive.get("features", {})
    offline_enabled = features.get("offline_access_enabled", None)

    if offline_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Drive offline access is disabled.",
            actual_value=offline_enabled,
            expected_value=False,
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
        expected_value=False,
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
        "Features and Applications. Disable 'Allow Google Drive for Desktop'. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    ),
)
def check_drive_desktop_access(data: dict) -> CheckResult:
    """Google Drive for Desktop should be disabled to prevent local syncing."""
    _ID = "CIS-3.1.2.2.2"
    _TITLE = "Ensure Desktop access to Drive is disabled"
    _L, _S, _SEC = "L2", "CIS", "Drive and Docs"
    _REMED = (
        "Admin console > Apps > Google Workspace > Drive and Docs > "
        "Features and Applications. Disable 'Allow Google Drive for Desktop'. https://knowledge.workspace.google.com/admin/drive/set-up-drive-for-desktop-for-your-organization"
    )

    policies = data.get("policies", {})
    drive = policies.get("drive", {})

    # OU-aware path
    ou_values = get_ou_values(drive, "drive_for_desktop")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            val = entry["value"].get("allowDriveForDesktop", None)
            if val is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": val})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Drive for Desktop enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Drive for Desktop disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
        )

    # Fallback: existing mapped value logic
    features = drive.get("features", {})
    desktop_enabled = features.get("desktop_access_enabled", None)

    if desktop_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Drive for Desktop is disabled.",
            actual_value=desktop_enabled,
            expected_value=False,
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
        expected_value=False,
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
        unsafe_ous = []
        for entry in ou_values:
            enabled = entry["value"].get("enableDriveSdkApiAccess",
                                         entry["value"].get("driveSdkEnabled",
                                         entry["value"].get("enabled", None)))
            if enabled is not False:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": enabled})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Drive SDK enabled: {ou_list}",
                actual_value=unsafe_ous, expected_value=False,
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Drive SDK disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value=False,
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
            expected_value=False,
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
        expected_value=False,
        remediation=_REMED,
    )
