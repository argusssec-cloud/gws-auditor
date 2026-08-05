# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.7: Sites checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Sites controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values, format_ou_values_readable
from ..models import CheckResult, Status


@check(
    check_id="CIS-3.1.7.1",
    title="Ensure Google Sites creation is disabled",
    level="L2",
    source="CIS",
    section="Sites",
    remediation="Admin console > Apps > Google Workspace > Sites > New Sites. Disable 'Allow users to create new Sites'. https://knowledge.workspace.google.com/admin/users/access/turn-google-sites-on-or-off-for-users",
)
def check_sites_creation_disabled(data: dict) -> CheckResult:
    """Google Sites creation should be disabled to prevent unmanaged web publishing."""
    _ID = "CIS-3.1.7.1"
    _TITLE = "Ensure Google Sites creation is disabled"
    _L, _S, _SEC = "L2", "CIS", "Sites"
    _REMED = (
        "Admin console > Apps > Google Workspace > Sites > "
        "New Sites. Disable 'Allow users to create new Sites'. https://knowledge.workspace.google.com/admin/users/access/turn-google-sites-on-or-off-for-users"
    )

    policies = data.get("policies", {})
    sites = policies.get("sites", {})

    # OU-aware path
    ou_values = get_ou_values(sites, "sites_creation_and_modification")
    if ou_values:
        unsafe_ous = []
        for entry in ou_values:
            allow = entry["value"].get("allowSitesCreation", None)
            if allow is True:
                unsafe_ous.append({"org_unit": entry["org_unit"], "value": allow})
        if unsafe_ous:
            ou_list = ", ".join(u["org_unit"] for u in unsafe_ous)
            return make_fail(
                check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
                details=f"{len(unsafe_ous)} OU(s) have Sites creation enabled: {ou_list}",
                actual_value=format_ou_values_readable(unsafe_ous), expected_value="Disabled for all OUs",
                remediation=_REMED,
            )
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=f"All {len(ou_values)} OU(s) have Sites creation disabled.",
            actual_value=f"{len(ou_values)} OU(s) safe", expected_value="Disabled for all OUs",
        )

    # Fallback: mapped root-level value
    creation_enabled = sites.get("sites_creation_enabled", None)

    if creation_enabled is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Google Sites creation is disabled.",
            actual_value=creation_enabled,
            expected_value="Disabled for all OUs",
        )

    if creation_enabled is None:
        return make_review(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details=(
                "Could not determine Google Sites creation setting. "
                "Verify manually in Admin console > Apps > Google Workspace > "
                "Sites > New Sites."
            ),
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="Google Sites creation is enabled, allowing users to publish web content.",
        actual_value=creation_enabled,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )
