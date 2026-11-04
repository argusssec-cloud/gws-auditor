# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.8-3.1.9: Groups (external) and Marketplace checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - External Groups and Marketplace controls.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, get_ou_values,
                   format_ou_values_readable, field_value, ou_verdict)
from ..models import CheckResult, Status


@check(
    check_id="CIS-3.1.8.1",
    title="Ensure external Google Groups is disabled",
    level="L2",
    source="CIS",
    section="Groups",
    remediation=(
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Disable access to external groups. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    ),
)
def check_external_groups_disabled(data: dict) -> CheckResult:
    """External Google Groups access should be disabled."""
    _ID = "CIS-3.1.8.1"
    _TITLE = "Ensure external Google Groups is disabled"
    _L, _S, _SEC = "L2", "CIS", "Groups"
    _REMED = (
        "Admin console > Apps > Google Workspace > Groups for Business > "
        "Sharing settings. Disable access to external groups. https://knowledge.workspace.google.com/admin/groups/set-organization-wide-policies-for-using-groups"
    )

    policies = data.get("policies", {})
    groups_policy = policies.get("groups", {})

    # OU-aware path
    ou_values = get_ou_values(groups_policy, "groups_sharing")
    if ou_values:
        def _judge(entry):
            # Policy API: groups_for_business.groups_sharing.collaborationCapability;
            # anything other than DOMAIN_USERS_ONLY opens groups to people outside the org.
            capability = field_value(entry, "collaborationCapability")
            if capability is not None:
                return capability == "DOMAIN_USERS_ONLY", capability
            # Legacy aliases (boolean "external groups access enabled").
            ext_groups = field_value(entry, "externalGroupsAccessEnabled", "allowExternalGroupsAccess")
            if ext_groups is None:
                return None
            return ext_groups is not True, ext_groups
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="have external Groups access enabled",
            pass_text="have external Groups access disabled",
            expected_value="Disabled for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    external_groups = groups_policy.get("external_groups_access_enabled", None)

    if external_groups is False:
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="External Google Groups access is disabled.",
            actual_value=external_groups,
            expected_value="Disabled for all OUs",
        )

    if external_groups is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine external Groups access setting.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details="External Google Groups access is enabled.",
        actual_value=external_groups,
        expected_value="Disabled for all OUs",
        remediation=_REMED,
    )


@check(
    check_id="CIS-3.1.9.1.1",
    title="Ensure Marketplace apps are restricted",
    level="L1",
    source="CIS",
    section="Marketplace",
    remediation=(
        "Admin console > Apps > Google Workspace Marketplace apps > Settings. "
        "Set 'Allow users to install and run only approved Marketplace Apps "
        "from the allow list'. https://knowledge.workspace.google.com/admin/apps/set-whether-users-can-install-marketplace-apps"
    ),
)
def check_marketplace_restriction(data: dict) -> CheckResult:
    """Marketplace app installation should be restricted to approved apps only."""
    _ID = "CIS-3.1.9.1.1"
    _TITLE = "Ensure Marketplace apps are restricted"
    _L, _S, _SEC = "L1", "CIS", "Marketplace"
    _REMED = (
        "Admin console > Apps > Google Workspace Marketplace apps > Settings. "
        "Set 'Allow users to install and run only approved Marketplace Apps "
        "from the allow list'. https://knowledge.workspace.google.com/admin/apps/set-whether-users-can-install-marketplace-apps"
    )

    policies = data.get("policies", {})
    marketplace = policies.get("marketplace", {})

    # OU-aware path
    ou_values = get_ou_values(marketplace, "apps_access_options")
    if ou_values:
        def _judge(entry):
            # Real field first; the others are legacy aliases.
            policy = field_value(entry, "accessLevel", "appInstallPolicy", "installPolicy", "accessOption")
            if not policy:
                return None  # edition-dependent default, not injected: unknown
            # ALLOW_NONE (block all installs) is stricter than an allowlist
            is_restricted = policy.lower() in ("allowlist_only", "allowlisted_only", "approved_only",
                                               "allow_listed_apps", "allow_none")
            return is_restricted, policy
        return ou_verdict(
            ou_values, _judge,
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            fail_text="do not restrict Marketplace apps",
            pass_text="restrict Marketplace apps to approved only",
            expected_value="approved_only for all OUs", remediation=_REMED,
        )

    # Fallback: mapped root-level value
    install_policy = marketplace.get("app_install_policy", "")
    approved_only = marketplace.get("restrict_to_approved_apps", None)

    if approved_only is True or install_policy in ("approved_only", "restricted"):
        return make_pass(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Marketplace app installation is restricted to approved apps only.",
            actual_value={
                "install_policy": install_policy,
                "approved_only": approved_only,
            },
            expected_value="approved_only",
        )

    if install_policy == "" and approved_only is None:
        return make_manual(
            check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
            details="Could not determine Marketplace app installation policy.",
            remediation=_REMED,
        )

    return make_fail(
        check_id=_ID, title=_TITLE, level=_L, source=_S, section=_SEC,
        details=f"Marketplace app installation policy is '{install_policy}', not restricted to approved apps.",
        actual_value={
            "install_policy": install_policy,
            "approved_only": approved_only,
        },
        expected_value="approved_only",
        remediation=_REMED,
    )
