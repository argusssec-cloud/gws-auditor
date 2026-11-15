# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 3.1.7: Sites checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.4.1 - Sites controls.
"""

from .base import (check, make_pass, make_fail, make_warn, make_manual, make_review, get_ou_values,
                   format_ou_values_readable, field_value, ou_verdict)
from ..models import CheckResult, Status


_SITES_REMED = (
    "Admin console > Apps > Google Workspace > Sites > Service status. Set the service to OFF for "
    "everyone, and turn it on only for the OUs or groups that need Google Sites. "
    "https://knowledge.workspace.google.com/admin/users/access/turn-sites-on-or-off-for-users"
)


@check(
    check_id="CIS-3.1.7.1",
    title="Ensure service status for Google Sites is set to off",
    level="L1",
    source="CIS",
    section="Sites",
    remediation=_SITES_REMED,
)
def check_sites_creation_disabled(data: dict) -> CheckResult:
    """CIS 3.1.7.1 (L1): the Google Sites service is OFF (``sites.service_status.serviceState``
    DISABLED) for every OU. Disabling only new-site creation leaves the service on, so it does not
    satisfy the benchmark; it is reported in the details. GWS.SITES.1.1 judges the same setting."""
    _ID = "CIS-3.1.7.1"
    _TITLE = "Ensure service status for Google Sites is set to off"
    common = dict(check_id=_ID, title=_TITLE, level="L1", source="CIS", section="Sites")
    policies = data.get("policies", {})
    sites = policies.get("sites", {})
    service = get_ou_values(sites, "service_status")
    if service:
        def _judge(entry):
            state = field_value(entry, "serviceState")
            if state is None:
                return None
            return str(state).upper() == "DISABLED", state
        result = ou_verdict(
            service, _judge, **common,
            fail_text="have the Google Sites service ON",
            pass_text="have the Google Sites service OFF",
            expected_value="Service status OFF for all OUs", remediation=_SITES_REMED,
        )
        if result.status == Status.FAIL:
            creation_off = sorted(
                e["org_unit"] for e in get_ou_values(sites, "sites_creation_and_modification")
                if field_value(e, "allowSitesCreation") is False)
            if creation_off:
                result.details = (result.details or "").rstrip() + (
                    f" New-site creation is disabled for {', '.join(creation_off)}, but the benchmark requires "
                    "the service itself to be OFF; users there can still open and edit existing sites.")
        return result
    status = str(sites.get("service_status") or "").lower()
    if status in ("disabled", "off"):
        return make_pass(**common, details="The Google Sites service is OFF.",
                         actual_value=status, expected_value="Service status OFF for all OUs")
    if status in ("enabled", "on"):
        return make_fail(**common, details="The Google Sites service is ON.",
                         actual_value=status, expected_value="Service status OFF for all OUs",
                         remediation=_SITES_REMED)
    return make_review(
        **common, remediation=_SITES_REMED,
        details=("'sites.service_status' was not returned by the Cloud Identity Policy API, so the service "
                 "state is unknown — verify in Admin console > Apps > Google Workspace > Sites."),
    )
