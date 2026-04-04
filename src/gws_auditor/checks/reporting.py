# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 5: Reporting checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.3.0 - Reporting controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review
from ..models import CheckResult, Status


@check(
    check_id="CIS-5.1.1.1",
    title="Ensure App Usage Activity Report is reviewed",
    level="L1",
    source="CIS",
    section="Reporting",
    remediation=(
        "Admin console > Reporting > App reports > Accounts. "
        "Review app usage activity regularly to detect anomalous behavior. "
        "Establish a review schedule (e.g., weekly or monthly). https://knowledge.workspace.google.com/admin/reports"
    ),
)
def check_usage_report_reviewed(data: dict) -> CheckResult:
    """App usage activity reports should be reviewed regularly."""
    usage_reports = data.get("usage_reports", [])

    if usage_reports:
        report_count = len(usage_reports)
        latest = usage_reports[0] if isinstance(usage_reports[0], dict) else {}
        latest_date = latest.get("date", "unknown")

        return make_review(
            check_id="CIS-5.1.1.1",
            title="Ensure App Usage Activity Report is reviewed",
            level="L1", source="CIS", section="Reporting",
            details=(
                f"Usage reports are available ({report_count} report entries found, "
                f"latest date: {latest_date}). Manual review is required to confirm "
                "reports are being regularly analyzed for anomalies."
            ),
            remediation=(
                "Admin console > Reporting > App reports > Accounts. "
                "Review app usage activity regularly to detect anomalous behavior. "
                "Establish a review schedule (e.g., weekly or monthly). https://knowledge.workspace.google.com/admin/reports"
            ),
        )

    return CheckResult(
        check_id="CIS-5.1.1.1",
        title="Ensure App Usage Activity Report is reviewed",
        status=Status.NOT_APPLICABLE,
        level="L1", source="CIS", section="Reporting",
        details=(
            "Usage reports are not available for this domain. "
            "The domain may not be verified, or the current Google Workspace "
            "edition does not include this feature."
        ),
        remediation=(
            "Verify your domain in the Admin console, or upgrade to a "
            "Google Workspace edition that includes usage reports. https://knowledge.workspace.google.com/admin/reports"
        ),
    )


@check(
    check_id="CIS-5.1.1.2",
    title="Ensure Security Investigation Tool is used",
    level="L1",
    source="CIS",
    section="Reporting",
    requires_license="enterprise_standard",
    remediation=(
        "Admin console > Security > Investigation tool. "
        "Train administrators to use the Security Investigation Tool "
        "for analyzing security threats, reviewing user activity, and "
        "investigating incidents. https://knowledge.workspace.google.com/admin/security/about-the-security-investigation-tool"
    ),
)
def check_security_investigation_tool(data: dict) -> CheckResult:
    """The Security Investigation Tool should be used for threat analysis."""
    admin_logs = data.get("admin_logs", [])

    # Heuristic: look for evidence of investigation tool usage in admin logs
    investigation_events = [
        log for log in admin_logs
        if log.get("event_name", "").lower() in (
            "security_investigation",
            "investigation_query",
            "security_center_query",
        )
        or "investigation" in log.get("event_name", "").lower()
    ]

    if investigation_events:
        return make_review(
            check_id="CIS-5.1.1.2",
            title="Ensure Security Investigation Tool is used",
            level="L1", source="CIS", section="Reporting",
            details=(
                f"Found {len(investigation_events)} security investigation event(s) in logs. "
                "Verify that the tool is being used regularly and effectively."
            ),
            remediation=(
                "Admin console > Security > Investigation tool. "
                "Use the Security Investigation Tool regularly to analyze "
                "security threats and take action on findings. https://knowledge.workspace.google.com/admin/security/about-the-security-investigation-tool"
            ),
        )

    return make_fail(
        check_id="CIS-5.1.1.2",
        title="Ensure Security Investigation Tool is used",
        level="L1", source="CIS", section="Reporting",
        details=(
            "No evidence of Security Investigation Tool usage found in admin logs."
        ),
        remediation=(
            "Admin console > Security > Investigation tool. "
            "Train administrators to use the Security Investigation Tool "
            "for analyzing security threats, reviewing user activity, and "
            "investigating incidents. https://knowledge.workspace.google.com/admin/security/about-the-security-investigation-tool"
        ),
    )
