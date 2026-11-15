# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Section 5: Reporting checks for GWS Security Auditor.

CIS Google Workspace Benchmark v1.4.1 - Reporting controls.
"""

from .base import check, make_pass, make_fail, make_warn, make_manual, make_review, admin_emails, user_usage_by_email
from ..models import CheckResult, Status


@check(
    check_id="CIS-5.1.1.1",
    scored=False,  # Admin-console-only control: no API or audit-log signal (plan Decision C)
    title="Ensure App Usage Activity Report is reviewed",
    level="L1",
    source="CIS",
    section="Reporting",
    remediation=(
        "Admin console > Reporting > Apps Reports > Accounts. "
        "Review app usage activity regularly to detect anomalous behavior. "
        "Establish a review schedule (e.g., weekly or monthly). https://knowledge.workspace.google.com/admin/reports/reports-overview"
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
                "Admin console > Reporting > Apps Reports > Accounts. "
                "Review app usage activity regularly to detect anomalous behavior. "
                "Establish a review schedule (e.g., weekly or monthly). https://knowledge.workspace.google.com/admin/reports/reports-overview"
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
            "Google Workspace edition that includes usage reports. https://knowledge.workspace.google.com/admin/reports/reports-overview"
        ),
    )



_SECURITY_REPORT_REMED = (
    "Admin console > Reporting > User Reports > Security. Review the report weekly, at a minimum "
    "for administrator accounts: enrol them in 2-Step Verification, require strong and compliant passwords "
    "and keep less secure app access off. https://knowledge.workspace.google.com/admin/reports/reports-overview"
)


@check(
    check_id="CIS-5.1.1.2",
    title="Ensure the Security Report is reviewed regularly for anomalies",
    level="L1",
    source="CIS",
    section="Reporting",
    remediation=_SECURITY_REPORT_REMED,
)
def check_security_report_reviewed(data: dict) -> CheckResult:
    """CIS 5.1.1.2 asks for a weekly review of Reporting > User reports > Security and says that
    "at a minimum, all Administrator and Super Administrator users should be reviewed". The
    report's columns are the ``accounts:*`` user usage parameters, so the administrator rows are
    judged here on 2-Step Verification enrolment, password strength, password length compliance
    and less secure app access. Security keys, passkeys and authorized apps are reported, not
    judged (CIS-4.1.1.2 and ADD-33 cover them)."""
    common = dict(check_id="CIS-5.1.1.2", title="Ensure the Security Report is reviewed regularly for anomalies",
                  level="L1", source="CIS", section="Reporting")
    admins = admin_emails(data)
    if not admins:
        return make_manual(**common, details="No administrator accounts were collected, so the Security report rows "
                                             "to review are unknown.", remediation=_SECURITY_REPORT_REMED)
    usage = user_usage_by_email(data)
    if not usage:
        return make_review(**common, details=(
            "The per-user usage report with the accounts:* parameters was not collected (Reports API, scope "
            "admin.reports.usage.readonly), so the Security report columns cannot be reviewed here. Review "
            "Admin console > Reporting > User Reports > Security, at least for administrators."),
            remediation=_SECURITY_REPORT_REMED)

    anomalies, missing, reviewed = [], [], {}
    for email in sorted(admins):
        row = usage.get(email)
        if row is None:
            missing.append(email)
            continue
        problems = []
        if row.get("accounts:is_2sv_enrolled") is False:
            problems.append("2SV not enrolled")
        strength = str(row.get("accounts:password_strength") or "").upper()
        if strength and strength != "STRONG":
            problems.append(f"password strength {strength}")
        compliance = str(row.get("accounts:password_length_compliance") or "").upper()
        if compliance and compliance != "COMPLIANT":
            problems.append(f"password length {compliance}")
        if row.get("accounts:is_less_secure_apps_access_allowed") is True:
            problems.append("less secure apps allowed")
        reviewed[email] = {
            "problems": problems,
            "security_keys": row.get("accounts:num_security_keys"),
            "passkeys": row.get("accounts:num_passkeys_enrolled"),
            "authorized_apps": row.get("accounts:num_authorized_apps"),
        }
        if problems:
            anomalies.append(f"{email} [{', '.join(problems)}]")

    expected = "Every administrator row of the Security report shows 2SV enrolled, a strong compliant password and no less secure app access"
    if anomalies:
        return make_fail(**common, details=(
            f"{len(anomalies)} of {len(admins)} administrator row(s) in the Security report show an anomaly: "
            + "; ".join(anomalies)), actual_value={"admins": reviewed, "no_row_yet": missing},
            expected_value=expected, remediation=_SECURITY_REPORT_REMED)
    if missing:
        return make_review(**common, details=(
            f"{len(reviewed)} administrator row(s) reviewed without anomaly, but {len(missing)} administrator(s) have "
            f"no Security report row yet (the report lags two to three days): {', '.join(missing)}. Review them in "
            "Admin console > Reporting > User Reports > Security."),
            actual_value={"admins": reviewed, "no_row_yet": missing}, expected_value=expected,
            remediation=_SECURITY_REPORT_REMED)
    return make_pass(**common, details=(
        f"All {len(reviewed)} administrator row(s) of the Security report are clean: 2SV enrolled, strong compliant "
        "password, no less secure app access."), actual_value={"admins": reviewed, "no_row_yet": []},
        expected_value=expected)


_DASHBOARD_REMED = (
    "Admin console > Security > Security center > Dashboard. Review the panels (DLP incidents, failed "
    "and suspicious sign-ins, OAuth grants, device events) at least weekly, at minimum for administrator "
    "accounts. https://knowledge.workspace.google.com/admin/security/about-the-security-dashboard"
)


@check(
    check_id="CIS-4.3.1",
    scored=False,  # Admin-console-only control: a review cadence has no API or audit-log signal
    title="Ensure the Security dashboard is reviewed regularly for anomalies",
    level="L1",
    source="CIS",
    section="Reporting",
    remediation=_DASHBOARD_REMED,
)
def check_security_dashboard_reviewed(data: dict) -> CheckResult:
    """CIS 4.3.1 (L1): the Security dashboard (Security center) is reviewed weekly. No API exposes
    whether anyone looked at it, so the result is MANUAL; the alert checks (CIS-6.x) and
    GWS.COMMONCONTROLS.13.1 cover the automated side of the same signals."""
    return make_review(
        check_id="CIS-4.3.1", title="Ensure the Security dashboard is reviewed regularly for anomalies",
        level="L1", source="CIS", section="Reporting",
        details=("Review cadence is a process control: confirm the Security dashboard is reviewed weekly "
                 "(availability of individual panels depends on the edition). Record the outcome with a "
                 "dashboard override once confirmed."),
        remediation=_DASHBOARD_REMED,
    )


_HEALTH_REMED = (
    "Admin console > Security > Security center > Security health. Review every setting flagged with a "
    "recommendation at least weekly and act on the ones that matter to your organisation. "
    "https://knowledge.workspace.google.com/admin/security/security-health-page"
)


@check(
    check_id="CIS-4.3.2",
    scored=False,  # Admin-console-only control: a review cadence has no API or audit-log signal
    title="Ensure the Security health page is reviewed regularly for anomalies",
    level="L1",
    source="CIS",
    section="Reporting",
    remediation=_HEALTH_REMED,
)
def check_security_health_reviewed(data: dict) -> CheckResult:
    """CIS 4.3.2 (L1): the Security health page is reviewed weekly. The settings it lists (2SV,
    security keys, mobile management, Drive sharing, forwarding) are judged by their own checks
    here; the review itself has no API signal, so the result is MANUAL."""
    return make_review(
        check_id="CIS-4.3.2", title="Ensure the Security health page is reviewed regularly for anomalies",
        level="L1", source="CIS", section="Reporting",
        details=("Review cadence is a process control: confirm the Security health page is reviewed weekly. "
                 "This report's individual settings are judged by the 2SV, security key, device, Drive "
                 "sharing and forwarding checks."),
        remediation=_HEALTH_REMED,
    )
