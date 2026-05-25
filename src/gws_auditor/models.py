# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Data models for GWS Security Auditor."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Status(Enum):
    """Check result status."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    PARTIAL = "PARTIAL"
    ERROR = "ERROR"
    MANUAL = "MANUAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(str, Enum):
    """Check severity level indicating business impact of a failure."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class CheckResult:
    """Result of a single security check."""
    check_id: str
    title: str
    status: Status
    level: str = "L1"
    source: str = "CIS"
    section: str = ""
    details: str = ""
    actual_value: Any = None
    expected_value: Any = None
    remediation: str = ""
    org_unit: str = "Global"
    cis_controls: list = field(default_factory=list)
    severity: "Severity" = Severity.MEDIUM
    critical_reason: str = ""
    scored: bool = True
    docs_url: str = ""
    console_link: str = ""
    gam_command: str = ""


@dataclass
class CheckMetadata:
    """Metadata for a registered check function."""
    check_id: str
    title: str
    level: str
    source: str
    section: str
    func: Any = None
    remediation: str = ""
    requires_license: str = ""
    severity: "Severity" = Severity.MEDIUM
    critical_reason: str = ""
    scored: bool = True
    docs_url: str = ""
    console_link: str = ""
    gam_command: str = ""


@dataclass
class AuditSummary:
    """Summary statistics for an audit run."""
    total: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    partial: int = 0
    errors: int = 0
    manual: int = 0
    not_applicable: int = 0
    critical_failed: int = 0
    posture_score: int = 0
    posture_grade: str = ""

    @property
    def pass_rate(self) -> float:
        # Denominator includes PASS, FAIL, WARN, and PARTIAL (soft failures).
        # ERROR, MANUAL, and NOT_APPLICABLE are excluded because they
        # represent checks that could not be evaluated. PARTIAL contributes
        # half-credit to the numerator.
        evaluated = self.passed + self.failed + self.warnings + self.partial
        if evaluated == 0:
            return 0.0
        credited = self.passed + (self.partial * 0.5)
        return (credited / evaluated) * 100

    @classmethod
    def from_results(cls, results: list["CheckResult"]) -> "AuditSummary":
        summary = cls(total=len(results))
        for r in results:
            if r.status == Status.PASS:
                summary.passed += 1
            elif r.status == Status.FAIL:
                summary.failed += 1
                if r.severity == Severity.CRITICAL:
                    summary.critical_failed += 1
            elif r.status == Status.WARN:
                summary.warnings += 1
            elif r.status == Status.PARTIAL:
                summary.partial += 1
            elif r.status == Status.ERROR:
                summary.errors += 1
            elif r.status == Status.MANUAL:
                summary.manual += 1
            elif r.status == Status.NOT_APPLICABLE:
                summary.not_applicable += 1
        return summary


@dataclass
class AuditReport:
    """Full audit report container."""
    timestamp: str = ""
    customer_id: str = ""
    domains: list = field(default_factory=list)
    results: list = field(default_factory=list)
    summary: AuditSummary = field(default_factory=AuditSummary)
    api_errors: list = field(default_factory=list)
    config: dict = field(default_factory=dict)
    org_units: list = field(default_factory=list)
    subscription_type: str = ""
