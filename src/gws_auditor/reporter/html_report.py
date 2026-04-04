# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""HTML report generator for GWS Security Auditor."""

import json
import re
from collections import OrderedDict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from gws_auditor.models import AuditReport, AuditSummary, Status
from gws_auditor._frozen import resolve_package_path


_TEMPLATE_DIR = resolve_package_path(__file__) / "templates"
_TEMPLATE_NAME = "report.html.j2"

INVENTORY_CHECK_IDS = frozenset({
    "ADD-28", "ADD-29", "ADD-30", "ADD-31", "ADD-32", "ADD-33", "ADD-34", "ADD-35",
    "ADD-38", "ADD-39",
})


def _tojson_safe(value) -> Markup:
    """Jinja2 filter that serializes a value to JSON for embedding in a <script> tag."""
    return Markup(json.dumps(value, default=str))


def _humanize_key(key: str) -> str:
    """Convert a snake_case or camelCase key to a readable label.

    ``"reject_if_spf_fail"`` → ``"Reject If SPF Fail"``
    ``"enableMailImport"``   → ``"Enable Mail Import"``
    """
    # camelCase → spaces
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    # snake_case → spaces
    s = s.replace("_", " ")
    return s.strip().title()


def _humanize_value(val) -> str:
    """Convert an UPPER_SNAKE enum-like string or bool to readable text."""
    if isinstance(val, bool):
        return "Yes" if val else "No"
    if val is None:
        return "N/A"
    if isinstance(val, str):
        # UPPER_SNAKE values like EXTERNAL_ALL_INFO_READ_ONLY
        if re.fullmatch(r"[A-Z][A-Z0-9_]+", val):
            return val.replace("_", " ").title()
        return val
    return str(val)


def format_value(value) -> str:
    """Format an actual_value / expected_value for human-readable display.

    Handles:
    - list of OU dicts  → ``/ou_path: Readable Value`` per line
    - plain dict        → ``Key: value`` per line
    - list of scalars   → comma-separated
    - bool / None / str → simple conversion
    """
    if value is None:
        return ""

    # List of OU dicts: [{"org_unit": "/path", "value": ...}, ...]
    if isinstance(value, list) and value and isinstance(value[0], dict) and "org_unit" in value[0]:
        lines = []
        for entry in value:
            ou = entry.get("org_unit", "/")
            v = entry.get("value", "")
            if isinstance(v, dict):
                parts = [f"{_humanize_key(k)}: {_humanize_value(vv)}" for k, vv in v.items()]
                lines.append(f"{ou} \u2192 {', '.join(parts)}")
            else:
                lines.append(f"{ou} \u2192 {_humanize_value(v)}")
        return "; ".join(lines)

    # Plain dict: {"key": value, ...}
    if isinstance(value, dict):
        parts = [f"{_humanize_key(k)}: {_humanize_value(v)}" for k, v in value.items()]
        return ", ".join(parts)

    # List of scalars
    if isinstance(value, list):
        return ", ".join(_humanize_value(v) for v in value)

    # Scalar
    return _humanize_value(value)


class HTMLReporter:
    """Generates a self-contained HTML report from a Jinja2 template."""

    def __init__(self, report: AuditReport):
        self.report = report

    def generate(self, output_path: str) -> None:
        """Render the audit report as an HTML file.

        Results are grouped by their ``section`` attribute so the
        template can render per-section drill-down tables.  Inventory
        checks (ADD-28 through ADD-33) are separated into their own
        tabbed dashboards.

        Args:
            output_path: Filesystem path for the generated HTML file.
        """
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=True,
        )
        env.filters["tojson_safe"] = _tojson_safe
        template = env.get_template(_TEMPLATE_NAME)

        audit_results, inventory = self._extract_inventory_checks()
        sections = self._group_by_section(audit_results)
        audit_summary = AuditSummary.from_results(audit_results)
        available_ous = self._collect_all_ous(sections)

        # Collect critical failures for the banner
        critical_findings = [
            {
                "check_id": r.check_id,
                "title": r.title,
                "details": r.details,
                "severity": getattr(r, "severity", "MEDIUM"),
                "critical_reason": getattr(r, "critical_reason", ""),
                "remediation": r.remediation,
                "section": r.section,
            }
            for r in audit_results
            if r.status == Status.FAIL and getattr(r, "severity", "") == "CRITICAL"
        ]

        html = template.render(
            timestamp=self.report.timestamp,
            customer_id=self.report.customer_id,
            subscription_type=self.report.subscription_type,
            domains=self.report.domains,
            summary=audit_summary,
            critical_findings=critical_findings,
            critical_failed=len(critical_findings),
            sections=sections,
            api_errors=self.report.api_errors,
            available_ous=available_ous,
            inventory=inventory,
        )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)

    @staticmethod
    def _extract_ou_fail_data(check) -> str:
        """Extract failing OU paths from a check's actual_value before formatting.

        If ``actual_value`` is a list of dicts with ``"org_unit"`` keys
        (the standard shape for OU-aware checks that fail), return a
        JSON-encoded list of OU path strings.  Otherwise return an empty
        string, meaning the check is not OU-aware or passed globally.
        """
        val = check.actual_value
        if (
            isinstance(val, list)
            and val
            and isinstance(val[0], dict)
            and "org_unit" in val[0]
        ):
            ou_paths = [entry.get("org_unit", "/") for entry in val]
            return json.dumps(ou_paths)
        return ""

    def _collect_all_ous(self, sections: OrderedDict) -> list[str]:
        """Build a sorted list of all known OU paths.

        Combines OUs from ``report.org_units`` (populated by the
        orchestrator) with any OUs embedded in check results (fallback
        for old cached reports).  The root OU ``"/"`` is always included.
        """
        ous: set[str] = {"/"}

        # From the report model (primary source)
        for ou in getattr(self.report, "org_units", []):
            if ou:
                ous.add(ou)

        # Fallback: extract from check result ou_fail_data
        for checks in sections.values():
            for entry in checks:
                raw = entry.get("ou_fail_data", "")
                if raw:
                    try:
                        for path in json.loads(raw):
                            if path:
                                ous.add(path)
                    except (json.JSONDecodeError, TypeError):
                        pass

        return sorted(ous, key=lambda p: (p != "/", p.lower()))

    def _extract_inventory_checks(self) -> tuple[list, dict]:
        """Partition results into audit checks and inventory checks.

        Returns:
            A tuple of ``(audit_results, inventory)`` where
            ``audit_results`` is a list of ``CheckResult`` objects and
            ``inventory`` is a dict keyed by check_id with structured
            data for the inventory tab dashboards.
        """
        audit_results = []
        inventory: dict[str, dict] = {}

        for check in self.report.results:
            if check.check_id in INVENTORY_CHECK_IDS:
                status_value = (
                    check.status.value
                    if isinstance(check.status, Status)
                    else str(check.status)
                )
                inventory[check.check_id] = {
                    "check_id": check.check_id,
                    "title": check.title,
                    "status": status_value,
                    "details": check.details,
                    "remediation": check.remediation,
                    "raw_data": check.actual_value if isinstance(check.actual_value, dict) else {},
                }
            else:
                audit_results.append(check)

        return audit_results, inventory

    def _group_by_section(self, results: list | None = None) -> OrderedDict:
        """Group CheckResult objects by section name.

        Args:
            results: Optional list of CheckResult objects to group.
                If ``None``, uses ``self.report.results``.

        Returns an OrderedDict mapping section names to lists of
        lightweight dicts suitable for template rendering.  Status enum
        values are converted to their string representation.
        """
        groups: OrderedDict[str, list[dict]] = OrderedDict()
        for check in (results if results is not None else self.report.results):
            section = check.section or "Uncategorized"
            status_value = (
                check.status.value
                if isinstance(check.status, Status)
                else str(check.status)
            )
            entry = {
                "check_id": check.check_id,
                "title": check.title,
                "status": status_value,
                "level": check.level,
                "source": check.source,
                "details": check.details,
                "actual_value": format_value(check.actual_value),
                "expected_value": format_value(check.expected_value),
                "remediation": check.remediation,
                "org_unit": check.org_unit,
                "ou_fail_data": self._extract_ou_fail_data(check),
            }
            groups.setdefault(section, []).append(entry)
        return groups
