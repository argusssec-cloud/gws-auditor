# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Tool definitions and executors for the AI security analyst.

Each tool is defined as a JSON Schema dict (sent to the LLM) and paired with
an executor function that operates on the audit report dict.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from ..constants import CHECK_TO_THEME, EFFORT_ESTIMATES, REMEDIATION_THEMES

# ---------------------------------------------------------------------------
# Tool JSON-Schema definitions (sent to LLM as function-calling tools)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_audit_summary",
            "description": (
                "Get a high-level summary of the current audit report including "
                "total checks, pass/fail counts, pass rate, and status breakdown."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_findings",
            "description": (
                "Search and filter audit findings by status, source, section, "
                "level, or check_id. Returns a list of matching results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["PASS", "FAIL", "WARN", "ERROR", "MANUAL", "NOT_APPLICABLE"],
                        },
                        "description": "Filter by one or more statuses.",
                    },
                    "source": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["CIS", "CISA", "GOOGLE", "OTHER"],
                        },
                        "description": "Filter by one or more framework sources.",
                    },
                    "section": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by one or more sections (e.g. Gmail, Drive).",
                    },
                    "level": {
                        "type": "string",
                        "enum": ["L1", "L2"],
                        "description": "Filter by level.",
                    },
                    "check_id": {
                        "type": "string",
                        "description": "Filter by exact check ID.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return (default 50).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_check_details",
            "description": (
                "Get full details of a specific check by its check_id, including "
                "status, actual/expected values, remediation, and CIS controls."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "check_id": {
                        "type": "string",
                        "description": "The unique check identifier (e.g. CIS-1.1.1).",
                    },
                },
                "required": ["check_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_compliance_by_framework",
            "description": (
                "Get compliance statistics broken down by framework source. "
                "Optionally filter to a single source."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "enum": ["CIS", "CISA", "GOOGLE", "OTHER"],
                        "description": "Optional: get stats for a specific framework only.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_compliance_by_section",
            "description": (
                "Get compliance statistics broken down by section (e.g. Gmail, "
                "Drive, Directory). Optionally filter to a single section."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "description": "Optional: get stats for a specific section only.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_remediation_plan",
            "description": (
                "Get a prioritised remediation plan. Returns failing checks "
                "ordered by severity (L1 FAIL first, then L2 FAIL, then WARN) "
                "with remediation steps."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "description": "Optional: limit to a specific section.",
                    },
                    "level": {
                        "type": "string",
                        "enum": ["L1", "L2"],
                        "description": "Optional: limit to a specific level.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum items to return (default 20).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_reports",
            "description": (
                "Compare two audit reports to find new failures, resolved issues, "
                "and changes in pass rate. Requires access to the report store."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "old_report": {
                        "type": "string",
                        "description": "Filename of the older report.",
                    },
                    "new_report": {
                        "type": "string",
                        "description": "Filename of the newer report.",
                    },
                },
                "required": ["old_report", "new_report"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_available_reports",
            "description": (
                "List all available audit report files with their timestamps, "
                "customer IDs, and pass rates."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_inventory_data",
            "description": (
                "Query structured inventory data from inventory checks (ADD-28 "
                "through ADD-39). Returns lists of stale devices, inactive "
                "spaces, dangerous OAuth apps, users without 2SV, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "check_id": {
                        "type": "string",
                        "description": (
                            "Inventory check ID. ADD-28=groups, ADD-29=chat spaces, "
                            "ADD-30=mobile devices, ADD-31=ChromeOS, ADD-32=2SV by OU, "
                            "ADD-33=OAuth apps, ADD-34=app passwords, ADD-35=shared drives, "
                            "ADD-38=endpoint devices, ADD-39=pending devices."
                        ),
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum items to return (default 25).",
                    },
                },
                "required": ["check_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_knowledge_base_url",
            "description": (
                "Extract Google Workspace documentation URLs from check "
                "remediation text. Returns links to knowledge.workspace.google.com "
                "for a specific check or topic keyword."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "check_id": {
                        "type": "string",
                        "description": "Get documentation URL for a specific check.",
                    },
                    "topic": {
                        "type": "string",
                        "description": (
                            "Search all check remediations for a topic keyword "
                            "(e.g. 'DKIM', 'shared drives', '2-step verification')."
                        ),
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_smart_remediation",
            "description": (
                "Generate a grouped, prioritized remediation plan organised by "
                "security theme (e.g. Email Authentication, MFA, External Sharing). "
                "Includes effort estimates and Admin Console navigation paths."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "section": {
                        "type": "string",
                        "description": "Optional: limit to a specific section.",
                    },
                    "group_by": {
                        "type": "string",
                        "enum": ["theme", "section", "effort"],
                        "description": "Grouping strategy (default: theme).",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum items per group (default 10).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_trend_analysis",
            "description": (
                "Analyze trends across multiple audit reports. Shows pass rate "
                "over time, persistent failures, and recently resolved issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Number of recent reports to analyze (default 5).",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "export_findings_csv",
            "description": (
                "Export filtered audit findings as CSV content. Returns the "
                "CSV string which can be presented to the user or saved to a file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Filter by statuses (e.g. ['FAIL', 'WARN']).",
                    },
                    "section": {
                        "type": "string",
                        "description": "Filter by section.",
                    },
                    "source": {
                        "type": "string",
                        "description": "Filter by framework source.",
                    },
                },
                "required": [],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool executor functions
# ---------------------------------------------------------------------------

def _get_audit_summary(report_data: dict) -> dict:
    summary = report_data.get("summary", {})
    results = report_data.get("results", [])

    status_counts: dict[str, int] = {}
    for r in results:
        s = r.get("status", "UNKNOWN")
        status_counts[s] = status_counts.get(s, 0) + 1

    return {
        "timestamp": report_data.get("timestamp", ""),
        "customer_id": report_data.get("customer_id", ""),
        "domains": report_data.get("domains", []),
        "total": summary.get("total", len(results)),
        "passed": summary.get("passed", status_counts.get("PASS", 0)),
        "failed": summary.get("failed", status_counts.get("FAIL", 0)),
        "warnings": summary.get("warnings", status_counts.get("WARN", 0)),
        "errors": summary.get("errors", status_counts.get("ERROR", 0)),
        "manual": summary.get("manual", status_counts.get("MANUAL", 0)),
        "not_applicable": summary.get("not_applicable", status_counts.get("NOT_APPLICABLE", 0)),
        "pass_rate": summary.get("pass_rate", 0.0),
        "status_breakdown": status_counts,
    }


def _search_findings(report_data: dict, **kwargs: Any) -> list[dict]:
    results = report_data.get("results", [])
    filtered = list(results)

    statuses = kwargs.get("status")
    if statuses:
        filtered = [r for r in filtered if r.get("status") in statuses]

    sources = kwargs.get("source")
    if sources:
        filtered = [r for r in filtered if r.get("source") in sources]

    sections = kwargs.get("section")
    if sections:
        filtered = [r for r in filtered if r.get("section") in sections]

    level = kwargs.get("level")
    if level:
        filtered = [r for r in filtered if r.get("level") == level]

    check_id = kwargs.get("check_id")
    if check_id:
        filtered = [r for r in filtered if r.get("check_id") == check_id]

    limit = kwargs.get("limit", 50)
    return filtered[:limit]


def _get_check_details(report_data: dict, check_id: str) -> dict | None:
    for r in report_data.get("results", []):
        if r.get("check_id") == check_id:
            return r
    return None


def _get_compliance_by_framework(report_data: dict, source: str | None = None) -> dict:
    results = report_data.get("results", [])
    frameworks: dict[str, dict] = {}

    for r in results:
        s = r.get("source", "UNKNOWN")
        if source and s != source:
            continue
        if s not in frameworks:
            frameworks[s] = {"total": 0, "passed": 0, "failed": 0, "warnings": 0}
        frameworks[s]["total"] += 1
        status = r.get("status", "")
        if status == "PASS":
            frameworks[s]["passed"] += 1
        elif status == "FAIL":
            frameworks[s]["failed"] += 1
        elif status == "WARN":
            frameworks[s]["warnings"] += 1

    for stats in frameworks.values():
        evaluated = stats["passed"] + stats["failed"]
        stats["pass_rate"] = round(stats["passed"] / evaluated * 100, 1) if evaluated else 0.0

    return frameworks


def _get_compliance_by_section(report_data: dict, section: str | None = None) -> dict:
    results = report_data.get("results", [])
    sections: dict[str, dict] = {}

    for r in results:
        sec = r.get("section", "UNKNOWN")
        if section and sec != section:
            continue
        if sec not in sections:
            sections[sec] = {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "failing_checks": []}
        sections[sec]["total"] += 1
        status = r.get("status", "")
        if status == "PASS":
            sections[sec]["passed"] += 1
        elif status == "FAIL":
            sections[sec]["failed"] += 1
            sections[sec]["failing_checks"].append(r.get("check_id", ""))
        elif status == "WARN":
            sections[sec]["warnings"] += 1

    for stats in sections.values():
        evaluated = stats["passed"] + stats["failed"]
        stats["pass_rate"] = round(stats["passed"] / evaluated * 100, 1) if evaluated else 0.0

    return sections


def _get_remediation_plan(
    report_data: dict,
    section: str | None = None,
    level: str | None = None,
    limit: int = 20,
) -> list[dict]:
    results = report_data.get("results", [])

    actionable = [
        r for r in results
        if r.get("status") in ("FAIL", "WARN")
        and (section is None or r.get("section") == section)
        and (level is None or r.get("level") == level)
    ]

    # Sort: FAIL before WARN, L1 before L2
    priority = {"FAIL": 0, "WARN": 1}
    level_priority = {"L1": 0, "L2": 1}
    actionable.sort(
        key=lambda r: (
            priority.get(r.get("status", ""), 2),
            level_priority.get(r.get("level", ""), 2),
        )
    )

    items = []
    for r in actionable[:limit]:
        items.append({
            "priority": len(items) + 1,
            "check_id": r.get("check_id", ""),
            "title": r.get("title", ""),
            "status": r.get("status", ""),
            "level": r.get("level", ""),
            "section": r.get("section", ""),
            "details": r.get("details", ""),
            "remediation": r.get("remediation", ""),
        })

    return items


def _compare_reports(
    old_data: dict,
    new_data: dict,
) -> dict:
    old_results = {r["check_id"]: r for r in old_data.get("results", []) if "check_id" in r}
    new_results = {r["check_id"]: r for r in new_data.get("results", []) if "check_id" in r}

    new_failures = []
    resolved = []
    changed = []

    for cid, new_r in new_results.items():
        old_r = old_results.get(cid)
        if old_r is None:
            if new_r.get("status") == "FAIL":
                new_failures.append({"check_id": cid, "title": new_r.get("title", ""), "status": "FAIL"})
            continue
        if old_r.get("status") != new_r.get("status"):
            entry = {
                "check_id": cid,
                "title": new_r.get("title", ""),
                "old_status": old_r.get("status"),
                "new_status": new_r.get("status"),
            }
            if old_r.get("status") == "FAIL" and new_r.get("status") == "PASS":
                resolved.append(entry)
            elif new_r.get("status") == "FAIL" and old_r.get("status") != "FAIL":
                new_failures.append(entry)
            else:
                changed.append(entry)

    old_summary = old_data.get("summary", {})
    new_summary = new_data.get("summary", {})

    return {
        "old_report": old_data.get("timestamp", ""),
        "new_report": new_data.get("timestamp", ""),
        "old_pass_rate": old_summary.get("pass_rate", 0),
        "new_pass_rate": new_summary.get("pass_rate", 0),
        "new_failures": new_failures,
        "resolved": resolved,
        "changed": changed,
    }


def _list_available_reports(report_store: Any) -> list[dict]:
    if report_store is None:
        return [{"error": "Report store not available. Cannot list reports."}]
    return report_store.list_reports()


_INVENTORY_IDS = frozenset({
    "ADD-28", "ADD-29", "ADD-30", "ADD-31", "ADD-32",
    "ADD-33", "ADD-34", "ADD-35", "ADD-38", "ADD-39",
})

_URL_PATTERN = re.compile(r"https://knowledge\.workspace\.google\.com/\S+")


def _query_inventory_data(report_data: dict, check_id: str, limit: int = 25) -> dict:
    if check_id not in _INVENTORY_IDS:
        return {"error": f"Not an inventory check. Valid: {sorted(_INVENTORY_IDS)}"}
    for r in report_data.get("results", []):
        if r.get("check_id") == check_id:
            actual = r.get("actual_value") or {}
            # Find the main list in actual_value (largest list)
            items = []
            summary = {}
            if isinstance(actual, dict):
                for k, v in actual.items():
                    if isinstance(v, list):
                        items = v[:limit]
                        summary[k + "_count"] = len(v)
                    else:
                        summary[k] = v
            return {
                "check_id": check_id,
                "title": r.get("title", ""),
                "status": r.get("status", ""),
                "summary": summary,
                "items": items,
                "total_items": len(items),
            }
    return {"error": f"Check {check_id} not found in report"}


def _get_knowledge_base_url(report_data: dict, check_id: str = "", topic: str = "") -> list[dict]:
    results_list = []
    for r in report_data.get("results", []):
        remed = r.get("remediation", "")
        if not remed:
            continue
        urls = _URL_PATTERN.findall(remed)
        if not urls:
            continue
        if check_id and r.get("check_id") != check_id:
            continue
        if topic and topic.lower() not in remed.lower() and topic.lower() not in r.get("title", "").lower():
            continue
        results_list.append({
            "check_id": r.get("check_id", ""),
            "title": r.get("title", ""),
            "urls": urls,
        })
    if not results_list:
        return [{"message": "No matching documentation URLs found."}]
    return results_list


def _get_smart_remediation(
    report_data: dict,
    section: str | None = None,
    group_by: str = "theme",
    limit: int = 10,
) -> dict:
    results = report_data.get("results", [])
    actionable = [
        r for r in results
        if r.get("status") in ("FAIL", "WARN")
        and (section is None or r.get("section") == section)
    ]

    # Sort by severity then level
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    status_order = {"FAIL": 0, "WARN": 1}
    level_order = {"L1": 0, "L2": 1}
    actionable.sort(key=lambda r: (
        status_order.get(r.get("status", ""), 2),
        severity_order.get(r.get("severity", "MEDIUM"), 2),
        level_order.get(r.get("level", ""), 2),
    ))

    grouped: dict[str, list] = {}
    for r in actionable:
        cid = r.get("check_id", "")
        if group_by == "theme":
            key = CHECK_TO_THEME.get(cid, "Other")
        elif group_by == "effort":
            key = EFFORT_ESTIMATES.get(cid, "Medium")
        else:
            key = r.get("section", "Unknown")

        grouped.setdefault(key, [])
        if len(grouped[key]) < limit:
            remed = r.get("remediation", "")
            urls = _URL_PATTERN.findall(remed)
            nav_path = remed.split("https://")[0].strip().rstrip(".") if "https://" in remed else remed
            grouped[key].append({
                "check_id": cid,
                "title": r.get("title", ""),
                "status": r.get("status", ""),
                "severity": r.get("severity", "MEDIUM"),
                "level": r.get("level", ""),
                "effort": EFFORT_ESTIMATES.get(cid, "Medium"),
                "admin_path": nav_path,
                "doc_url": urls[0] if urls else "",
            })

    return {
        "group_by": group_by,
        "total_actionable": len(actionable),
        "groups": {k: {"count": len(v), "items": v} for k, v in grouped.items()},
    }


def _get_trend_analysis(report_store: Any, limit: int = 5) -> dict:
    if report_store is None:
        return {"error": "Report store not available."}
    reports_list = report_store.list_reports()
    if not reports_list:
        return {"error": "No reports available."}

    reports_list = sorted(reports_list, key=lambda r: r.get("timestamp", ""), reverse=True)[:limit]

    timeline = []
    all_fail_sets: list[set] = []
    for entry in reversed(reports_list):
        filename = entry.get("filename", "")
        try:
            data = report_store.load_report(filename)
        except Exception:
            continue
        summary = data.get("summary", {})
        fails = {r["check_id"] for r in data.get("results", []) if r.get("status") == "FAIL"}
        all_fail_sets.append(fails)
        timeline.append({
            "timestamp": data.get("timestamp", ""),
            "pass_rate": summary.get("pass_rate", 0),
            "total": summary.get("total", 0),
            "failed": summary.get("failed", 0),
        })

    persistent = set.intersection(*all_fail_sets) if all_fail_sets else set()
    recently_resolved = (all_fail_sets[0] - all_fail_sets[-1]) if len(all_fail_sets) >= 2 else set()
    new_failures = (all_fail_sets[-1] - all_fail_sets[0]) if len(all_fail_sets) >= 2 else set()

    return {
        "reports_analyzed": len(timeline),
        "timeline": timeline,
        "persistent_failures": sorted(persistent),
        "recently_resolved": sorted(recently_resolved),
        "new_failures": sorted(new_failures),
    }


def _export_findings_csv(
    report_data: dict,
    status: list[str] | None = None,
    section: str | None = None,
    source: str | None = None,
) -> str:
    results = report_data.get("results", [])
    filtered = results
    if status:
        filtered = [r for r in filtered if r.get("status") in status]
    if section:
        filtered = [r for r in filtered if r.get("section") == section]
    if source:
        filtered = [r for r in filtered if r.get("source") == source]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["check_id", "title", "status", "severity", "level", "source", "section", "details", "remediation"])
    for r in filtered:
        writer.writerow([
            r.get("check_id", ""), r.get("title", ""), r.get("status", ""),
            r.get("severity", ""), r.get("level", ""), r.get("source", ""),
            r.get("section", ""), r.get("details", ""), r.get("remediation", ""),
        ])
    return output.getvalue()


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def execute_tool(
    name: str,
    arguments: dict,
    report_data: dict,
    report_store: Any = None,
) -> str:
    """Execute a tool by name and return a JSON string result.

    Args:
        name: Tool function name.
        arguments: Parsed arguments dict from the LLM.
        report_data: The current audit report dict.
        report_store: Optional ``ReportStore`` for multi-report tools.

    Returns:
        JSON-encoded result string.
    """
    if name == "get_audit_summary":
        result = _get_audit_summary(report_data)

    elif name == "search_findings":
        result = _search_findings(report_data, **arguments)

    elif name == "get_check_details":
        check_id = arguments.get("check_id", "")
        found = _get_check_details(report_data, check_id)
        result = found if found else {"error": f"Check {check_id} not found"}

    elif name == "get_compliance_by_framework":
        result = _get_compliance_by_framework(report_data, arguments.get("source"))

    elif name == "get_compliance_by_section":
        result = _get_compliance_by_section(report_data, arguments.get("section"))

    elif name == "get_remediation_plan":
        result = _get_remediation_plan(
            report_data,
            section=arguments.get("section"),
            level=arguments.get("level"),
            limit=arguments.get("limit", 20),
        )

    elif name == "compare_reports":
        if report_store is None:
            result = {"error": "Report store not available. Cannot compare reports."}
        else:
            old_file = arguments.get("old_report", "")
            new_file = arguments.get("new_report", "")
            try:
                old_data = report_store.load_report(old_file)
                new_data = report_store.load_report(new_file)
                result = _compare_reports(old_data, new_data)
            except Exception as exc:
                result = {"error": f"Failed to load reports: {exc}"}

    elif name == "list_available_reports":
        result = _list_available_reports(report_store)

    elif name == "query_inventory_data":
        result = _query_inventory_data(
            report_data,
            check_id=arguments.get("check_id", ""),
            limit=arguments.get("limit", 25),
        )

    elif name == "get_knowledge_base_url":
        result = _get_knowledge_base_url(
            report_data,
            check_id=arguments.get("check_id", ""),
            topic=arguments.get("topic", ""),
        )

    elif name == "get_smart_remediation":
        result = _get_smart_remediation(
            report_data,
            section=arguments.get("section"),
            group_by=arguments.get("group_by", "theme"),
            limit=arguments.get("limit", 10),
        )

    elif name == "get_trend_analysis":
        result = _get_trend_analysis(
            report_store,
            limit=arguments.get("limit", 5),
        )

    elif name == "export_findings_csv":
        csv_content = _export_findings_csv(
            report_data,
            status=arguments.get("status"),
            section=arguments.get("section"),
            source=arguments.get("source"),
        )
        result = {"csv": csv_content, "row_count": csv_content.count("\n") - 1}

    else:
        result = {"error": f"Unknown tool: {name}"}

    return json.dumps(result, default=str)
