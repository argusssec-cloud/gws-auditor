# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Posture score computation for GWS Security Auditor.

The posture score is a 0-100 metric that weights audit findings by
severity.  Critical failures are squared so they dominate the score.
Only checks tagged ``scored=True`` participate.

Formula
-------
For each severity tier *T* with at least one scored check:

    weight(T)  = {CRITICAL: 8, HIGH: 6, MEDIUM: 3, LOW: 2}
    penalty_w  = weight² for CRITICAL (= 64), weight otherwise
    tier_penalty = fails × penalty_w
                 + (warns + partials) × penalty_w × 0.5
    tier_max     = scored_count(T) × penalty_w

    score = max(0, round((1 − Σ tier_penalty / Σ tier_max) × 100))

Tiers with zero scored checks are excluded from both numerator and
denominator.  WARN and PARTIAL each count as a half-failure, matching
the half credit ``AuditSummary.pass_rate`` gives them.  ERROR, MANUAL,
and NOT_APPLICABLE results are excluded.
"""

from __future__ import annotations

from typing import Any

from .models import Severity

# Severity weights — the critical weight is squared during scoring.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 8,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
}

_GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (50, "D"),
    (0, "F"),
]


def _grade_for(score: int) -> str:
    for threshold, letter in _GRADE_THRESHOLDS:
        if score >= threshold:
            return letter
    return "F"


def _normalize_severity(sev: Any) -> Severity | None:
    """Convert a severity value (enum or string) to a Severity member."""
    if isinstance(sev, Severity):
        return sev
    if isinstance(sev, str):
        try:
            return Severity(sev.upper())
        except (ValueError, KeyError):
            return None
    return None


def _normalize_status(status: Any) -> str:
    """Normalize a status to its uppercase string form."""
    s = getattr(status, "value", status)
    return str(s).upper().replace(" ", "_") if s else ""


def compute_posture_score(
    results: list,
    overrides: dict[str, str] | None = None,
) -> dict:
    """Compute the posture score from audit results.

    Parameters
    ----------
    results:
        List of ``CheckResult`` objects or dicts (from JSON reports).
    overrides:
        Optional mapping of ``check_id`` → override status (``"PASS"``
        or ``"FAIL"``).  Applied before scoring so that muting a
        finding can improve the score.

    Returns
    -------
    A dict with keys:

    - ``score`` (int 0-100)
    - ``grade`` (str A/B/C/D/F)
    - ``tier_breakdown`` (dict per severity tier)
    - ``scored_count`` (int)
    - ``excluded_count`` (int)
    """
    overrides = overrides or {}

    # Accumulate per-tier stats
    tiers: dict[Severity, dict] = {}
    scored_count = 0
    excluded_count = 0

    for r in results:
        # Support both CheckResult objects and dicts
        if isinstance(r, dict):
            scored = r.get("scored", True)
            status = _normalize_status(r.get("status", ""))
            severity = _normalize_severity(r.get("severity", "MEDIUM"))
            check_id = r.get("check_id", "")
        else:
            scored = getattr(r, "scored", True)
            status = _normalize_status(getattr(r, "status", ""))
            severity = _normalize_severity(getattr(r, "severity", Severity.MEDIUM))
            check_id = getattr(r, "check_id", "")

        if not scored:
            excluded_count += 1
            continue

        # Only PASS, FAIL, WARN, PARTIAL participate in scoring
        if status not in ("PASS", "FAIL", "WARN", "PARTIAL"):
            excluded_count += 1
            continue

        if severity is None or severity not in SEVERITY_WEIGHTS:
            excluded_count += 1
            continue

        # Apply override
        if check_id in overrides:
            override = overrides[check_id].upper()
            if override in ("PASS", "FAIL"):
                status = override

        scored_count += 1

        if severity not in tiers:
            tiers[severity] = {
                "total": 0, "passed": 0, "failed": 0, "warned": 0, "partial": 0,
            }

        tiers[severity]["total"] += 1
        if status == "PASS":
            tiers[severity]["passed"] += 1
        elif status == "FAIL":
            tiers[severity]["failed"] += 1
        elif status == "WARN":
            tiers[severity]["warned"] += 1
        elif status == "PARTIAL":
            tiers[severity]["partial"] += 1

    # Compute score
    total_penalty = 0.0
    max_penalty = 0.0
    tier_breakdown: dict[str, dict] = {}

    for sev, stats in tiers.items():
        weight = SEVERITY_WEIGHTS[sev]
        # Critical weight is squared
        penalty_w = weight * weight if sev == Severity.CRITICAL else weight

        # WARN and PARTIAL are both half-failures.
        half_failures = stats["warned"] + stats["partial"]
        tier_penalty = (stats["failed"] * penalty_w) + (half_failures * penalty_w * 0.5)
        tier_max = stats["total"] * penalty_w

        total_penalty += tier_penalty
        max_penalty += tier_max

        tier_breakdown[str(sev.value)] = {
            "weight": weight,
            "effective_weight": penalty_w,
            "total": stats["total"],
            "passed": stats["passed"],
            "failed": stats["failed"],
            "warned": stats["warned"],
            "partial": stats["partial"],
            "penalty": tier_penalty,
            "max_penalty": tier_max,
        }

    if max_penalty == 0:
        score = 100
    else:
        score = max(0, round((1 - total_penalty / max_penalty) * 100))

    return {
        "score": score,
        "grade": _grade_for(score),
        "tier_breakdown": tier_breakdown,
        "scored_count": scored_count,
        "excluded_count": excluded_count,
    }


def compute_posture_score_from_report(report_data: dict, overrides: dict[str, str] | None = None) -> dict:
    """Convenience wrapper for computing posture score from a JSON report dict."""
    results = report_data.get("results", [])
    return compute_posture_score(results, overrides=overrides)
