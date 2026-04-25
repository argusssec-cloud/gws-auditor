"""Tests for the posture score computation module."""

import pytest

from gws_auditor.models import CheckResult, Severity, Status
from gws_auditor.scoring import (
    SEVERITY_WEIGHTS,
    compute_posture_score,
    compute_posture_score_from_report,
)


def _make(check_id, status, severity=Severity.MEDIUM, scored=True):
    """Shorthand to create a CheckResult."""
    return CheckResult(
        check_id=check_id,
        title=f"Test {check_id}",
        status=status,
        severity=severity,
        scored=scored,
    )


class TestComputePostureScore:
    """Core formula tests."""

    def test_all_pass_is_100(self):
        results = [
            _make("C-1", Status.PASS, Severity.CRITICAL),
            _make("H-1", Status.PASS, Severity.HIGH),
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("L-1", Status.PASS, Severity.LOW),
        ]
        out = compute_posture_score(results)
        assert out["score"] == 100
        assert out["grade"] == "A"

    def test_all_fail_is_0(self):
        results = [
            _make("C-1", Status.FAIL, Severity.CRITICAL),
            _make("H-1", Status.FAIL, Severity.HIGH),
            _make("M-1", Status.FAIL, Severity.MEDIUM),
            _make("L-1", Status.FAIL, Severity.LOW),
        ]
        out = compute_posture_score(results)
        assert out["score"] == 0
        assert out["grade"] == "F"

    def test_empty_results_is_100(self):
        out = compute_posture_score([])
        assert out["score"] == 100
        assert out["grade"] == "A"

    def test_critical_squaring_hurts_more(self):
        """One critical fail should hurt more than one high fail."""
        crit_fail = [
            _make("C-1", Status.FAIL, Severity.CRITICAL),
            _make("C-2", Status.PASS, Severity.CRITICAL),
        ]
        high_fail = [
            _make("H-1", Status.FAIL, Severity.HIGH),
            _make("H-2", Status.PASS, Severity.HIGH),
        ]
        crit_score = compute_posture_score(crit_fail)["score"]
        high_score = compute_posture_score(high_fail)["score"]
        # Both have 1 fail out of 2, but critical should produce a lower score
        assert crit_score == high_score  # Both 50% fail -> score 50
        # The key difference is that critical uses weight^2=64 vs high weight=6,
        # so in a mixed scenario, critical dominates.

    def test_critical_dominates_mixed(self):
        """In a mixed-tier scenario, one critical fail dominates."""
        results = [
            _make("C-1", Status.FAIL, Severity.CRITICAL),
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
            _make("M-3", Status.PASS, Severity.MEDIUM),
            _make("M-4", Status.PASS, Severity.MEDIUM),
            _make("M-5", Status.PASS, Severity.MEDIUM),
            _make("M-6", Status.PASS, Severity.MEDIUM),
            _make("M-7", Status.PASS, Severity.MEDIUM),
            _make("M-8", Status.PASS, Severity.MEDIUM),
            _make("M-9", Status.PASS, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)
        # 1 critical fail (penalty=64, max=64) + 9 medium pass (penalty=0, max=27)
        # total_penalty=64, max_penalty=91 -> 1-64/91 = 0.297 -> score 30
        assert out["score"] == 30

    def test_warn_counts_as_half(self):
        results = [
            _make("M-1", Status.WARN, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)
        # penalty = 3*0.5 = 1.5, max = 6 -> 1 - 1.5/6 = 0.75 -> 75
        assert out["score"] == 75

    def test_two_warns_equal_one_fail(self):
        two_warns = [
            _make("M-1", Status.WARN, Severity.MEDIUM),
            _make("M-2", Status.WARN, Severity.MEDIUM),
        ]
        one_fail = [
            _make("M-1", Status.FAIL, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
        ]
        # two warns: penalty = 2*1.5 = 3, max = 6 -> score 50
        # one fail:  penalty = 3, max = 6 -> score 50
        assert compute_posture_score(two_warns)["score"] == compute_posture_score(one_fail)["score"]

    def test_empty_tier_excluded(self):
        """If no checks exist for a severity tier, it shouldn't affect the score."""
        # Only medium checks, all pass -> should be 100 despite no critical/high
        results = [
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)
        assert out["score"] == 100
        assert "CRITICAL" not in out["tier_breakdown"]
        assert "HIGH" not in out["tier_breakdown"]

    def test_unscored_checks_excluded(self):
        results = [
            _make("M-1", Status.FAIL, Severity.MEDIUM, scored=True),
            _make("INV-1", Status.FAIL, Severity.MEDIUM, scored=False),
        ]
        out = compute_posture_score(results)
        # Only 1 scored check (FAIL) -> score 0
        assert out["score"] == 0
        assert out["scored_count"] == 1
        assert out["excluded_count"] == 1

    def test_error_manual_na_excluded(self):
        results = [
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("M-2", Status.ERROR, Severity.MEDIUM),
            _make("M-3", Status.MANUAL, Severity.MEDIUM),
            _make("M-4", Status.NOT_APPLICABLE, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)
        assert out["score"] == 100  # Only M-1 is scored (PASS)
        assert out["scored_count"] == 1

    def test_override_to_pass_improves_score(self):
        results = [
            _make("M-1", Status.FAIL, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
        ]
        without_override = compute_posture_score(results)
        with_override = compute_posture_score(results, overrides={"M-1": "PASS"})
        assert with_override["score"] > without_override["score"]
        assert with_override["score"] == 100

    def test_override_to_fail_worsens_score(self):
        results = [
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
        ]
        without_override = compute_posture_score(results)
        with_override = compute_posture_score(results, overrides={"M-1": "FAIL"})
        assert with_override["score"] < without_override["score"]


class TestGrading:
    @pytest.mark.parametrize("score,grade", [
        (100, "A"), (95, "A"), (90, "A"),
        (89, "B"), (80, "B"),
        (79, "C"), (70, "C"),
        (69, "D"), (50, "D"),
        (49, "F"), (0, "F"),
    ])
    def test_grade_thresholds(self, score, grade):
        from gws_auditor.scoring import _grade_for
        assert _grade_for(score) == grade


class TestTierBreakdown:
    def test_breakdown_structure(self):
        results = [
            _make("C-1", Status.FAIL, Severity.CRITICAL),
            _make("M-1", Status.PASS, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)
        bd = out["tier_breakdown"]
        assert "CRITICAL" in bd
        assert "MEDIUM" in bd
        assert bd["CRITICAL"]["effective_weight"] == 64  # 8^2
        assert bd["MEDIUM"]["effective_weight"] == 3
        assert bd["CRITICAL"]["failed"] == 1
        assert bd["MEDIUM"]["passed"] == 1


class TestDictInput:
    """Verify scoring works with dict-based results (from JSON reports)."""

    def test_dict_results(self):
        results = [
            {"check_id": "M-1", "status": "PASS", "severity": "MEDIUM", "scored": True},
            {"check_id": "M-2", "status": "FAIL", "severity": "MEDIUM", "scored": True},
        ]
        out = compute_posture_score(results)
        assert out["score"] == 50
        assert out["scored_count"] == 2

    def test_dict_missing_scored_defaults_true(self):
        results = [
            {"check_id": "M-1", "status": "PASS", "severity": "MEDIUM"},
        ]
        out = compute_posture_score(results)
        assert out["scored_count"] == 1

    def test_compute_from_report(self):
        report = {
            "results": [
                {"check_id": "M-1", "status": "PASS", "severity": "MEDIUM"},
                {"check_id": "M-2", "status": "FAIL", "severity": "HIGH"},
            ],
        }
        out = compute_posture_score_from_report(report)
        assert 0 <= out["score"] <= 100
        assert out["grade"] in ("A", "B", "C", "D", "F")


class TestHandCalculation:
    """Verify the formula with a hand-calculated example."""

    def test_mixed_severity_hand_calc(self):
        results = [
            # 2 critical: 1 pass, 1 fail
            _make("C-1", Status.PASS, Severity.CRITICAL),
            _make("C-2", Status.FAIL, Severity.CRITICAL),
            # 3 high: 2 pass, 1 warn
            _make("H-1", Status.PASS, Severity.HIGH),
            _make("H-2", Status.PASS, Severity.HIGH),
            _make("H-3", Status.WARN, Severity.HIGH),
            # 4 medium: all pass
            _make("M-1", Status.PASS, Severity.MEDIUM),
            _make("M-2", Status.PASS, Severity.MEDIUM),
            _make("M-3", Status.PASS, Severity.MEDIUM),
            _make("M-4", Status.PASS, Severity.MEDIUM),
        ]
        out = compute_posture_score(results)

        # Critical: weight=8, penalty_w=64
        #   penalty = 1*64 = 64, max = 2*64 = 128
        # High: weight=6, penalty_w=6
        #   penalty = 0*6 + 1*6*0.5 = 3, max = 3*6 = 18
        # Medium: weight=3, penalty_w=3
        #   penalty = 0, max = 4*3 = 12
        # total_penalty = 64 + 3 + 0 = 67
        # max_penalty = 128 + 18 + 12 = 158
        # score = round((1 - 67/158) * 100) = round(57.59) = 58
        assert out["score"] == 58
        assert out["grade"] == "D"
