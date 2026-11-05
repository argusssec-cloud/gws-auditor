"""Plan Layer 5: aggregation and reporting.

Every status must flow through ``AuditSummary``, ``compute_posture_score`` and the
three reporters unchanged; unscored checks must never move the posture score or the
critical-failure count; and a ``--cached`` run of a golden snapshot must reproduce the
pinned statuses through the orchestrator path, including the reports it writes.
"""

import csv
import gzip
import json
from pathlib import Path

import pytest

from gws_auditor.models import AuditReport, AuditSummary, CheckResult, Severity, Status
from gws_auditor.reporter.csv_report import CSVReporter
from gws_auditor.reporter.html_report import INVENTORY_CHECK_IDS, HTMLReporter
from gws_auditor.reporter.json_report import JSONReporter
from gws_auditor.scoring import compute_posture_score, compute_posture_score_from_report

ALL_STATUSES = list(Status)
SCORING_STATUSES = {Status.PASS, Status.FAIL, Status.WARN, Status.PARTIAL}
BUCKET = {
    Status.PASS: "passed", Status.FAIL: "failed", Status.WARN: "warnings",
    Status.PARTIAL: "partial", Status.ERROR: "errors", Status.MANUAL: "manual",
    Status.NOT_APPLICABLE: "not_applicable",
}


def _r(check_id, status, severity=Severity.MEDIUM, scored=True, **kw):
    kw.setdefault("title", f"Title {check_id}")
    kw.setdefault("section", "Security")
    return CheckResult(check_id=check_id, status=status, severity=severity, scored=scored, **kw)


@pytest.fixture
def seven_status_results():
    """One result per status with varied severities and value shapes, plus two unscored
    checks: an inventory-style CRITICAL FAIL (like ADD-33) and a pure-MANUAL control."""
    return [
        _r("C-PASS", Status.PASS, Severity.CRITICAL, actual_value=True, expected_value=True),
        _r("C-FAIL", Status.FAIL, Severity.CRITICAL, actual_value=[{"org_unit": "/", "value": False}],
           expected_value=True, details="root OU is off", critical_reason="takeover"),
        _r("H-WARN", Status.WARN, Severity.HIGH, actual_value={"mode": "ALLOWLISTED_DOMAINS", "count": 3},
           expected_value="DISABLED"),
        _r("M-PARTIAL", Status.PARTIAL, Severity.MEDIUM, actual_value=[1, 2, 3], expected_value=[]),
        _r("L-ERROR", Status.ERROR, Severity.LOW, actual_value=None, expected_value="x",
           details="policy data unavailable"),
        _r("M-MANUAL", Status.MANUAL, Severity.MEDIUM, actual_value="UNSPECIFIED", section="Gmail"),
        _r("H-NA", Status.NOT_APPLICABLE, Severity.HIGH, section="Gmail"),
        _r("ADD-33", Status.FAIL, Severity.CRITICAL, scored=False,
           actual_value={"summary": {"apps": 2}, "per_ou": []}, section="Security"),
        _r("GWS.COMMONCONTROLS.8.3", Status.MANUAL, Severity.MEDIUM, scored=False),
    ]


def _report(results):
    summary = AuditSummary.from_results(results)
    posture = compute_posture_score(results)
    summary.posture_score, summary.posture_grade = posture["score"], posture["grade"]
    return AuditReport(timestamp="2026-11-05T10:00:00Z", customer_id="C0test", domains=["example.com"],
                       results=results, summary=summary, org_units=["/", "/Sales"],
                       config={"checks": {"levels": ["L1", "L2"]}})


class TestAuditSummary:
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=[s.value for s in ALL_STATUSES])
    def test_every_status_lands_in_exactly_one_bucket(self, status):
        s = AuditSummary.from_results([_r("X", status)])
        counts = {name: getattr(s, name) for name in BUCKET.values()}
        assert s.total == 1
        assert counts == {name: int(name == BUCKET[status]) for name in BUCKET.values()}

    def test_buckets_sum_to_total(self, seven_status_results):
        s = AuditSummary.from_results(seven_status_results)
        assert s.total == len(seven_status_results) == sum(getattr(s, n) for n in BUCKET.values())

    def test_pass_rate_gives_partial_half_credit_and_excludes_unevaluated(self):
        s = AuditSummary.from_results([_r(st.value, st) for st in ALL_STATUSES])
        # numerator 1 PASS + 0.5 PARTIAL; denominator PASS, FAIL, WARN, PARTIAL
        assert s.pass_rate == pytest.approx(1.5 / 4 * 100)

    def test_critical_failed_counts_scored_critical_fails_only(self, seven_status_results):
        s = AuditSummary.from_results(seven_status_results)
        assert s.critical_failed == 1  # C-FAIL; ADD-33 is unscored
        assert AuditSummary.from_results([_r("C", Status.WARN, Severity.CRITICAL)]).critical_failed == 0
        assert AuditSummary.from_results([_r("H", Status.FAIL, Severity.HIGH)]).critical_failed == 0

    def test_critical_failed_agrees_with_posture_and_html_banner(self, seven_status_results, tmp_path):
        report = _report(seven_status_results)
        HTMLReporter(report).generate(str(tmp_path / "r.html"))
        html = (tmp_path / "r.html").read_text()
        assert f"{report.summary.critical_failed} Critical Security Finding" in html
        assert compute_posture_score(seven_status_results)["tier_breakdown"]["CRITICAL"]["failed"] == 1


class TestPostureScoreStatuses:
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=[s.value for s in ALL_STATUSES])
    def test_only_pass_fail_warn_partial_participate(self, status):
        out = compute_posture_score([_r("X", status)])
        if status in SCORING_STATUSES:
            assert out["scored_count"] == 1 and out["excluded_count"] == 0
            assert out["score"] == {Status.PASS: 100, Status.FAIL: 0, Status.WARN: 50, Status.PARTIAL: 50}[status]
        else:
            assert out["scored_count"] == 0 and out["excluded_count"] == 1
            assert out["score"] == 100 and out["tier_breakdown"] == {}

    @pytest.mark.parametrize("severity", list(Severity), ids=[s.value for s in Severity])
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=[s.value for s in ALL_STATUSES])
    def test_unscored_checks_never_move_the_score(self, status, severity):
        base = [_r("M", Status.PASS), _r("H", Status.FAIL, Severity.HIGH), _r("C", Status.WARN, Severity.CRITICAL)]
        before = compute_posture_score(base)
        after = compute_posture_score(base + [_r("U", status, severity, scored=False)])
        assert (after["score"], after["grade"], after["tier_breakdown"]) == (before["score"], before["grade"], before["tier_breakdown"])
        assert after["scored_count"] == before["scored_count"]
        assert after["excluded_count"] == before["excluded_count"] + 1

    def test_object_and_json_dict_paths_agree(self, seven_status_results):
        report = _report(seven_status_results)
        from_objects = compute_posture_score(seven_status_results)
        from_json = compute_posture_score_from_report(json.loads(json.dumps(JSONReporter(report).to_dict(), default=str)))
        assert from_json == from_objects
        assert report.summary.posture_score == from_objects["score"]

    def test_half_failures_in_every_tier(self):
        results = [_r(f"{sev.value}-{st.value}", st, sev)
                   for sev in Severity for st in (Status.WARN, Status.PARTIAL)]
        bd = compute_posture_score(results)["tier_breakdown"]
        for sev in Severity:
            tier = bd[sev.value]
            assert tier["warned"] == tier["partial"] == 1
            assert tier["penalty"] == tier["effective_weight"]  # two half-failures = one failure
            assert tier["max_penalty"] == 2 * tier["effective_weight"]


class TestReportersPreserveResults:
    def test_json_preserves_every_field_verbatim(self, seven_status_results, tmp_path):
        report = _report(seven_status_results)
        JSONReporter(report).generate(str(tmp_path / "r.json"))
        data = json.loads((tmp_path / "r.json").read_text())
        assert [d["check_id"] for d in data["results"]] == [r.check_id for r in seven_status_results]
        for d, r in zip(data["results"], seven_status_results):
            assert d["status"] == r.status.value
            assert d["severity"] == r.severity.value
            assert d["scored"] is r.scored
            assert d["actual_value"] == r.actual_value
            assert d["expected_value"] == r.expected_value
            for field in ("title", "details", "remediation", "org_unit", "section", "level", "source", "critical_reason"):
                assert d[field] == getattr(r, field)
        assert {d["status"] for d in data["results"]} == {s.value for s in Status}

    def test_json_summary_matches_audit_summary(self, seven_status_results, tmp_path):
        report = _report(seven_status_results)
        data = JSONReporter(report).to_dict()
        s = data["summary"]
        assert s["total"] == len(seven_status_results) == sum(s[n] for n in BUCKET.values())
        for name in BUCKET.values():
            assert s[name] == getattr(report.summary, name)
        assert s["critical_failed"] == report.summary.critical_failed == 1
        assert s["pass_rate"] == pytest.approx(report.summary.pass_rate)
        assert (s["posture_score"], s["posture_grade"]) == (report.summary.posture_score, report.summary.posture_grade)

    def test_csv_preserves_status_severity_and_values(self, seven_status_results, tmp_path):
        report = _report(seven_status_results)
        CSVReporter(report).generate(str(tmp_path / "r.csv"))
        with open(tmp_path / "r.csv", newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == len(seven_status_results)
        for row, r in zip(rows, seven_status_results):
            assert row["Check ID"] == r.check_id
            assert row["Status"] == r.status.value
            assert row["Severity"] == r.severity.value  # "CRITICAL", not "Severity.CRITICAL"
            assert row["Actual Value"] == ("" if r.actual_value is None else str(r.actual_value))
            assert row["Expected Value"] == ("" if r.expected_value is None else str(r.expected_value))
            assert row["Details"] == r.details and row["Org Unit"] == r.org_unit

    def test_html_renders_every_status_and_the_summary_cards(self, seven_status_results, tmp_path):
        report = _report(seven_status_results)
        HTMLReporter(report).generate(str(tmp_path / "r.html"))
        html = (tmp_path / "r.html").read_text()
        for status in Status:
            assert f'badge--{status.value}' in html
        for r in seven_status_results:
            assert r.check_id in html
        # The HTML summary excludes inventory checks (ADD-33 lives in its own tab).
        audit = [r for r in seven_status_results if r.check_id not in INVENTORY_CHECK_IDS]
        expected = AuditSummary.from_results(audit)
        assert f'id="card-total">{expected.total}<' in html
        assert f'id="card-partial">{expected.partial}<' in html
        assert f'id="card-na">{expected.not_applicable}<' in html
        assert f'id="card-score">{report.summary.posture_score}/100<' in html

    def test_inventory_ids_are_unscored_and_shared_with_the_dashboard(self):
        from gws_auditor.checks.registry import CheckRegistry
        registry = CheckRegistry()
        registry.load()
        scored = {m.check_id: m.scored for m in registry.get_all_checks()}
        assert INVENTORY_CHECK_IDS <= set(scored)
        assert [cid for cid in sorted(INVENTORY_CHECK_IDS) if scored[cid]] == []
        components = pytest.importorskip("gws_auditor.dashboard.components")
        assert set(components.INVENTORY_CHECK_IDS) == set(INVENTORY_CHECK_IDS)


GOLDEN = Path(__file__).parent / "fixtures" / "golden"
SNAPSHOTS = sorted(GOLDEN.glob("*.json.gz"))


@pytest.mark.parametrize("path", SNAPSHOTS, ids=[p.name[:-8] for p in SNAPSHOTS])
class TestCachedRunReproducesGoldenSnapshot:
    """``Orchestrator.run_cached`` (the ``--cached`` path) must reach the same verdicts as the
    registry path used by test_golden_snapshots and write reports that agree with each other."""

    def _run(self, path, tmp_path):
        from gws_auditor.config import load_config
        from gws_auditor.orchestrator import Orchestrator

        cache = tmp_path / "gws_data_golden.json"
        with gzip.open(path, "rb") as fh:
            cache.write_bytes(fh.read())
        config = load_config(None)
        config["output"] = {"directory": str(tmp_path / "reports"), "formats": ["json", "csv", "html"]}
        report = Orchestrator(config).run_cached(str(cache))
        outputs = {p.suffix: p for p in (tmp_path / "reports").iterdir()}
        return report, outputs

    def test_statuses_match_pinned_expectations(self, path, tmp_path):
        expected = json.loads((GOLDEN / "expected_statuses.json").read_text())[path.name[:-8]]
        report, _ = self._run(path, tmp_path)
        got = {r.check_id: r.status.value for r in report.results}
        assert got == {cid: e["status"] for cid, e in expected.items()}

    def test_reports_agree_with_the_in_memory_run(self, path, tmp_path):
        report, outputs = self._run(path, tmp_path)
        assert set(outputs) == {".json", ".csv", ".html"}
        data = json.loads(outputs[".json"].read_text())
        assert [(d["check_id"], d["status"], d["severity"], d["scored"]) for d in data["results"]] == \
            [(r.check_id, r.status.value, r.severity.value, r.scored) for r in report.results]
        s = data["summary"]
        assert s["total"] == len(report.results) == sum(s[n] for n in BUCKET.values())
        assert s == {**s, **{n: getattr(report.summary, n) for n in BUCKET.values()}}
        assert s["posture_score"] == compute_posture_score_from_report(data)["score"] == report.summary.posture_score
        assert s["critical_failed"] == sum(
            1 for d in data["results"] if d["status"] == "FAIL" and d["severity"] == "CRITICAL" and d["scored"])
        with open(outputs[".csv"], newline="") as fh:
            rows = list(csv.DictReader(fh))
        assert [(row["Check ID"], row["Status"]) for row in rows] == [(r.check_id, r.status.value) for r in report.results]
        assert f'id="card-score">{report.summary.posture_score}/100<' in outputs[".html"].read_text()
