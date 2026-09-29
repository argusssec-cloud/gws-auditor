"""ReportStore: report discovery and the comments sidecar."""

import json

import pytest

pytest.importorskip("pandas")  # dashboard extra

from gws_auditor.dashboard.data_loader import ReportStore  # noqa: E402

REPORT = "audit_20260920_100000.json"


@pytest.fixture
def reports_dir(tmp_path):
    (tmp_path / REPORT).write_text(json.dumps({
        "timestamp": "2026-09-20T10:00:00", "customer_id": "C0",
        "results": [{"check_id": "CIS-1.1.1", "status": "PASS"}, {"check_id": "CIS-1.1.2", "status": "MANUAL"}],
    }))
    return tmp_path


def test_comments_sidecar_is_not_listed_as_a_report(reports_dir):
    ReportStore(reports_dir).save_comment(REPORT, "CIS-1.1.1", "verified", "alice")
    assert (reports_dir / f"{REPORT}.comments.json").exists()
    # A fresh store simulates restarting the dashboard
    assert [r["filename"] for r in ReportStore(reports_dir).list_reports()] == [REPORT]


def test_comment_and_override_round_trip(reports_dir):
    store = ReportStore(reports_dir)
    store.save_comment(REPORT, "CIS-1.1.2", "checked in Admin console", "alice")
    store.save_override(REPORT, "CIS-1.1.2", "PASS")
    entry = ReportStore(reports_dir).load_comments(REPORT)["CIS-1.1.2"]
    assert entry["comment"] == "checked in Admin console" and entry["author"] == "alice"
    assert entry["override_status"] == "PASS" and entry["timestamp"]
    # Clearing the comment keeps the override; clearing both removes the entry
    store.save_comment(REPORT, "CIS-1.1.2", "")
    assert store.load_comments(REPORT)["CIS-1.1.2"] == {"override_status": "PASS"}
    store.save_override(REPORT, "CIS-1.1.2", "")
    assert "CIS-1.1.2" not in store.load_comments(REPORT)


def test_report_filename_cannot_escape_the_directory(reports_dir):
    with pytest.raises(ValueError):
        ReportStore(reports_dir).load_report("../secrets.json")


def test_analyst_default_report_skips_comments_sidecar(reports_dir):
    pytest.importorskip("rich")
    from gws_auditor.ai.cli_repl import _load_report

    ReportStore(reports_dir).save_comment(REPORT, "CIS-1.1.1", "verified", "alice")
    data, filename = _load_report(str(reports_dir))
    assert filename == REPORT and data["customer_id"] == "C0"
