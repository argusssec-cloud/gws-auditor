# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Load and cache JSON audit reports for the dashboard."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


class ReportStore:
    """Scan, load, and cache JSON report files from a directory."""

    def __init__(self, reports_dir: str | Path):
        self.reports_dir = Path(reports_dir)
        self._cache: dict[str, dict] = {}
        self._file_list: list[Path] | None = None

    def _scan(self) -> list[Path]:
        if not self.reports_dir.exists():
            return []
        files = sorted(self.reports_dir.glob("audit_*.json"), reverse=True)
        return files

    def refresh(self) -> None:
        """Re-scan the reports directory."""
        self._file_list = None
        self._cache.clear()

    def list_reports(self) -> list[dict]:
        """Return metadata for each discovered report file.

        The ``pass_rate`` and ``total`` values exclude inventory checks
        (ADD-28 through ADD-33) so the report selector shows audit-only
        statistics matching the Overview page.
        """
        from .components import INVENTORY_CHECK_IDS

        if self._file_list is None:
            self._file_list = self._scan()
        result = []
        for fp in self._file_list:
            data = self.load_report(fp.name)
            # Compute audit-only stats, excluding inventory checks
            all_results = data.get("results", [])
            audit_results = [
                r for r in all_results
                if r.get("check_id", "") not in INVENTORY_CHECK_IDS
            ]
            total = len(audit_results)
            passed = sum(
                1 for r in audit_results
                if (r.get("status", "") or "").upper().replace(" ", "_") == "PASS"
            )
            failed = sum(
                1 for r in audit_results
                if (r.get("status", "") or "").upper().replace(" ", "_") == "FAIL"
            )
            evaluated = passed + failed
            pass_rate = (passed / evaluated * 100) if evaluated else 0.0

            result.append({
                "filename": fp.name,
                "timestamp": data.get("timestamp", ""),
                "customer_id": data.get("customer_id", ""),
                "total": total,
                "pass_rate": pass_rate,
            })
        return result

    def load_report(self, filename: str) -> dict:
        """Load and cache a single report by filename."""
        if filename in self._cache:
            return self._cache[filename]
        fp = self.reports_dir / filename
        with open(fp, encoding="utf-8") as fh:
            data = json.load(fh)
        self._cache[filename] = data
        return data

    def get_results_dataframe(self, filename: str) -> pd.DataFrame:
        """Convert a report's results list into a DataFrame."""
        data = self.load_report(filename)
        results = data.get("results", [])
        if not results:
            return pd.DataFrame(columns=[
                "check_id", "title", "status", "level", "source",
                "section", "details", "remediation", "org_unit",
            ])
        df = pd.DataFrame(results)
        # Normalise status strings
        df["status"] = df["status"].str.upper().str.replace(" ", "_")
        keep = [
            "check_id", "title", "status", "level", "source",
            "section", "details", "remediation", "org_unit",
        ]
        return df[[c for c in keep if c in df.columns]]

    def _comments_path(self, filename: str) -> Path:
        """Return the sidecar comments file path for a report."""
        return self.reports_dir / f"{filename}.comments.json"

    def load_comments(self, filename: str) -> dict:
        """Load comments for a report from its sidecar JSON file."""
        path = self._comments_path(filename)
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        return {}

    def save_comment(
        self, filename: str, check_id: str, comment: str, author: str = ""
    ) -> dict:
        """Save a comment for a check and return the updated comments dict."""
        comments = self.load_comments(filename)
        if comment.strip():
            entry = comments.get(check_id, {})
            entry.update({
                "comment": comment.strip(),
                "author": author.strip(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            comments[check_id] = entry
        else:
            # Remove comment but keep override_status if present
            entry = comments.get(check_id, {})
            entry.pop("comment", None)
            entry.pop("author", None)
            entry.pop("timestamp", None)
            if entry:
                comments[check_id] = entry
            else:
                comments.pop(check_id, None)
        path = self._comments_path(filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(comments, fh, indent=2)
        return comments

    def save_override(
        self, filename: str, check_id: str, override_status: str
    ) -> dict:
        """Save a manual status override for a check.

        ``override_status`` should be ``"PASS"``, ``"FAIL"``, or ``""`` to
        clear.  Returns the updated comments dict.
        """
        comments = self.load_comments(filename)
        entry = comments.get(check_id, {})
        if override_status in ("PASS", "FAIL"):
            entry["override_status"] = override_status
            comments[check_id] = entry
        else:
            entry.pop("override_status", None)
            if not entry:
                comments.pop(check_id, None)
            else:
                comments[check_id] = entry
        path = self._comments_path(filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(comments, fh, indent=2)
        return comments

    @staticmethod
    def get_filter_options(df: pd.DataFrame) -> dict[str, list[str]]:
        """Extract unique values for filter dropdowns."""
        opts: dict[str, list[str]] = {}
        for col in ("source", "section", "level", "status"):
            if col in df.columns:
                opts[col] = sorted(df[col].dropna().unique().tolist())
            else:
                opts[col] = []
        return opts
