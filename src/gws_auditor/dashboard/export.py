# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Generate a standalone HTML report with auditor comments."""

import html
import json


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text)) if text else ""


def generate_html_export(report_data: dict, comments: dict) -> str:
    """Build a self-contained HTML page from report data and comments.

    Args:
        report_data: The full audit report dict (from JSON).
        comments: Dict mapping check_id to comment info dicts.

    Returns:
        A complete HTML string ready for download.
    """
    customer_id = _esc(report_data.get("customer_id", ""))
    timestamp = _esc(report_data.get("timestamp", ""))
    subscription = _esc(report_data.get("subscription_type", ""))
    domains = ", ".join(_esc(d) for d in report_data.get("domains", []))
    summary = report_data.get("summary", {})
    results = report_data.get("results", [])

    pass_rate = summary.get("pass_rate", 0)

    # Build table rows
    rows_html = []
    for r in results:
        check_id = r.get("check_id", "")
        status = r.get("status", "")
        status_cls = {
            "PASS": "pass", "FAIL": "fail", "WARN": "warn", "PARTIAL": "partial",
            "ERROR": "error", "MANUAL": "manual", "NOT_APPLICABLE": "na",
        }.get(status, "")

        comment_info = comments.get(check_id, {})
        comment_text = _esc(comment_info.get("comment", ""))
        comment_author = _esc(comment_info.get("author", ""))
        comment_ts = _esc(comment_info.get("timestamp", ""))
        comment_cell = ""
        if comment_text:
            comment_cell = comment_text
            if comment_author:
                comment_cell += f'<br><small class="comment-meta">- {comment_author}'
                if comment_ts:
                    comment_cell += f" ({comment_ts})"
                comment_cell += "</small>"

        rows_html.append(
            f'<tr class="status-{status_cls}">'
            f"<td><code>{_esc(check_id)}</code></td>"
            f"<td>{_esc(r.get('title', ''))}</td>"
            f'<td><span class="badge badge-{status_cls}">{_esc(status)}</span></td>'
            f"<td>{_esc(r.get('level', ''))}</td>"
            f"<td>{_esc(r.get('source', ''))}</td>"
            f"<td>{_esc(r.get('section', ''))}</td>"
            f"<td>{_esc(r.get('details', ''))}</td>"
            f"<td>{_esc(r.get('remediation', ''))}</td>"
            f'<td class="comment-cell">{comment_cell}</td>'
            f"</tr>"
        )

    table_body = "\n".join(rows_html)
    edition_line = f"<span><strong>Edition:</strong> {subscription}</span>" if subscription else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GWS Security Audit Report &mdash; {customer_id}</title>
<style>
  :root {{
    --bg: #ffffff; --fg: #1a202c; --bg-card: #f7fafc; --border: #e2e8f0;
    --header-bg: #1a2540; --header-fg: #ffffff;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #1a202c; --fg: #e2e8f0; --bg-card: #2d3748; --border: #4a5568;
             --header-bg: #0f172a; }}
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: var(--bg); color: var(--fg); line-height: 1.5; }}
  header {{ background: var(--header-bg); color: var(--header-fg); padding: 1.5rem 2rem; }}
  header h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 1.5rem; font-size: 0.85rem; opacity: 0.85; }}
  .meta strong {{ opacity: 1; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 1rem; padding: 1.5rem 2rem;
              background: var(--bg-card); border-bottom: 1px solid var(--border); }}
  .summary-item {{ text-align: center; min-width: 80px; }}
  .summary-item .val {{ font-size: 1.5rem; font-weight: 700; }}
  .summary-item .lbl {{ font-size: 0.75rem; text-transform: uppercase; opacity: 0.7; }}
  .container {{ padding: 1.5rem 2rem; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ background: #2d3748; color: white; padding: 0.6rem 0.75rem; text-align: left;
       text-transform: uppercase; font-size: 0.75rem; font-weight: 600;
       position: sticky; top: 0; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border);
       vertical-align: top; }}
  code {{ font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.82rem;
          font-weight: 600; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600;
            color: white; display: inline-block; }}
  .badge-pass {{ background: #38a169; }}
  .badge-fail {{ background: #e53e3e; }}
  .badge-warn {{ background: #d69e2e; color: #1a202c; }}
  .badge-partial {{ background: #dd6b20; }}
  .badge-error {{ background: #9b2c2c; }}
  .badge-manual {{ background: #3182ce; }}
  .badge-na {{ background: #a0aec0; }}
  tr.status-pass {{ background: #f0fff4; }}
  tr.status-fail {{ background: #fff5f5; }}
  tr.status-warn {{ background: #fffff0; }}
  tr.status-partial {{ background: #fffaf0; }}
  tr.status-manual {{ background: #ebf8ff; }}
  @media (prefers-color-scheme: dark) {{
    th {{ background: #1e293b; }}
    tr.status-pass {{ background: rgba(56, 161, 105, 0.1); }}
    tr.status-fail {{ background: rgba(229, 62, 62, 0.1); }}
    tr.status-warn {{ background: rgba(214, 158, 46, 0.1); }}
    tr.status-partial {{ background: rgba(221, 107, 32, 0.1); }}
    tr.status-manual {{ background: rgba(49, 130, 206, 0.1); }}
  }}
  .comment-cell {{ min-width: 200px; font-style: italic; }}
  .comment-meta {{ color: #718096; font-style: normal; }}
  @media print {{
    header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    .badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  }}
</style>
</head>
<body>
<header>
  <h1>GWS Security Audit Report</h1>
  <div class="meta">
    <span><strong>Customer:</strong> {customer_id}</span>
    {edition_line}
    <span><strong>Timestamp:</strong> {timestamp}</span>
    <span><strong>Domains:</strong> {domains}</span>
  </div>
</header>
<div class="summary">
  <div class="summary-item"><div class="val">{summary.get('total', 0)}</div><div class="lbl">Total</div></div>
  <div class="summary-item"><div class="val" style="color:#38a169">{summary.get('passed', 0)}</div><div class="lbl">Passed</div></div>
  <div class="summary-item"><div class="val" style="color:#e53e3e">{summary.get('failed', 0)}</div><div class="lbl">Failed</div></div>
  <div class="summary-item"><div class="val" style="color:#d69e2e">{summary.get('warnings', 0)}</div><div class="lbl">Warnings</div></div>
  <div class="summary-item"><div class="val" style="color:#3182ce">{summary.get('manual', 0)}</div><div class="lbl">Manual</div></div>
  <div class="summary-item"><div class="val" style="color:#38a169">{pass_rate:.1f}%</div><div class="lbl">Pass Rate</div></div>
</div>
<div class="container">
<table>
<thead>
<tr>
  <th>Check ID</th><th>Title</th><th>Status</th><th>Level</th>
  <th>Source</th><th>Section</th><th>Details</th><th>Remediation</th><th>Comments</th>
</tr>
</thead>
<tbody>
{table_body}
</tbody>
</table>
</div>
</body>
</html>"""
