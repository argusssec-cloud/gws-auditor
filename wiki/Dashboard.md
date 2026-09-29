# Dashboard

An interactive web UI (Plotly Dash) for exploring audit reports: filter findings, drill into a framework or section, review inventory, annotate results and export them. It reads the JSON reports the auditor already writes -- it never contacts Google and needs no credentials.

## Install and run

```bash
pip install "gws-security-auditor[dashboard]"     # dash, dash-bootstrap-components, plotly, pandas

gws-auditor dashboard                             # http://127.0.0.1:8050
gws-auditor dashboard --reports-dir ./reports --port 9000
```

| Option | Default | Description |
|--------|---------|-------------|
| `--reports-dir` | `./reports` | Directory containing `audit_*.json` reports |
| `--host` | `127.0.0.1` | Interface to bind to |
| `--port` | `8050` | Port to serve on |
| `--debug` | off | Dash debug mode with hot reload (development only) |

The dashboard lists every `audit_<timestamp>.json` file in the reports directory, newest first. Produce them with a normal audit run that includes the `json` format (the default: `formats: [html, json, csv]`). Use the report selector in the sidebar to switch between runs; each entry shows the timestamp, customer id and pass rate. The directory is scanned when the dashboard starts, so restart it after a new audit.

> **The dashboard has no authentication.** It binds to `127.0.0.1` by default so that only you can reach it. Audit reports contain user emails, group names, OAuth client ids and a map of your tenant's weaknesses. If you bind to another interface (`--host 0.0.0.0`), put it behind something that authenticates -- an SSH tunnel, a VPN, or a reverse proxy with SSO -- and never expose it to the internet. Do not use `--debug` anywhere but your own machine: it turns on Flask/Dash developer tooling, including an interactive debugger.

## Pages

### Overview (`/`)

- **Report metadata and posture score** for the selected run (see [Posture Score](Posture-Score)).
- **Filters** by source (CIS / CISA / GOOGLE / OTHER), section, level (L1 / L2) and status. All charts and the table follow the filters.
- **Metric cards** for each status; click a card to filter the table to that status.
- **Critical findings** -- failed CRITICAL-severity checks, listed first (see [Critical Checks](Critical-Checks)).
- **Charts** -- status distribution, results by section, results by source, L1 vs L2.
- **Findings table** with search, sorting and a configurable page size. Click a row for the full detail: actual and expected value, per-OU breakdown, remediation steps and links.
- **Export** -- *Export CSV* (the filtered findings) and *Export HTML with Comments* (a standalone report including your annotations, suitable for sharing with auditors).

### Compliance (`/compliance`)

A per-framework view. Pick a framework to see its status breakdown, the sections with the most failures, and each section's checks with pass/fail badges. Click a check for the same detail view as on the Overview.

### Inventory (`/inventory`)

One tab per inventory check: stale groups (ADD-28), inactive Chat spaces (ADD-29), stale mobile devices (ADD-30), stale ChromeOS devices (ADD-31), 2SV enrollment (ADD-32), OAuth risk (ADD-33), app passwords (ADD-34) and Shared Drives (ADD-35). A tab is marked `(!)` when its check is WARN or FAIL. Inventory checks are informational and do not affect the posture score.

### AI Analyst (`/analyst`)

A chat page backed by the same engine as `gws-auditor analyst`, working on the report selected in the sidebar. It needs the AI extras and an API key -- see [AI Analyst](AI-Analyst). The provider and key are read from the `ai:` section of `config.yaml` in the directory the dashboard was started from, or from environment variables.

The analyst conversation is held in the dashboard process, not per browser: everyone connected to the same dashboard instance shares one conversation. Another reason to keep it on localhost.

## Comments and status overrides

Open a finding and you can:

- **Add a comment** (with an author name) on any finding -- for example the ticket number, the accepted-risk rationale, or the evidence you checked. Comments can also be typed directly into the Comment column of the findings table.
- **Set the status of a MANUAL result** to PASS or FAIL once you have verified it in the Admin console. The override control is only offered for results that the auditor itself reported as MANUAL; an automated PASS or FAIL cannot be overridden. The posture score shown in the dashboard is recomputed with your overrides, and an overridden check keeps its override control so the decision can be changed or cleared later.

Both are stored in a sidecar file next to the report, `audit_<timestamp>.json.comments.json`:

```json
{
  "CIS-4.1.1.2": {
    "comment": "Hardware keys rolled out to all admins, verified 2026-09-12 (SEC-481)",
    "author": "alice",
    "timestamp": "2026-09-12T14:03:22.118305+00:00",
    "override_status": "PASS"
  }
}
```

The audit report itself is never modified, so re-running the auditor or the [CI/CD](CICD-Integration) pipeline is unaffected by overrides -- they are a reviewer's annotation layer, not a way to suppress checks. To exclude a check from the audit itself use `checks.exclude` ([Configuration](Configuration)). Keep the sidecar files with the reports if you want the annotations to follow them (they are plain JSON and diff well in version control).

## Dark mode

The toggle in the sidebar switches between light and dark themes, including the charts. The preference is stored in the browser (`localStorage`), not on the server.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `Dashboard dependencies are not installed` | Install the extra: `pip install "gws-security-auditor[dashboard]"` |
| Report selector is empty | No `audit_*.json` in `--reports-dir`. Run an audit with the `json` format enabled, or point `--reports-dir` at the right folder |
| A new audit does not appear | The reports directory is scanned once, when the dashboard starts. Restart `gws-auditor dashboard` to pick up new reports |
| AI Analyst page says dependencies are missing | Install an AI extra and set an API key -- see [AI Analyst](AI-Analyst) |
| Port already in use | Pass another `--port` |

More in [Troubleshooting](Troubleshooting).
