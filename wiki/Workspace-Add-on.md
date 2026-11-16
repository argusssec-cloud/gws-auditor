# Workspace Add-on

Argus Cloud is listed on the [Google Workspace Marketplace](https://workspace.google.com/marketplace/app/argussec/133488094837). The add-on puts your latest audit inside Gmail, Drive, Sheets and Google Chat. It is a thin layer of cards over Argus Cloud: the open-source engine in this repository produces every finding it shows, and the CLI and self-hosted dashboard work without it.

[Install from the Marketplace](https://workspace.google.com/marketplace/app/argussec/133488094837) | [Announcement](https://argussec.io/blog/argussec-on-google-workspace-marketplace.html)

## What it does

| Surface | What you get |
|---------|--------------|
| **Gmail side panel** | Gmail posture score, number of failing checks and the top failures by severity, each with its check ID and a remediation link |
| **Drive side panel** | The same view for Drive sharing, external access and content security checks |
| **Sheets side panel** | A scan picker and two buttons, **Import all** and **Failures only**, that write one row per check into the open spreadsheet: `check_id`, `title`, `status`, `severity`, `level`, `source`, `section`, `details`, `remediation` |
| **Google Chat app** | Slash commands plus free-text questions answered by the AI Analyst from your scan data |

### Chat commands

| Command | Result |
|---------|--------|
| `/gws-status` | Posture summary for the latest scan, with a button to the dashboard |
| `/gws-audit` | Starts a new scan of your default tenant |
| `/gws-findings [section]` | Top failures, optionally filtered to one section such as `gmail` or `drive` |
| `/gws-remediate <check_id>` | Remediation steps for one check, with the Admin console path |
| `/gws-help` | The command list |

Any other message goes to the AI Analyst.

## Installing

1. Open the [listing](https://workspace.google.com/marketplace/app/argussec/133488094837) and click **Install**. Workspace admins can install for the whole domain or for selected organizational units; individual users can install for themselves.
2. Sign in at [app.argussec.io](https://app.argussec.io/) with the same Google account and connect a tenant (service-account setup, about two minutes).
3. Run your first audit. It is free and needs no credit card.
4. Open Gmail, Drive or Sheets and click the ArgusSec icon in the side panel. In Chat, add the ArgusSec app and send `/gws-help`.

The add-on works with any Argus Cloud account, including the free first audit. Keeping the panels current requires scans to keep running, which a subscription provides. See [Argus Cloud](Argus-Cloud) for pricing.

## Permissions

The add-on requests five OAuth scopes. None is classified by Google as sensitive or restricted, so it needed neither sensitive-scope verification nor a CASA assessment.

| Scope | Used for |
|-------|----------|
| `userinfo.email`, `openid` | Matching the signed-in Google user to their Argus Cloud account |
| `gmail.addons.execute` | Required by Google to render any panel in Gmail; grants no access to message content |
| `spreadsheets.currentonly` | Writing rows into the sheet you have open when you click Import |
| `drive.file` | Google's per-file grant so the Sheets panel can reach the spreadsheet you opened it in |

The add-on does not read mail or browse Drive. Audit data comes from the read-only service account connected in the console, which uses the same scopes as this CLI.

## Troubleshooting

- **"Sign in to Argus" card** -- the Google account you are using in Workspace is not a member of an Argus Cloud organization. Sign up at app.argussec.io with that account, or ask an org admin to invite it.
- **Empty panel** -- no completed scan yet. Run one from the console or with `/gws-audit`.
- **Sheets import does nothing** -- grant file access when the add-on asks; the `drive.file` scope is per spreadsheet.
- **Chat app not found** -- a Workspace admin may need to allow Marketplace apps, or install the add-on domain-wide.
