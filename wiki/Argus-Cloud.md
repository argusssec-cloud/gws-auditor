# Argus Cloud

Argus Cloud is the hosted version of GWS Security Auditor for teams and organizations that need automated scanning, compliance tracking, and collaboration features.

[Sign up at app.argussec.io](https://app.argussec.io/) | [Pricing](https://argussec.io/pricing.html)

## Open Source vs Argus Cloud

The open-source CLI is fully featured for individual auditors. Argus Cloud adds the operational layer teams need:

| Feature | Open Source (Free) | Argus Cloud (€15/mo per workspace) |
|---------|:---:|:---:|
| **Audit Engine** | | |
| 227 security checks | ✓ | ✓ |
| 4 frameworks (CIS, CISA, Google, Other) | ✓ | ✓ |
| HTML, JSON, CSV reports | ✓ | ✓ |
| CLI + Docker support | ✓ | ✓ |
| GitHub Actions compatible | ✓ | ✓ |
| **Dashboard** | | |
| Interactive Dash dashboard | ✓ (self-hosted) | ✓ (hosted) |
| Trend charts & compliance history | — | 12 months |
| **AI Analyst** | | |
| Natural language audit queries | BYO API key | Included (no key needed) |
| **Automation** | | |
| Automated daily/weekly scans | — | ✓ |
| Regression alerts (Slack, email) | — | ✓ |
| **Collaboration** | | |
| Multi-tenant management | — | ✓ |
| Team access & sharing | — | ✓ |
| Role-based access control | — | ✓ |
| **Risk Reports** | | |
| Entity-level exposure reports (public & externally shared files, shared drive members, calendar sharing, Chrome policy baseline, apps & shadow IT, groups, admin roles, domain security, user posture, devices, DLP coverage) | — | ✓ |
| Per-item remediation steps and GAM commands, CSV export | — | ✓ |
| Alerts on newly detected exposure items (email, webhook, Jira, GCS) | — | ✓ |
| Risk Reports section in branded PDF reports; AI Analyst can query exposed entities | — | ✓ |
| New / resolved tracking per entity, CSV export, per-item mute | — | ✓ |
| **Finding Management** | | |
| Severity classification | — | ✓ |
| Mute rules & finding management | — | ✓ |
| **Integrations** | | |
| Webhooks | — | ✓ |
| JIRA integration | — | ✓ |
| API keys | — | ✓ |
| Google Workspace add-on (Gmail, Drive, Sheets, Chat) | — | ✓ |
| **Auth & Access** | | |
| Google SSO login | — | ✓ |
| Onboarding walkthrough | — | ✓ |
| **Support** | | |
| Community support | ✓ | ✓ |
| Priority email support | — | ✓ |

## Inside Google Workspace

Argus Cloud is listed on the [Google Workspace Marketplace](https://workspace.google.com/marketplace/app/argussec/133488094837). The add-on reads from your Argus Cloud account and adds:

- **Gmail and Drive side panels** – posture score and the top failing checks for that service from the latest scan, with check IDs and remediation links.
- **Sheets import** – "Import all" or "Failures only" writes one row per check (ID, title, status, severity, level, framework, section, details, remediation) into the open spreadsheet.
- **Google Chat app** – `/gws-status`, `/gws-audit`, `/gws-findings [section]`, `/gws-remediate <check_id>` and `/gws-help`; any other message goes to the AI Analyst.

Install it from the listing (domain-wide from the Admin console, or per user), sign in to [app.argussec.io](https://app.argussec.io/) with the same Google account, and the panels appear in Gmail, Drive and Sheets. The add-on requests five non-sensitive scopes and does not read mail or Drive content; the audit data comes from the service account connected in the console. Read the [announcement](https://argussec.io/blog/argussec-on-google-workspace-marketplace.html).

## Pricing

| Plan | Monthly | Annual (save ~17%) |
|------|--------:|-------------------:|
| Per workspace | €15/mo | €12.50/mo (billed at €150/year) |

A free trial is available at [app.argussec.io](https://app.argussec.io/).

## Suppressing the CLI Banner

The CLI shows a brief Argus Cloud info message on interactive runs. To suppress it:

```bash
# Per-run
gws-auditor --no-cloud-info

# Permanent (add to shell profile or CI environment)
export GWS_AUDITOR_NO_CLOUD_INFO=1
```

The banner is automatically suppressed when:
- `--quiet` flag is used
- Output is piped or redirected (non-TTY)
- Running in CI/CD environments (no TTY on stderr)
