# Argus Cloud

Argus Cloud is the hosted version of GWS Security Auditor for teams and organizations that need automated scanning, compliance tracking, and collaboration features.

[Sign up at app.argussec.io](https://app.argussec.io/) | [Pricing](https://argussec.io/pricing.html)

## Open Source vs Argus Cloud

The open-source CLI is fully featured for individual auditors. Argus Cloud adds the operational layer teams need:

| Feature | Open Source (Free) | Argus Cloud (€15/mo per workspace) |
|---------|:---:|:---:|
| **Audit Engine** | | |
| 200 security checks | ✓ | ✓ |
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
| **Finding Management** | | |
| Severity classification | — | ✓ |
| Mute rules & finding management | — | ✓ |
| **Integrations** | | |
| Webhooks | — | ✓ |
| JIRA integration | — | ✓ |
| API keys | — | ✓ |
| **Auth & Access** | | |
| Google SSO login | — | ✓ |
| Onboarding walkthrough | — | ✓ |
| **Support** | | |
| Community support | ✓ | ✓ |
| Priority email support | — | ✓ |

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
