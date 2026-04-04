# Setup Guide

## Automated Setup (Recommended)

The `gws-auditor setup` command automates most of the configuration:

```bash
gws-auditor setup
```

### What it automates:
| Step | Manual before | With setup wizard |
|------|---------------|-------------------|
| GCP project selection/creation | Navigate GCP Console | Interactive picker or auto-create |
| Enable 10 APIs | 10 separate clicks | Single batch API call |
| Create service account | Navigate IAM Console | Automated via IAM API |
| Download JSON key | Manual download | Auto-saved to `credentials/` |
| Get Client ID for DWD | Copy from Console | Auto-extracted + clipboard copy |
| Generate scope string | Copy from docs | Auto-generated from code |
| Generate config.yaml | Manual text editing | Auto-generated with all values |
| Validate connectivity | Manual `--dry-run` | Auto-runs at end |

### What remains manual:
**Domain-Wide Delegation authorization** -- The wizard provides the Client ID, scope string, and a direct link to the Admin Console page. You paste and click Authorize.

### Options

```bash
# Interactive (recommended for first-time setup)
gws-auditor setup

# Pre-set values
gws-auditor setup --project my-gcp-project --subject admin@company.com

# Use existing service account (avoids OAuth flow)
gws-auditor setup --existing-sa-key credentials.json

# Non-interactive (CI/CD)
gws-auditor setup --project my-project --subject admin@co.com --non-interactive
```

### If "Access blocked" by admin

If your Workspace admin restricts third-party OAuth apps, use `--existing-sa-key` to bypass the OAuth flow entirely:

```bash
gws-auditor setup --existing-sa-key path/to/your-sa-key.json
```

---

## Manual Setup

### Phase 1: GCP Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project

### Phase 2: Enable APIs

Enable these 10 APIs in **APIs & Services > Library**:

| API | Service Name |
|-----|-------------|
| Admin SDK API | `admin.googleapis.com` |
| Gmail API | `gmail.googleapis.com` |
| Google Drive API | `drive.googleapis.com` |
| Google Calendar API | `calendar-json.googleapis.com` |
| Groups Settings API | `groupssettings.googleapis.com` |
| Cloud Identity API | `cloudidentity.googleapis.com` |
| Chrome Policy API | `chromepolicy.googleapis.com` |
| Google Chat API | `chat.googleapis.com` |
| Google Workspace Alert Center API | `alertcenter.googleapis.com` |
| Enterprise License Manager API | `licensing.googleapis.com` |

### Phase 3: Service Account

1. Go to **IAM & Admin > Service Accounts**
2. Create service account (e.g., `gws-security-auditor`)
3. Create JSON key and download
4. Save to `credentials/` directory

### Phase 4: Domain-Wide Delegation

1. Go to [Admin Console > Security > API Controls > Domain-wide Delegation](https://admin.google.com/ac/owl/domainwidedelegation)
2. Click **Add new**
3. Paste the **Client ID** from the service account JSON (`client_id` field)
4. Paste all required scopes (comma-separated, one line):

```
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.domain.readonly,https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,https://www.googleapis.com/auth/admin.directory.orgunit.readonly,https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,https://www.googleapis.com/auth/admin.reports.audit.readonly,https://www.googleapis.com/auth/admin.reports.usage.readonly,https://www.googleapis.com/auth/apps.groups.settings,https://www.googleapis.com/auth/gmail.settings.basic,https://www.googleapis.com/auth/calendar,https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/chrome.management.policy.readonly,https://www.googleapis.com/auth/apps.licensing,https://www.googleapis.com/auth/chat.admin.spaces.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/apps.alerts
```

5. Click **Authorize**

> All scopes are **read-only**. The tool never modifies your Google Workspace configuration.

### Phase 5: Configure and Validate

```bash
# Create config.yaml (or use gws-auditor setup to generate it)
gws-auditor --validate    # test all API connections
gws-auditor               # run first audit
```
