# Minimal GCP Permissions

In enterprise environments, the person running the auditor may not be a GCP project owner. This page documents the minimum IAM permissions needed for each role.

## Role Separation

| Role | Who | What they do |
|------|-----|-------------|
| **GCP Admin** | Cloud/platform team | Creates project, grants permissions |
| **GWS Admin** | Workspace/security team | Runs `gws-auditor setup`, configures DWD, runs audits |

## Permissions for the GWS Admin

The GWS admin needs these GCP IAM permissions on the auditor's project:

| Permission | Service | Reason |
|-----------|---------|--------|
| `clientauthconfig.brands.create` | OAuth | Create OAuth consent screen |
| `clientauthconfig.brands.update` | OAuth | Update consent screen |
| `clientauthconfig.clients.create` | OAuth | Create OAuth client ID |
| `clientauthconfig.clients.createSecret` | OAuth | Generate client secret |
| `clientauthconfig.clients.get` | OAuth | Read client config |
| `clientauthconfig.clients.list` | OAuth | List clients |
| `iam.serviceAccountKeys.create` | IAM | Download SA key file |
| `iam.serviceAccounts.create` | IAM | Create service account |
| `iam.serviceAccounts.list` | IAM | List service accounts |
| `oauthconfig.testusers.get` | OAuth | Read test user config |
| `oauthconfig.verification.get` | OAuth | Read verification status |
| `resourcemanager.projects.get` | Resource Manager | Read project info |
| `serviceusage.services.enable` | Service Usage | Enable APIs |
| `serviceusage.services.get` | Service Usage | Check API status |
| `serviceusage.services.list` | Service Usage | List enabled APIs |

### Creating a Custom Role

The GCP admin can create a minimal custom role:

```bash
gcloud iam roles create gwsAuditorSetup \
    --project=PROJECT_ID \
    --title="GWS Auditor Setup" \
    --permissions="clientauthconfig.brands.create,clientauthconfig.brands.update,clientauthconfig.clients.create,clientauthconfig.clients.createSecret,clientauthconfig.clients.get,clientauthconfig.clients.list,iam.serviceAccountKeys.create,iam.serviceAccounts.create,iam.serviceAccounts.list,oauthconfig.testusers.get,oauthconfig.verification.get,resourcemanager.projects.get,serviceusage.services.enable,serviceusage.services.get,serviceusage.services.list"
```

Then grant it:

```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:admin@company.com" \
    --role="projects/PROJECT_ID/roles/gwsAuditorSetup"
```

## Permissions for Keyless Auth (GCE / WIF)

When using [keyless authentication](Keyless-Authentication), the SA does not need `iam.serviceAccountKeys.create`. Instead:

**GCE attached SA** — the SA needs:
- `iam.serviceAccountTokenCreator` role **on itself** (for DWD JWT signing)

**Workload Identity Federation** — the SA needs:
- `iam.workloadIdentityUser` role granted to the external identity principal

## Required GCP APIs

The auditor requires these 10 APIs enabled on the project:

```
admin.googleapis.com              # Admin SDK (Directory + Reports)
gmail.googleapis.com              # Gmail API
drive.googleapis.com              # Drive API
calendar-json.googleapis.com      # Calendar API
groupssettings.googleapis.com     # Groups Settings API
cloudidentity.googleapis.com      # Cloud Identity Policy API
chromepolicy.googleapis.com       # Chrome Policy API
chat.googleapis.com               # Chat API
alertcenter.googleapis.com        # Alert Center API
licensing.googleapis.com          # License Manager API
```

Enable all at once:
```bash
gcloud services enable admin.googleapis.com gmail.googleapis.com \
    drive.googleapis.com calendar-json.googleapis.com \
    groupssettings.googleapis.com cloudidentity.googleapis.com \
    chromepolicy.googleapis.com chat.googleapis.com \
    alertcenter.googleapis.com licensing.googleapis.com \
    --project=PROJECT_ID
```

## Required DWD Scopes

See the [Setup Guide](Setup-Guide) for the full list of 21 OAuth scopes that must be authorized in Admin Console > Security > API controls > Domain-wide Delegation.

## Service Account Runtime Permissions

The service account itself does **not** need any GCP IAM roles to run the auditor. All Workspace API access is granted through Domain-Wide Delegation, not GCP IAM. The SA only needs:
- DWD authorization in Admin Console (scopes)
- The `subject` user to be a super admin (or delegated admin with sufficient privileges)
