# Keyless Authentication

GWS Security Auditor supports keyless authentication methods that eliminate the need for a service account JSON key file on disk. This reduces the attack surface — there is no long-lived key to steal, rotate, or accidentally commit to version control.

## Methods

| Method | Use Case | Key File Required | Config Value |
|--------|----------|:-----------------:|:------------:|
| Service Account | Traditional setup | Yes | `service_account` |
| OAuth 2.0 | Interactive / one-off | No (browser flow) | `oauth` |
| **GCE Attached SA** | Running on Google Cloud | **No** | `gce` |
| **Workload Identity Federation** | CI/CD, AWS, GitHub Actions | **No** | `workload_identity` |

## GCE Attached Service Account

When running the auditor on a Google Compute Engine VM, you can use the VM's attached service account instead of a key file. The credentials are obtained from the [instance metadata server](https://cloud.google.com/compute/docs/access/authenticate-workloads) and are short-lived tokens — no private key exists on disk.

### Setup

1. **Create a service account** in the GCP Console (IAM & Admin > Service Accounts). Do not download a key.

2. **Grant the SA the `Service Account Token Creator` role** on itself (needed for DWD JWT signing):
   ```bash
   gcloud iam service-accounts add-iam-policy-binding SA_EMAIL \
       --member="serviceAccount:SA_EMAIL" \
       --role="roles/iam.serviceAccountTokenCreator"
   ```

3. **Create a GCE VM** with the service account attached:
   - Set `Service account` to the SA you created
   - Set `Access scopes` to "Allow full access to all Cloud APIs" (scopes are enforced via DWD, not VM scopes)

4. **Enable required APIs** on the GCP project:
   ```bash
   gcloud services enable admin.googleapis.com gmail.googleapis.com \
       drive.googleapis.com calendar-json.googleapis.com \
       groupssettings.googleapis.com cloudidentity.googleapis.com \
       chromepolicy.googleapis.com chat.googleapis.com \
       alertcenter.googleapis.com licensing.googleapis.com
   ```

5. **Configure Domain-Wide Delegation** in Admin Console (Security > API controls > Domain-wide Delegation). Add the SA's Client ID with the required OAuth scopes (same as the standard setup).

6. **Run the auditor**:
   ```bash
   gws-auditor --auth-method gce --subject admin@company.com
   ```
   Or in `config.yaml`:
   ```yaml
   auth:
     method: gce
     subject: admin@company.com
     customer_id: auto
   ```

### Security Benefits

- No key file on disk — eliminates key theft, accidental exposure, and rotation burden
- Short-lived tokens (1 hour) from the metadata server
- VM-level access controls (IAM, network, OS Login) protect the credentials
- Recommended by Google for workloads running inside GCP

## Workload Identity Federation (WIF)

WIF enables keyless authentication from **outside** Google Cloud — CI/CD systems, AWS, Azure, or any OIDC/SAML provider. Instead of a static SA key, your external identity (e.g., GitHub Actions OIDC token, AWS IAM role) is exchanged for short-lived Google credentials.

### GitHub Actions Setup

1. **Create a Workload Identity Pool and Provider**:
   ```bash
   gcloud iam workload-identity-pools create gws-auditor-pool \
       --location="global"

   gcloud iam workload-identity-pools providers create-oidc github \
       --workload-identity-pool="gws-auditor-pool" \
       --issuer-uri="https://token.actions.githubusercontent.com" \
       --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
       --attribute-condition="assertion.repository_owner=='YOUR_GITHUB_ORG'" \
       --location="global"
   ```

2. **Allow GitHub to impersonate the SA**:
   ```bash
   gcloud iam service-accounts add-iam-policy-binding SA_EMAIL \
       --role="roles/iam.workloadIdentityUser" \
       --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gws-auditor-pool/attribute.repository/YOUR_ORG/YOUR_REPO"
   ```

3. **GitHub Actions workflow**:
   ```yaml
   jobs:
     audit:
       runs-on: ubuntu-latest
       permissions:
         id-token: write
         contents: read
       steps:
         - uses: actions/checkout@v4
         - uses: google-github-actions/auth@v2
           with:
             workload_identity_provider: 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gws-auditor-pool/providers/github'
             service_account: 'SA_EMAIL'
         - run: pip install gws-security-auditor
         - run: |
             gws-auditor --auth-method workload_identity \
               --subject admin@company.com \
               --fail-on-critical
   ```

### AWS Setup

1. Create a WIF provider for AWS:
   ```bash
   gcloud iam workload-identity-pools providers create-aws aws-provider \
       --workload-identity-pool="gws-auditor-pool" \
       --account-id="YOUR_AWS_ACCOUNT_ID" \
       --location="global"
   ```

2. Generate the credential configuration:
   ```bash
   gcloud iam workload-identity-pools create-cred-config \
       projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/gws-auditor-pool/providers/aws-provider \
       --service-account=SA_EMAIL \
       --aws \
       --output-file=wif-config.json
   ```

3. Run:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=wif-config.json
   gws-auditor --auth-method workload_identity --subject admin@company.com
   ```

### Security Benefits

- No long-lived keys to store as CI/CD secrets
- Short-lived tokens (configurable, default 1 hour)
- Attribute conditions restrict which repos/roles/accounts can authenticate
- Native integration with cloud provider identity systems
- Google's officially recommended method for external workloads

## Choosing an Auth Method

| Scenario | Recommended Method |
|----------|-------------------|
| Running on a GCE VM | `gce` |
| GitHub Actions CI/CD | `workload_identity` |
| AWS/Azure hosted | `workload_identity` |
| Interactive one-off audit | `oauth` or `service_account` |
| On-premises server | `service_account` (with key rotation) |
| Docker on GCE/GKE | `gce` (metadata server available) |

## Domain-Wide Delegation Requirement

All auth methods still require **Domain-Wide Delegation** to be configured in the Google Admin Console. The DWD grant authorizes the service account (identified by Client ID) to access Workspace APIs on behalf of the `subject` user, regardless of how the SA authenticates.

The only difference is how the SA proves its identity:
- **Service Account key**: RSA private key signs JWT
- **GCE**: Metadata server provides signed token
- **WIF**: External identity token exchanged for Google token
