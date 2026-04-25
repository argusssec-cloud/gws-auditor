# Advanced Authentication Methods

This page documents authentication methods that are not yet supported but are under consideration for future releases.

## Delegated Admin Service Account (DASA)

DASA is an authentication pattern used by [GAM](https://github.com/GAM-team/GAM/wiki/Using-GAM7-with-a-delegated-admin-service-account) where the service account itself is granted a delegated admin role in the Google Admin Console, instead of using Domain-Wide Delegation (DWD) to impersonate a super admin.

### Advantages

- **Better audit logging** — Admin audit logs show the SA made the action, not the impersonated user
- **Simpler permission model** — Uses admin roles instead of OAuth scopes + DWD
- **No `subject` email needed** — The SA authenticates directly
- **No license consumed** — SAs don't require a Workspace license
- **Faster auth** — Uses JWT auth directly, no OAuth token exchange

### Why GWS Auditor Cannot Use DASA (Yet)

The auditor relies heavily on the **Cloud Identity Policy API** (`cloudidentity.googleapis.com`) for reading Workspace app settings (Gmail, Drive, Calendar, Chat, Meet, etc.). This API currently **does not work with delegated admin service accounts** — it requires DWD impersonation of a user with appropriate access.

This means a DASA-authenticated auditor would fail on approximately 100+ policy-based checks (most of the CIS and CISA checks).

### When This May Change

If Google extends Cloud Identity Policy API access to delegated admin accounts, DASA support would be straightforward to add. The auth flow is simpler than the current DWD setup.

### Workaround: Partial DASA Mode

A future feature could support a "DASA mode" that runs only the checks that don't require the Policy API (Directory checks, DNS checks, Reports/logs checks, Groups Settings checks, Alert Rules checks). This would cover approximately 40-50 checks.

## YubiKey-Protected Service Account Keys

GAM supports [storing the SA private key on a YubiKey](https://github.com/GAM-team/GAM/wiki/Using-GAM7-with-a-YubiKey) hardware token. The key is generated on the YubiKey and can never be exported — signing requests are sent to the YubiKey, which returns the signature.

### How It Works

1. A PIV slot on the YubiKey generates and stores an RSA 2048 key pair
2. The public key is uploaded to Google Cloud as a SA key
3. The `credentials.json` file contains the YubiKey serial number and PIN but **no private key**
4. When the auditor needs to sign a JWT, it sends the request to the YubiKey

### Security Benefits

- Private key never exists on disk or in memory
- Key cannot be digitally stolen — requires physical YubiKey + PIN
- No key rotation needed (key cannot be exported)

### Why Not Implemented Yet

- Requires `ykman` / `yubikey-manager` dependency
- PIV interaction adds latency to every API call (YubiKey signs each JWT)
- Niche audience — [Keyless authentication](Keyless-Authentication) (GCE/WIF) provides the same "no key on disk" benefit with less friction
- Would need PKCS#11 integration in `google-auth`

### Recommendation

For the "no key file on disk" use case:
- **On GCP**: Use `--auth-method gce` (attached service account)
- **In CI/CD**: Use `--auth-method workload_identity` (WIF)
- **On-premises with high-security requirements**: YubiKey would be the solution, pending implementation
