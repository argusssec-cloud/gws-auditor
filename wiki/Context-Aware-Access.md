# Context-Aware Access Checks

GWS Security Auditor ships two checks that audit your Context-Aware Access (CAA) coverage:

- **ADD-20** -- Ensure Context-Aware Access is applied to OIDC apps
- **ADD-40** -- Ensure default Context-Aware Access policy is enabled for SAML applications *(new in v1.2.0)*

Both checks require **Enterprise Standard or higher** (`requires_license="enterprise_standard"`) and live under the **Security** section.

## Background

Context-Aware Access lets Workspace admins gate access to apps by device posture, location, IP, and other contextual signals. SAML and OIDC apps require an explicit per-app assignment to be covered by a CAA policy. Google's [May 2026 update](https://workspaceupdates.googleblog.com/2026/05/default-CAA-for-SAML.html) added a global default CAA policy for *all* SAML apps -- a single org-wide switch that catches any SAML app without a specific assignment. The toggle ships **off** by default.

Neither the SAML default toggle nor the OIDC per-app coverage is exposed by any public Workspace policy API. We verified this against a live tenant: 10 plausible prefixes on the Cloud Identity Policy API (`v1` and `v1beta1`) all return zero results, and Access Context Manager only manages CAA primitives, not the toggles.

## How the checks work

Both checks use the same three-state decision tree, fed by Reports API audit logs.

### Step 1 -- Inventory

Detect whether the relevant app class is in active use during the audit-log retention window (~30 days by default).

| Check | Data source | Detection rule |
|---|---|---|
| ADD-20 | `data["token_logs"]` (`applicationName=token`) | OAuth events where `client_id` ends in `.apps.googleusercontent.com` and `app_name` does not start with `"Google "` (excludes Google first-party apps) |
| ADD-40 | `data["login_logs"]` (`applicationName=login`) | Login events where `parameters.login_type == "saml"` |

If the count is zero, the check returns `NOT_APPLICABLE` -- the toggle has nothing to apply to, so it should not count against the posture score.

### Step 2 -- Enforcement evidence

Look for proof that CAA is actively blocking traffic for the relevant app class.

- Data source: `data["caa_events"]` (`applicationName=context_aware_access`, `eventName=ACCESS_DENY_EVENT`)
- Filter: `parameters.application_type` matching `"OAUTH"`/`"OIDC"` for ADD-20, `"SAML"` for ADD-40. Events lacking the parameter are counted for both classes (conservative).

If any matching denial exists, the check returns `PASS`. Even a single denial is hard evidence that CAA is configured and enforcing.

### Step 3 -- Inconclusive

Apps exist, but no denial events were found in the window. The check returns `MANUAL` (REVIEW) with the actual app inventory in the details, plus the explicit note: **"absence of denials does not prove CAA is disabled."** Monitor-mode policies and strict-enforce policies that simply weren't violated produce no denial events.

## Decision tree

```
                  ┌─ Step 1: inventory ─┐
data["token_logs"]│                     │data["login_logs"]
  (ADD-20)        ▼                     ▼   (ADD-40)
            count == 0? ──── yes ──→ NOT_APPLICABLE
                  │
                  no
                  ▼
            ┌─ Step 2: enforcement ─┐
            │ data["caa_events"]    │
            │ matching denials      │
            └──────────┬────────────┘
                       │
                ┌──────┴──────┐
                │             │
              count > 0     count == 0
                │             │
                ▼             ▼
              PASS         MANUAL
                          (with app
                           inventory)
```

## Example outputs

### ADD-20 -- third-party OIDC apps detected, no denials

```
ADD-20  status=MANUAL
  10 third-party OIDC app(s) detected (ArgusSec, Notion, LinkedIn,
  CapCut-Web, Curier rapid...) but no CAA ACCESS_DENY_EVENT was
  logged in the window. Absence of denials does not prove CAA is
  disabled -- verify the policy assignment in Admin console >
  Security > Context-Aware Access.
  actual_value: {oidc_apps: 10, denials: 0}
```

### ADD-40 -- no SAML logins in audit window

```
ADD-40  status=NOT_APPLICABLE
  No SAML SSO logins detected in the audit-log window; the
  default-CAA-for-SAML control has nothing to apply to.
  actual_value: 0
```

### ADD-40 -- SAML apps in use with active CAA enforcement

```
ADD-40  status=PASS
  CAA is actively enforcing on SAML traffic: 3 ACCESS_DENY_EVENT(s)
  in the window across 2 app(s).
  actual_value: {saml_apps: 5, denials: 3}
```

## Caveats

These caveats are documented inside each check's own output so a reviewer sees them in context:

- **"Detected" means used in the Reports API retention window** (~30 days). An app that is configured but never used during the lookback period is invisible. A tenant with provisioned-but-dormant SAML apps may falsely appear as `NOT_APPLICABLE`.
- **`ACCESS_DENY_EVENT` only fires on actual blocks.** Monitor-mode policies generate no denial events. A correctly-configured enforce-mode policy where no user ever violated context also produces none. Such tenants stay in `MANUAL` -- we do not falsely claim `PASS` without hard evidence.
- **App-class filtering is conservative.** The `application_type` parameter on `ACCESS_DENY_EVENT` is not rigidly documented; events without an explicit type are counted for both OIDC and SAML rather than dropped.

## Remediation paths

| Outcome | What to do |
|---|---|
| `NOT_APPLICABLE` | No action needed. If you know SAML/OIDC apps are configured but the check did not see them, increase the Reports API lookback window or trigger a sign-in to refresh activity. |
| `MANUAL` | Confirm the policy is assigned. For OIDC: **Admin console > Security > Access and data control > Context-Aware Access** -- assign access levels to OAuth/OIDC third-party apps. For SAML: **Admin console > Security > Context-Aware Access > General settings** -- enable the default CAA policy for all SAML apps (this is the new toggle that ADD-40 audits). |
| `PASS` | CAA is enforcing. Review the denial events themselves in the Admin console's CAA log to confirm the denied attempts match your policy intent. |

## Required scopes

Both checks rely on data already collected by the default DWD scopes:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly` -- powers `applicationName=token`, `applicationName=login`, **and** the new `applicationName=context_aware_access` stream

No additional DWD scope authorization is required to enable these checks.

## Forward compatibility

If Google later publishes a Policy API surface for either CAA toggle, both checks will pick it up automatically. The implementation already includes a forward-compatible probe slot in `Provider._SKU_EDITION_MAP`'s sibling `REQUIRED_SETTINGS["security"]` list; populating it requires one string change and a tiny extraction tweak in `provider.py`. Until that day, the log-driven approach is the most accurate signal available.

## Related

- [Posture Score](Posture-Score) -- how `NOT_APPLICABLE` results are excluded from the score
- [Check Reference](Check-Reference) -- complete list of all 200 checks
- [Critical Checks](Critical-Checks) -- the 24 critical-severity checks (ADD-20 and ADD-40 are MEDIUM)
