# Context-Aware Access Checks

GWS Security Auditor ships six checks that audit your Context-Aware Access (CAA) coverage:

- **ADD-20** -- Ensure Context-Aware Access is applied to OIDC apps
- **ADD-40** -- Ensure default Context-Aware Access policy is enabled for SAML applications *(new in v1.2.0)*
- **ADD-53** -- Ensure the Admin console is protected by a Context-Aware Access level *(unscored: Google supports it but advises against it unless needed)*
- **ADD-54** -- Ensure a device-based Context-Aware Access level is enforced
- **ADD-55** -- Review Context-Aware Access levels that are not assigned to any app *(unscored)*
- **ADD-56** -- Review Context-Aware Access denials *(unscored)*

All six, together with GWS.COMMONCONTROLS.2.1 (CAA implemented) and CIS-4.2.2.1 (geo-blocking), which use the same evidence, live under the **Security** section and are gated to the editions Google lists for Context-Aware Access (`EDITIONS_CAA` in `constants.py`: Frontline Standard and Plus, Enterprise Standard and Plus, Education Standard and Plus, Enterprise Essentials Plus). Other editions get NOT_APPLICABLE. This page describes ADD-20 and ADD-40 in detail; the four posture checks are summarised in [Posture checks](#posture-checks-add-53-to-add-56).

## Background

Context-Aware Access lets Workspace admins gate access to apps by device posture, location, IP, and other contextual signals. SAML and OIDC apps require an explicit per-app assignment to be covered by a CAA policy. Google's [May 2026 update](https://workspaceupdates.googleblog.com/2026/05/default-CAA-for-SAML.html) added a global default CAA policy for *all* SAML apps -- a single org-wide switch that catches any SAML app without a specific assignment. The toggle ships **off** by default.

Neither the SAML default toggle nor the OIDC per-app coverage is exposed by any public Workspace policy API. We verified this against a live tenant: 10 plausible prefixes on the Cloud Identity Policy API (`v1` and `v1beta1`) all return zero results, and Access Context Manager holds the access levels themselves (which the auditor reads when granted) but not the per-app Workspace assignments.

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

Look for proof that CAA is actively enforced for the relevant apps.

- Data source: `data["caa_events"]` (`applicationName=context_aware_access`). The Reports API appendix documents only `ACCESS_DENY_EVENT`; live tenants also log `ACCESS_LEVELS_EVALUATED` for every **allowed** access ("Access Evaluated" in the Admin console). Both carry `CAA_ACCESS_LEVEL_APPLIED` / `_SATISFIED` / `_UNSATISFIED` (level titles) and `CAA_APPLICATION`.
- Filter: an active-mode evaluation (allowed or denied) whose `CAA_APPLICATION` names one of the detected apps. An evaluation for Gmail or Drive says nothing about a third-party app, and event names containing `MONITOR` are monitor mode and never count.

If any matching evaluation exists, the check returns `PASS`.

### Step 2b -- Configuration evidence

Without an evaluation, the admin audit log decides where it can: `TOGGLE_CAA_ENABLEMENT` off, or `CHANGE_CAA_APP_ASSIGNMENTS` (one event per app and mode: `MODE` BLOCK / WARN / ACTIVE enforce, MONITOR does not; `CAA_ACCESS_ASSIGNMENTS_NEW` lists the levels, `_OLD` alone means removed) give `FAIL` or `PASS`. When the [Access Context Manager inventory](Configuration#context-aware-access-levels-from-access-context-manager) is collected and the organisation has **no access level at all**, both checks `FAIL`: nothing can be assigned.

### Step 3 -- Inconclusive

Apps exist, but no evaluation names them and the admin log holds no decisive change. The check returns `MANUAL` (REVIEW) with the app inventory in the details. Assignments made before the 180-day window are invisible to the auditor, and no API exposes per-app Workspace assignments.

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
            │ active-mode evaluation│
            │ naming a detected app │
            └──────────┬────────────┘
                       │
                ┌──────┴──────┐
                │             │
              count > 0     count == 0
                │             │
                ▼             ▼
              PASS      Step 2b: admin log
                        (assignments, toggle,
                         level inventory)
                              │
                              ▼
                      PASS / FAIL / MANUAL
                      (with app inventory)
```

## Example outputs

### ADD-20 -- third-party OIDC apps detected, no denials

```
ADD-20  status=MANUAL
  9 third-party OIDC app(s) detected (AI Directories, ArgusSec,
  Email deliverability tracker, Hunter, ...) but no active-mode CAA
  evaluation names them and no access-level assignment change for
  them was logged in the admin-log window. Verify the assignment in
  Admin console > Security > Access and data control >
  Context-Aware Access.
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
  CAA is actively enforcing on SAML traffic: 3 active-mode
  evaluation(s) in the window name 2 of the detected SAML app(s).
```

## Caveats

These caveats are documented inside each check's own output so a reviewer sees them in context:

- **"Detected" means used in the Reports API retention window** (~30 days). An app that is configured but never used during the lookback period is invisible. A tenant with provisioned-but-dormant SAML apps may falsely appear as `NOT_APPLICABLE`.
- **A PASS needs an evaluation or an assignment in the window.** Allowed evaluations (`ACCESS_LEVELS_EVALUATED`) are logged for every access to an app under an active-mode policy, so a used app produces evidence quickly. Monitor-mode policies log `MONITOR_MODE_ACCESS_EVALUATED_EVENT`, which never counts. A policy assigned before the 180-day admin-log window whose app nobody used inside the CAA log window stays `MANUAL` -- we do not claim `PASS` without hard evidence.
- **App matching is by name.** An evaluation counts only when its `CAA_APPLICATION` names a detected app. An evaluation for Gmail or Drive says nothing about a third-party OIDC or SAML app and is ignored.

## Remediation paths

| Outcome | What to do |
|---|---|
| `NOT_APPLICABLE` | No action needed. If you know SAML/OIDC apps are configured but the check did not see them, increase the Reports API lookback window or trigger a sign-in to refresh activity. |
| `MANUAL` | Confirm the policy is assigned. For OIDC: **Admin console > Security > Access and data control > Context-Aware Access** -- assign access levels to OAuth/OIDC third-party apps. For SAML: **Admin console > Security > Context-Aware Access > General settings** -- enable the default CAA policy for all SAML apps (this is the new toggle that ADD-40 audits). |
| `PASS` | CAA is enforcing. Review the evaluations and denials in the Admin console's Context-Aware Access log (and ADD-56) to confirm they match your policy intent. |

## Posture checks (ADD-53 to ADD-56)

These four checks combine three sources: the access-level inventory from Access Context Manager (`data["access_context"]`, see [Configuration](Configuration#context-aware-access-levels-from-access-context-manager)), the per-app assignment events in the admin audit log (`CHANGE_CAA_APP_ASSIGNMENTS`), and the evaluations in the CAA user log (`ACCESS_LEVELS_EVALUATED`, `ACCESS_DENY_EVENT`). The inventory alone never produces a PASS, because no API exposes which Workspace apps a level is assigned to; it does produce a FAIL when it shows that the required kind of level does not exist.

| Check | PASS when | FAIL when | MANUAL when |
|---|---|---|---|
| ADD-53 Admin console (unscored) | An active-mode evaluation names the Admin console app, or the latest assignment for it uses the Block action | CAA switched off; the Admin console assignment was removed or left in monitor mode; Access Context Manager lists no level at all | Assignment uses the Warn action only; or levels exist but no Admin console assignment or evaluation is in the log window |
| ADD-54 device-based level | A level with device conditions (screen lock, encryption, OS, company-owned, admin approval) is applied in an evaluation or assigned with the Block action | CAA switched off; Access Context Manager shows that no level requires device posture | A device-based level exists but is unassigned, Warn-only or monitor-only; or the inventory is not readable |
| ADD-55 unassigned levels (unscored) | Every known level appears in an assignment or an evaluation | never | Some level never appears, or a level has no condition at all (always satisfied) |
| ADD-56 denials (unscored) | Evaluations exist and none was denied | never | Denials exist: counts per app, user, region and unsatisfied level, with denied super admins called out |

The Warn action "allows access to the app and sends the user a warning notification" (Google's help article), so a Warn-only assignment counts as an implemented policy for GWS.COMMONCONTROLS.2.1, ADD-20 and ADD-40 but never as blocking for CIS-4.2.2.1, ADD-53 and ADD-54. Several active levels on one app are OR'd: a user who satisfies any one of them gets in.

ADD-54 also reports how many evaluations carried device signals (`CAA_DEVICE_STATE`). A device-based level whose evaluations all say "No Device Signals" means Endpoint Verification or device management is not deployed, so the level cannot be satisfied. ADD-55 and ADD-56 return NOT_APPLICABLE when there is nothing to review (no level known, or no evaluation in the window).

## Required scopes

The checks rely on data already collected by the default DWD scopes:

- `https://www.googleapis.com/auth/admin.reports.audit.readonly` -- powers `applicationName=token`, `applicationName=login`, **and** the new `applicationName=context_aware_access` stream

No additional DWD scope authorization is required to enable these checks.

## Forward compatibility

The access levels themselves are already read from Access Context Manager when the service account holds `roles/accesscontextmanager.policyReader`. If Google later exposes per-app Workspace assignments or the SAML default toggle through an API, the checks should read that ahead of the log inference. Until then, the log-driven approach is the most accurate signal available.

## Related

- [Posture Score](Posture-Score) -- how `NOT_APPLICABLE` results are excluded from the score
- [Check Reference](Check-Reference) -- complete list of all 288 checks
- [Critical Checks](Critical-Checks) -- the 24 critical-severity checks (ADD-20 and ADD-40 are MEDIUM)
