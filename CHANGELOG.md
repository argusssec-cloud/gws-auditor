# Changelog

All notable changes to GWS Security Auditor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-08-03

### Added

- **Drive trust-rule awareness** -- Drive trust rules (Admin console > Drive and Docs > Trust rules) are not exposed by any read API, so a new `options.trust_rules_file` config key points at a JSON export of them. `Provider` loads the file on live runs and on `--cached` re-scoring alike, exposing it as `data["policies"]["drive"]["trust_rules"]`. **CIS-3.1.2.1.1.1** (warn on external sharing) and **CIS-3.1.2.1.1.2** (public publishing) resolve active rules per-OU by `orgUnitId` (with or without the `id:` prefix) for the `DRIVE_SHARE_TRUST` trigger: a `BLOCK_SHARE` action clears the OU outright, while `ALLOW_SHARE` / `ALLOW_SHARE_WITH_WARNING` downgrades the result to MANUAL review naming the rules, instead of a blanket FAIL. Inactive rules and rules for other triggers or other OUs are ignored.
- **Intentional external-sharing OUs downgrade FAIL to `PARTIAL`** -- Tenants routinely carve out an OU whose purpose is sharing with outside parties. `options.external_sharing_ous` (OU paths or fnmatch patterns) marks them; with no configuration a built-in pattern set applies (`*External*`, `*Contractors*`, `*Vendors*`, `*Third*Part*`, ...). When every remaining violation in a Drive sharing check sits in such an OU the result is `PARTIAL` rather than `FAIL`, and the exempt OUs stay visible in the details either way. An explicit trust rule takes precedence over the naming convention, since a rule is a deliberate control and the OU name is only a heuristic. This wires up `evaluate_ous()` and `is_external_sharing_ou()`, which shipped unused in 1.3.0.
- **`format_ou_values_readable()`** -- Renders per-OU findings as `"/Sales → Enabled"` lines, with booleans humanized to Enabled/Disabled, `None` to "Not set", and an optional value humanizer for enums and ACL roles.

### Changed

- **Human-readable actual/expected values across the board** -- 127 OU failure lists now render through `format_ou_values_readable()` instead of dumping raw dicts into the report, and roughly 400 `expected_value` literals moved from bare `True`/`False` to phrases such as `"Enabled for all OUs"` / `"Disabled for all OUs"`. Calendar sharing enums and ACL roles additionally pass through a `_humanize_sharing_level()` map (`EXTERNAL_FREE_BUSY_ONLY` becomes "Free/busy information only", `freeBusyReader` becomes "Can see only free/busy").
- **`PARTIAL` now participates in the posture score** -- 1.3.0 gave PARTIAL half credit in `AuditSummary.pass_rate` but `scoring.py` skipped the status entirely, so the two numbers disagreed on any tenant with a partial result. PARTIAL is now a half-failure exactly like WARN, and appears in the per-tier breakdown.
- **`PARTIAL` surfaced everywhere else it was missing** -- HTML report summary card, filter button, legend, proportion bars, stacked-bar and donut charts, per-section stats and sort order; dashboard status colors, section badges, inventory badges and the standalone HTML export; the console result colors; and the AI analyst (status enum, per-framework and per-section counters, remediation ordering between FAIL and WARN, and the FAIL/PARTIAL/WARN CSV export).
- **CIS-1.1.2 (super admin maximum) now FAILs at 4 or more accounts** -- previously WARN, and the pass boundary moved from `<= 4` to `< 4`. Remediation now links the admin-roles console page directly.
- **Admin console deep links re-verified against the live console (2026-06)** -- the modern console serves per-app settings under customer-specific `/ac/managedsettings/<nodeId>` paths that cannot be hardcoded for a multi-tenant tool, so Calendar, Drive, Chat, Meet and Sites now point at `/ac/appslist/core` (one click from the specific app). Gmail (`/usersettings`), Marketplace, Authentication (`/ac/security/2sv`), Reporting (`/ac/reporting/home`), Alert Center (`/ac/ac`), Gemini (`/ac/ai/home`) and Classroom (`/ac/appslist/additional`) were corrected.
- **`--cached` takes a file, not a directory** -- metavar and help updated. Auth config validation is skipped in cached mode since no API calls are made, so a cache can be re-scored without credentials on the machine. `Provider.from_cache()` accepts the config so trust rules load on cached runs too.
- **AI Directory section agent benchmark text corrected** -- `BENCHMARK_REQUIREMENTS` described the wrong controls for CIS-1.1.1 and CIS-1.1.2 (1.1.2 was labelled as 2SV enforcement); both now match what the checks assert.
- **HTML report modal drops the Org Unit row** -- per-OU detail now lives inline in Actual Value.

### Fixed

- **`is_external_sharing_ou()` never saw tenant configuration** -- it read `data["config"]["options"]["external_sharing_ous"]`, but the orchestrator injects options as `data["_options"]` and nothing ever set `data["config"]`, so user-configured exception OUs were silently ignored and only the built-in patterns applied. It now reads `_options` first and falls back to the old path. `external_sharing_ous` was also missing from `DEFAULT_CONFIG`; both it and `trust_rules_file` are now documented in `config.yaml.sample`.

## [1.3.0] - 2026-05-24

### Added

- **`PARTIAL` check status** -- New status for controls that are partly compliant (e.g., 2SV policy enforced at every OU but a small slice of users not yet enrolled). `PARTIAL` contributes half-credit to the pass rate numerator (`PASS=1, PARTIAL=0.5, FAIL/WARN=0`). `AuditSummary` tracks it as a dedicated counter, and the HTML report renders an orange badge in both light and dark themes.
- **`make_partial()` helper** -- Builder function paralleling `make_pass`, `make_fail`, etc., for checks that need to express partial compliance across OUs or user populations.
- **`evaluate_ous()` utility** -- Partitions per-OU policy entries into safe / unsafe / exception / default buckets using a caller-supplied predicate. Supports external-sharing exception OUs via `is_external_sharing_ou()` (configurable patterns in `config.options.external_sharing_ous`). Ready for adoption across checks.
- **`is_admin_configured()` / `is_external_sharing_ou()` helpers** -- `is_admin_configured()` is the inverse of `is_default_policy()`. `is_external_sharing_ou()` identifies intentional exception OUs by name patterns (e.g. `*External*`, `*Contractors*`, `*Vendors*`), with tenant-level overrides.
- **DKIM multi-selector probing** -- `DNSClient.check_dkim()` now tries 11 common selectors (`google`, `google2025`, `selector1`, `selector2`, `default`, `k1`, `mail`, `s1`, `s2`, etc.) when no explicit selector is given. The first match with `p=` wins. Response includes `selectors_tried` for auditability.
- **DMARC organisational-domain fallback** -- `DNSClient.check_dmarc()` walks up the domain hierarchy per RFC 7489 §6.6.3 when no record exists at the queried FQDN. Reports `inherited_from` (the parent domain whose record matched) and `subdomain_policy` (the `sp=` tag, defaulting to `p=` per the RFC).
- **`tier_keys_present` in subscription info** -- `_get_subscription_info()` now returns all distinct license tier keys found across SKU assignments, enabling mixed-edition tenant handling.
- **Provider mapping improvements**:
  - Gmail content-compliance rules exposed as `content_compliance_rules` for DLP checks.
  - Inbound gateway detection handles explicit empty IP allowlists (no gateway) vs populated lists (gateway configured).
  - Drive external-file warning (`highlightingEnabled`) mapped to `sharing_settings.out_of_domain_warning_enabled`.
  - Drive SDK state also exposed as `features.add_ons_enabled`.
  - Data processing region (`limitToStorageRegion`) mapped to `security.data_regions.processing_in_region`.
  - Groups: `ownersCanAllowIncomingMailFromPublic`, `ownersCanHideGroups`, `newGroupsAreHidden`, and `viewTopicsDefaultAccessLevel` mapped and normalized.

### Changed

- **`admin_only=True` on all OU-aware checks** -- Every `get_ou_values()` call across calendar, chat, drive, gmail, groups, meet, CISA, and additional checks now passes `admin_only=True`, filtering out SYSTEM/DEFAULT policy entries. Eliminates false positives from unset defaults that previously appeared as violations.
- **DMARC strict alignment downgraded to WARN** -- `GWS.GMAIL.4.3` now returns WARN instead of FAIL. Relaxed alignment is the RFC 7489 default and remains protocol-compliant; strict alignment is a hardening recommendation, not a compliance failure.
- **`make_manual` → `make_review` for API-unexposed settings** -- 9 checks that returned `MANUAL` with generic "Could not determine…" messages now provide specific explanations (e.g., "Security Sandbox status is not exposed by the Cloud Identity Policy API — verify in Admin console"). Affected checks: ADD-02 (Security Sandbox), ADD-09 (Takeout), ADD-12 (Gmail DLP), CIS-4.2.2.1 (geo-blocking), CIS-4.2.3.1 (Drive DLP), GWS.COMMONCONTROLS.7.1 (conflicting accounts), GWS.COMMONCONTROLS.15.2 (data processing region), GWS.COMMONCONTROLS.18.2 (Chat DLP), GWS.COMMONCONTROLS.18.4 (DLP block external), GWS.DRIVEDOCS.1.9 (OOD warnings), GWS.DRIVEDOCS.5.1 (Drive Add-Ons), GWS.MEET.6.2 (auto-transcription).
- **Shared Drive checks require `business_standard`** -- Three Shared Drive checks (CIS-3.1.2.3.1 manager override, CIS-3.1.2.3.2 member access, CIS-3.1.2.3.3 viewer restrictions) changed `requires_license` from `business_starter` to `business_standard`, matching actual feature availability.
- **Mixed-edition license detection** -- `_check_license_sufficient()` now uses `tier_keys_present` to handle tenants with multiple SKU tiers. If ANY assigned SKU meets the check's requirement, the check runs. Unknown SKUs in mixed-tier environments are treated as ambiguous (check runs rather than skipping).
- **Groups external access reworked** -- `GWS.GROUPS.1.1` now handles the real Policy API shape: `collaborationCapability` as the master toggle with `ownersCanAllowExternalMembers` as a refinement, plus legacy field fallback.
- **MX record handling updated** -- `ADD-03` now handles both the new `{"mx": {"records": [...], "uses_google": bool}}` shape and the legacy flat list, trusting the `uses_google` flag when present.
- **2SV check uses PARTIAL** -- `CIS-4.1.1.3` returns `PARTIAL` instead of `FAIL` when 2SV policy is enforced at every OU but <20% of users haven't enrolled yet (grace-period users, new hires).

### Fixed

- **Boolean logic false positives** -- Several OU-aware checks tested `if value is not False` (which treats `None` as unsafe). Changed to `if value is True` in: POP/IMAP access (`CIS-3.1.3.6.1`), spam bypass for internal senders (`GWS.GMAIL.18.3`), groups external posting (`GWS.GROUPS.4.1`), and groups directory hiding (`GWS.GROUPS.4.2`).

## [1.2.0] - 2026-05-17

### Added

- **ADD-40 -- Default Context-Aware Access policy for SAML apps** -- Audits the new Google Workspace control (announced 2026-05-15) that lets admins apply a single global CAA policy to all SAML applications. No Workspace policy API exposes the toggle, so the check uses a three-state log-driven decision tree: count SAML logins in `login_logs` (zero → `NOT_APPLICABLE`), then check `caa_events` for `ACCESS_DENY_EVENT` entries (any → `PASS`), else `MANUAL` with the SAML app inventory in the details. `requires_license="enterprise_standard"`. Total check count: 199 → **200**.
- **`caa_events` data stream** -- New Reports API collector for `applicationName=context_aware_access` (`ACCESS_DENY_EVENT`). `ReportsClient.get_caa_activities()` is rate-limit-aware and reuses the existing pagination helper. Wired into `Provider.collect_all()` and normalized through `_normalize_activity_logs`. Available to all checks as `data["caa_events"]`.
- **Action metadata on every check result** -- `CheckResult` and `CheckMetadata` gain `docs_url`, `console_link`, and `gam_command` fields. The `@check` decorator auto-resolves `docs_url` by scanning remediation text for Google documentation URLs (`support.google.com`, `cloud.google.com`, `developers.google.com`, `workspace.google.com`) and `console_link` from the new `CONSOLE_SECTION_LINKS` mapping. Reports, dashboard, and AI analyst surfaces can now offer "Open in Admin console" deep links and "Fix with GAM" command snippets without per-check boilerplate.
- **`CONSOLE_SECTION_LINKS`** -- Default Admin Console deep links per check section (Directory, Gmail, Drive, Chat, Security, ...) in `constants.py`. Used by `@check` when no explicit `console_link` is set on the decorator.

### Changed

- **ADD-20 (CAA for OIDC apps) rebuilt with log-driven logic** -- Previously always returned `MANUAL` because no API exposes the OIDC CAA toggle. Now follows the same three-state pattern as ADD-40: third-party OIDC clients in `token_logs` → `NOT_APPLICABLE` when none, `PASS` when CAA `ACCESS_DENY_EVENT` denials match OIDC traffic, `MANUAL` when apps exist but no denials were seen in the window. Third-party detection excludes Google first-party app names (`"Google "` prefix) to keep the inventory honest.

### Fixed

- **Workspace SKU map had multiple swapped entries** -- Continuing the v1.1.0 correction, the SKU map in `Provider._SKU_EDITION_MAP` still mislabeled six SKUs that no longer matched Google's authoritative [Admin SDK Licensing reference](https://developers.google.com/workspace/admin/licensing/v1/how-tos/products). Notably `1010020026` was labeled "Enterprise Essentials" instead of **Enterprise Standard**, `1010020025` was labeled "Enterprise Plus" instead of **Business Plus**, and `1010020020` was labeled "Business Plus" instead of **Enterprise Plus**. On a real Enterprise Standard tenant this caused 22 license-gated checks to incorrectly emit `NOT_APPLICABLE`. The map is now aligned with Google's reference (cross-checked 2026-05-17), adds Frontline Plus (`1010020034`), Enterprise Essentials Plus (`1010060005`), and Business Continuity SKUs (`1010020035/36`), and corrects Cloud Identity Free to `1010010001`. Subscription tests rewritten to use the correct SKU IDs.

## [1.1.0] - 2026-04-24

### Added (continued)

- **Agent mode** (`gws-auditor agent`) -- Runs the full audit and pushes the JSON report to ArgusSec Console via API. Supports `--console-url` (default: `https://console.argussec.io`), `--api-key`, env vars (`ARGUSSEC_CONSOLE_URL`, `ARGUSSEC_API_KEY`), and `agent.*` config keys. Inherits all audit flags (credentials, check filtering, output). Exit codes: 0 (all pass), 1 (failures), 2 (critical failures).
- **`JSONReporter.to_dict()`** -- Public method to get the serialized report as a dict without writing to disk.

### Security Fixes

- **XSS hardening in HTML reports** -- `_tojson_safe` now escapes `</script>` and `<!--` sequences before embedding JSON in `<script>` blocks (defense-in-depth). Added `escAttr()` function for attribute-context escaping in dynamic CSS class names across 4 innerHTML injection points.
- **OAuth token file permissions** -- Token cache file is now created with `0o600` (owner-only) permissions via `os.open()` instead of the default umask, preventing other local users from reading the refresh token.
- **Path traversal guard** -- `ReportStore.load_report()` now rejects filenames containing `..`, `/`, or `\`, hardening the dashboard and AI analyst against crafted report filenames.
- **SSL verification warning** -- `--disable-ssl-verification` now prints a prominent red warning to stderr explaining MITM risks. The flag still works but the risk is clearly communicated.
- **AI tool argument validation** -- Tool dispatcher validates tool names against an allowlist, clamps integer arguments to safe ranges, and validates filenames for path traversal before execution.
- **Exception tracebacks preserved** -- All `logger.error()` calls inside exception handlers (9 instances across 7 files) replaced with `logger.exception()` to capture full stack traces for debugging.

### Added

- **Posture Score** -- New 0-100 severity-weighted security score. Critical findings are squared (weight 64 vs 8) so they dominate the score. WARN counts as 0.5x penalty. Inventory checks are excluded (`scored=False`). Muting a finding via dashboard overrides improves the score. Appears in CLI output, JSON/HTML/CSV reports, dashboard, and AI analyst. Grade thresholds: A (90+), B (80+), C (70+), D (50+), F (<50).
- **Version check and auto-update** -- Tool checks PyPI for newer versions at startup (3s timeout, non-blocking). Prompts to update on interactive TTY sessions. `--update` flag performs update and exits. `--skip-update-check` suppresses the check. Skipped automatically in CI/non-TTY and PyInstaller frozen builds.
- **Argus Cloud banner** -- Brief informational message about the hosted cloud version shown at startup on interactive sessions. Suppressed by `--quiet`, `--no-cloud-info`, or `GWS_AUDITOR_NO_CLOUD_INFO=1` env var. Auto-suppressed in CI/non-TTY.
- **GCE attached service account auth** (`--auth-method gce`) -- Keyless authentication using the VM's metadata server when running on Google Compute Engine. No service account key file needed.
- **Workload Identity Federation auth** (`--auth-method workload_identity`) -- Keyless authentication from external environments (GitHub Actions, AWS, Azure) via `GOOGLE_APPLICATION_CREDENTIALS`. Google's recommended method for CI/CD.

### Fixed

- **Hardcoded date in API probe** -- Usage Reports API probe used a hardcoded `"2026-02-23"` date instead of computing a dynamic recent date. The `recent_date` variable was dead code. Fixed by computing the date dynamically at call time.
- **Config dict mutation** -- `orchestrator._authenticate()` mutated the shared config dict with the resolved customer ID. Now stores it on `self._resolved_customer_id` as well for internal use while still writing to config for Provider compatibility.
- **Cached mode customer_id** -- `run_cached()` now extracts the customer ID from cached data so reports show the real org ID instead of `"my_customer"`.
- **Pass rate denominator** -- `AuditSummary.pass_rate` now includes WARN (soft failures) in the denominator: `passed / (passed + failed + warnings)`. Previously excluded warnings, inflating the pass rate.
- **Severity enum consistency** -- `CheckResult.severity` and `CheckMetadata.severity` changed from `str` to `Severity` enum. Eliminated dual `r.severity == "CRITICAL" or r.severity == Severity.CRITICAL` comparisons throughout the codebase.
- **`--validate` now pinpoints missing DWD scopes** -- The previous "OAuth Scopes" check only verified what the Python SDK requested, not what was authorized in Admin Console. Replaced with a per-scope token-refresh probe: each required scope is exchanged individually so missing scopes are listed by name with the service account's client ID. Distinguishes three failure modes: client ID not registered for DWD at all, subject not super-admin, and specific scopes missing from a partial grant. Redundant `unauthorized_client` errors from per-API probes are suppressed when scopes were already pinpointed.
- **Subscription detection misidentified Enterprise tenants as Frontline** -- The SKU mapping table had several wrong entries (`1010020027` was labelled "Enterprise Starter" instead of Enterprise Standard, `1010020026` was labelled "Frontline Standard" instead of Enterprise Essentials, etc.) and the missing `1010310005` (real Frontline Standard SKU). Detection also used `maxResults=1`, so a single arbitrary user's license decided the whole tenant's edition. Fixed by correcting the table, paginating across all license assignments for both `Google-Apps` and `Google-Apps-For-Education` products, and selecting the highest-tier SKU as the primary edition. Reports now expose a per-SKU breakdown with assignment counts.
- **Pre-existing test bug** -- Fixed `test_session.py` tests that checked `in result` against the full `(text, input_tokens, output_tokens)` tuple instead of unpacking.

### Changed

- **180-day lookback centralized** -- Usage report lookback constant moved from `reports.py` to `constants.py` as `DEFAULT_USAGE_REPORT_LOOKBACK_DAYS` alongside other lookback constants.
- **Per-client rate bucket documented** -- `BaseAPIClient` docstring now explains that each client has its own token bucket and concurrent clients multiply effective QPS.

### Documentation

- **Posture Score wiki page** -- Full formula with worked examples, grade thresholds, improvement guidance, and explanation of where the score appears.
- **Keyless Authentication wiki page** -- Complete setup guides for GCE attached service accounts and Workload Identity Federation (GitHub Actions and AWS), with security benefits and auth method comparison.
- **Minimal GCP Permissions wiki page** -- Exact IAM permissions for enterprise role separation, custom role creation commands, and API enablement reference.
- **Advanced Auth Methods wiki page** -- Documents DASA limitation (Cloud Identity Policy API incompatible) and YubiKey hardware key protection as future possibilities.
- **Argus Cloud wiki page** -- Full open-source vs cloud feature comparison table, pricing, and banner suppression instructions.
- **README updates** -- Added Argus Cloud section with feature comparison table, Posture Score section with grade reference, HTML report screenshot, and new CLI flags in reference.
- **CLAUDE.md rewrite** -- Reduced from ~650 to 151 lines (77% smaller) by removing content derivable from code.

## [1.0.0] - 2026-04-04

### Added

- **199 security checks** across 4 frameworks:
  - CIS Google Workspace Foundations Benchmark v1.3.0 (84 checks)
  - CISA SCuBA Baselines for Google Workspace (82 checks)
  - Google Security Checklist for Medium & Large Businesses (20 checks)
  - Additional best-practice checks (13 checks)
- **24 critical-severity checks** with business impact explanations
- **License-aware gating** -- checks auto-skip on unsupported editions (Business Starter through Enterprise Plus)
- **Interactive setup wizard** (`gws-auditor setup`) automating GCP project, API enablement, service account creation, and DWD scope guidance
- **Multi-credential profiles** -- switch between tenants with `--profile`
- **Customer ID auto-discovery** using narrow-scope credentials for reliability
- **Google Workspace edition detection** via the Licensing API (SKU-to-edition mapping)
- **Data collection** from 11 Google APIs: Admin SDK Directory, Reports, Gmail, Calendar, Drive, Groups Settings, Cloud Identity (policies + devices), Chrome Policy, Chat Admin, Alert Center, License Manager
- **21 delegated OAuth scopes** covering all API endpoints
- **Inventory checks** (ADD-28 through ADD-39): stale devices, inactive Chat spaces with owner resolution, dangerous OAuth apps, app-specific passwords, shared drive restrictions, endpoint verification devices, pending device approval
- **DNS checks** for SPF, DKIM, DMARC, and MX records across all domains
- **Per-OU policy evaluation** with deduplication of admin vs system-default entries
- **Output formats**: HTML report with interactive JS, JSON with severity fields, CSV with remediation columns
- **CI/CD integration** with `--fail-on-critical` (exit code 2)
- **Interactive dashboard** (Plotly Dash) with overview, compliance, inventory, and AI analyst pages; light/dark mode toggle
- **AI security analyst** with 13 LLM-invoked tools:
  - `get_audit_summary`, `search_findings`, `get_check_details`
  - `get_compliance_by_framework`, `get_compliance_by_section`
  - `get_remediation_plan`, `get_smart_remediation` (grouped by theme with effort estimates)
  - `compare_reports`, `list_available_reports`, `get_trend_analysis`
  - `query_inventory_data`, `get_knowledge_base_url`, `export_findings_csv`
- **Slash commands** for the analyst REPL: `/critical`, `/summary`, `/remediate`, `/compare`, `/inventory`, `/search`, `/trends`, `/export md`, `/export csv`
- **3 LLM providers**: OpenAI, Anthropic (Claude), AWS Bedrock
- **582 documentation links** to `knowledge.workspace.google.com` in check remediation text
- **16 remediation theme groups** for smart grouping (Email Authentication, MFA, External Sharing, DLP, etc.)
- **Standalone executables** via PyInstaller for Linux and Windows
- **Docker support** with Dockerfile and docker-compose.yml
- **GitHub Actions workflow** for automated release builds

[1.3.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.3.0
[1.2.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.2.0
[1.1.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.0.0
