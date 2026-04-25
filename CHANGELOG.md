# Changelog

All notable changes to GWS Security Auditor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.1.0
[1.0.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.0.0
