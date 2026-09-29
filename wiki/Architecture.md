# Architecture

How an audit runs, where each piece lives, and the design rules the checks follow. For the step-by-step guide to adding a check see [Contributing](https://github.com/argusssec-cloud/gws-auditor/blob/main/CONTRIBUTING.md).

## The pipeline

```
 config.yaml + CLI flags
          |
          v
   +-------------+     +------------+     +-------------+     +-----------+
   | Authenticate| --> |  Collect   | --> |  Evaluate   | --> |  Report   |
   |   auth.py   |     | provider.py|     |  checks/    |     | reporter/ |
   +-------------+     +------------+     +-------------+     +-----------+
                             |                   |                  |
                        cache/*.json      CheckResult list    reports/audit_<ts>
                                                 |            .json .csv .html
                                                 v
                                          scoring.py (posture score)
```

`orchestrator.py` drives the four steps. The important property is the boundary in the middle: **collection is the only stage that talks to Google, and evaluation is a pure function of the collected data.** Every check has the signature `check(data: dict) -> CheckResult` and performs no I/O. That is what makes `--cached` re-scoring, unit tests without credentials, and reproducible results possible.

### 1. Authenticate (`auth.py`)

Service account with domain-wide delegation (impersonating an admin `subject`), OAuth, or keyless options (see [Keyless Authentication](Keyless-Authentication)). `--dry-run` and `--validate` stop after this stage and report which APIs and scopes work. The customer id is discovered automatically when set to `auto`.

### 2. Collect (`provider.py`, `api/`)

`Provider` calls one method per dataset, in the order listed in `Provider.COLLECTION_ENDPOINTS`: users, domains, org units, groups and their settings, group members, admin roles, Cloud Identity policies, Chrome policies, admin / login / token audit logs, Context-Aware Access events, usage reports, DNS records, Alert Center rules, Chat spaces, mobile / ChromeOS / endpoint devices, app passwords, OAuth tokens, Shared Drives and (opt-in) per-mailbox forwarding.

- **API clients** live in `api/`, one per Google API. They share `api/base.py`, which provides pagination, exponential backoff with jitter on HTTP 429 / 500 / 503 (capped at 60 s, `options.max_retries` attempts) and token-bucket rate limiting (`options.rate_limit_qps`). `api/dns.py` is the one client that does not talk to Google: it resolves SPF, DKIM, DMARC, MX, MTA-STS and TLS-RPT records.
- **A failed call never aborts the audit.** The error is recorded in `data["api_errors"]` and that dataset comes back empty. Checks that depend on it must notice and return ERROR rather than treat "empty" as "nothing to find".
- **Caching.** With `options.cache_data` (default on) the raw collected data is written to `cache/gws_data_<timestamp>.json` when collection finishes. `--cached <file>` skips authentication and collection entirely and re-evaluates a saved dataset -- useful after upgrading the auditor, for comparing check logic, and for offline analysis; it needs no credentials on the machine. Datasets added in a newer version are absent from older caches, and the checks that need them report ERROR or MANUAL until a fresh collection. The cache contains the same sensitive data as the tenant itself: protect it accordingly.
- **Normalization.** `normalize_data()` turns the raw API output into the shape checks consume: users get `snake_case` keys, audit-log entries are flattened to one entry per event with `event_name`, `time` and a `parameters` dict, and DNS results get uniform `record_found` flags.
- **Policies.** The Cloud Identity Policy API is queried per category (`api/policy.py`, `POLICY_CATEGORIES`). Each category keeps every raw per-OU policy under `_ou_policies`; `_map_*` functions in `provider.py` additionally derive a few convenience values for the root OU. `config.options` is injected as `data["_options"]` so checks can read thresholds.

### 3. Evaluate (`checks/`)

A check is a function decorated with `@check(...)`, which registers it with its id, title, level, framework source, section, severity, remediation text and optional licence requirement. `CheckRegistry` imports the modules listed in `CHECK_MODULES`, applies the `--check` / `--level` / `--source` / `--section` / `--exclude` filters, and runs what is left. An exception inside a check becomes an ERROR result for that check only.

Conventions that every check follows:

- **Per-OU evaluation.** `get_ou_values(category, setting_key, admin_only=False)` returns the policy value for every OU that has one, preferring admin-set values over Google defaults. A finding names the OUs that violate the control rather than reporting a single tenant-wide value.
- **Real field names only.** Checks read fields the Policy API actually returns. `tests/fixtures/policy_api_shapes.json` catalogues them, and a test fails when a check looks up a known setting but references none of its real fields.
- **Unknown is MANUAL.** When a setting is not returned, or its state cannot be determined, the check returns MANUAL (`make_review`) or ERROR (`make_manual`, for data that could not be collected). It never defaults to PASS or FAIL.
- **Audit-log inference.** Some settings (Gemini access, Drive add-ons, multi-party approval, access approvals, external recipient warnings) are not exposed by any settings API, but changes to them are logged. `result_from_setting_changes()` reads the most recent change per OU from `admin_logs`. No event inside the log window means unknown, hence MANUAL.
- **Licence gating.** `requires_license="enterprise_plus"` (and similar) makes the decorator return NOT_APPLICABLE on tiers that lack the feature. The tier is detected from licence assignments during collection, or set explicitly with `auth.subscription_type`; when it cannot be determined the check runs rather than being skipped.
- **Severity.** Set on the decorator, or resolved from `CRITICAL_CHECKS` / `HIGH_CHECKS` / `LOW_CHECKS` in `constants.py`; MEDIUM otherwise. Checks marked `scored=False` are informational inventory and do not affect the score.

Result statuses: PASS, FAIL, WARN, PARTIAL, ERROR, MANUAL, NOT_APPLICABLE -- defined in `models.py` and explained in the [Check Reference](Check-Reference).

### 4. Report (`reporter/`, `scoring.py`)

`scoring.py` computes the 0-100 posture score and grade from the scored results, weighting by severity (CRITICAL 8, HIGH 6, MEDIUM 3, LOW 2); see [Posture Score](Posture-Score). The reporters write `audit_<timestamp>.json`, `.csv` and `.html` (a self-contained page rendered from `reporter/templates/report.html.j2`) into `output.directory`. The JSON report is the interchange format: the [Dashboard](Dashboard) and the [AI Analyst](AI-Analyst) work from it, and it is the artifact to keep from [CI/CD](CICD-Integration) runs (`--fail-on-critical` sets exit code 2 when a CRITICAL check fails).

## Source layout

```
src/gws_auditor/
├── __main__.py        entry point; dispatches audit / dashboard / analyst / setup
├── cli.py             argparse definitions
├── config.py          config.yaml loading, DEFAULT_CONFIG, profiles
├── constants.py       scopes, rate limits, severity tables, remediation themes
├── auth.py            service account / OAuth / keyless auth, access validation
├── orchestrator.py    the pipeline: run, run_cached, dry_run, validate, run_single_check
├── provider.py        data collection, caching, normalize_data(), policy mapping
├── models.py          Status, Severity, CheckResult, CheckMetadata, AuditSummary
├── scoring.py         posture score
├── api/               one client per API; base.py = retry, rate limit, pagination
├── checks/            check modules
│   ├── base.py        @check, make_* helpers, get_ou_values, audit-log inference
│   └── registry.py    CHECK_MODULES, discovery, filtering, execution
├── reporter/          JSON, CSV, HTML
├── dashboard/         Plotly Dash UI (optional extra)
└── ai/                analyst: providers, tools, session, REPL (optional extra)
    └── agents/        developer utility: PydanticAI agents that review check quality
scripts/
└── generate_check_reference.py   writes docs/checks.md and wiki/Check-Reference.md
```

Check modules are organized by origin rather than by product: `directory.py`, `apps_*.py`, `security_*.py`, `reporting.py` and `rules.py` follow the CIS benchmark's structure; `cisa_scuba.py`, `cisa_commoncontrols.py`, `cisa_services.py` and `cisa_additions.py` hold CISA SCuBA controls; `additional.py` and `additional_identity.py` hold Google-checklist and best-practice checks (`ADD-*`). Where CIS and SCuBA describe the same control, it is implemented once (usually under the CIS id), which is why not every SCuBA id appears in the catalogue. The report's *section* (Gmail, Drive, Security, ...) comes from the decorator, not from the module.

## Optional components

The core package depends on the Google API client and auth libraries plus `dnspython`, `jinja2`, `pyyaml`, `rich`, `pydantic` and `PySocks` (proxy support). Everything else is an extra, imported lazily so that a missing extra produces an install hint instead of a traceback:

| Extra | Adds |
|-------|------|
| `dashboard` | [Dashboard](Dashboard) -- reads `reports/`, no Google access |
| `ai`, `ai-openai`, `ai-anthropic`, `ai-bedrock` | [AI Analyst](AI-Analyst) -- reads `reports/`, sends report data to the chosen LLM provider |
| `agents` | Developer-only check-quality review agents (not part of the CLI) |
| `build` | PyInstaller, for the [Standalone Build](Standalone-Build) |

## Trust boundaries

- **Google Workspace**: read operations only. The delegated scope list is in the [Setup Guide](Setup-Guide); a few scopes have no read-only variant.
- **Local files**: `credentials/` (service account key), `cache/` (raw tenant data) and `reports/` (findings) are all sensitive. None of them belongs in version control.
- **Network egress**: Google APIs, DNS lookups for your domains, a PyPI version check at startup (disable with `--skip-update-check`), and -- only if you start it -- the LLM provider used by the analyst. The Argus Cloud notice printed at startup is static text and makes no network request (`--no-cloud-info` hides it).
- **Dashboard**: no authentication; binds to localhost by default.

## Testing

`pytest` runs entirely offline. Check tests take the `full_audit_data` fixture (`tests/conftest.py`), override the fields they care about and assert on the returned `CheckResult`. Policy payloads are built with `tests.factories.make_ou_policy(category, setting_key, value, org_unit)` using real field names. Two guard tests keep documentation and code honest: `test_policy_field_names.py` (checks read real API fields) and `test_check_reference_docs.py` (the generated check reference matches the registry).
