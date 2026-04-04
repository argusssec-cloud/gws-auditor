# Changelog

All notable changes to GWS Security Auditor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/argusssec-cloud/gws-auditor/releases/tag/v1.0.0
