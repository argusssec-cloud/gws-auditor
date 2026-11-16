# GWS Security Auditor Wiki

Welcome to the GWS Security Auditor wiki. This tool audits Google Workspace tenants against 288 security checks from 4 industry frameworks.

## Pages

- **[Quick Start](Quick-Start)** -- Get auditing in 5 minutes
- **[Setup Guide](Setup-Guide)** -- Detailed setup with automated wizard and manual steps
- **[Configuration](Configuration)** -- config.yaml reference, profiles, and CLI options
- **[Check Reference](Check-Reference)** -- All 288 checks with level, framework, severity and licence notes (generated from the check registry)
- **[Context-Aware Access Checks](Context-Aware-Access)** -- ADD-20 (OIDC) and ADD-40 (SAML default) log-driven audit logic
- **[Critical Checks](Critical-Checks)** -- 24 critical-severity checks explained
- **[Posture Score](Posture-Score)** -- How the 0-100 posture score is computed, grades, and how to improve it
- **[Dashboard](Dashboard)** -- Interactive web UI with dark mode
- **[AI Analyst](AI-Analyst)** -- Natural language audit queries with 13 tools and slash commands
- **[CI/CD Integration](CICD-Integration)** -- Pipeline integration with `--fail-on-critical`
- **[Standalone Build](Standalone-Build)** -- Build single-file executables
- **[Keyless Authentication](Keyless-Authentication)** -- GCE attached SA and Workload Identity Federation (no key file)
- **[Minimal GCP Permissions](Minimal-GCP-Permissions)** -- Least-privilege IAM setup for enterprise environments
- **[Advanced Auth Methods](Advanced-Auth-Methods)** -- DASA and YubiKey (future)
- **[Argus Cloud](Argus-Cloud)** -- Hosted version with automated scans, team features, and compliance history
- **[Workspace Add-on](Workspace-Add-on)** -- Findings in Gmail, Drive and Sheets, and a Google Chat bot, from the Google Workspace Marketplace
- **[Troubleshooting](Troubleshooting)** -- Common errors and solutions
- **[Architecture](Architecture)** -- Project structure and data flow
- **[Contributing](https://github.com/argusssec-cloud/gws-auditor/blob/main/CONTRIBUTING.md)** -- Adding checks, writing tests, real Policy API field names, regenerating the check reference

## Frameworks

| Framework | Checks | Description |
|-----------|-------:|-------------|
| CIS | 86 | CIS Google Workspace Foundations Benchmark v1.4.1 |
| CISA | 138 | CISA SCuBA Secure Configuration Baselines for Google Workspace v1 |
| GOOGLE | 35 | Google Workspace Admin Help security recommendations (security checklists, administrator-account best practices, Gemini and data-protection guidance) |
| OTHER | 29 | Additional best-practice checks |
| **Total** | **288** | |
