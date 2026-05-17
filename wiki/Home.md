# GWS Security Auditor Wiki

Welcome to the GWS Security Auditor wiki. This tool audits Google Workspace tenants against 200 security checks from 4 industry frameworks.

## Pages

- **[Quick Start](Quick-Start)** -- Get auditing in 5 minutes
- **[Setup Guide](Setup-Guide)** -- Detailed setup with automated wizard and manual steps
- **[Configuration](Configuration)** -- config.yaml reference, profiles, and CLI options
- **[Check Reference](Check-Reference)** -- All 200 checks with severity levels
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
- **[Troubleshooting](Troubleshooting)** -- Common errors and solutions
- **[Architecture](Architecture)** -- Project structure and data flow
- **[Contributing](Contributing)** -- Adding checks, writing tests

## Frameworks

| Framework | Checks | Description |
|-----------|-------:|-------------|
| CIS | 84 | CIS Google Workspace Foundations Benchmark v1.3.0 |
| CISA | 82 | CISA SCuBA Baselines for Google Workspace |
| GOOGLE | 21 | Google Security Checklist for Medium & Large Businesses |
| OTHER | 13 | Additional best-practice checks |
| **Total** | **200** | |
