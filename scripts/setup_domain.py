#!/usr/bin/env python3
# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Domain setup helper for GWS Security Auditor.

Automates the GCP-side setup required before running an audit against a new
Google Workspace domain:

  1. Creates (or reuses) a GCP project.
  2. Enables all APIs the auditor requires.
  3. Creates a service account and downloads a key into the per-domain
     credentials folder.
  4. Writes a ready-to-use ``config.yaml`` for the domain.
  5. Prints the exact Client ID and OAuth scope string to paste into the
     Google Admin Console for domain-wide delegation (the one step that
     cannot be automated).

Usage
-----
  python scripts/setup_domain.py <domain> <admin-email> [--project PROJECT_ID]

Examples
--------
  # Let the script create a new GCP project automatically:
  python scripts/setup_domain.py acme.com admin@acme.com

  # Reuse an existing GCP project:
  python scripts/setup_domain.py acme.com admin@acme.com --project my-existing-project

Requirements
------------
  - The ``gcloud`` CLI must be installed and on PATH.
  - You must already be authenticated for the Google account that owns (or
    will own) the target GCP project::

      gcloud auth login --no-launch-browser

  - Application Default Credentials must also be set for that same account::

      gcloud auth application-default login --no-launch-browser

Run those two commands in the browser that is signed into the admin account
for this domain before running this script.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_APIS = [
    "admin.googleapis.com",
    "groupssettings.googleapis.com",
    "cloudidentity.googleapis.com",
    "chromepolicy.googleapis.com",
    "alertcenter.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "serviceusage.googleapis.com",
    "logging.googleapis.com",
]

REQUIRED_SCOPES = ",".join([
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/chrome.management.policy.readonly",
    "https://www.googleapis.com/auth/cloud-platform",
])

SERVICE_ACCOUNT_NAME = "gws-auditor"
SERVICE_ACCOUNT_DISPLAY = "GWS Security Auditor"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(args: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess, streaming output to the terminal when capture=False."""
    return subprocess.run(
        args,
        check=check,
        text=True,
        capture_output=capture,
    )


def _gcloud(*args, check: bool = True) -> subprocess.CompletedProcess:
    return _run(["gcloud"] + list(args), check=check)


def _project_id_from_domain(domain: str) -> str:
    """Derive a GCP-safe project ID from a domain name.

    GCP project IDs must be 6-30 characters, lowercase letters, digits, and
    hyphens, and must start with a letter.
    """
    base = re.sub(r"[^a-z0-9-]", "-", domain.lower())
    base = re.sub(r"-+", "-", base).strip("-")
    suffix = "-audit"
    max_base = 30 - len(suffix)
    return (base[:max_base] + suffix)


def _step(msg: str) -> None:
    print(f"\n→ {msg}")


def _ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def _warn(msg: str) -> None:
    print(f"  ⚠ {msg}", file=sys.stderr)


def _fatal(msg: str) -> None:
    print(f"\n✗ {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Setup steps
# ---------------------------------------------------------------------------

def ensure_project(project_id: str) -> str:
    """Create the GCP project if it does not already exist."""
    _step(f"Checking GCP project: {project_id}")
    result = _gcloud("projects", "describe", project_id, check=False)
    if result.returncode == 0:
        _ok("Project already exists — reusing it.")
        return project_id

    _step(f"Creating GCP project: {project_id}")
    _gcloud("projects", "create", project_id)
    _ok(f"Project created: {project_id}")
    return project_id


def enable_apis(project_id: str) -> None:
    """Enable all APIs required by the auditor."""
    _step(f"Enabling {len(REQUIRED_APIS)} required APIs (this may take a minute)…")
    _gcloud(
        "services", "enable",
        *REQUIRED_APIS,
        "--project", project_id,
        "--quiet",
    )
    _ok("All APIs enabled.")


def ensure_service_account(project_id: str) -> str:
    """Create the service account if it does not already exist.

    Returns the full service account email.
    """
    sa_email = f"{SERVICE_ACCOUNT_NAME}@{project_id}.iam.gserviceaccount.com"
    _step(f"Checking service account: {sa_email}")

    result = _gcloud(
        "iam", "service-accounts", "describe", sa_email,
        "--project", project_id,
        check=False,
    )
    if result.returncode == 0:
        _ok("Service account already exists — reusing it.")
        return sa_email

    _step("Creating service account…")
    _gcloud(
        "iam", "service-accounts", "create", SERVICE_ACCOUNT_NAME,
        "--display-name", SERVICE_ACCOUNT_DISPLAY,
        "--project", project_id,
    )
    _ok(f"Service account created: {sa_email}")
    return sa_email


def create_key(project_id: str, sa_email: str, key_path: Path) -> str:
    """Generate a new service account key and save it to key_path.

    Returns the numeric client ID extracted from the key file.
    """
    _step(f"Generating service account key → {key_path}")
    key_path.parent.mkdir(parents=True, exist_ok=True)

    _gcloud(
        "iam", "service-accounts", "keys", "create", str(key_path),
        "--iam-account", sa_email,
        "--project", project_id,
    )
    _ok("Key file created.")

    with open(key_path) as fh:
        client_id = json.load(fh)["client_id"]
    return client_id


def create_config(domain: str, admin_email: str, key_path: Path, domains_root: Path) -> Path:
    """Write a config.yaml for the domain and return its path."""
    domain_dir = domains_root / domain
    config_path = domain_dir / "config.yaml"

    if config_path.exists():
        _ok(f"config.yaml already exists at {config_path} — skipping.")
        return config_path

    _step(f"Writing config.yaml → {config_path}")

    # Use forward slashes in the YAML so it works on all platforms.
    def rel(p: Path) -> str:
        return p.relative_to(domains_root.parent).as_posix()

    config_content = textwrap.dedent(f"""\
        # GWS Security Auditor Configuration
        # Domain: {domain}
        # Generated by scripts/setup_domain.py

        auth:
          method: service_account
          credentials_file: {rel(key_path)}
          credentials_dir: {rel(key_path.parent)}
          subject: {admin_email}
          customer_id: auto

        checks:
          levels: [L1, L2]
          sources: [CIS, OTHER, GOOGLE, CISA]
          sections: all
          exclude: []

        output:
          directory: {rel(domain_dir / "reports")}
          formats: [html, json, csv]

        options:
          cache_data: true
          cache_directory: {rel(domain_dir / "cache")}
          org_units: all
          max_retries: 5
          rate_limit_qps: 10
    """)

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(config_content, encoding="utf-8")
    _ok("config.yaml written.")
    return config_path


def print_dwd_instructions(client_id: str, admin_email: str, domain: str, config_path: Path) -> None:
    """Print the manual domain-wide delegation step."""
    print("\n" + "=" * 70)
    print("MANUAL STEP REQUIRED: Domain-Wide Delegation")
    print("=" * 70)
    print(textwrap.dedent(f"""
    1. Open the Google Admin Console in the browser signed into {admin_email}:
       https://admin.google.com

    2. Navigate to:
       Security → Access and data control → API controls
       → Manage Domain Wide Delegation

    3. Click "Add new" and enter:

       Client ID:
         {client_id}

       OAuth scopes (paste the entire block below as one line):
         {REQUIRED_SCOPES}

    4. Click "Authorize".

    Note: Propagation can take up to 15 minutes. Once done, run the audit:

      python -m gws_auditor --config {config_path}
    """))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Set up a new GWS domain for auditing with gws-auditor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Before running this script, authenticate gcloud for the admin account
            that owns (or will own) the GCP project:

              gcloud auth login --no-launch-browser
              gcloud auth application-default login --no-launch-browser

            Use --no-launch-browser to paste the URL into the correct browser profile
            when your default browser is signed into a different Google account.
        """),
    )
    parser.add_argument("domain", help="Google Workspace domain (e.g. acme.com)")
    parser.add_argument("admin_email", help="Super-admin email for the domain (e.g. admin@acme.com)")
    parser.add_argument(
        "--project",
        metavar="PROJECT_ID",
        help="Existing GCP project ID to use. If omitted, a new project is created.",
    )
    args = parser.parse_args()

    # Locate the repo root (this script lives in scripts/, one level up is root)
    repo_root = Path(__file__).resolve().parent.parent
    domains_root = repo_root / "domains"

    project_id = args.project or _project_id_from_domain(args.domain)
    key_filename = f"{project_id}-key.json"
    key_path = domains_root / args.domain / "credentials" / key_filename

    print(f"\nSetting up GWS audit for: {args.domain}")
    print(f"  Admin email : {args.admin_email}")
    print(f"  GCP project : {project_id}")
    print(f"  Key file    : {key_path}")

    try:
        ensure_project(project_id)
        enable_apis(project_id)
        sa_email = ensure_service_account(project_id)
        client_id = create_key(project_id, sa_email, key_path)
        config_path = create_config(args.domain, args.admin_email, key_path, domains_root)
        print_dwd_instructions(client_id, args.admin_email, args.domain, config_path)
    except subprocess.CalledProcessError as exc:
        _fatal(
            f"gcloud command failed (exit {exc.returncode}).\n"
            f"  stdout: {exc.stdout.strip() if exc.stdout else '(none)'}\n"
            f"  stderr: {exc.stderr.strip() if exc.stderr else '(none)'}"
        )


if __name__ == "__main__":
    main()
