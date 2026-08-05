# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CLI argument parsing for GWS Security Auditor."""

import argparse
import sys


def _add_audit_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the common audit-related arguments to a parser."""
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to configuration YAML file (default: config.yaml)",
    )

    # Authentication options
    auth_group = parser.add_argument_group("authentication")
    auth_group.add_argument(
        "--credentials",
        help="Path to credentials JSON file (overrides config)",
    )
    auth_group.add_argument(
        "--subject",
        help="Delegated admin email for service account (overrides config)",
    )
    auth_group.add_argument(
        "--customer-id",
        help="Google Workspace customer ID (overrides config)",
    )
    auth_group.add_argument(
        "--auth-method",
        choices=["service_account", "oauth", "gce", "workload_identity"],
        help="Authentication method (overrides config). "
             "'gce' uses the VM's attached service account (no key file). "
             "'workload_identity' uses Workload Identity Federation via "
             "GOOGLE_APPLICATION_CREDENTIALS (no key file).",
    )
    auth_group.add_argument(
        "--profile",
        help="Use a named credential profile from config.yaml "
             "(use '?' to list available profiles)",
    )

    # Check filtering
    check_group = parser.add_argument_group("check filtering")
    check_group.add_argument(
        "--check",
        help="Run a single check by ID (e.g., CIS-1.1.1)",
    )
    check_group.add_argument(
        "--level",
        choices=["L1", "L2"],
        action="append",
        help="Filter checks by level (can be repeated)",
    )
    check_group.add_argument(
        "--source",
        choices=["CIS", "OTHER", "GOOGLE", "CISA"],
        action="append",
        help="Filter checks by source (can be repeated)",
    )
    check_group.add_argument(
        "--section",
        action="append",
        help="Filter checks by section (can be repeated)",
    )
    check_group.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude specific check IDs (can be repeated)",
    )
    check_group.add_argument(
        "--exclude-section",
        action="append",
        default=[],
        help="Exclude all checks in a section (can be repeated, e.g. 'Google Meet')",
    )

    # Output options
    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--output-dir", "-o",
        help="Output directory for reports (overrides config)",
    )
    output_group.add_argument(
        "--format", "-f",
        choices=["html", "json", "csv"],
        action="append",
        help="Output format(s) (can be repeated, overrides config)",
    )

    # Operational modes
    mode_group = parser.add_argument_group("modes")
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate auth and API connectivity without running checks",
    )
    mode_group.add_argument(
        "--cached",
        metavar="FILE",
        help="Re-run checks against previously cached API data (path to .json cache file)",
    )
    mode_group.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit",
    )
    mode_group.add_argument(
        "--validate",
        action="store_true",
        help="Validate credentials, API enablement, and scopes with detailed diagnostics",
    )
    mode_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume a previously interrupted data collection run",
    )
    mode_group.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with code 2 if any critical-severity check fails (for CI/CD)",
    )
    mode_group.add_argument(
        "--skip-update-check",
        action="store_true",
        default=False,
        help="Skip the automatic check for newer versions at startup",
    )
    mode_group.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Check for and install the latest version, then exit (no audit)",
    )
    mode_group.add_argument(
        "--no-cloud-info",
        action="store_true",
        default=False,
        help="Suppress the Argus Cloud informational message at startup",
    )

    # Network options
    net_group = parser.add_argument_group("network")
    net_group.add_argument(
        "--proxy",
        help="HTTP proxy URL (e.g. http://proxy:8080). Overrides config and env vars.",
    )
    net_group.add_argument(
        "--no-proxy",
        help="Comma-separated list of hosts to bypass proxy (e.g. localhost,.internal)",
    )
    net_group.add_argument(
        "--ca-cert",
        help="Path to CA certificate bundle for proxy TLS interception",
    )
    net_group.add_argument(
        "--disable-ssl-verification",
        action="store_true",
        default=False,
        help="Disable SSL certificate verification (insecure, use only for testing)",
    )

    # Misc
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress all output except errors",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="gws-auditor",
        description="Google Workspace Security Posture Auditor - "
                    "Audit GWS configuration against CIS Benchmarks and best practices.",
    )

    subparsers = parser.add_subparsers(dest="command")

    # --- dashboard subcommand ---
    dash_parser = subparsers.add_parser(
        "dashboard",
        help="Launch the interactive web dashboard",
    )
    dash_parser.add_argument(
        "--port", type=int, default=8050,
        help="Port to serve the dashboard on (default: 8050)",
    )
    dash_parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    dash_parser.add_argument(
        "--reports-dir", default="./reports",
        help="Directory containing audit JSON reports (default: ./reports)",
    )
    dash_parser.add_argument(
        "--debug", action="store_true",
        help="Run Dash in debug mode with hot-reload",
    )

    # --- analyst subcommand ---
    analyst_parser = subparsers.add_parser(
        "analyst",
        help="Interactive AI security analyst",
    )
    analyst_parser.add_argument(
        "--reports-dir",
        default="./reports",
        help="Directory containing audit JSON reports (default: ./reports)",
    )
    analyst_parser.add_argument(
        "--report",
        default=None,
        help="Specific report file to analyze",
    )
    analyst_parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "bedrock"],
        default=None,
        help="AI provider (overrides config)",
    )
    analyst_parser.add_argument(
        "--model",
        default=None,
        help="Model name (overrides config)",
    )
    analyst_parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to configuration YAML file (default: config.yaml)",
    )

    # --- setup subcommand ---
    setup_parser = subparsers.add_parser(
        "setup",
        help="Interactive setup wizard for GCP project, APIs, and service account",
    )
    setup_parser.add_argument(
        "--project",
        default="",
        help="GCP project ID to use (skip project selection)",
    )
    setup_parser.add_argument(
        "--subject",
        default="",
        help="Super admin email for service account impersonation",
    )
    setup_parser.add_argument(
        "--credentials-dir",
        default="credentials",
        help="Directory to store credential files (default: credentials)",
    )
    setup_parser.add_argument(
        "--existing-sa-key",
        default="",
        help="Path to an existing service account JSON key "
             "(skips SA creation, avoids OAuth flow)",
    )
    setup_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip interactive prompts (requires --project and --subject)",
    )

    # --- agent subcommand ---
    agent_parser = subparsers.add_parser(
        "agent",
        help="Run audit and push results to ArgusSec Console",
    )
    agent_parser.add_argument(
        "--console-url", "--url",
        default="",
        help="ArgusSec Console API URL "
             "(default: https://console.argussec.io; or env ARGUSSEC_CONSOLE_URL; or agent.console_url in config.yaml)",
    )
    agent_parser.add_argument(
        "--api-key",
        default="",
        help="Tenant-scoped API key for the console "
             "(or env ARGUSSEC_API_KEY; or agent.api_key in config.yaml)",
    )
    _add_audit_arguments(agent_parser)

    # --- default (audit) arguments on the root parser ---
    _add_audit_arguments(parser)

    args = parser.parse_args(argv)

    # When no subcommand is given, default to audit behaviour
    if args.command is None:
        args.command = "audit"

    return args


def apply_cli_overrides(config: dict, args: argparse.Namespace) -> dict:
    """Apply CLI argument overrides to the loaded config."""
    # Apply named profile first (before individual overrides)
    profile = getattr(args, "profile", None) or config.get("auth", {}).get("profile", "")
    if profile and profile != "?":
        from .credentials import apply_profile
        apply_profile(config, profile)

    if args.credentials:
        config["auth"]["credentials_file"] = args.credentials
    if args.subject:
        config["auth"]["subject"] = args.subject
    if args.customer_id:
        config["auth"]["customer_id"] = args.customer_id
    if args.auth_method:
        config["auth"]["method"] = args.auth_method

    if args.level:
        config["checks"]["levels"] = args.level
    if args.source:
        config["checks"]["sources"] = args.source
    if args.section:
        config["checks"]["sections"] = args.section
    if args.exclude:
        config["checks"]["exclude"] = args.exclude
    if args.exclude_section:
        config["checks"]["exclude_sections"] = args.exclude_section

    if args.output_dir:
        config["output"]["directory"] = args.output_dir
    if args.format:
        config["output"]["formats"] = args.format

    if getattr(args, "proxy", None):
        config.setdefault("network", {})["proxy"] = args.proxy
    if getattr(args, "no_proxy", None):
        config.setdefault("network", {})["no_proxy"] = args.no_proxy
    if getattr(args, "ca_cert", None):
        config.setdefault("network", {})["ca_cert"] = args.ca_cert
    if getattr(args, "disable_ssl_verification", False):
        config.setdefault("network", {})["disable_ssl_verification"] = True
        import sys
        print(
            "\033[91m\033[1mWARNING: SSL certificate verification is DISABLED.\033[0m\n"
            "  Connections are vulnerable to man-in-the-middle attacks.\n"
            "  OAuth tokens and admin credentials may be intercepted.\n"
            "  Do NOT use this option outside of isolated test environments.\n",
            file=sys.stderr,
        )

    return config
