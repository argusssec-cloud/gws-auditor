# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""CLI entry point for GWS Security Auditor."""

import logging
import sys

from .cli import apply_cli_overrides, parse_args
from .config import load_config
from .orchestrator import Orchestrator


def _launch_dashboard(args):
    """Start the interactive Dash dashboard."""
    try:
        from .dashboard import create_app
    except ImportError:
        print(
            "ERROR: Dashboard dependencies are not installed.\n"
            "Install them with:  pip install gws-security-auditor[dashboard]",
            file=sys.stderr,
        )
        return 1

    app = create_app(reports_dir=args.reports_dir)
    print(f"Starting GWS Auditor Dashboard on http://{args.host}:{args.port}/")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


def _launch_analyst(args):
    """Start the interactive AI analyst REPL."""
    try:
        from .ai.cli_repl import run_analyst_repl
        from .ai.config import load_ai_config
    except ImportError:
        print(
            "ERROR: AI analyst dependencies are not installed.\n"
            "Install them with:  pip install gws-security-auditor[ai]",
            file=sys.stderr,
        )
        return 1

    config = load_config(args.config)
    ai_config = load_ai_config(
        config_dict=config.get("ai"),
        cli_args={
            "provider": getattr(args, "provider", None),
            "model": getattr(args, "model", None),
        },
    )
    run_analyst_repl(
        config=ai_config,
        reports_dir=args.reports_dir,
        report_filename=args.report,
    )
    return 0


def _list_profiles(config: dict):
    """List available credential profiles and scanned credential files."""
    from rich.console import Console
    from rich.table import Table
    from .credentials import list_profiles, scan_credentials_dir

    console = Console()

    profiles = list_profiles(config)
    creds_dir = config.get("auth", {}).get("credentials_dir", "credentials")
    scanned = scan_credentials_dir(creds_dir)

    if profiles:
        table = Table(title="Configured Profiles")
        table.add_column("Name", style="cyan")
        table.add_column("Credentials File")
        table.add_column("Subject")
        table.add_column("Customer ID")
        for p in profiles:
            table.add_row(p["name"], p["credentials_file"],
                          p["subject"], p["customer_id"])
        console.print(table)
    else:
        console.print("[yellow]No profiles configured in config.yaml[/yellow]")

    if scanned:
        table = Table(title=f"Credential Files in '{creds_dir}/'")
        table.add_column("Filename", style="cyan")
        table.add_column("Service Account Email")
        table.add_column("Project ID")
        for s in scanned:
            table.add_row(s["filename"], s["client_email"], s["project_id"])
        console.print(table)
    else:
        console.print(f"[dim]No credential files found in '{creds_dir}/'[/dim]")

    console.print("\n[dim]Usage: gws-auditor --profile <name>[/dim]")


def main(argv: list[str] | None = None):
    """Main entry point."""
    args = parse_args(argv)

    # Dashboard subcommand – no config / orchestrator needed
    if args.command == "dashboard":
        return _launch_dashboard(args)

    # Analyst subcommand
    if args.command == "analyst":
        return _launch_analyst(args)

    # Setup wizard subcommand
    if args.command == "setup":
        from .setup import SetupWizard
        wizard = SetupWizard(
            project_id=getattr(args, "project", ""),
            subject=getattr(args, "subject", ""),
            credentials_dir=getattr(args, "credentials_dir", "credentials"),
            non_interactive=getattr(args, "non_interactive", False),
            existing_sa_key=getattr(args, "existing_sa_key", ""),
        )
        return wizard.run()

    # Configure logging
    if args.quiet:
        log_level = logging.ERROR
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Load config and apply CLI overrides
    config = load_config(args.config)

    # Handle --profile ? (list profiles and exit)
    if getattr(args, "profile", None) == "?":
        _list_profiles(config)
        return 0

    config = apply_cli_overrides(config, args)

    orchestrator = Orchestrator(config)

    # Handle operational modes
    if args.list_checks:
        orchestrator.list_checks()
        return 0

    if args.validate:
        success = orchestrator.validate()
        return 0 if success else 1

    if args.dry_run:
        success = orchestrator.dry_run()
        return 0 if success else 1

    if args.cached:
        orchestrator.run_cached(args.cached)
        return 0

    if args.resume:
        orchestrator.run_resume()
        return 0

    if args.check:
        orchestrator.run_single_check(args.check)
        return 0

    # Full audit run
    report = orchestrator.run()

    # Exit code 2 for critical failures (CI/CD gate)
    if getattr(args, "fail_on_critical", False) and report.summary.critical_failed > 0:
        return 2

    # Exit with non-zero if there are failures
    if report.summary.failed > 0:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BrokenPipeError, OSError):
        # Handle broken pipe (e.g. `gws-auditor --list-checks | head`)
        # and Windows legacy console errors from Rich
        try:
            sys.stdout.close()
        except OSError:
            pass
        sys.exit(0)
