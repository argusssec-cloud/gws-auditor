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


def _validate_auth_config(config: dict, args) -> None:
    """Exit with a clear error if credentials or subject are not configured."""
    import os

    auth = config.get("auth", {})
    method = auth.get("method", "service_account")

    # Only service_account requires a credentials file on disk.
    # OAuth handles its own discovery; GCE and WIF are keyless.
    if method != "service_account":
        return

    creds_file = auth.get("credentials_file", "")
    subject = auth.get("subject", "")
    config_exists = os.path.exists(getattr(args, "config", "config.yaml"))

    missing = []
    if not creds_file or not os.path.exists(creds_file):
        missing.append("--credentials <path-to-credentials.json>")
    if not subject:
        missing.append("--subject <admin@yourdomain.com>")

    if missing:
        hint = (
            "No config.yaml found. " if not config_exists
            else "config.yaml is missing required auth fields. "
        )
        items = "\n".join(f"  {m}" for m in missing)
        print(
            f"ERROR: {hint}"
            f"Please provide the following:\n\n"
            f"{items}\n\n"
            f"Example:\n"
            f"  gws-auditor --credentials credentials.json --subject admin@yourdomain.com\n\n"
            f"Or create a config.yaml with 'auth.credentials_file' and 'auth.subject' set.\n"
            f"See: gws-auditor setup --help",
            file=sys.stderr,
        )
        sys.exit(1)


def _main(argv: list[str] | None = None) -> int:
    """Main entry point (see main() for the exit-code wrapper)."""
    args = parse_args(argv)

    # Handle --update: perform update and exit (before any config loading)
    if getattr(args, "update", False):
        from .version_check import run_update_only
        return run_update_only()

    # Dashboard subcommand – no config / orchestrator needed
    if args.command == "dashboard":
        return _launch_dashboard(args)

    # Analyst subcommand
    if args.command == "analyst":
        return _launch_analyst(args)

    # Agent subcommand — run audit and push results to console
    if args.command == "agent":
        import os

        # Configure logging early
        if getattr(args, "quiet", False):
            log_level = logging.ERROR
        elif getattr(args, "verbose", 0) >= 2:
            log_level = logging.DEBUG
        elif getattr(args, "verbose", 0) >= 1:
            log_level = logging.INFO
        else:
            log_level = logging.WARNING
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        config = load_config(args.config)
        config = apply_cli_overrides(config, args)
        _validate_auth_config(config, args)

        # Resolve console_url and api_key: CLI flag > env var > config.yaml
        agent_config = config.get("agent", {})
        console_url = (
            args.console_url
            or os.environ.get("ARGUSSEC_CONSOLE_URL", "")
            or agent_config.get("console_url", "")
            or "https://console.argussec.io"
        )
        api_key = (
            args.api_key
            or os.environ.get("ARGUSSEC_API_KEY", "")
            or agent_config.get("api_key", "")
        )
        if not api_key:
            print(
                "ERROR: --api-key is required.\n"
                "Set it via CLI flag, ARGUSSEC_API_KEY env var, or agent.api_key in config.yaml.",
                file=sys.stderr,
            )
            return 1

        from .agent import run_agent
        return run_agent(config, console_url, api_key)

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

    # Non-blocking version check (before config loading so the user
    # sees the update prompt before any config validation errors).
    from .version_check import check_and_prompt_update
    check_and_prompt_update(
        skip=getattr(args, "skip_update_check", False),
        quiet=getattr(args, "quiet", False),
    )

    # Argus Cloud informational banner
    from .cloud_info import show_cloud_info
    show_cloud_info(
        quiet=getattr(args, "quiet", False),
        no_cloud_info=getattr(args, "no_cloud_info", False),
    )

    # Load config and apply CLI overrides. A config path the user named must exist;
    # only the default "config.yaml" may be absent (the CLI flags then carry the auth).
    import os
    if args.config != "config.yaml" and not os.path.exists(args.config):
        print(f"ERROR: config file not found: {args.config}", file=sys.stderr)
        return 1
    config = load_config(args.config)

    # Handle --profile ? (list profiles and exit)
    if getattr(args, "profile", None) == "?":
        _list_profiles(config)
        return 0

    try:
        config = apply_cli_overrides(config, args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.quiet:
        from . import orchestrator as _orch
        _orch.console.quiet = True

    # Validate that sufficient auth config is present before proceeding.
    # A valid config.yaml may supply credentials_file and subject, but when
    # no config file exists the user must provide them via CLI flags.
    # Skip validation when using --cached (no API calls needed).
    if not args.list_checks and not args.cached:
        _validate_auth_config(config, args)

    orchestrator = Orchestrator(config)

    # Handle operational modes
    if args.list_checks:
        orchestrator.list_checks()
        return 0

    if args.check:
        orchestrator.registry.load()
        if orchestrator.registry.get_by_id(args.check) is None:
            print(f"ERROR: unknown check id: {args.check} (see --list-checks)", file=sys.stderr)
            return 1

    try:
        if args.validate:
            success = orchestrator.validate()
            return 0 if success else 1
        if args.dry_run:
            success = orchestrator.dry_run()
            return 0 if success else 1
        if args.cached:
            if not os.path.exists(args.cached):
                print(f"ERROR: cache file not found: {args.cached}", file=sys.stderr)
                return 1
            report = orchestrator.run_cached(args.cached, check_id=args.check)
        elif args.resume:
            report = orchestrator.run_resume()
        elif args.check:
            report = orchestrator.run_single_check(args.check)
        else:
            report = orchestrator.run()
    except _AUTH_ERRORS as exc:
        return _report_auth_error(exc, args)
    return _exit_code(report, args)


def _exit_code(report, args) -> int:
    """0 clean, 1 when any check failed, 2 for critical failures under --fail-on-critical.

    The same rule applies to a live run, a cached re-run and a single check, so a CI gate
    behaves the same whichever mode produced the report.
    """
    summary = getattr(report, "summary", None)
    if summary is None:
        return 0
    if getattr(args, "fail_on_critical", False) and summary.critical_failed > 0:
        return 2
    if summary.failed > 0:
        return 1
    return 0


def _auth_error_types() -> tuple:
    types: list = []
    try:
        from google.auth.exceptions import GoogleAuthError, TransportError
        types += [GoogleAuthError, TransportError]
    except ImportError:  # pragma: no cover
        pass
    return tuple(types) + (FileNotFoundError, ConnectionError)


_AUTH_ERRORS = _auth_error_types()


def _report_auth_error(exc: Exception, args) -> int:
    """One clear line (plus the remediation the AuthManager knows) instead of a traceback."""
    hint = ""
    if not isinstance(exc, (FileNotFoundError, ConnectionError)):
        from .auth import AuthManager
        try:
            hint = AuthManager._auth_remediation(exc)
        except Exception:  # pragma: no cover - remediation text is best effort
            hint = ""
    print(f"ERROR: {type(exc).__name__}: {str(exc).splitlines()[0][:300]}", file=sys.stderr)
    if hint:
        print(hint, file=sys.stderr)
    if getattr(args, "verbose", 0) >= 2:
        import traceback
        traceback.print_exception(exc)
    return 1


def main(argv: list[str] | None = None) -> int:
    """Console-script entry: _main()'s exit code; a closed pipe is not an error, any other OSError is."""
    import errno
    try:
        return _main(argv)
    except BrokenPipeError:
        # `gws-auditor --list-checks | head`: point stdout at /dev/null so the interpreter's
        # final flush does not raise again (closing it would break any captured stdout).
        try:
            import os
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except OSError as exc:
        # Windows legacy console errors from Rich surface as EINVAL on stdout; every other
        # OSError (a missing file, a refused proxy, an unreadable CA bundle) is a real failure.
        if exc.errno == errno.EPIPE or (exc.errno == errno.EINVAL and "stdout" in str(exc).lower()):
            return 0
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
