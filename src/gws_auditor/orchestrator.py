# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Main workflow coordinator for GWS Security Auditor."""

import logging
import os
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .auth import AuthManager
from .checks.registry import CheckRegistry
from .config import load_config
from .models import AuditReport, AuditSummary, Status
from .provider import Provider

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """Coordinates the full audit workflow: auth -> collect -> evaluate -> report."""

    def __init__(self, config: dict):
        self.config = config
        self.auth_manager = AuthManager(config)
        self.registry = CheckRegistry()
        self.report = AuditReport(config=config)

    def run(self) -> AuditReport:
        """Execute the full audit workflow."""
        console.print("\n[bold blue]GWS Security Auditor[/bold blue]")
        console.print("=" * 50)

        # Step 1: Authenticate
        self._authenticate()

        # Step 2: Collect data
        data = self._collect_data()

        # Step 3: Evaluate checks
        results = self._evaluate(data)

        # Step 4: Generate reports
        self._generate_reports(results)

        # Step 5: Print summary
        self._print_summary()

        return self.report

    def dry_run(self) -> bool:
        """Validate auth and API connectivity without running checks."""
        console.print("\n[bold blue]GWS Security Auditor - Dry Run[/bold blue]")
        console.print("=" * 50)

        self._authenticate()
        success = self.auth_manager.test_connection()

        if success:
            console.print("[green]Dry run successful - API connectivity verified[/green]")
        else:
            console.print("[red]Dry run failed - API connectivity issues detected[/red]")

        # List available checks
        self.registry.load()
        checks = self.registry.get_all_checks()
        console.print(f"\nAvailable checks: {len(checks)}")

        return success

    def validate(self) -> bool:
        """Validate credentials, API enablement, and scope access.

        Runs the comprehensive access validation and prints a detailed
        diagnostic table showing which APIs are accessible and which
        require attention.

        Returns
        -------
        True if all probes passed, False if any errors were found.
        """
        console.print("\n[bold blue]GWS Security Auditor - Access Validation[/bold blue]")
        console.print("=" * 50)

        results = self.auth_manager.validate_access()

        table = Table(title="API Access Validation Results")
        table.add_column("API / Check", style="white", no_wrap=True)
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")

        all_ok = True
        errors = []

        for r in results:
            if r["status"] == "ok":
                status_str = "[green]OK[/green]"
            else:
                status_str = "[red]FAIL[/red]"
                all_ok = False
                errors.append(r)

            # Truncate long messages for the table
            msg = r["message"]
            if len(msg) > 80:
                msg = msg[:77] + "..."
            table.add_row(r["api"], status_str, msg)

        console.print(table)

        if all_ok:
            console.print(
                "\n[green bold]All checks passed.[/green bold] "
                "The auditor has access to all required APIs."
            )
        else:
            console.print(
                f"\n[red bold]{len(errors)} issue(s) detected.[/red bold] "
                "Remediation steps:"
            )
            for i, r in enumerate(errors, 1):
                console.print(f"\n[red]{i}. {r['api']}[/red]")
                console.print(f"   Error: {r['message']}")
                if r.get("remediation"):
                    console.print(f"   [yellow]Fix:[/yellow]")
                    for line in r["remediation"].split("\n"):
                        console.print(f"   {line}")

        return all_ok

    def list_checks(self):
        """List all available checks in a table."""
        self.registry.load()
        checks = self.registry.get_all_checks()

        table = Table(title="Available Security Checks")
        table.add_column("ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Level", style="green")
        table.add_column("Source", style="yellow")
        table.add_column("Section", style="magenta")

        for c in sorted(checks, key=lambda x: x.check_id):
            table.add_row(c.check_id, c.title, c.level, c.source, c.section)

        console.print(table)
        console.print(f"\nTotal: {len(checks)} checks")

    def run_cached(self, cache_path: str) -> AuditReport:
        """Re-run checks against previously cached API data."""
        console.print("\n[bold blue]GWS Security Auditor - Cached Mode[/bold blue]")
        console.print(f"Loading data from: {cache_path}")

        data = Provider.from_cache(cache_path)
        # Inject config options so checks can read configurable thresholds
        data["_options"] = self.config.get("options", {})

        self.report.api_errors = data.get("api_errors", [])
        self.report.domains = [
            d.get("domainName", d.get("domain", ""))
            for d in data.get("domains", [])
        ]
        self.report.org_units = [
            ou.get("orgUnitPath", "/")
            for ou in data.get("org_units", [])
            if ou.get("orgUnitPath")
        ]
        self.report.subscription_type = (
            data.get("subscription_info", {}).get("edition", "")
            or self.config.get("auth", {}).get("subscription_type", "")
        )
        # Make subscription_type available to checks for license gating
        data["subscription_type"] = self.report.subscription_type

        results = self._evaluate(data)
        self._generate_reports(results)
        self._print_summary()

        return self.report

    def run_resume(self) -> AuditReport:
        """Resume a previously interrupted data collection run."""
        console.print("\n[bold blue]GWS Security Auditor - Resume Mode[/bold blue]")

        cache_dir = self.config.get("options", {}).get("cache_directory", "./cache")
        partial_data = Provider.from_partial_cache(cache_dir)

        if partial_data is None:
            console.print(
                f"[red]No partial cache found in {cache_dir}. "
                "Nothing to resume.[/red]"
            )
            return self.report

        metadata = partial_data.get("_collection_metadata", {})
        completed = metadata.get("completed_endpoints", [])
        console.print(
            f"Found partial cache with {len(completed)} completed endpoint(s). "
            "Resuming collection..."
        )

        self._authenticate()
        provider = Provider(self.auth_manager, self.config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Resuming data collection...", total=None)
            data = provider.collect_all_resumable(resume_data=partial_data)
            progress.update(task, description="Data collection complete")

        # Inject config options for checks
        data["_options"] = self.config.get("options", {})

        self.report.api_errors = data.get("api_errors", [])
        self.report.domains = [
            d.get("domainName", d.get("domain", ""))
            for d in data.get("domains", [])
        ]
        self.report.org_units = [
            ou.get("orgUnitPath", "/")
            for ou in data.get("org_units", [])
            if ou.get("orgUnitPath")
        ]
        self.report.subscription_type = (
            data.get("subscription_info", {}).get("edition", "")
            or self.config.get("auth", {}).get("subscription_type", "")
        )
        # Make subscription_type available to checks for license gating
        data["subscription_type"] = self.report.subscription_type

        results = self._evaluate(data)
        self._generate_reports(results)
        self._print_summary()

        return self.report

    def run_single_check(self, check_id: str, data: dict | None = None) -> AuditReport:
        """Run a single check by ID."""
        self.registry.load()
        meta = self.registry.get_by_id(check_id)
        if not meta:
            console.print(f"[red]Check not found: {check_id}[/red]")
            return self.report

        if data is None:
            self._authenticate()
            data = self._collect_data()

        console.print(f"\nRunning check: [cyan]{check_id}[/cyan] - {meta.title}")
        results = self.registry.execute_checks(data, [meta])

        self.report.results = results
        self.report.summary = AuditSummary.from_results(results)
        self.report.timestamp = datetime.now(timezone.utc).isoformat()

        for r in results:
            status_color = {
                Status.PASS: "green",
                Status.FAIL: "red",
                Status.WARN: "yellow",
                Status.ERROR: "red",
                Status.MANUAL: "blue",
                Status.NOT_APPLICABLE: "dim",
            }.get(r.status, "white")

            console.print(f"  [{status_color}]{r.status.value}[/{status_color}] - {r.details}")

        return self.report

    def _authenticate(self):
        """Authenticate to Google APIs and auto-discover customer ID."""
        with console.status("[bold green]Authenticating..."):
            self.auth_manager.authenticate()
            # Auto-discover customer ID if set to "auto" or "my_customer"
            resolved_cid = self.auth_manager.resolve_customer_id()
            self.config["auth"]["customer_id"] = resolved_cid
        console.print("[green]Authentication successful[/green]")

    def _collect_data(self) -> dict:
        """Collect all configuration data from APIs."""
        provider = Provider(self.auth_manager, self.config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Collecting GWS configuration data...", total=None)
            data = provider.collect_all()
            progress.update(task, description="Data collection complete")

        # Inject config options so checks can read configurable thresholds
        data["_options"] = self.config.get("options", {})

        self.report.api_errors = data.get("api_errors", [])
        self.report.domains = [
            d.get("domainName", d.get("domain", ""))
            for d in data.get("domains", [])
        ]
        self.report.org_units = [
            ou.get("orgUnitPath", "/")
            for ou in data.get("org_units", [])
            if ou.get("orgUnitPath")
        ]
        self.report.subscription_type = (
            data.get("subscription_info", {}).get("edition", "")
            or self.config.get("auth", {}).get("subscription_type", "")
        )
        # Make subscription_type available to checks for license gating
        data["subscription_type"] = self.report.subscription_type

        if self.report.api_errors:
            console.print(
                f"[yellow]Warning: {len(self.report.api_errors)} API errors during collection[/yellow]"
            )

        return data

    def _evaluate(self, data: dict) -> list:
        """Run all applicable checks against collected data."""
        self.registry.load()

        check_config = self.config.get("checks", {})
        checks = self.registry.filter_checks(
            levels=check_config.get("levels"),
            sources=check_config.get("sources"),
            sections=check_config.get("sections"),
            exclude=check_config.get("exclude"),
            exclude_sections=check_config.get("exclude_sections"),
        )

        console.print(f"\nRunning {len(checks)} checks...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Evaluating security checks...", total=len(checks))
            results = []
            for meta in checks:
                progress.update(task, description=f"Checking {meta.check_id}...")
                result = self.registry.execute_checks(data, [meta])
                results.extend(result)
                progress.advance(task)

        self.report.results = results
        self.report.summary = AuditSummary.from_results(results)
        self.report.timestamp = datetime.now(timezone.utc).isoformat()
        # Use the resolved customer ID; fall back to auth_manager's value
        cid = self.config.get("auth", {}).get("customer_id", "")
        if not cid or cid in ("my_customer", "auto"):
            cid = getattr(self.auth_manager, "customer_id", cid)
        self.report.customer_id = cid

        return results

    def _generate_reports(self, results: list):
        """Generate output reports in configured formats."""
        output_config = self.config.get("output", {})
        output_dir = output_config.get("directory", "./reports")
        formats = output_config.get("formats", ["json"])

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        for fmt in formats:
            try:
                if fmt == "json":
                    from .reporter.json_report import JSONReporter
                    path = os.path.join(output_dir, f"audit_{timestamp}.json")
                    JSONReporter(self.report).generate(path)
                    console.print(f"  JSON report: {path}")
                elif fmt == "csv":
                    from .reporter.csv_report import CSVReporter
                    path = os.path.join(output_dir, f"audit_{timestamp}.csv")
                    CSVReporter(self.report).generate(path)
                    console.print(f"  CSV report:  {path}")
                elif fmt == "html":
                    from .reporter.html_report import HTMLReporter
                    path = os.path.join(output_dir, f"audit_{timestamp}.html")
                    HTMLReporter(self.report).generate(path)
                    console.print(f"  HTML report: {path}")
            except Exception as e:
                logger.error("Failed to generate %s report: %s", fmt, e)
                console.print(f"  [red]Failed to generate {fmt} report: {e}[/red]")

    def _print_critical_findings(self):
        """Print a red banner listing critical check failures."""
        from rich.panel import Panel

        critical = [
            r for r in self.report.results
            if r.status == Status.FAIL and r.severity == "CRITICAL"
        ]
        if not critical:
            return

        lines = []
        for r in critical:
            lines.append(f"[bold]{r.check_id}[/bold]  {r.title}")
            if r.critical_reason:
                # Show first sentence of reason
                reason = r.critical_reason.split(". ")[0] + "."
                lines.append(f"  [dim]{reason}[/dim]")
        body = "\n".join(lines)

        panel = Panel(
            body,
            title=f"[bold red]CRITICAL SECURITY FINDINGS ({len(critical)})[/bold red]",
            border_style="red",
            subtitle="[dim]These findings require immediate attention[/dim]",
        )
        console.print()
        console.print(panel)

    def _print_summary(self):
        """Print audit summary to console."""
        # Show critical findings banner first
        self._print_critical_findings()

        s = self.report.summary

        table = Table(title="\nAudit Summary")
        table.add_column("Metric", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Total Checks", str(s.total))
        table.add_row("[green]Passed[/green]", str(s.passed))
        table.add_row("[red]Failed[/red]", str(s.failed))
        if s.critical_failed:
            table.add_row(
                "[bold red]  Critical Failures[/bold red]",
                f"[bold red]{s.critical_failed}[/bold red]",
            )
        table.add_row("[yellow]Warnings[/yellow]", str(s.warnings))
        table.add_row("[red]Errors[/red]", str(s.errors))
        table.add_row("[blue]Manual Review[/blue]", str(s.manual))
        table.add_row("[dim]Not Applicable[/dim]", str(s.not_applicable))
        table.add_row("", "")
        table.add_row("[bold]Pass Rate[/bold]", f"{s.pass_rate:.1f}%")

        console.print(table)
