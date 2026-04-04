# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Interactive CLI REPL for the AI security analyst."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Prompt

from .commands import CommandContext, registry as command_registry
from .config import AIConfig, load_ai_config
from .providers import get_provider
from .session import AnalystSession

console = Console()


def _load_report(reports_dir: str, filename: str | None = None) -> tuple[dict, str]:
    """Load a report from the reports directory.

    Returns:
        Tuple of (report_data, filename).
    """
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        console.print(f"[red]Reports directory not found: {reports_dir}[/red]")
        sys.exit(1)

    if filename:
        fp = reports_path / filename
        if not fp.exists():
            console.print(f"[red]Report not found: {fp}[/red]")
            sys.exit(1)
    else:
        # Find most recent audit report
        files = sorted(reports_path.glob("audit_*.json"), reverse=True)
        if not files:
            console.print(f"[red]No audit reports found in {reports_dir}[/red]")
            sys.exit(1)
        fp = files[0]
        filename = fp.name

    with open(fp, encoding="utf-8") as fh:
        data = json.load(fh)

    return data, filename


def _print_welcome(report_data: dict, filename: str, config: AIConfig) -> None:
    """Print the welcome banner with report summary."""
    summary = report_data.get("summary", {})
    domains = ", ".join(report_data.get("domains", []))

    welcome = (
        f"[bold]GWS Security Analyst[/bold]  |  "
        f"Provider: [cyan]{config.provider}[/cyan]  |  "
        f"Model: [cyan]{config.model or 'default'}[/cyan]\n\n"
        f"Report: [yellow]{filename}[/yellow]\n"
        f"Timestamp: {report_data.get('timestamp', 'unknown')}  |  "
        f"Domains: {domains}\n\n"
        f"Total: {summary.get('total', 0)}  |  "
        f"[green]Pass: {summary.get('passed', 0)}[/green]  |  "
        f"[red]Fail: {summary.get('failed', 0)}[/red]  |  "
        f"[yellow]Warn: {summary.get('warnings', 0)}[/yellow]  |  "
        f"Pass Rate: {summary.get('pass_rate', 0):.1f}%\n\n"
        f"Type your question or use /help for commands."
    )
    console.print(Panel(welcome, border_style="blue"))


def _print_help() -> None:
    """Print available REPL commands via the command registry."""
    cmd = command_registry.get("/help")
    if cmd:
        cmd.handler(None, console, "", CommandContext())
    else:
        console.print("[yellow]No commands registered.[/yellow]")


def run_analyst_repl(
    config: AIConfig,
    reports_dir: str = "./reports",
    report_filename: str | None = None,
) -> None:
    """Run the interactive AI analyst REPL.

    Args:
        config: AI configuration.
        reports_dir: Directory containing audit JSON reports.
        report_filename: Specific report file to analyze (or None for most recent).
    """
    report_data, current_file = _load_report(reports_dir, report_filename)

    provider = get_provider(config)
    session = AnalystSession(
        provider=provider,
        report_data=report_data,
        business_context=config.business_context,
    )

    _print_welcome(report_data, current_file, config)

    while True:
        try:
            user_input = Prompt.ask("\n[bold blue]You[/bold blue]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye![/dim]")
            break

        user_input = user_input.strip()
        if not user_input:
            continue

        # Handle commands
        if user_input.startswith("/"):
            cmd_parts = user_input.split(maxsplit=1)
            cmd_name = cmd_parts[0].lower()
            cmd_args = cmd_parts[1] if len(cmd_parts) > 1 else ""

            cmd = command_registry.get(cmd_name)
            if cmd is None:
                console.print(f"[yellow]Unknown command: {cmd_name}. Type /help for commands.[/yellow]")
                continue

            ctx = CommandContext(
                reports_dir=reports_dir,
                current_file=current_file,
                report_data=report_data,
                config=config,
            )
            result = cmd.handler(session, console, cmd_args, ctx)

            # Update mutable state from context (e.g. /report switches the report)
            if ctx.current_file != current_file:
                current_file = ctx.current_file
                report_data = ctx.report_data

            if result == "__QUIT__":
                console.print("[dim]Goodbye![/dim]")
                break
            continue

        # Send to AI
        console.print("\n[bold green]Analyst[/bold green]")
        try:
            collected = ""
            for token in session.ask_stream(user_input):
                collected += token

            # Render the complete response as Markdown
            if collected:
                console.print(Markdown(collected))
        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
