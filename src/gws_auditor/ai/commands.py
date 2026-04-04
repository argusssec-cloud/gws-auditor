# Copyright 2026 Argus Security
# Licensed under the GNU Affero General Public License v3.0
# See LICENSE file for details

"""Slash command registry and built-in commands for the AI analyst REPL.

Commands are registered via the ``@command`` decorator and dispatched by
the REPL loop.  Two types of commands:

- **Direct commands**: execute logic immediately (e.g. ``/help``, ``/export``)
- **Skill commands**: send a crafted prompt to the LLM via ``session.ask_stream()``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from rich.console import Console

    from .session import AnalystSession

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


@dataclass
class Command:
    """A registered slash command."""

    name: str
    description: str
    handler: Callable  # (session, console, args_str, ctx) -> str | None
    aliases: list[str] = field(default_factory=list)
    category: str = "General"


class CommandRegistry:
    """Simple registry for slash commands."""

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}

    def register(self, cmd: Command) -> None:
        self._commands[cmd.name] = cmd
        for alias in cmd.aliases:
            self._commands[alias] = cmd

    def get(self, name: str) -> Command | None:
        return self._commands.get(name)

    def list_all(self) -> list[Command]:
        """Return unique commands (no alias duplicates), sorted by category + name."""
        seen: set[str] = set()
        result = []
        for cmd in self._commands.values():
            if cmd.name not in seen:
                seen.add(cmd.name)
                result.append(cmd)
        return sorted(result, key=lambda c: (c.category, c.name))


registry = CommandRegistry()


def command(
    name: str,
    description: str,
    aliases: list[str] | None = None,
    category: str = "General",
):
    """Decorator to register a REPL slash command."""

    def decorator(func: Callable) -> Callable:
        cmd = Command(
            name=name,
            description=description,
            handler=func,
            aliases=aliases or [],
            category=category,
        )
        registry.register(cmd)
        return func

    return decorator


# ---------------------------------------------------------------------------
# Context passed to command handlers
# ---------------------------------------------------------------------------


@dataclass
class CommandContext:
    """Shared state passed to every command handler."""

    reports_dir: str = "./reports"
    current_file: str = ""
    report_data: dict = field(default_factory=dict)
    config: object = None  # AIConfig


# ---------------------------------------------------------------------------
# Built-in commands (migrated from cli_repl.py hardcoded logic)
# ---------------------------------------------------------------------------


@command("/quit", "Exit the analyst", aliases=["/exit"], category="General")
def cmd_quit(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    return "__QUIT__"


@command("/help", "Show available commands", category="General")
def cmd_help(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    lines = ["[bold]Commands:[/bold]\n"]
    current_cat = ""
    for cmd in registry.list_all():
        if cmd.category != current_cat:
            current_cat = cmd.category
            lines.append(f"\n  [bold dim]{current_cat}[/bold dim]")
        alias_str = f" ({', '.join(cmd.aliases)})" if cmd.aliases else ""
        lines.append(f"  {cmd.name:20s} {cmd.description}{alias_str}")
    from rich.panel import Panel
    console.print(Panel("\n".join(lines), title="Help", border_style="blue"))
    return None


@command("/reset", "Clear conversation history", category="General")
def cmd_reset(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    session.reset()
    console.print("[green]Conversation history cleared.[/green]")
    return None


@command("/reports", "List available reports", category="General")
def cmd_reports(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    report_files = sorted(Path(ctx.reports_dir).glob("audit_*.json"), reverse=True)
    if not report_files:
        console.print("[yellow]No reports found.[/yellow]")
    else:
        console.print("[bold]Available reports:[/bold]")
        for rf in report_files:
            marker = " [cyan](current)[/cyan]" if rf.name == ctx.current_file else ""
            console.print(f"  {rf.name}{marker}")
    return None


@command("/report", "Switch to a different report", category="General")
def cmd_report(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    if not args.strip():
        console.print("[yellow]Usage: /report <filename>[/yellow]")
        return None
    filename = args.strip()
    fp = Path(ctx.reports_dir) / filename
    if not fp.exists():
        console.print(f"[red]Report not found: {fp}[/red]")
        return None
    with open(fp, encoding="utf-8") as fh:
        data = json.load(fh)
    ctx.report_data = data
    ctx.current_file = filename
    session.set_report(data)
    console.print(f"[green]Switched to report: {filename}[/green]")
    return None


# ---------------------------------------------------------------------------
# Skill commands — send crafted prompts to the LLM
# ---------------------------------------------------------------------------


def _stream_prompt(session: AnalystSession, console: Console, prompt: str) -> None:
    """Send a prompt through the session and render the streamed response."""
    from rich.markdown import Markdown
    console.print("\n[bold green]Analyst[/bold green]")
    try:
        collected = ""
        for token in session.ask_stream(prompt):
            collected += token
        if collected:
            console.print(Markdown(collected))
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")


@command("/critical", "Show critical failures with remediation", category="Skills")
def cmd_critical(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    _stream_prompt(
        session, console,
        "List all CRITICAL severity check failures with their full remediation "
        "steps and documentation links. Group by section and include the Admin "
        "Console navigation path for each fix."
    )
    return None


@command("/summary", "Generate an executive summary", category="Skills")
def cmd_summary(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    _stream_prompt(
        session, console,
        "Generate a concise executive summary of the current audit report "
        "suitable for management. Include: overall compliance posture, top 3 "
        "risk areas, critical failures count, and a brief recommendation."
    )
    return None


@command("/remediate", "Grouped remediation plan [section]", category="Skills")
def cmd_remediate(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    section = args.strip()
    if section:
        prompt = (
            f"Generate a grouped remediation plan for the '{section}' section. "
            f"Use the get_smart_remediation tool grouped by theme. Include "
            f"effort estimates and documentation links."
        )
    else:
        prompt = (
            "Generate a grouped remediation plan for all failing checks. "
            "Use the get_smart_remediation tool grouped by theme. "
            "Prioritize by severity and include effort estimates and "
            "documentation links for each group."
        )
    _stream_prompt(session, console, prompt)
    return None


@command("/compare", "Compare with previous report", category="Skills")
def cmd_compare(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    _stream_prompt(
        session, console,
        "List all available reports, then compare the current report with "
        "the most recent previous report. Highlight new failures, resolved "
        "issues, and the change in pass rate."
    )
    return None


@command("/inventory", "Query inventory data [check_id]", category="Skills")
def cmd_inventory(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    check_id = args.strip()
    if check_id:
        prompt = (
            f"Query and analyze the inventory data for check {check_id}. "
            f"Use the query_inventory_data tool. Summarize the findings and "
            f"highlight any concerns."
        )
    else:
        prompt = (
            "Provide an overview of all inventory checks (ADD-28 through ADD-39). "
            "For each that has a WARN or FAIL status, use query_inventory_data "
            "to show the key findings. Summarize the overall inventory health."
        )
    _stream_prompt(session, console, prompt)
    return None


@command("/search", "Search findings for a keyword", category="Skills")
def cmd_search(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    query = args.strip()
    if not query:
        console.print("[yellow]Usage: /search <keyword>[/yellow]")
        return None
    _stream_prompt(
        session, console,
        f"Search all audit findings for anything related to: {query}. "
        f"Show matching checks with their status, details, and remediation."
    )
    return None


@command("/trends", "Analyze trends across reports", category="Skills")
def cmd_trends(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    _stream_prompt(
        session, console,
        "Analyze trends across the available audit reports using the "
        "get_trend_analysis tool. Show pass rate over time, persistent "
        "failures, and recently resolved issues."
    )
    return None


# ---------------------------------------------------------------------------
# Export commands — operate directly, no LLM involvement
# ---------------------------------------------------------------------------


@command("/export", "Export conversation or findings (md|csv)", category="Export")
def cmd_export(session: AnalystSession, console: Console, args: str, ctx: CommandContext) -> str | None:
    fmt = args.strip().lower()
    if fmt == "md":
        return _export_markdown(session, console, ctx)
    elif fmt == "csv":
        return _export_csv(console, ctx)
    else:
        console.print("[yellow]Usage: /export md  or  /export csv[/yellow]")
        return None


def _export_markdown(session: AnalystSession, console: Console, ctx: CommandContext) -> None:
    """Export the conversation history as a Markdown file."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outpath = Path(ctx.reports_dir) / f"analyst_{ts}.md"

    lines = [f"# GWS Security Analyst Session\n"]
    lines.append(f"Report: {ctx.current_file}\n")
    lines.append(f"Exported: {datetime.now(timezone.utc).isoformat()}\n\n---\n")

    for msg in session.history:
        if msg.role == "system" or msg.role == "tool":
            continue
        if msg.role == "user":
            lines.append(f"\n## User\n\n{msg.content}\n")
        elif msg.role == "assistant" and msg.content:
            lines.append(f"\n## Analyst\n\n{msg.content}\n")

    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]Conversation exported to: {outpath}[/green]")
    return None


def _export_csv(console: Console, ctx: CommandContext) -> None:
    """Export FAIL/WARN findings as a CSV file."""
    from .tools import _export_findings_csv

    csv_content = _export_findings_csv(
        ctx.report_data,
        status=["FAIL", "WARN"],
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    outpath = Path(ctx.reports_dir) / f"findings_{ts}.csv"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(csv_content, encoding="utf-8")

    row_count = csv_content.count("\n") - 1
    console.print(f"[green]Exported {row_count} findings to: {outpath}[/green]")
    return None
