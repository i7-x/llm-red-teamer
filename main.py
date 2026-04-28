#!/usr/bin/env python3
"""
LLM Red Teamer — CLI Entry Point
=================================
Usage:
    python main.py scan --url https://api.openai.com/v1 --model gpt-4o --key sk-...
    python main.py scan --provider anthropic --model claude-3-5-sonnet-20241022 --key sk-ant-...
    python main.py scan --url http://localhost:11434/v1 --provider custom --model llama3 --key none
    python main.py list-payloads
    python main.py list-payloads --category jailbreak

Options:
    --url           Target API base URL (default: https://api.openai.com/v1)
    --model         Model name to test
    --key           API key (or set OPENAI_API_KEY / LLM_API_KEY env var)
    --provider      openai | anthropic | mistral | custom (default: openai)
    --categories    Comma-separated categories to test (default: all)
    --system        System prompt to use during testing
    --output        Output JSON file path
    --workers       Max parallel workers (default: 4)
    --verbose       Show full response content in findings
    --no-color      Disable Rich colored output
"""

import sys
import os
import logging
import argparse
from datetime import datetime

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(__file__))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from core.client import LLMClient, Provider
from core.engine import AttackEngine, AttackResult
from core.scoring import AttackCategory
from reporting.reporter import print_scan_report, export_json
from config.settings import load_config
from payloads.loader import load_payloads

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="llm-red-teamer",
        description="LLM Red Teamer — Automated Prompt Injection & Jailbreak Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── scan subcommand ────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Run attack suite against a target LLM")

    scan_parser.add_argument(
        "--url",
        default="https://api.openai.com/v1",
        help="Target API base URL (default: https://api.openai.com/v1)",
    )
    scan_parser.add_argument(
        "--model", "-m",
        required=True,
        help="Model name (e.g. gpt-4o, claude-3-5-sonnet-20241022, llama3)",
    )
    scan_parser.add_argument(
        "--key", "-k",
        default=None,
        help="API key. Falls back to OPENAI_API_KEY or LLM_API_KEY env var.",
    )
    scan_parser.add_argument(
        "--provider",
        choices=["openai", "anthropic", "mistral", "custom"],
        default="openai",
        help="LLM provider (default: openai)",
    )
    scan_parser.add_argument(
        "--categories",
        default=None,
        help="Comma-separated attack categories to run. "
             "Options: prompt_injection,jailbreak,system_prompt_extraction,role_confusion,data_exfiltration",
    )
    scan_parser.add_argument(
        "--system",
        default=None,
        help="Optional system prompt to use when testing",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output path for JSON report (e.g. reports/scan_result.json)",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Max concurrent workers for parallel payload execution (default: 4)",
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full response content in detailed findings section",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable Rich colored output",
    )
    scan_parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging level (default: WARNING)",
    )

    # ── list-payloads subcommand ───────────────────────────────────────────────
    list_parser = subparsers.add_parser("list-payloads", help="List available payloads")
    list_parser.add_argument(
        "--category",
        default=None,
        help="Filter by category",
    )

    return parser.parse_args()


def resolve_api_key(args_key: str | None) -> str:
    """Resolve API key from argument or environment."""
    if args_key:
        return args_key
    for env_var in ("OPENAI_API_KEY", "LLM_API_KEY", "ANTHROPIC_API_KEY"):
        key = os.environ.get(env_var)
        if key:
            return key
    console.print("[red]✗ No API key provided. Use --key or set OPENAI_API_KEY / LLM_API_KEY.[/red]")
    sys.exit(1)


def resolve_categories(categories_str: str | None) -> list[AttackCategory] | None:
    """Parse comma-separated category string into AttackCategory list."""
    if not categories_str:
        return None
    result = []
    for raw in categories_str.split(","):
        raw = raw.strip()
        try:
            result.append(AttackCategory(raw))
        except ValueError:
            console.print(f"[red]✗ Unknown category: '{raw}'[/red]")
            console.print(f"  Valid options: {', '.join(c.value for c in AttackCategory)}")
            sys.exit(1)
    return result if result else None


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the scan command."""
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    api_key = resolve_api_key(args.key)
    categories = resolve_categories(args.categories)
    provider = Provider(args.provider)

    console.print()
    console.print("[bold cyan]⚡ LLM Red Teamer[/bold cyan] [dim]by omar0x[/dim]")
    console.print(f"  Target: [bold]{args.url}[/bold]")
    console.print(f"  Model:  [bold]{args.model}[/bold]")
    console.print(f"  Provider: [bold]{args.provider}[/bold]")
    if categories:
        console.print(f"  Categories: [bold]{', '.join(c.value for c in categories)}[/bold]")
    else:
        console.print(f"  Categories: [bold]ALL[/bold]")
    console.print()

    # Track progress
    progress_state = {"completed": 0, "total": 0}
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    )
    task_id = None

    def on_progress(current: int, total: int, result: AttackResult) -> None:
        nonlocal task_id
        if task_id is None:
            task_id = progress.add_task("[cyan]Running attack suite...", total=total)
        progress.update(
            task_id,
            completed=current,
            description=f"[cyan]Testing: [bold]{result.payload.name[:40]}[/bold]",
        )

    with LLMClient(
        provider=provider,
        api_key=api_key,
        model=args.model,
        base_url=args.url,
        max_retries=3,
    ) as client:
        engine = AttackEngine(
            client=client,
            categories=categories,
            max_workers=args.workers,
            system_prompt=args.system,
            progress_callback=on_progress,
        )

        with progress:
            scan_result = engine.run()

    # Print report
    print_scan_report(scan_result, verbose=args.verbose)

    # Export JSON if requested
    if args.output:
        export_json(scan_result, args.output)
    else:
        # Auto-save to reports/ with timestamp
        timestamp = datetime.fromtimestamp(scan_result.start_time).strftime("%Y%m%d_%H%M%S")
        safe_model = args.model.replace('/', '-').replace(':', '-').replace('\\', '-')
        auto_path = os.path.join("reports", f"scan_{timestamp}_{safe_model}.json")
        export_json(scan_result, auto_path)


def cmd_list_payloads(args: argparse.Namespace) -> None:
    """List all available payloads."""
    from rich.table import Table
    from rich import box

    category_filter = None
    if args.category:
        try:
            category_filter = [AttackCategory(args.category)]
        except ValueError:
            console.print(f"[red]Unknown category: {args.category}[/red]")
            sys.exit(1)

    payloads = load_payloads(categories=category_filter)

    table = Table(
        title=f"Available Payloads ({len(payloads)} total)",
        box=box.ROUNDED,
        header_style="bold cyan",
    )
    table.add_column("ID", style="dim", min_width=30)
    table.add_column("Name", min_width=35)
    table.add_column("Category", min_width=22)
    table.add_column("OWASP", justify="center", width=8)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Source", justify="center", width=8)
    table.add_column("Tags")

    severity_colors = {
        "low": "green", "medium": "yellow",
        "high": "orange3", "critical": "red",
    }

    for p in payloads:
        sev_color = severity_colors.get(p.severity_hint, "white")
        table.add_row(
            p.id,
            p.name,
            p.category.value.replace("_", " ").title(),
            p.owasp_ref,
            f"[{sev_color}]{p.severity_hint.upper()}[/{sev_color}]",
            f"[dim]{p.source}[/dim]",
            ", ".join(p.tags[:3]),
        )

    console.print()
    console.print(table)
    console.print()


def main() -> None:
    args = parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list-payloads":
        cmd_list_payloads(args)


if __name__ == "__main__":
    main()
