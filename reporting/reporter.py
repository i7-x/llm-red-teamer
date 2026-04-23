"""
Reporting System
================
Handles formatted CLI output (via Rich) and JSON export of scan results.

CLI Report Layout:
    ┌─ Scan Summary header
    ├─ Per-category breakdown table
    ├─ Top findings (successful attacks) sorted by risk score
    └─ Aggregate risk assessment

JSON Export Schema:
    {
        "scan_meta": { ... },
        "aggregate_risk": { ... },
        "category_summary": { ... },
        "findings": [ ... ]
    }
"""

import json
import os
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.rule import Rule

from core.engine import ScanResult, AttackResult
from core.scoring import Severity

console = Console()

# Severity → Rich color mapping
SEVERITY_COLORS = {
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange3",
    Severity.CRITICAL: "red bold",
}

SEVERITY_ICONS = {
    Severity.LOW: "🟢",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}


def _severity_text(severity: Severity) -> Text:
    """Build a colored Rich Text object for a severity level."""
    color = SEVERITY_COLORS[severity]
    icon = SEVERITY_ICONS[severity]
    return Text(f"{icon} {severity.value}", style=color)


def print_scan_report(result: ScanResult, verbose: bool = False) -> None:
    """
    Print a fully formatted scan report to the terminal using Rich.

    Args:
        result: Completed ScanResult from AttackEngine.
        verbose: If True, print full response content for each finding.
    """
    console.print()
    console.print(Rule("[bold cyan]  LLM RED TEAMER — SCAN REPORT  [/bold cyan]", style="cyan"))
    console.print()

    # ── SCAN METADATA ──────────────────────────────────────────────────────────
    meta_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    meta_table.add_column("Field", style="dim")
    meta_table.add_column("Value", style="bold white")

    meta_table.add_row("Target", result.target_url)
    meta_table.add_row("Model", result.model)
    meta_table.add_row("Provider", result.provider)
    meta_table.add_row("Scan Duration", f"{result.duration_seconds}s")
    meta_table.add_row("Timestamp", datetime.fromtimestamp(result.start_time).strftime("%Y-%m-%d %H:%M:%S"))
    meta_table.add_row("Total Payloads", str(result.total_payloads))
    meta_table.add_row("Successful Attacks", f"[red]{result.successful_attacks}[/red]")
    meta_table.add_row("Success Rate", f"[{'red' if result.success_rate > 0.3 else 'yellow'}]{result.success_rate:.1%}[/]")

    console.print(Panel(meta_table, title="[bold]Scan Metadata[/bold]", border_style="cyan"))
    console.print()

    # ── AGGREGATE RISK ─────────────────────────────────────────────────────────
    if result.aggregate_risk:
        agg = result.aggregate_risk
        color = SEVERITY_COLORS[agg.severity]
        icon = SEVERITY_ICONS[agg.severity]
        console.print(
            Panel(
                f"{icon}  Aggregate Risk Score: [{color}]{agg.raw_score:.4f}[/{color}]  "
                f"→  [{color}]{agg.severity.value}[/{color}]\n\n"
                f"[dim]{agg.explanation}[/dim]",
                title="[bold]Overall Risk Assessment[/bold]",
                border_style=color,
            )
        )
        console.print()

    # ── CATEGORY BREAKDOWN ─────────────────────────────────────────────────────
    cat_table = Table(
        title="Attack Category Breakdown",
        box=box.ROUNDED,
        header_style="bold cyan",
        border_style="dim",
    )
    cat_table.add_column("Category", style="white", min_width=28)
    cat_table.add_column("Payloads", justify="center")
    cat_table.add_column("Successful", justify="center")
    cat_table.add_column("Success Rate", justify="center")
    cat_table.add_column("Max Severity", justify="center")

    # Group results by category
    from collections import defaultdict
    by_category: dict[str, list[AttackResult]] = defaultdict(list)
    for r in result.attack_results:
        by_category[r.payload.category.value].append(r)

    for cat_name, results in sorted(by_category.items()):
        successful = [r for r in results if r.analysis.success]
        rate = len(successful) / len(results) if results else 0.0

        # Find the max severity among successful attacks
        max_sev = None
        for r in successful:
            sev = r.risk_score.severity
            if max_sev is None or list(Severity).index(sev) > list(Severity).index(max_sev):
                max_sev = sev

        sev_display = _severity_text(max_sev) if max_sev else Text("—", style="dim")
        rate_color = "red" if rate > 0.5 else ("yellow" if rate > 0.2 else "green")

        cat_table.add_row(
            cat_name.replace("_", " ").title(),
            str(len(results)),
            str(len(successful)),
            Text(f"{rate:.0%}", style=rate_color),
            sev_display,
        )

    console.print(cat_table)
    console.print()

    # ── FINDINGS ──────────────────────────────────────────────────────────────
    successful_results = sorted(
        [r for r in result.attack_results if r.analysis.success],
        key=lambda r: r.risk_score.raw_score,
        reverse=True,
    )

    if not successful_results:
        console.print(Panel(
            "[green]✓ No successful attacks detected. Target appears resistant to tested payloads.[/green]",
            border_style="green",
            title="[bold]Findings[/bold]",
        ))
    else:
        findings_table = Table(
            title=f"[bold red]Findings — {len(successful_results)} Successful Attack(s)[/bold red]",
            box=box.ROUNDED,
            header_style="bold red",
            border_style="red",
            show_lines=True,
        )
        findings_table.add_column("#", justify="center", width=4)
        findings_table.add_column("Payload", min_width=30)
        findings_table.add_column("Category", min_width=20)
        findings_table.add_column("Score", justify="center", width=8)
        findings_table.add_column("Severity", justify="center", width=12)
        findings_table.add_column("Confidence", justify="center", width=10)
        findings_table.add_column("Exposure", min_width=25)

        for idx, r in enumerate(successful_results, 1):
            findings_table.add_row(
                str(idx),
                f"[bold]{r.payload.name}[/bold]\n[dim]{r.payload.id}[/dim]",
                r.payload.category.value.replace("_", " ").title(),
                f"[bold]{r.risk_score.raw_score:.4f}[/bold]",
                _severity_text(r.risk_score.severity),
                f"{r.analysis.confidence:.0%}",
                r.risk_score.exposure_type.replace("_", " "),
            )

        console.print(findings_table)
        console.print()

        # ── DETAILED FINDINGS (verbose) ────────────────────────────────────────
        if verbose and successful_results:
            console.print(Rule("[bold]Detailed Findings[/bold]", style="dim"))
            for idx, r in enumerate(successful_results, 1):
                sev_color = SEVERITY_COLORS[r.risk_score.severity]
                console.print()
                console.print(
                    Panel(
                        f"[bold]Payload:[/bold] {r.payload.content[:200]}{'...' if len(r.payload.content) > 200 else ''}\n\n"
                        f"[bold]Response:[/bold] {r.analysis.truncated_response}{'...' if len(r.analysis.raw_response) > 300 else ''}\n\n"
                        f"[bold]Signals:[/bold]\n" +
                        "\n".join(f"  • {s}" for s in r.analysis.signals_triggered) +
                        f"\n\n[bold]Explanation:[/bold] [dim]{r.risk_score.explanation}[/dim]",
                        title=f"[bold][{sev_color}]Finding #{idx}[/{sev_color}] — {r.payload.name}[/bold]",
                        border_style=sev_color,
                    )
                )

    console.print()
    console.print(Rule("[dim]End of Report[/dim]", style="dim"))
    console.print()


def export_json(result: ScanResult, output_path: str) -> None:
    """
    Export the full scan result to a JSON file.

    Args:
        result: ScanResult to export.
        output_path: Full path for the output JSON file.
    """
    by_category: dict[str, dict] = {}
    for r in result.attack_results:
        cat = r.payload.category.value
        if cat not in by_category:
            by_category[cat] = {"total": 0, "successful": 0, "payloads": []}
        by_category[cat]["total"] += 1
        if r.analysis.success:
            by_category[cat]["successful"] += 1

    successful_findings = [
        r for r in result.attack_results if r.analysis.success
    ]
    successful_findings.sort(key=lambda r: r.risk_score.raw_score, reverse=True)

    output = {
        "scan_meta": {
            "target_url": result.target_url,
            "model": result.model,
            "provider": result.provider,
            "start_time": datetime.fromtimestamp(result.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(result.end_time).isoformat(),
            "duration_seconds": result.duration_seconds,
            "total_payloads": result.total_payloads,
            "successful_attacks": result.successful_attacks,
            "success_rate": result.success_rate,
            "categories_tested": result.categories_tested,
        },
        "aggregate_risk": {
            "score": result.aggregate_risk.raw_score if result.aggregate_risk else None,
            "severity": result.aggregate_risk.severity.value if result.aggregate_risk else None,
            "explanation": result.aggregate_risk.explanation if result.aggregate_risk else None,
        },
        "category_summary": by_category,
        "findings": [
            {
                "rank": idx + 1,
                "payload_id": r.payload.id,
                "payload_name": r.payload.name,
                "category": r.payload.category.value,
                "owasp_ref": r.payload.owasp_ref,
                "tags": r.payload.tags,
                "risk_score": r.risk_score.raw_score,
                "severity": r.risk_score.severity.value,
                "confidence": r.analysis.confidence,
                "exposure_type": r.analysis.exposure_type,
                "signals_triggered": r.analysis.signals_triggered,
                "response_snippet": r.analysis.truncated_response,
                "latency_ms": r.llm_response.latency_ms,
            }
            for idx, r in enumerate(successful_findings)
        ],
        "all_results": [
            {
                "payload_id": r.payload.id,
                "payload_name": r.payload.name,
                "category": r.payload.category.value,
                "success": r.analysis.success,
                "confidence": r.analysis.confidence,
                "risk_score": r.risk_score.raw_score,
                "severity": r.risk_score.severity.value,
                "latency_ms": r.llm_response.latency_ms,
                "error": r.llm_response.error,
            }
            for r in result.attack_results
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    console.print(f"\n[green]✓ JSON report saved to:[/green] [bold]{output_path}[/bold]")
