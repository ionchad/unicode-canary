from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
from collections import defaultdict

console = Console()

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold orange3",
    "LOW":      "dim white",
}

CATEGORY_LABELS = {
    "bidi":       "BiDi Override",
    "zero_width": "Zero-Width",
    "tag":        "Tag/AI Inject",
    "homoglyph":  "Homoglyph",
    "pua":        "PUA Encoded",
}


def print_banner():
    banner = Text()
    banner.append("  unicode", style="bold white")
    banner.append("-canary", style="bold yellow")
    banner.append(" 🐦", style="")
    banner.append("  v1.0.0\n", style="dim white")
    banner.append("  Invisible Unicode Threat Scanner\n", style="dim cyan")
    console.print(Panel(banner, border_style="yellow", padding=(0, 2)))


def print_scan_start(target: str):
    console.print(f"\n[dim]Scanning:[/dim] [bold cyan]{target}[/bold cyan]\n")


def print_finding(finding, index: int):
    risk_color = RISK_COLORS.get(finding.risk_level, "white")
    category_label = CATEGORY_LABELS.get(finding.category, finding.category)

    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
    table.add_column("Key", style="dim", width=18)
    table.add_column("Value")

    table.add_row("Risk",       f"[{risk_color}]{finding.risk_level}[/{risk_color}]")
    table.add_row("Category",   category_label)
    table.add_row("File",       f"[cyan]{finding.file_path}[/cyan]")
    table.add_row("Location",   f"Line [bold]{finding.line_number}[/bold], Col [bold]{finding.column}[/bold]")
    table.add_row("Character",  f"[bold red]{finding.char_unicode}[/bold red]  ({finding.char_name})")
    table.add_row("Context",    f"[dim]{finding.context_safe}[/dim]")
    table.add_row("Line",       f"[dim white on grey11] {finding.line_preview} [/dim white on grey11]")

    console.print(Panel(
        table,
        title=f"[{risk_color}]Finding #{index}[/{risk_color}]",
        border_style=risk_color.replace("bold ", ""),
        padding=(0, 1),
    ))


def print_summary(result, elapsed: float):
    console.print()

    by_category = defaultdict(int)
    by_risk = defaultdict(int)
    for f in result.findings:
        by_category[f.category] += 1
        by_risk[f.risk_level] += 1

    stats = Table(title="Scan Summary", box=box.ROUNDED, border_style="dim white")
    stats.add_column("Metric", style="dim")
    stats.add_column("Count", justify="right")

    stats.add_row("Files scanned",         str(result.files_scanned))
    stats.add_row("Files with threats",     f"[bold red]{result.files_with_findings}[/bold red]")
    stats.add_row("Total findings",         f"[bold yellow]{result.total_findings}[/bold yellow]")
    stats.add_row("Scan time",              f"{elapsed:.2f}s")
    console.print(stats)

    if result.findings:
        console.print()
        breakdown = Table(title="Findings Breakdown", box=box.SIMPLE)
        breakdown.add_column("Category")
        breakdown.add_column("Count", justify="right")
        breakdown.add_column("Risk")

        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            label = CATEGORY_LABELS.get(cat, cat)
            sample = next(f for f in result.findings if f.category == cat)
            risk_color = RISK_COLORS.get(sample.risk_level, "white")
            breakdown.add_row(
                label,
                str(count),
                f"[{risk_color}]{sample.risk_level}[/{risk_color}]"
            )
        console.print(breakdown)

    console.print()
    if result.total_findings == 0:
        console.print(Panel(
            "[bold green]Clean![/bold green]  No suspicious Unicode characters detected.",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"[bold red]THREATS DETECTED[/bold red]  "
            f"Found [bold]{result.total_findings}[/bold] suspicious character(s) "
            f"in [bold]{result.files_with_findings}[/bold] file(s).\n"
            f"[dim]Review each finding above. Do NOT run or merge this code until verified.[/dim]",
            border_style="red"
        ))

    if result.errors:
        console.print(f"\n[dim]Skipped {len(result.errors)} file(s) due to read errors.[/dim]")