import time
import click
from unicode_canary.scanner import scan_file, scan_directory, DEFAULT_EXTENSIONS
from unicode_canary.reporter import (
    console, print_banner, print_scan_start,
    print_finding, print_summary
)


@click.group()
def cli():
    pass

@cli.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--no-recursive", is_flag=True, default=False,
              help="Only scan the toplevel directory, not subdirectories")
@click.option("--ext", multiple=True,
              help="File extensions to scan (e.g., --ext .py --ext .js)")
@click.option("--show-all", is_flag=True, default=False,
              help="Show all findings in detail (default: show first 20)")
@click.option("--quiet", is_flag=True, default=False,
              help="Only print the summary, not individual findings")
def scan(target, no_recursive, ext, show_all, quiet):
    import os
    print_banner()
    print_scan_start(target)

    extensions = set(ext) if ext else DEFAULT_EXTENSIONS
    start_time = time.time()
    if os.path.isfile(target):
        findings, error = scan_file(target)
        elapsed = time.time() - start_time

        if error:
            console.print(f"[red]Error:[/red] {error}")
            return
        from unicode_canary.scanner import ScanResult
        result = ScanResult(
            files_scanned=1,
            files_with_findings=1 if findings else 0,
            total_findings=len(findings),
            findings=findings,
        )

        if not quiet:
            limit = len(findings) if show_all else min(20, len(findings))
            for i, finding in enumerate(findings[:limit], start=1):
                print_finding(finding, i)
            if len(findings) > 20 and not show_all:
                console.print(f"\n[dim]...and {len(findings) - 20} more. Use --show-all to see everything.[/dim]")

        print_summary(result, elapsed)

    else:
        result = scan_directory(
            target,
            extensions=extensions,
            recursive=not no_recursive,
        )
        elapsed = time.time() - start_time

        if not quiet:
            limit = len(result.findings) if show_all else min(20, len(result.findings))
            for i, finding in enumerate(result.findings[:limit], start=1):
                print_finding(finding, i)
            if result.total_findings > 20 and not show_all:
                console.print(
                    f"\n[dim]...and {result.total_findings - 20} more findings. "
                    f"Use --show-all to see everything.[/dim]"
                )

        print_summary(result, elapsed)


@cli.command()
def demo():
    import tempfile, os
    print_banner()

    demo_content = (
        "# Safe Python file\n"
        "def check_admin(user):\n"
        "    # Normal comment\n"
        "    return user.role == 'admin'\n"
        "\n"
        "# ===== ATTACK ZONE BELOW =====\n"
        "\n"
        "# Bidi attack: the next line contains U+202E (Right-to-Left Override)\n"
        f"access_level = \u202E'user'  # Looks different when rendered\n"
        "\n"
        "# Zero-width attack: empty string that's not empty\n"
        f"secret = '\u200B\u200C\u200D\u200B'  # Contains hidden binary payload\n"
        "\n"
        "# Homoglyph attack: 'admin' with Cyrillic 'а'\n"
        f"def \u0430dmin_check():  # Looks like 'admin_check' but isn't\n"
        "    pass\n"
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(demo_content)
        temp_path = f.name

    try:
        console.print(f"[dim]Running demo against temporary file:[/dim] [cyan]{temp_path}[/cyan]\n")
        findings, error = scan_file(temp_path)

        from unicode_canary.scanner import ScanResult
        result = ScanResult(
            files_scanned=1,
            files_with_findings=1 if findings else 0,
            total_findings=len(findings),
            findings=findings,
        )

        for i, finding in enumerate(findings, start=1):
            print_finding(finding, i)

        import time
        print_summary(result, 0.01)
    finally:
        os.unlink(temp_path)


if __name__ == "__main__":
    cli()