"""
CLI entry point — VECTOR Vulnerability Triage & Remediation System.

CLI Skill design decisions:
  - `vector run --cve CVE-XXXX` runs the full pipeline on a specific CVE,
    selecting the highest-priority asset pairing automatically.
  - `vector run --top N` runs on the top N scored vulnerabilities.
  - `--auto-approve` bypasses the human gate for automated testing ONLY.
    In production, this flag should be disabled or require elevated privilege.

Run: python vector.py --help
"""

import sys
import click
from rich.console import Console
from rich.table import Table

console = Console(force_terminal=True, highlight=False)


@click.group()
def cli():
    """VECTOR — AI Vulnerability Triage & Remediation System."""
    pass


@cli.command()
def status():
    """Show system status and loaded assets."""
    import json
    from pathlib import Path

    console.print("\n[bold cyan]AI Vulnerability Triage System[/bold cyan]")
    console.print("[dim]Day 0 — Scaffold verification[/dim]\n")

    data_dir = Path(__file__).parent.parent / "data"

    # Assets
    assets_file = data_dir / "assets.json"
    if assets_file.exists():
        data = json.loads(assets_file.read_text())
        assets = data.get("assets", [])
        table = Table(title=f"Asset Inventory ({len(assets)} assets)")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Environment", style="yellow")
        table.add_column("Business Tag", style="magenta")
        table.add_column("Internet Exposed", style="red")
        for a in assets[:5]:
            table.add_row(
                a["asset_id"],
                a["name"],
                a["environment"],
                a["business_tag"],
                "[YES]" if a["internet_exposed"] else "[NO]",
            )
        if len(assets) > 5:
            table.add_row("...", f"({len(assets) - 5} more)", "", "", "")
        console.print(table)
    else:
        console.print("[red]❌ assets.json not found[/red]")

    # CVE seeds
    cve_file = data_dir / "cve_seed_list.json"
    if cve_file.exists():
        data = json.loads(cve_file.read_text())
        cves = data.get("cves", [])
        console.print(f"\n[green]✅ CVE seed list loaded:[/green] {len(cves)} CVEs")
        for cve in cves[:3]:
            console.print(f"  • [bold]{cve['cve_id']}[/bold] — CVSS {cve['cvss_score']} — {cve['severity']}")
        if len(cves) > 3:
            console.print(f"  [dim]...and {len(cves) - 3} more[/dim]")
    else:
        console.print("[red]❌ cve_seed_list.json not found[/red]")


@cli.command()
def verify():
    """Run all Day 0 verification checks."""
    console.print("\n[bold]Running Day 0 verification checks...[/bold]\n")
    console.print("[dim]Run python verify_day0.py for the full check suite.[/dim]")


@cli.command()
@click.option("--cve", default=None, help="Specific CVE ID to process (e.g. CVE-2021-44228)")
@click.option("--asset", default=None, help="Specific Asset ID to pair with --cve")
@click.option("--top", default=None, type=int, help="Process top N highest-priority vulnerabilities")
@click.option("--auto-approve", is_flag=True, default=False,
              help="[TEST ONLY] Skip human gate — never use in production")
def run(cve, asset, top, auto_approve):
    """
    Run the full vulnerability triage pipeline.

    Examples:

      vector run --cve CVE-2021-44228

      vector run --cve CVE-2024-6387 --asset ASSET-001

      vector run --top 5

      vector run --top 3 --auto-approve   (automated testing only)
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from agents.full_pipeline import run_full_pipeline

    if not cve and not top:
        console.print("[yellow]Hint:[/yellow] specify --cve CVE-XXXX or --top N")
        console.print("[dim]Example: python vector.py run --cve CVE-2021-44228[/dim]")
        return

    results = run_full_pipeline(
        cve_id=cve,
        asset_id=asset,
        top_n=top,
        auto_approve=auto_approve,
    )

    delivered = [r for r in results if r.get("status") == "delivered"]
    rejected = [r for r in results if r.get("status") == "rejected"]

    console.print(f"\n[bold]Summary:[/bold] {len(delivered)} delivered, {len(rejected)} rejected")
    for r in delivered:
        console.print(f"  [green]✅[/green] {r['cve_id']} × {r['asset_id']} → {r.get('ticket_id', 'N/A')}")
    for r in rejected:
        console.print(f"  [red]❌[/red] {r['cve_id']} × {r['asset_id']} → rejected")


if __name__ == "__main__":
    cli()
