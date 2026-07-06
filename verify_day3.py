"""
verify_day3.py — Run all Day 3 verification checks.

Checks:
  1. CLI help — vector.py responds to --help (CLI skill is importable)
  2. Full pipeline on CVE-2021-44228 (Log4Shell) — auto-approve
  3. Full pipeline on CVE-2024-6387 (OpenSSH regreSSHion) — auto-approve
  4. Full pipeline on CVE-2024-3094 (XZ Utils backdoor) — auto-approve
  5. Human gate blocks delivery — mock stdin with 'n' (reject)
  6. No secrets in tracked files — git grep check
"""

import os
import sys
import json
import subprocess
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv

load_dotenv()

console = Console(force_terminal=True, highlight=False)
results = []


def check(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((name, status, detail))
    console.print(f"  {status}  {name}" + (f" — {detail}" if detail else ""))


# ── 1. CLI importable ─────────────────────────────────────────────────────────

console.print("\n[bold cyan]1. CLI Skill (vector.py)[/bold cyan]")
try:
    from click.testing import CliRunner
    from cli.main import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    check("CLI -- --help", result.exit_code == 0, "VECTOR CLI responds to --help")

    result2 = runner.invoke(cli, ["run", "--help"])
    check("CLI run --help", result2.exit_code == 0, "'run' command registered")
except Exception as e:
    check("CLI Skill", False, str(e)[:80])


# ── 2–4. Full pipeline on 3 different CVEs (auto-approve) ────────────────────

console.print("\n[bold cyan]2-4. Full Pipeline — 3 CVEs (auto-approve)[/bold cyan]")

TEST_CVES = [
    ("CVE-2021-44228", "Log4Shell"),
    ("CVE-2024-6387", "OpenSSH regreSSHion"),
    ("CVE-2024-3094", "XZ Utils backdoor"),
]

try:
    from agents.full_pipeline import run_full_pipeline

    for cve_id, cve_name in TEST_CVES:
        try:
            console.print(f"\n  Running pipeline for [bold]{cve_id}[/bold] ({cve_name})...")
            pipeline_results = run_full_pipeline(
                cve_id=cve_id,
                auto_approve=True,  # Testing only — skip human gate
            )
            ran = len(pipeline_results) > 0
            delivered = any(r.get("status") == "delivered" for r in pipeline_results)
            has_ticket = any(r.get("ticket_id") for r in pipeline_results)
            ticket_id = next((r.get("ticket_id") for r in pipeline_results if r.get("ticket_id")), "N/A")

            check(
                f"Pipeline — {cve_id}",
                ran and delivered and has_ticket,
                f"Status: delivered, ticket={ticket_id}",
            )
        except Exception as e:
            check(f"Pipeline — {cve_id}", False, str(e)[:80])

except Exception as e:
    for cve_id, _ in TEST_CVES:
        check(f"Pipeline — {cve_id}", False, str(e)[:80])


# ── 5. Human gate blocks delivery ────────────────────────────────────────────

console.print("\n[bold cyan]5. Human Gate — Blocks Delivery on Rejection[/bold cyan]")
try:
    from agents.full_pipeline import run_full_pipeline

    # Mock stdin to simulate analyst typing 'n' (reject)
    with patch("builtins.input", return_value="n"):
        console.print("  Simulating analyst rejection (input='n')...")
        pipeline_results = run_full_pipeline(
            cve_id="CVE-2024-4577",
            auto_approve=False,  # Use the real human gate
        )
        all_rejected = all(r.get("status") == "rejected" for r in pipeline_results)
        no_tickets = all(not r.get("ticket_id") for r in pipeline_results)
        check(
            "Human gate — rejection blocks delivery",
            all_rejected and no_tickets,
            "status=rejected, no ticket created",
        )
except Exception as e:
    check("Human gate — rejection blocks delivery", False, str(e)[:80])


# ── 6. No secrets in tracked files ───────────────────────────────────────────

console.print("\n[bold cyan]6. Secret Hygiene — No Secrets in Tracked Files[/bold cyan]")
try:
    # Run git grep for known secret patterns
    patterns = ["sk-ant", "AIzaSy", "AQ\\.Ab8", "63BC8BEE"]
    found_secrets = []

    for pattern in patterns:
        result = subprocess.run(
            ["git", "grep", "-i", pattern, "--", "*.py", "*.txt", "*.json", "*.md", "*.yml"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent,
        )
        if result.stdout.strip():
            # Filter out .env.example and verify_day* (they reference placeholders/patterns)
            lines = [
                l for l in result.stdout.strip().split("\n")
                if l and ".env" not in l and "verify_day" not in l
            ]
            if lines:
                found_secrets.extend(lines)

    check(
        "No secrets in tracked Python/config files",
        len(found_secrets) == 0,
        f"{'Clean' if not found_secrets else f'{len(found_secrets)} potential leak(s) found'}",
    )

    # Also check .env is gitignored
    gitignore = Path(".gitignore").read_text()
    check(
        ".env in .gitignore",
        ".env" in gitignore,
        ".env excluded from version control",
    )

except Exception as e:
    check("Secret hygiene", False, str(e)[:80])


# ── Summary ───────────────────────────────────────────────────────────────────

console.print("\n")
table = Table(title="Day 3 Verification Summary")
table.add_column("Check", style="white")
table.add_column("Result", style="bold")
table.add_column("Detail", style="dim")
for name, status, detail in results:
    color = "green" if "PASS" in status else "red"
    table.add_row(name, f"[{color}]{status}[/{color}]", detail)
console.print(table)

passed_count = sum(1 for _, s, _ in results if "PASS" in s)
console.print(f"\n[bold]{passed_count}/{len(results)} checks passed[/bold]")

if passed_count < len(results):
    sys.exit(1)
