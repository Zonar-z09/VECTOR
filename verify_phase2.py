"""
verify_phase2.py — Run all Phase 2 verification checks.

Phase 2 added: RemediationTestAgent (local sandbox retest), a real
multi-backend MCP ticketing integration, the two-turn ADK orchestrator
(human-in-the-loop across async tool calls), and the Batch Remediation UI.

Checks:
  1. Full pytest regression suite (123+ tests, includes Day 0-3 unit coverage)
  2. RemediationTestAgent — skip condition (no Ollama call unless sandbox FAILed)
  3. Ticketing — approval gate rejects unapproved calls before any MCP call
  4. Ticketing — all 3 backends (jira/servicenow/webhook) registered and callable
  5. Two-turn orchestrator, live — Turn 1 (triage) then Turn 2 (approve → ticket)
  6. full_pipeline.py drives the orchestrator as its live path (auto-approve)
  7. No secrets in tracked files (same check as verify_day3.py)

Live checks (5-6) call real Gemini, Ollama, and the MCP server — same
requirements as verify_day0-3.py (API keys in .env, `ollama serve` running).
"""

import asyncio
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

console = Console(force_terminal=True, highlight=False)
results = []


def check(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((name, status, detail))
    console.print(f"  {status}  {name}" + (f" — {detail}" if detail else ""))


# ── 1. Full pytest regression suite ───────────────────────────────────────────

console.print("\n[bold cyan]1. Full pytest regression suite[/bold cyan]")
try:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        capture_output=True, text=True, cwd=Path(__file__).parent,
    )
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    check("pytest suite", result.returncode == 0, last_line)
except Exception as e:
    check("pytest suite", False, str(e)[:80])


# ── 2. RemediationTestAgent skip condition ────────────────────────────────────

console.print("\n[bold cyan]2. RemediationTestAgent — skip condition[/bold cyan]")
try:
    from agents.remediation_test_agent import RemediationTestAgent

    agent = RemediationTestAgent()
    result = agent.test_remediation(
        vulnerability={"cve_id": "CVE-TEST-0001"},
        asset={"asset_id": "ASSET-TEST-01"},
        enrichment={},
        sandbox_result={"verdict": "PASS"},  # not FAIL — should skip, no Ollama call
    )
    check(
        "Skips Ollama call when sandbox verdict is not FAIL",
        result.get("remediation_verdict") == "NOT_APPLICABLE",
        f"verdict={result.get('remediation_verdict')}",
    )
except Exception as e:
    check("RemediationTestAgent skip condition", False, str(e)[:80])


# ── 3. Ticketing — approval gate ──────────────────────────────────────────────

console.print("\n[bold cyan]3. Ticketing — approval gate rejects unapproved calls[/bold cyan]")
try:
    from src.integrations.ticketing import create_ticket

    async def _try_unapproved():
        try:
            await create_ticket("VULN-VERIFY-0001", {"cve_id": "CVE-TEST-0001"}, backend="jira", approved=False)
            return False  # should have raised
        except ValueError:
            return True

    gate_held = asyncio.run(_try_unapproved())
    check("create_ticket(approved=False) raises before calling MCP", gate_held)
except Exception as e:
    check("Ticketing approval gate", False, str(e)[:80])


# ── 4. Ticketing — all backends registered ────────────────────────────────────

console.print("\n[bold cyan]4. Ticketing — all backends registered and callable[/bold cyan]")
try:
    from src.integrations.ticketing import TICKET_BACKENDS

    expected = {"jira", "servicenow", "webhook"}
    demo_report = {"cve_id": "CVE-TEST-0001", "asset_id": "ASSET-TEST-01", "risk_score": 0.9}
    all_callable = all(
        isinstance(TICKET_BACKENDS[name]("VULN-VERIFY-0001", demo_report, "TICK-VERIFY"), dict)
        for name in expected if name in TICKET_BACKENDS
    )
    check(
        "jira, servicenow, webhook all registered and produce dict payloads",
        expected.issubset(TICKET_BACKENDS.keys()) and all_callable,
        f"registered: {sorted(TICKET_BACKENDS.keys())}",
    )
except Exception as e:
    check("Ticketing backends", False, str(e)[:80])


# ── 5. Two-turn orchestrator, live ────────────────────────────────────────────

console.print("\n[bold cyan]5. Two-turn ADK orchestrator — live Turn 1 + Turn 2[/bold cyan]")
try:
    from agents.orchestrator import run_turn_one, run_turn_two

    async def _run_two_turns():
        turn1 = await run_turn_one("CVE-2021-44228", "ASSET-005", "VULN-VERIFY-0002")
        turn2 = await run_turn_two(turn1["runner"], turn1["session_id"], "APPROVED", backend="jira")
        return turn1, turn2

    turn1, turn2 = asyncio.run(_run_two_turns())
    report = turn1.get("report", {})
    ticket_result = turn2.get("ticket_result", {})

    check(
        "Turn 1 assembles a report with a risk score",
        "risk_score" in report,
        f"risk_score={report.get('risk_score')}",
    )
    check(
        "Turn 2 creates a ticket via the real MCP path on approval",
        ticket_result.get("status") == "success" and bool(ticket_result.get("ticket_id")),
        f"ticket_id={ticket_result.get('ticket_id')}",
    )
except Exception as e:
    check("Two-turn orchestrator", False, str(e)[:80])


# ── 6. full_pipeline.py drives the orchestrator (live path) ──────────────────

console.print("\n[bold cyan]6. full_pipeline.py — live orchestrator path, auto-approve[/bold cyan]")
try:
    from agents.full_pipeline import run_full_pipeline

    pipeline_results = run_full_pipeline(cve_id="CVE-2024-6387", auto_approve=True)
    delivered = any(r.get("status") == "delivered" for r in pipeline_results)
    has_ticket = any(r.get("ticket_id") for r in pipeline_results)
    ticket_id = next((r.get("ticket_id") for r in pipeline_results if r.get("ticket_id")), "N/A")

    check(
        "run_full_pipeline() delivers a ticket via the orchestrator",
        delivered and has_ticket,
        f"ticket={ticket_id}",
    )
except Exception as e:
    check("full_pipeline live path", False, str(e)[:80])


# ── 7. No secrets in tracked files ────────────────────────────────────────────

console.print("\n[bold cyan]7. Secret Hygiene — No Secrets in Tracked Files[/bold cyan]")
try:
    patterns = ["sk-ant", "AIzaSy", "AQ\\.Ab8", "63BC8BEE"]
    found_secrets = []

    for pattern in patterns:
        result = subprocess.run(
            ["git", "grep", "-i", pattern, "--", "*.py", "*.txt", "*.json", "*.md", "*.yml"],
            capture_output=True, text=True, cwd=Path(__file__).parent,
        )
        if result.stdout.strip():
            lines = [
                l for l in result.stdout.strip().split("\n")
                if l and ".env" not in l and "verify_day" not in l and "verify_phase2" not in l
            ]
            if lines:
                found_secrets.extend(lines)

    check(
        "No secrets in tracked Python/config files",
        len(found_secrets) == 0,
        "Clean" if not found_secrets else f"{len(found_secrets)} potential leak(s) found",
    )
except Exception as e:
    check("Secret hygiene", False, str(e)[:80])


# ── Summary ───────────────────────────────────────────────────────────────────

console.print("\n")
table = Table(title="Phase 2 Verification Summary")
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
