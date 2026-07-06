"""
agents/full_pipeline.py

End-to-end vulnerability triage pipeline.
Orchestrates all four agents through ADK:

  ingest → prioritize → enrich → validate → approve → deliver

Design decisions:

  WHY THIS ORDER:
    Prioritization runs first (before cloud calls) so we only enrich
    and sandbox the vulnerabilities that actually matter. This avoids
    burning API credits on low-priority noise.

  WHY ADK ORCHESTRATES THE WHOLE TRIAGE, INCLUDING APPROVAL:
    agents/orchestrator.py drives enrichment, sandbox validation, optional
    remediation testing, and report assembly as Turn 1 of an ADK session,
    then resumes that SAME session as Turn 2 once a human has approved or
    rejected — this is how blocking human input coexists with ADK's async
    tool-calling loop (see orchestrator.py's module docstring for the full
    two-turn design). This file just drives those two turns per target and
    keeps the CLI output/contract unchanged.

  WHY WRITE-ONCE CACHE MATTERS FOR THE PIPELINE:
    Running the pipeline on 3+ CVEs would call Gemini 3x without the
    cache. With the cache, repeated runs on the same CVE IDs (common
    in day-to-day operations) are free. The cache is checked before
    any cloud call in EnrichmentAgent.
"""

import sys
import json
import asyncio
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from rich.console import Console

from src.db.database import get_db_connection, init_db
from src.ingest.ingest_pipeline import main as run_ingest
from src.engine.prioritization import score_vulnerability, DEFAULT_WEIGHTS
from agents.orchestrator import run_turn_one, run_turn_two
from agents.playbook_agent import _print_report

load_dotenv()
console = Console(force_terminal=True, highlight=False)


def _get_vulnerabilities_by_cve(cve_id: str, asset_id: str = None) -> list:
    """
    Fetches vulnerability record(s) for a given CVE ID, optionally restricted
    to one asset. Returns asset + CVE + vuln_id triples, scored and sorted.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure the CVE exists
    cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve_row = cursor.fetchone()
    if not cve_row:
        conn.close()
        return []

    # Get asset pairing(s) for this CVE, restricted to asset_id if given
    query = """
        SELECT v.vuln_id, v.asset_id, v.cve_id, v.status,
               a.*, c.cvss_score, c.description, c.severity
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.asset_id
        JOIN cves c ON v.cve_id = c.cve_id
        WHERE v.cve_id = ?
    """
    params = [cve_id]
    if asset_id:
        query += " AND v.asset_id = ?"
        params.append(asset_id)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        # Create a synthetic pairing — against the requested asset if one was
        # given, otherwise the highest-risk internet-exposed production asset.
        conn = get_db_connection()
        cursor = conn.cursor()
        if asset_id:
            cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        else:
            cursor.execute(
                "SELECT * FROM assets WHERE internet_exposed = 1 AND environment = 'production' LIMIT 1"
            )
        asset_row = cursor.fetchone()
        conn.close()

        if asset_row:
            asset = dict(asset_row)
            cve = dict(cve_row)
            vuln = {"vuln_id": f"VULN-SYNTH-{cve_id.replace('-', '')}"}
            score = score_vulnerability(vuln, asset, cve, DEFAULT_WEIGHTS)
            return [{
                "vuln_id": vuln["vuln_id"],
                "asset_id": asset["asset_id"],
                "cve_id": cve_id,
                "risk_score": score["final_score"],
                "asset": asset,
                "cve": cve,
            }]
        return []

    # Score and sort by priority
    scored = []
    for row in rows:
        d = dict(row)
        vuln = {"vuln_id": d["vuln_id"]}
        asset = {k: d[k] for k in d if k in [
            "asset_id", "name", "type", "os", "internet_exposed",
            "environment", "business_tag", "patch_cadence_days", "dependencies_json"
        ]}
        cve = {"cve_id": d["cve_id"], "cvss_score": d["cvss_score"]}
        score = score_vulnerability(vuln, asset, cve, DEFAULT_WEIGHTS)
        scored.append({
            "vuln_id": d["vuln_id"],
            "asset_id": d["asset_id"],
            "cve_id": d["cve_id"],
            "risk_score": score["final_score"],
            "asset": asset,
            "cve": {
                "cve_id": d["cve_id"],
                "cvss_score": d["cvss_score"],
                "description": d["description"],
                "severity": d["severity"],
            },
        })

    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def _get_top_vulnerabilities(n: int) -> list:
    """
    Fetches all vulnerabilities from the DB, scores them, and returns the top N.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT v.vuln_id, v.asset_id, v.cve_id,
               a.internet_exposed, a.environment, a.business_tag,
               a.dependencies_json, a.name as asset_name,
               c.cvss_score, c.description, c.severity
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.asset_id
        JOIN cves c ON v.cve_id = c.cve_id
        """
    )
    rows = cursor.fetchall()
    conn.close()

    scored = []
    for row in rows:
        d = dict(row)
        vuln = {"vuln_id": d["vuln_id"]}
        asset = {k: d[k] for k in d if k in [
            "internet_exposed", "environment", "business_tag", "dependencies_json"
        ]}
        asset["asset_id"] = d["asset_id"]
        cve = {"cve_id": d["cve_id"], "cvss_score": d["cvss_score"]}
        score = score_vulnerability(vuln, asset, cve, DEFAULT_WEIGHTS)
        scored.append({
            "vuln_id": d["vuln_id"],
            "asset_id": d["asset_id"],
            "cve_id": d["cve_id"],
            "risk_score": score["final_score"],
            "asset": asset,
            "cve": {
                "cve_id": d["cve_id"],
                "cvss_score": d["cvss_score"],
                "description": d["description"],
                "severity": d["severity"],
            },
        })

    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)[:n]


async def _process_target(target: dict, auto_approve: bool) -> dict:
    """
    Drives one target through both ADK orchestrator turns: Turn 1 (automated
    triage) prints the assembled report, then the human gate runs (or is
    skipped via auto_approve), then Turn 2 resumes the SAME session with the
    decision and, on approval, creates the ticket via the real MCP path.
    """
    turn1 = await run_turn_one(target["cve_id"], target["asset_id"], target["vuln_id"])
    report = turn1["report"]

    console.print()
    _print_report(report)
    console.print()

    if auto_approve:
        console.print("[dim]  [auto-approve] Skipping human gate for automated test.[/dim]")
        decision = "APPROVED"
    else:
        console.print(
            "[bold yellow]>>> Human-in-the-Loop Gate[/bold yellow]\n"
            "[dim]A security analyst must review the above report before a "
            "ticket is created.[/dim]"
        )
        try:
            answer = input("\nApprove remediation ticket? [y/N]: ").strip().lower()
            decision = "APPROVED" if answer in ("y", "yes") else "REJECTED"
        except (EOFError, KeyboardInterrupt):
            decision = "REJECTED"

    turn2 = await run_turn_two(turn1["runner"], turn1["session_id"], decision)
    ticket_result = turn2["ticket_result"]

    if decision == "APPROVED" and ticket_result.get("status") == "success":
        report["status"] = "delivered"
        report["ticket_id"] = ticket_result["ticket_id"]
        console.print(f"[bold green]  Ticket created:[/bold green] {ticket_result['ticket_id']}")
    else:
        report["status"] = "rejected"
        console.print("[red]  ❌ Rejected — no ticket created. Pipeline halted.[/red]")

    return report


def run_full_pipeline(
    cve_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    top_n: Optional[int] = None,
    auto_approve: bool = False,
) -> list:
    """
    Runs the complete ingestion → prioritize → enrich → validate → approve → deliver pipeline.

    Args:
        cve_id: Specific CVE to process (exclusive with top_n)
        asset_id: Specific asset to pair with cve_id (optional)
        top_n: Process the top N highest-priority vulnerabilities
        auto_approve: Skip the human gate (for automated testing ONLY)

    Returns:
        List of final report dicts for each vulnerability processed.
    """
    console.print("\n[bold cyan]VECTOR Vulnerability Triage Pipeline[/bold cyan]")
    console.print("[dim]─────────────────────────────────────────────[/dim]")

    # ── Stage 1: Ensure data is ingested ─────────────────────────────────────
    console.print("\n[bold]Stage 1:[/bold] Checking data lake...")
    init_db()
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    conn.close()
    if count == 0:
        console.print("  Data lake empty — running ingestion...")
        run_ingest()
    else:
        console.print(f"  Data lake ready: {count} vulnerabilities")

    # ── Stage 2: Prioritize — select targets ─────────────────────────────────
    console.print("\n[bold]Stage 2:[/bold] Prioritizing targets...")
    if cve_id:
        targets = _get_vulnerabilities_by_cve(cve_id, asset_id=asset_id)
        if not targets:
            label = f"{cve_id} × {asset_id}" if asset_id else cve_id
            console.print(f"  [yellow]No pairing found for {label}.[/yellow]")
        targets = targets[:1]  # Take highest-priority asset for this CVE
    elif top_n:
        targets = _get_top_vulnerabilities(top_n)
    else:
        targets = _get_top_vulnerabilities(1)

    console.print(f"  Selected {len(targets)} target(s) for processing.")

    results = []
    for i, target in enumerate(targets, 1):
        console.print(
            f"\n[bold]Processing {i}/{len(targets)}:[/bold] "
            f"{target['cve_id']} × {target['asset_id']} "
            f"(score={target['risk_score']:.4f})"
        )
        console.print("[dim]─────────────────────────────────────────────[/dim]")

        # ── Stage 3-5: ADK Turn 1 — enrich, validate, (maybe) test remediation,
        # assemble report. All automated, no human involved yet.
        console.print("\n[bold]Stage 3-5:[/bold] ADK orchestrator — triage (Turn 1)...")
        final_report = asyncio.run(
            _process_target(target, auto_approve)
        )
        results.append(final_report)

    console.print("\n[bold cyan]Pipeline complete.[/bold cyan]")
    console.print(
        f"Processed {len(results)} vulnerability/asset pair(s). "
        f"Delivered: {sum(1 for r in results if r.get('status') == 'delivered')}, "
        f"Rejected: {sum(1 for r in results if r.get('status') == 'rejected')}"
    )

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run the full VECTOR pipeline")
    parser.add_argument("--cve", help="Specific CVE ID to process")
    parser.add_argument("--asset", help="Specific Asset ID (use with --cve)")
    parser.add_argument("--top", type=int, help="Process top N vulnerabilities")
    parser.add_argument("--auto-approve", action="store_true", help="Skip human gate")
    args = parser.parse_args()

    results = run_full_pipeline(
        cve_id=args.cve,
        asset_id=args.asset,
        top_n=args.top,
        auto_approve=args.auto_approve,
    )
    print(f"\nFinal: {len(results)} report(s) generated.")
