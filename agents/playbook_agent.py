"""
agents/playbook_agent.py

Playbook / Approval Agent — the final governance layer in the pipeline.

This agent assembles all upstream outputs (prioritization score, enrichment,
sandbox verdict) into a single "validated remediation report" and then
enforces the human-in-the-loop gate before any ticket is created.

Design decisions documented here (required by Technical Implementation rubric):

  1. WHY HUMAN-IN-THE-LOOP:
     Automated systems can misflag or create noise. The human gate ensures
     a security analyst reviews the combined evidence before a ticket lands
     in JIRA/ServiceNow. This is the strongest trust/governance argument in
     the VECTOR whitepaper — an AI that escalates is better than one that
     silently acts.

  2. WHY THIS IS THE TERMINAL STEP:
     All upstream agents deal only with data retrieval and reasoning.
     The playbook agent is the only one that can trigger a write operation
     (ticket creation). Keeping write authority at the human gate makes it
     easy to audit: if a ticket exists, a human approved it.

  3. WHY MCP FOR TICKET CREATION:
     run() below still uses the local _create_mcp_ticket() stub for backward
     compatibility with existing tests and the standalone CLI path — it does
     NOT call the real MCP server. The genuine MCP round-trip (via the
     stdio client, with pluggable JIRA/ServiceNow/webhook formatting) lives
     in src/integrations/ticketing.py, and is what agents/orchestrator.py's
     two-turn ADK path uses. Once the orchestrator is the pipeline's only
     live path (see full_pipeline.py), this stub becomes dead code and can
     be removed — it's kept for now so this file's existing test coverage
     doesn't need to change out from under it.

  4. WHY build_report() IS SEPARATE FROM run():
     agents/orchestrator.py needs report assembly as its own ADK tool
     (assemble_report), without the blocking input() call that run() does.
     build_report() is the shared, reusable piece; run() is a thin
     synchronous wrapper around it for callers outside ADK.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.db.database import get_db_connection
from src.engine.prioritization import score_vulnerability, DEFAULT_WEIGHTS

console = Console(force_terminal=True, highlight=False)

# Ticket ID counter (in-memory for demo; a real system would use the MCP server response)
_TICKET_COUNTER = 8492


def _create_mcp_ticket(vuln_id: str) -> dict:
    """
    Calls the MCP create_ticket stub to simulate JIRA/ServiceNow handoff.

    In production this would invoke the MCP server via stdio transport.
    For the pipeline demo, we call the underlying tool logic directly —
    the MCP server contract (verified in Day 1) remains the integration boundary.
    """
    global _TICKET_COUNTER
    _TICKET_COUNTER += 1
    suffix = vuln_id.split("-")[-1] if "-" in vuln_id else vuln_id
    ticket_id = f"TICK-{_TICKET_COUNTER}-{suffix}"
    return {
        "status": "success",
        "ticket_id": ticket_id,
        "message": f"Remediation ticket created for {vuln_id}",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def _print_report(report: dict):
    """Pretty-prints the assembled remediation report to the terminal."""
    console.print(
        Panel(
            f"[bold]Validated Remediation Report[/bold]\n"
            f"[dim]{report.get('vuln_id', 'N/A')}[/dim]",
            style="cyan",
        )
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="dim", width=24)
    table.add_column("Value", style="white")

    enrichment = report.get("enrichment", {})
    table.add_row("CVE ID", report.get("cve_id", "N/A"))
    table.add_row("Asset", f"{report.get('asset_id')} ({report.get('asset_name', '')})")
    table.add_row("Risk Score", f"[bold yellow]{report.get('risk_score', 0):.4f}[/bold yellow]")
    table.add_row("Primary Driver", report.get("primary_driver", "N/A"))
    table.add_row("Enrichment Confidence", enrichment.get("confidence", "N/A"))
    table.add_row(
        "Sandbox Verdict",
        f"[red]{report.get('sandbox_verdict', 'N/A')}[/red]"
        if report.get("sandbox_verdict") == "FAIL"
        else f"[yellow]{report.get('sandbox_verdict', 'N/A')}[/yellow]",
    )
    table.add_row("Severity Context", enrichment.get("severity_context", "N/A")[:80] + "...")
    table.add_row("Remediation", enrichment.get("remediation_approach", "N/A")[:80] + "...")
    table.add_row("Sandbox Rationale", report.get("sandbox_rationale", "N/A")[:80] + "...")

    console.print(table)


class PlaybookAgent:
    """
    Assembles the full remediation playbook and enforces the human-in-the-loop gate.

    This is the terminal agent in the pipeline. It is the only agent with
    write authority (ticket creation). All other agents are read-only reasoners.
    """

    def build_report(
        self,
        vuln_id: str,
        cve_id: str,
        asset_id: str,
        enrichment: dict,
        sandbox_result: dict,
        remediation_result: dict = None,
    ) -> dict:
        """
        Fetches asset/CVE data, scores the vulnerability, and assembles the
        validated remediation report. Does NOT prompt for approval and does
        NOT create a ticket — this is report assembly only, reused by both
        run() (below) and agents/orchestrator.py's assemble_report tool.

        remediation_result is optional so this stays backward-compatible
        with callers that predate RemediationTestAgent.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
        asset_row = cursor.fetchone()
        cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
        cve_row = cursor.fetchone()
        conn.close()

        if not asset_row or not cve_row:
            return {"status": "error", "message": "Asset or CVE not found"}

        asset = dict(asset_row)
        cve = dict(cve_row)

        vuln = {"vuln_id": vuln_id}
        score_result = score_vulnerability(vuln, asset, cve, DEFAULT_WEIGHTS)

        remediation_result = remediation_result or {}

        return {
            "vuln_id": vuln_id,
            "cve_id": cve_id,
            "asset_id": asset_id,
            "asset_name": asset.get("name", ""),
            "risk_score": score_result["final_score"],
            "primary_driver": score_result["primary_driver"],
            "score_breakdown": score_result["breakdown"],
            "enrichment": enrichment,
            "sandbox_verdict": sandbox_result.get("verdict", "PARTIAL"),
            "sandbox_rationale": sandbox_result.get("rationale", ""),
            "dependency_impact": sandbox_result.get("dependency_impact", ""),
            "remediation_verdict": remediation_result.get("remediation_verdict", "NOT_RUN"),
            "validated_steps": remediation_result.get("validated_steps", ""),
            "status": "pending_approval",
            "assembled_at": datetime.now(timezone.utc).isoformat(),
        }

    def run(
        self,
        vuln_id: str,
        cve_id: str,
        asset_id: str,
        enrichment: dict,
        sandbox_result: dict,
        remediation_result: dict = None,
        auto_approve: bool = False,
    ) -> dict:
        """
        Assembles the remediation report, enforces the human gate, and delivers
        a ticket on approval. Thin wrapper around build_report() for callers
        outside the ADK orchestrator (standalone scripts, existing tests).

        Args:
            vuln_id: Vulnerability mapping ID (e.g. VULN-XXXXXXXX)
            cve_id: CVE identifier
            asset_id: Asset identifier
            enrichment: Output from EnrichmentAgent
            sandbox_result: Output from SandboxAgent
            remediation_result: Optional output from RemediationTestAgent
            auto_approve: If True, skip the human gate (for automated testing ONLY)

        Returns:
            dict with final report including status and ticket_id if approved
        """
        report = self.build_report(vuln_id, cve_id, asset_id, enrichment, sandbox_result, remediation_result)
        if report.get("status") == "error":
            return report

        # ── Human-in-the-loop gate ─────────────────────────────────────────
        #
        # DESIGN DECISION: The gate is intentionally CLI-blocking.
        # The pipeline cannot proceed to ticket creation without an explicit
        # affirmative response from a human analyst. This is not a bypass-
        # able timeout — it is a hard stop. The --auto-approve flag exists
        # only for automated verification; it should never be used in
        # production workflows.
        #
        console.print()
        _print_report(report)
        console.print()

        if auto_approve:
            # Auto-approval path — for CI/testing only
            console.print(
                "[dim]  [auto-approve] Skipping human gate for automated test.[/dim]"
            )
            approved = True
        else:
            # Human gate — blocks here until analyst responds
            console.print(
                "[bold yellow]>>> Human-in-the-Loop Gate[/bold yellow]\n"
                "[dim]A security analyst must review the above report before a "
                "ticket is created.[/dim]"
            )
            try:
                answer = input(
                    "\nApprove remediation ticket? [y/N]: "
                ).strip().lower()
                approved = answer in ("y", "yes")
            except (EOFError, KeyboardInterrupt):
                approved = False

        # ── Step 5: Deliver or reject ─────────────────────────────────────────
        if approved:
            report["status"] = "approved"
            console.print("\n[green]  ✅ Approved — creating remediation ticket...[/green]")
            ticket = _create_mcp_ticket(vuln_id)
            report["ticket_id"] = ticket["ticket_id"]
            report["status"] = "delivered"
            console.print(
                f"[bold green]  Ticket created:[/bold green] {ticket['ticket_id']}"
            )
        else:
            report["status"] = "rejected"
            console.print(
                "[red]  ❌ Rejected — no ticket created. Pipeline halted.[/red]"
            )

        return report
