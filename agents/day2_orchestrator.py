"""
agents/day2_orchestrator.py

ADK Orchestrator — wires EnrichmentAgent and SandboxAgent into a
single pipeline with a defined handoff.

The orchestrator is an ADK Agent that uses two tool functions:
  1. enrich_cve()    — calls EnrichmentAgent (Claude, cloud)
  2. validate_asset() — calls SandboxAgent (Ollama, local only)

Handoff contract:
  enrich_cve output → passed as enrichment context to validate_asset

Usage:
  python agents/day2_orchestrator.py CVE-2021-44228 ASSET-005
"""

import os
import json
import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agents.enrichment_agent import EnrichmentAgent
from agents.sandbox_agent import SandboxAgent
from src.db.database import get_db_connection

load_dotenv()

# ── Shared agent instances ────────────────────────────────────────────────────

_enrichment_agent = EnrichmentAgent()
_sandbox_agent = SandboxAgent()


# ── Tool Functions (registered with ADK) ─────────────────────────────────────

def enrich_cve(cve_id: str) -> str:
    """
    Tool: Enrich a CVE using the cloud-based Claude agent.
    Checks write-once cache first; calls Claude only on cache miss.
    Returns JSON string with enrichment result.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT description, cvss_score FROM cves WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return json.dumps({"error": f"CVE {cve_id} not found in database"})

    result = _enrichment_agent.enrich(
        cve_id=cve_id,
        description=row["description"],
        cvss_score=row["cvss_score"],
    )
    return json.dumps(result)


def validate_asset(asset_id: str, cve_id: str, enrichment_json: str) -> str:
    """
    Tool: Validate exploitability using the local Ollama sandbox agent.
    Accepts the enrichment JSON from enrich_cve as context.
    Returns JSON string with PASS/FAIL/PARTIAL verdict and rationale.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
    asset_row = cursor.fetchone()
    cursor.execute(
        "SELECT * FROM vulnerabilities WHERE asset_id = ? AND cve_id = ?",
        (asset_id, cve_id),
    )
    vuln_row = cursor.fetchone()
    cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve_row = cursor.fetchone()
    conn.close()

    if not asset_row:
        return json.dumps({"error": f"Asset {asset_id} not found"})

    asset = dict(asset_row)
    vulnerability = dict(cve_row) if cve_row else {"cve_id": cve_id}

    try:
        enrichment = json.loads(enrichment_json) if enrichment_json else None
    except Exception:
        enrichment = None

    result = _sandbox_agent.validate(vulnerability, asset, enrichment)
    return json.dumps(result)


# ── ADK Orchestrator Agent ─────────────────────────────────────────────────────

def create_orchestrator() -> Agent:
    """Creates and returns the ADK orchestrator agent."""
    return Agent(
        name="vulnerability_orchestrator",
        model="gemini-2.5-flash",
        description="Orchestrates CVE enrichment (cloud) and asset validation (local) pipeline.",
        instruction="""You are a vulnerability management pipeline orchestrator.

When given a CVE ID and Asset ID, you must:
1. Call enrich_cve(cve_id) to get structured enrichment from the cloud agent.
2. Call validate_asset(asset_id, cve_id, enrichment_json) with the enrichment JSON to get the local sandbox verdict.
3. Summarize the combined result as: CVE, enrichment confidence, sandbox verdict, and key rationale.

Always call both tools in order. The handoff from step 1 to step 2 is the enrichment_json output.""",
        tools=[enrich_cve, validate_asset],
    )


# ── Pipeline Runner ───────────────────────────────────────────────────────────

async def run_pipeline(cve_id: str, asset_id: str) -> dict:
    """
    Runs the full enrichment → sandbox pipeline via ADK orchestration.
    Returns a combined result dict.
    """
    print(f"\n[Orchestrator] Starting pipeline: {cve_id} × {asset_id}")

    orchestrator = create_orchestrator()
    session_service = InMemorySessionService()
    runner = Runner(
        agent=orchestrator,
        app_name="vuln_pipeline",
        session_service=session_service,
    )

    session = await session_service.create_session(
        app_name="vuln_pipeline",
        user_id="pipeline_user",
    )

    message = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=f"Run the full pipeline for CVE ID: {cve_id} on Asset ID: {asset_id}")],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id="pipeline_user",
        session_id=session.id,
        new_message=message,
    ):
        if event.is_final_response():
            final_response = event.content.parts[0].text if event.content else ""
            break

    print(f"[Orchestrator] Pipeline complete.")
    return {
        "cve_id": cve_id,
        "asset_id": asset_id,
        "orchestrator_summary": final_response,
    }


if __name__ == "__main__":
    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asset_id = sys.argv[2] if len(sys.argv) > 2 else "ASSET-005"
    result = asyncio.run(run_pipeline(cve_id, asset_id))
    print("\n=== Pipeline Result ===")
    print(result["orchestrator_summary"])
