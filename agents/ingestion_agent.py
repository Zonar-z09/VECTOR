"""
agents/ingestion_agent.py

Ingestion Sub-Agent — the extensibility hook for pulling assets and
vulnerabilities from external security tools instead of only the static
seed files in data/. Mirrors agents/orchestrator.py's sub-agent pattern:
an ADK Agent (Gemini, for the tool-calling turn itself) wraps a plain-Python,
local-only Ollama class that does the actual reasoning over asset/endpoint
data — same split as agents/sandbox_agent.py + orchestrator.py's
create_sandbox_agent().

Sources are pluggable connectors (src/ingest/connectors.py): code-scan/SAST,
EDR, Google Security Command Center (all 7 detector categories), Cloud Asset
Inventory, Artifact Analysis, Cloud DLP, IAM Recommender, plus two simplified
mocks (Chronicle SecOps, VirusTotal/Mandiant threat intel — see connectors.py
for why those two are simplifications, not realistic integrations). Adding a
real source later means writing one new fetch_* function there — nothing
here or in the DB schema needs to change.

Not wired into agents/orchestrator.py's per-CVE two-turn triage session:
ingestion is a bulk, upstream pipeline stage (like src/ingest/ingest_pipeline.py),
not a per-CVE decision, so it runs as its own standalone agent/session,
triggered from the CLI or the "External Sources" dashboard page.
"""

import json
import sys
import uuid
import asyncio
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agents.normalization_agent import NormalizationAgent
from src.ingest.connectors import fetch_all
from src.db.database import get_db_connection

load_dotenv()

GEMINI_MODEL = "gemini-2.5-flash"

_normalization_impl = NormalizationAgent()

# ── Queue + result sink — same rationale as orchestrator.py's sink ─────────
# The Gemini tool-calling turn never sees or retypes an asset_id/cve_id; it
# only knows "call the tool again" / "stop". All identifiers are generated
# and written to the DB here, in trusted Python.

_pending_queue: list[dict] = []
_last_ingestion_results: list[dict] = []


def process_next_record_tool() -> str:
    """
    Tool: pops one raw record off the pending queue, runs it through the
    local-only NormalizationAgent, and writes the resulting asset/CVE/
    vulnerability rows to the data lake. No arguments — the queue and all
    generated IDs are Python-managed, not model-supplied.
    """
    global _pending_queue, _last_ingestion_results

    if not _pending_queue:
        return json.dumps({"done": True, "total_processed": len(_last_ingestion_results)})

    record = _pending_queue.pop(0)
    conn = get_db_connection()
    cursor = conn.cursor()

    known_assets = [dict(row) for row in cursor.execute("SELECT asset_id, name FROM assets").fetchall()]
    result = _normalization_impl.normalize(record, known_assets)
    raw = record.get("raw", {})
    record_type = record.get("record_type", "vulnerability")

    # source_type written to the DB folds in the SCC category (e.g.
    # "gcp_scc:security_health_analytics") so rows stay filterable by
    # category without a schema change — still one string column.
    db_source_type = record["source_type"]
    if record.get("category"):
        db_source_type = f"{record['source_type']}:{record['category'].lower()}"

    # Resolve asset: use the matched one if it's real, otherwise create a new one.
    asset_id = result.get("matched_asset_id")
    if not asset_id or not any(a["asset_id"] == asset_id for a in known_assets):
        asset_id = f"ASSET-EXT-{uuid.uuid4().hex[:6].upper()}"
        new_name = (result.get("new_asset_name") or raw.get("hostname") or raw.get("repo")
                    or raw.get("display_name") or asset_id)
        cursor.execute(
            """
            INSERT OR REPLACE INTO assets
            (asset_id, name, type, os, internet_exposed, environment, business_tag,
             patch_cadence_days, dependencies_json, raw_data, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (asset_id, new_name, "external_finding", raw.get("os", "unknown"),
             bool(raw.get("public_ip", False)), result["environment"], result["business_tag"],
             30, "[]", json.dumps(raw), db_source_type),
        )

    if record_type == "asset":
        # Pure asset-metadata record (e.g. Cloud Asset Inventory) — there's
        # no vulnerability to create, just the asset row resolved above.
        conn.commit()
        conn.close()
        outcome = {
            "source_type": db_source_type,
            "record_type": "asset",
            "asset_id": asset_id,
            "cve_id": None,
            "vuln_id": None,
            "severity": None,
            "rationale": result["rationale"],
        }
        _last_ingestion_results.append(outcome)
        return json.dumps({"done": False, "processed": outcome, "remaining": len(_pending_queue)})

    # Resolve CVE: reuse a real CVE ID if the source gave one, otherwise mint
    # a pseudo-finding ID (most connectors emit non-CVE findings — EDR
    # detections, SCC categories, IAM recommendations — not every finding
    # maps to a CVE). Either way, a cves row must exist: vulnerabilities is
    # INNER JOINed to cves elsewhere (data_access.py's
    # get_prioritized_vulnerabilities()) — a reused real CVE ID that isn't
    # already in the seed list (e.g. Artifact Analysis findings) would
    # otherwise leave the vulnerability silently missing from every
    # downstream view. INSERT OR IGNORE is a no-op if the CVE is already
    # seeded (e.g. from data/cve_seed_list.json), so this never overwrites
    # real NVD data with the estimate below.
    cve_id = raw.get("cve")
    if not cve_id:
        cve_id = f"FINDING-{record['source_type'].upper()}-{uuid.uuid4().hex[:6].upper()}"

    description = (raw.get("message") or raw.get("detection_name") or raw.get("description")
                    or raw.get("vulnerability_type") or raw.get("recommendation")
                    or (f"Vulnerable package: {raw['package']}" if raw.get("package") else None)
                    or "External finding")
    cursor.execute(
        """
        INSERT OR IGNORE INTO cves (cve_id, description, cvss_score, severity, published, raw_data, source_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (cve_id, description, result["cvss_score_estimate"], result["severity"],
         datetime.now(timezone.utc).date().isoformat(), json.dumps(raw), db_source_type),
    )

    vuln_id = f"VULN-EXT-{uuid.uuid4().hex[:8].upper()}"
    cursor.execute(
        """
        INSERT INTO vulnerabilities (vuln_id, asset_id, cve_id, status, discovered_at, source_type)
        VALUES (?, ?, ?, 'open', ?, ?)
        """,
        (vuln_id, asset_id, cve_id, datetime.now(timezone.utc).isoformat(), db_source_type),
    )
    conn.commit()
    conn.close()

    outcome = {
        "source_type": db_source_type,
        "record_type": "vulnerability",
        "asset_id": asset_id,
        "cve_id": cve_id,
        "vuln_id": vuln_id,
        "severity": result["severity"],
        "rationale": result["rationale"],
    }
    _last_ingestion_results.append(outcome)
    return json.dumps({"done": False, "processed": outcome, "remaining": len(_pending_queue)})


def create_ingestion_agent() -> Agent:
    return Agent(
        name="ingestion_agent",
        model=GEMINI_MODEL,
        description=(
            "Ingests and normalizes findings from external security tools "
            "(code scanners, EDR, Google SCC) into the unified data lake."
        ),
        instruction="""You process a queue of pending records from external security tools.
Call process_next_record_tool() — it takes no arguments, it already knows the queue.
Each call processes exactly one record and tells you if more remain (done: false) or the queue is empty (done: true).
Keep calling it until you receive done: true, then summarize in 1-2 sentences how many records were ingested in total.""",
        tools=[process_next_record_tool],
    )


async def run_ingestion(sources: list[str] | None = None) -> dict:
    """
    Fetches raw records from the given source ids (or all sources), runs
    them through the ingestion agent, and returns a summary + per-record
    outcomes for display (e.g. by web/pages/6_External_Sources.py).
    """
    global _pending_queue, _last_ingestion_results
    _pending_queue = fetch_all(sources)
    _last_ingestion_results = []
    total_records = len(_pending_queue)

    agent = create_ingestion_agent()
    session_service = InMemorySessionService()
    runner = Runner(agent=agent, app_name="vector_ingestion", session_service=session_service)
    session = await session_service.create_session(app_name="vector_ingestion", user_id="pipeline_user")

    message = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=f"Ingest all {total_records} pending records now.")],
    )

    summary = ""
    async for event in runner.run_async(user_id="pipeline_user", session_id=session.id, new_message=message):
        if event.is_final_response():
            if event.content and event.content.parts:
                summary = event.content.parts[0].text or ""
        # No `break` — see agents/orchestrator.py's run_turn_one for why.

    return {
        "summary": summary,
        "results": list(_last_ingestion_results),
        "total_processed": len(_last_ingestion_results),
    }


if __name__ == "__main__":
    selected = sys.argv[1:] or None
    outcome = asyncio.run(run_ingestion(selected))
    print(outcome["summary"])
    print(json.dumps(outcome["results"], indent=2))
