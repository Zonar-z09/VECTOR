"""
agents/orchestrator.py

ADK Orchestrator — genuine multi-agent delegation, the live path for VECTOR.

A Root Orchestrator Agent delegates to four independent ADK sub-agents
(Enrichment, Sandbox, RemediationTest, Ticketing) via AgentTool — each
sub-agent is a real google.adk.agents.Agent with its own model turn and
its own tool(s), not a plain Python function dressed up as an "agent".
This supersedes the earlier single-agent-with-flat-tools design (see git
history) once the user asked for delegation to mirror a genuine
root-orchestrator → sub-agent architecture, and to move the cloud tier
from Claude to Gemini (native ADK support, no LiteLlm wrapper needed).

Supersedes agents/day2_orchestrator.py for pipeline purposes (kept as-is
for Day 2 history/reference).

═══════════════════════════════════════════════════════════════════════════
TWO-TURN SESSION DESIGN — unchanged from the original design; read before
changing anything below
═══════════════════════════════════════════════════════════════════════════

PlaybookAgent's human-approval gate used to be a blocking input() call.
That doesn't work inside ADK's async tool-calling loop. Rather than force a
blocking call into an async context, human approval is modeled as TWO TURNS
of the SAME ADK session:

  TURN 1 (fully automated, no human involved yet):
    Root delegates to enrichment_agent → sandbox_agent → (if exploitable)
    remediation_agent → assembles the report via a plain tool. The Root
    then stops and summarizes, stating it is awaiting human approval. The
    ticketing_agent sub-agent is NOT called in this turn.

  TURN 2 (triggered whenever the human responds — seconds or hours later):
    the driving code sends a new message into the SAME session_id:
    "HUMAN_DECISION: APPROVED" or "HUMAN_DECISION: REJECTED". Only on
    APPROVED does the Root delegate to the ticketing_agent sub-agent.

Both the CLI and the Streamlit UI drive this exact same two-turn session —
they only differ in HOW they collect the human's decision. run_turn_one /
run_turn_two / _standalone_demo keep the exact same external signature as
before, so full_pipeline.py and web/pages/5_Batch_Remediation.py did not
need to change for this rebuild.

DEFENSE IN DEPTH: the ticketing sub-agent's create_ticket_tool requires
approved: bool as an explicit argument, and the underlying
src.integrations.ticketing.create_ticket() hard-raises if it isn't
literally True. This is a code-enforced gate, not an instruction-following
gate — no amount of prompt injection across two LLM hops (Root →
ticketing_agent) changes that.

═══════════════════════════════════════════════════════════════════════════
WHY A MODULE-LEVEL RESULT SINK, NOT FREE-TEXT HANDOFF BETWEEN AGENTS
═══════════════════════════════════════════════════════════════════════════

AgentTool hands a natural-language request to a sub-agent and gets back
that sub-agent's natural-language final response — reliable for simple
instructions ("enrich this CVE"), unreliable for exact structured data
(a multi-field enrichment record, a full sandbox verdict) if the Root had
to read it back out of prose and re-forward it to the next sub-agent.
Instead, each sub-agent's OWN tool writes its structured result straight
into a module-level sink (_last_enrichment, _last_sandbox_result, etc.);
downstream tools read the sink directly in Python, never through an LLM's
retelling. The Root's LLM only ever needs to pass simple scalars (cve_id,
asset_id, vuln_id) between steps — exactly the same reliability profile as
the original flat-tool design already proved out live.

Same sequential-use caveat as before: this sink is safe only because one
target's both turns fully complete before the next target starts (true in
full_pipeline.py and in the Batch Remediation page). If that ever changes,
this needs to become session-keyed (e.g. via ToolContext.state) instead.
"""

import json
import sys
import asyncio
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types as genai_types

from agents.sandbox_agent import SandboxAgent
from agents.remediation_test_agent import RemediationTestAgent
from agents.playbook_agent import PlaybookAgent
from src.integrations.ticketing import create_ticket
from src.db.database import get_db_connection
from src.security.scrubber import scrub

load_dotenv()

GEMINI_MODEL = "gemini-2.5-flash"

# ── Shared plain-Python agent instances (local/Ollama tier — unchanged) ────

_sandbox_agent_impl = SandboxAgent()
_remediation_agent_impl = RemediationTestAgent()
_playbook_agent_impl = PlaybookAgent()

# ── Result sink — see module docstring ──────────────────────────────────────

_last_enrichment: dict = {}
_last_sandbox_result: dict = {}
_last_remediation_result: dict = {}
_last_report: dict = {}
_last_ticket_result: dict = {}

# The current target's IDs — set once by run_turn_one() from trusted Python
# values (never from an LLM). Downstream tools read from here instead of
# accepting cve_id/asset_id/vuln_id as model-supplied arguments: a live run
# showed a genuine failure mode where a sub-agent retyped a CVE ID one digit
# wrong across the Root -> sub-agent natural-language handoff
# ("CVE-2021-44228" -> "CVE-2021-44218"), silently losing the real CVE record.
# IDs are ground truth we already have — there's no reason to let an LLM
# reconstruct them from memory.
_current_target: dict = {}


# ═════════════════════════════════════════════════════════════════════════
# Enrichment Sub-Agent — Gemini-native cloud tier, public CVE data only
# ═════════════════════════════════════════════════════════════════════════

def fetch_and_scrub_cve() -> str:
    """
    Tool: fetches the CVE record (from the sink, not a model-supplied
    argument — see _current_target) and returns its SCRUBBED description, or
    the already-cached enrichment if one exists (write-once cache check).
    Scrubbing happens here, in Python, BEFORE any text reaches an LLM —
    never left to the model to do or skip.
    """
    global _last_enrichment
    cve_id = _current_target["cve_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,))
    cached = cursor.fetchone()
    if cached:
        conn.close()
        _last_enrichment = {
            "cve_id": cve_id,
            "severity_context": cached["severity_context"],
            "exploitation_intelligence": cached["exploitation_intelligence"],
            "remediation_approach": cached["remediation_approach"],
            "confidence": cached["confidence"],
            "from_cache": True,
            "redaction_log": [],
        }
        return json.dumps({"cached": True, **_last_enrichment})

    cursor.execute("SELECT description, cvss_score FROM cves WHERE cve_id = ?", (cve_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return json.dumps({"error": f"CVE {cve_id} not found"})

    scrubbed_desc, redactions = scrub(row["description"])
    return json.dumps({
        "cached": False,
        "cve_id": cve_id,
        "cvss_score": row["cvss_score"],
        "description": scrubbed_desc,
        "redaction_log": [r[0] for r in redactions],
    })


def save_enrichment(
    severity_context: str, exploitation_intelligence: str,
    remediation_approach: str, confidence: str,
) -> str:
    """
    Tool: the Enrichment sub-agent's OWN Gemini reasoning calls this with
    its structured analysis — the analysis itself happens in the sub-agent's
    model turn, not a hidden API call, and lands here as typed tool-call
    arguments (reliable) rather than free-text JSON the caller has to parse.
    cve_id comes from the sink, not a model argument — see _current_target.
    Write-once: INSERT OR IGNORE.
    """
    global _last_enrichment
    cve_id = _current_target["cve_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR IGNORE INTO enrichments
        (cve_id, severity_context, exploitation_intelligence, remediation_approach, confidence, enriched_at, raw_response)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (cve_id, severity_context, exploitation_intelligence, remediation_approach, confidence,
         datetime.now(timezone.utc).isoformat(), ""),
    )
    conn.commit()
    conn.close()

    _last_enrichment = {
        "cve_id": cve_id,
        "severity_context": severity_context,
        "exploitation_intelligence": exploitation_intelligence,
        "remediation_approach": remediation_approach,
        "confidence": confidence,
        "from_cache": False,
        "redaction_log": [],
    }
    return json.dumps({"status": "saved", **_last_enrichment})


def create_enrichment_agent() -> Agent:
    return Agent(
        name="enrichment_agent",
        model=GEMINI_MODEL,
        description="Analyzes a CVE (public data only) and produces a structured severity/exploitation/remediation assessment.",
        instruction="""You are a cybersecurity CVE analyst, analyzing whichever CVE you've been asked to enrich.

1. Call fetch_and_scrub_cve() first, always — it already knows which CVE to fetch.
2. If the result has "cached": true, you are done — just confirm the cached enrichment exists. Do NOT call save_enrichment again.
3. Otherwise, analyze the returned (already-scrubbed) description and CVSS score, then call save_enrichment (it already knows which CVE this is for) with:
   - severity_context: 2-3 sentences on real-world severity and attack surface
   - exploitation_intelligence: whether it's known to be exploited in the wild / has a known PoC
   - remediation_approach: concrete remediation steps (patch version, workaround, mitigation)
   - confidence: "High", "Medium", or "Low" based on how well-understood this CVE is
4. Confirm completion in one sentence.""",
        tools=[fetch_and_scrub_cve, save_enrichment],
    )


# ═════════════════════════════════════════════════════════════════════════
# Sandbox Sub-Agent — local-only (Ollama), never touches the cloud
# ═════════════════════════════════════════════════════════════════════════

def validate_asset_tool() -> str:
    """
    Tool: runs the local Ollama sandbox validation, using the enrichment
    sink if available. asset_id/cve_id come from the sink, not model
    arguments — see _current_target.
    """
    global _last_sandbox_result
    asset_id = _current_target["asset_id"]
    cve_id = _current_target["cve_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
    asset_row = cursor.fetchone()
    cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve_row = cursor.fetchone()
    conn.close()

    if not asset_row:
        return json.dumps({"error": f"Asset {asset_id} not found"})

    asset = dict(asset_row)
    vulnerability = dict(cve_row) if cve_row else {"cve_id": cve_id}
    enrichment = _last_enrichment or None

    result = _sandbox_agent_impl.validate(vulnerability, asset, enrichment)
    _last_sandbox_result = result
    return json.dumps({"verdict": result.get("verdict"), "rationale": result.get("rationale", "")[:200]})


def create_sandbox_agent() -> Agent:
    return Agent(
        name="sandbox_agent",
        model=GEMINI_MODEL,
        description="Validates whether a CVE is actually exploitable against a specific asset, using a local-only model.",
        instruction="""Call validate_asset_tool() exactly once — it already knows which asset and CVE to check — then report back the verdict (PASS/FAIL/PARTIAL) in one sentence.""",
        tools=[validate_asset_tool],
    )


# ═════════════════════════════════════════════════════════════════════════
# RemediationTest Sub-Agent — local-only (Ollama)
# ═════════════════════════════════════════════════════════════════════════

def test_remediation_tool() -> str:
    """
    Tool: retests the proposed remediation locally. RemediationTestAgent
    itself enforces the skip condition (NOT_APPLICABLE unless the sandbox
    verdict in the sink was FAIL) — not re-implemented here. asset_id/cve_id
    come from the sink, not model arguments — see _current_target.
    """
    global _last_remediation_result
    asset_id = _current_target["asset_id"]
    cve_id = _current_target["cve_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,))
    asset_row = cursor.fetchone()
    cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    cve_row = cursor.fetchone()
    conn.close()

    if not asset_row:
        return json.dumps({"error": f"Asset {asset_id} not found"})

    asset = dict(asset_row)
    vulnerability = dict(cve_row) if cve_row else {"cve_id": cve_id}
    enrichment = _last_enrichment or None
    sandbox_result = _last_sandbox_result or None

    result = _remediation_agent_impl.test_remediation(vulnerability, asset, enrichment, sandbox_result)
    _last_remediation_result = result
    return json.dumps({"remediation_verdict": result.get("remediation_verdict")})


def create_remediation_agent() -> Agent:
    return Agent(
        name="remediation_agent",
        model=GEMINI_MODEL,
        description="Retests a proposed remediation locally, only when the sandbox found the asset exploitable.",
        instruction="""Call test_remediation_tool() exactly once — it already knows which asset and CVE to check — then report back the remediation verdict in one sentence.""",
        tools=[test_remediation_tool],
    )


# ═════════════════════════════════════════════════════════════════════════
# Ticketing Sub-Agent — real MCP round-trip, human-gated
# ═════════════════════════════════════════════════════════════════════════

async def create_ticket_tool(backend: str, approved: bool) -> str:
    """
    Tool: creates a real ticket via the MCP server — only if approved is
    literally True. Must never be called during Turn 1. vuln_id/cve_id/
    asset_id come from the sink, not model arguments — see _current_target.
    backend/approved genuinely need to come from the model, since they're
    extracted from the human's decision message, not known ahead of time.
    """
    global _last_ticket_result
    vuln_id = _current_target["vuln_id"]
    if not approved:
        result = {"status": "rejected", "message": "No ticket created — not approved."}
        _last_ticket_result = result
        return json.dumps(result)

    report = {"cve_id": _current_target["cve_id"], "asset_id": _current_target["asset_id"]}
    result = await create_ticket(vuln_id, report, backend=backend or "jira", approved=True)
    _last_ticket_result = result
    return json.dumps(result)


def create_ticketing_agent() -> Agent:
    return Agent(
        name="ticketing_agent",
        model=GEMINI_MODEL,
        description="Creates a remediation ticket via MCP, but only when explicitly told the human approved it.",
        instruction="""You will be told a ticket backend and whether the human approved this (true or false) — the vulnerability itself is already known, you don't need to be told which one.
Call create_ticket_tool(backend, approved) exactly once, passing `approved` EXACTLY as you were told — never infer or default it to true.
Report back the outcome in one sentence.""",
        tools=[create_ticket_tool],
    )


# ═════════════════════════════════════════════════════════════════════════
# Root Orchestrator — delegates to the four sub-agents above via AgentTool
# ═════════════════════════════════════════════════════════════════════════

def assemble_report() -> str:
    """
    Tool (Root's own — no LLM reasoning needed for pure data assembly):
    builds the validated remediation report from the sink values left by
    the sub-agents above. Kept as a plain tool rather than its own
    sub-agent since there's no judgment call here, just deterministic
    scoring + dict assembly (see agents/playbook_agent.py build_report).
    vuln_id/cve_id/asset_id come from the sink, not model arguments.
    """
    global _last_report
    report = _playbook_agent_impl.build_report(
        _current_target["vuln_id"], _current_target["cve_id"], _current_target["asset_id"],
        _last_enrichment, _last_sandbox_result, _last_remediation_result or None,
    )
    _last_report = report
    return json.dumps(report)


def create_orchestrator() -> Agent:
    """Creates the Root Orchestrator, delegating to 4 sub-agents via AgentTool."""
    enrichment_agent = create_enrichment_agent()
    sandbox_agent = create_sandbox_agent()
    remediation_agent = create_remediation_agent()
    ticketing_agent = create_ticketing_agent()

    return Agent(
        name="vulnerability_orchestrator",
        model=GEMINI_MODEL,
        description=(
            "Root orchestrator: delegates vulnerability triage to specialized sub-agents across two turns — "
            "automated triage (Turn 1), then a human-gated ticketing decision (Turn 2)."
        ),
        instruction="""You are the VECTOR vulnerability triage Root Orchestrator. You delegate work to specialized sub-agents rather than doing analysis yourself. You operate across two turns per vulnerability. The vulnerability's IDs are already known to every sub-agent's tools internally — you never need to state or retype a CVE ID or Asset ID when delegating; just tell each sub-agent what task to do.

TURN 1 — when asked to run Turn 1 (and no HUMAN_DECISION message yet):
1. Delegate to the enrichment_agent sub-agent: ask it to enrich the CVE.
2. Delegate to the sandbox_agent sub-agent: ask it to validate exploitability against the asset.
3. The sandbox_agent's response states a verdict (PASS/FAIL/PARTIAL). If and only if it is FAIL, delegate to the remediation_agent sub-agent to retest the proposed remediation. If it is not FAIL, skip this step entirely.
4. Call assemble_report() — this is your own tool, not a sub-agent; it assembles the final report from what the sub-agents above already produced.
5. Summarize the assembled report clearly: risk score, sandbox verdict, remediation verdict (if tested). End by stating you are awaiting human approval.
Do NOT delegate to the ticketing_agent sub-agent during Turn 1 under any circumstances.

TURN 2 — only when you receive a message starting with "HUMAN_DECISION:":
- That message also states the ticket backend, e.g. "Ticket backend: jira".
- Delegate to the ticketing_agent sub-agent, telling it: the stated backend, and whether the human approved (true only if the message says APPROVED, false if it says REJECTED).
- Never tell the ticketing_agent that it was approved unless you actually received a HUMAN_DECISION: APPROVED message in this turn.""",
        tools=[
            AgentTool(agent=enrichment_agent),
            AgentTool(agent=sandbox_agent),
            AgentTool(agent=remediation_agent),
            AgentTool(agent=ticketing_agent),
            assemble_report,
        ],
    )


# ── Two-Turn Session Driver — same external signature as before ────────────

async def run_turn_one(cve_id: str, asset_id: str, vuln_id: str) -> dict:
    """
    Runs Turn 1 on a fresh session and returns everything Turn 2 needs to
    resume the SAME session later (runner, session_service, session_id).
    """
    global _current_target
    _current_target = {"vuln_id": vuln_id, "cve_id": cve_id, "asset_id": asset_id}

    orchestrator = create_orchestrator()
    session_service = InMemorySessionService()
    runner = Runner(agent=orchestrator, app_name="vector_pipeline", session_service=session_service)

    session = await session_service.create_session(app_name="vector_pipeline", user_id="pipeline_user")

    message = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=(
            f"Run Turn 1 for vuln_id={vuln_id}, CVE ID: {cve_id}, Asset ID: {asset_id}."
        ))],
    )

    summary = ""
    async for event in runner.run_async(user_id="pipeline_user", session_id=session.id, new_message=message):
        if event.is_final_response():
            if event.content and event.content.parts:
                summary = event.content.parts[0].text or ""
        # Deliberately no `break` — letting the generator run to completion
        # (StopAsyncIteration) avoids a GeneratorExit being thrown into ADK's
        # OpenTelemetry span context later, during garbage collection, from
        # a different task/context than the one that opened it.

    return {
        "session_id": session.id,
        "runner": runner,
        "session_service": session_service,
        "summary": summary,
        "report": dict(_last_report),
    }


async def run_turn_two(runner: Runner, session_id: str, decision: str, backend: str = "jira") -> dict:
    """
    Resumes the SAME ADK session with the human's decision.
    decision must be the literal string "APPROVED" or "REJECTED".
    backend selects the ticket format (jira/servicenow/webhook) — passed in
    the message text since Turn 1 has no prior knowledge of it.
    """
    message = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=f"HUMAN_DECISION: {decision}. Ticket backend: {backend}.")],
    )
    summary = ""
    async for event in runner.run_async(user_id="pipeline_user", session_id=session_id, new_message=message):
        if event.is_final_response():
            if event.content and event.content.parts:
                summary = event.content.parts[0].text or ""
        # No `break` here either — see run_turn_one for why.
    return {"summary": summary, "ticket_result": dict(_last_ticket_result)}


# ── Standalone isolated test — before wiring into full_pipeline.py/UI ──────

async def _standalone_demo(cve_id: str, asset_id: str):
    """
    Standalone runner to prove the two-turn, multi-agent-delegation
    mechanics in isolation.
    Usage: python -m agents.orchestrator <CVE> <ASSET>
    """
    vuln_id = f"VULN-DEMO-{cve_id.replace('-', '')}"

    print(f"\n=== TURN 1: {cve_id} x {asset_id} ===")
    turn1 = await run_turn_one(cve_id, asset_id, vuln_id)
    print(turn1["summary"])

    print("\n=== Waiting for human decision ===")
    print("(this input() call is OUTSIDE the ADK async loop, by design — "
          "Turn 1 has already fully completed and returned control here)")
    answer = input("Approve remediation ticket? [y/N]: ").strip().lower()
    decision = "APPROVED" if answer in ("y", "yes") else "REJECTED"

    print(f"\n=== TURN 2: {decision} ===")
    turn2 = await run_turn_two(turn1["runner"], turn1["session_id"], decision)
    print(turn2["summary"])


if __name__ == "__main__":
    cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    asset = sys.argv[2] if len(sys.argv) > 2 else "ASSET-005"
    asyncio.run(_standalone_demo(cve, asset))
