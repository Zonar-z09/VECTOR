"""
web/pages/5_Batch_Remediation.py — Batch remediation review + ticket creation.

Select multiple CVE×asset pairs, run automated triage (Turn 1 of the ADK
orchestrator) for all of them, review the assembled reports together, then
approve/reject each independently and submit — each approval fires Turn 2
of that item's own ADK session, creating a real ticket via MCP.

Sequential, not concurrent: each item's Turn 1 fully completes before the
next starts, and the same is true for Turn 2 on submit. This matches
agents/orchestrator.py's documented assumption that only one orchestrator
session is in flight against this module at a time (see its
_last_report / _last_ticket_result sink comment).
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

from web.data_access import get_prioritized_vulnerabilities
from agents.orchestrator import run_turn_one, run_turn_two
from src.integrations.ticketing import TICKET_BACKENDS
from web.theme import brand_header

async def _run_batch_turn1(targets: list, progress) -> dict:
    """
    Runs Turn 1 for every target sequentially, inside ONE asyncio.run() call.
    Calling asyncio.run() once per item (one per loop iteration) triggers a
    "cannot be called from a running event loop" error on the second item
    under Streamlit — something in ADK/OpenTelemetry's async cleanup leaves
    the thread's event-loop state inconsistent between separate asyncio.run()
    invocations here (this doesn't happen in the plain CLI process). Looping
    inside a single run() call sidesteps it.
    """
    results = {}
    for i, target in enumerate(targets, 1):
        progress.progress(
            (i - 1) / len(targets),
            text=f"Triaging {target['cve_id']} × {target['asset_id']} ({i}/{len(targets)})...",
        )
        results[target["vuln_id"]] = await run_turn_one(target["cve_id"], target["asset_id"], target["vuln_id"])
    return results


async def _run_batch_turn2(pending: list, decisions: dict, turn1_by_vuln: dict, backend: str, progress) -> dict:
    """Runs Turn 2 for every pending target sequentially, inside ONE asyncio.run() call — see _run_batch_turn1."""
    results = {}
    for i, target in enumerate(pending, 1):
        vuln_id = target["vuln_id"]
        turn1 = turn1_by_vuln[vuln_id]
        decision = "APPROVED" if decisions.get(vuln_id) == "Approve" else "REJECTED"

        progress.progress(
            (i - 1) / len(pending),
            text=f"Submitting {target['cve_id']} × {target['asset_id']} ({i}/{len(pending)})...",
        )
        turn2 = await run_turn_two(turn1["runner"], turn1["session_id"], decision, backend=backend)
        ticket_result = turn2["ticket_result"]

        report = dict(turn1["report"])
        if decision == "APPROVED" and ticket_result.get("status") == "success":
            report["status"] = "delivered"
            report["ticket_id"] = ticket_result["ticket_id"]
        else:
            report["status"] = "rejected"
        results[vuln_id] = report
    return results


st.set_page_config(page_title="Batch Remediation — VECTOR", page_icon="📦", layout="wide")
brand_header(
    page_title="Batch Remediation",
    subtitle="Triage multiple vulnerabilities at once, then approve or reject each before ticket creation.",
)

# ── Session state ────────────────────────────────────────────────────────────

for key, default in [
    ("batch_selected", []),
    ("batch_turn1", {}),
    ("batch_final", {}),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── Step 1: Select targets ────────────────────────────────────────────────────

st.subheader("Step 1: Select vulnerabilities")

all_vulns = get_prioritized_vulnerabilities()
mode = st.radio("Selection mode", ["Top N by risk score", "Manual selection"], horizontal=True)

if mode == "Top N by risk score":
    n = st.number_input("Number of top-risk vulnerabilities", min_value=1, max_value=len(all_vulns) or 1, value=min(3, len(all_vulns) or 1))
    chosen = all_vulns[:n]
else:
    options = {v["vuln_id"]: f"{v['cve_id']} × {v['asset_id']} ({v['asset_name']}) — risk {v['risk_score']}" for v in all_vulns}
    picked_ids = st.multiselect("Vulnerabilities", list(options.keys()), format_func=lambda k: options[k])
    chosen = [v for v in all_vulns if v["vuln_id"] in picked_ids]

if chosen:
    st.dataframe(
        [{"CVE": v["cve_id"], "Asset": v["asset_id"], "Risk Score": v["risk_score"], "Severity": v["severity"]} for v in chosen],
        width="stretch", hide_index=True,
    )

backend = st.selectbox("Ticket backend for this batch", list(TICKET_BACKENDS.keys()))

# Reset downstream state if the selection changed
sel_key = tuple(sorted(v["vuln_id"] for v in chosen))
if st.session_state.get("batch_sel_key") != sel_key:
    st.session_state.batch_turn1 = {}
    st.session_state.batch_final = {}
    st.session_state.batch_sel_key = sel_key

st.divider()

# ── Step 2: Run Turn 1 (automated triage) for the whole batch ────────────────

st.subheader("Step 2: Run triage")

if not chosen:
    st.info("Select at least one vulnerability above to run triage.")
elif st.button("▶️ Run Triage on Selected Batch", type="primary"):
    progress = st.progress(0.0, text="Starting...")
    results = asyncio.run(_run_batch_turn1(chosen, progress))
    st.session_state.batch_turn1.update(results)
    progress.progress(1.0, text="Triage complete.")
    st.session_state.batch_final = {}

st.divider()

# ── Step 3: Review + decide ───────────────────────────────────────────────────

if st.session_state.batch_turn1:
    st.subheader("Step 3: Review and decide")

    decisions = {}
    for target in chosen:
        vuln_id = target["vuln_id"]
        turn1 = st.session_state.batch_turn1.get(vuln_id)
        if not turn1:
            continue
        report = turn1["report"]

        already_final = st.session_state.batch_final.get(vuln_id)

        with st.expander(
            f"{target['cve_id']} × {target['asset_id']} — risk {report.get('risk_score', 0):.4f} — "
            f"sandbox: {report.get('sandbox_verdict', 'N/A')}",
            expanded=not already_final,
        ):
            st.markdown(f"**Primary driver:** {report.get('primary_driver', 'N/A')}")
            st.markdown(f"**Remediation verdict:** {report.get('remediation_verdict', 'NOT_RUN')}")
            st.write(report.get("enrichment", {}).get("remediation_approach", "—"))

            if already_final:
                if already_final.get("status") == "delivered":
                    st.success(f"✅ Ticket created: {already_final.get('ticket_id')}")
                else:
                    st.error("❌ Rejected — no ticket created.")
            else:
                decisions[vuln_id] = st.radio(
                    "Decision", ["Approve", "Reject"], key=f"decision_{vuln_id}", horizontal=True,
                )

    pending = [v for v in chosen if v["vuln_id"] not in st.session_state.batch_final]
    if pending and st.button("✅ Submit Decisions", type="primary"):
        progress = st.progress(0.0, text="Submitting...")
        results = asyncio.run(
            _run_batch_turn2(pending, decisions, st.session_state.batch_turn1, backend, progress)
        )
        st.session_state.batch_final.update(results)
        progress.progress(1.0, text="Done.")
        st.rerun()

if st.session_state.batch_final:
    st.divider()
    delivered = sum(1 for r in st.session_state.batch_final.values() if r.get("status") == "delivered")
    rejected = sum(1 for r in st.session_state.batch_final.values() if r.get("status") == "rejected")
    st.markdown(f"**Batch summary:** {delivered} delivered, {rejected} rejected")
