"""
web/pages/6_External_Sources.py — External source ingestion demo.

The extensibility hook: shows how VECTOR ingests assets/vulnerabilities from
external security tools (code-scanning, EDR, Google Cloud's security
services) via pluggable connectors, instead of only the static seed files in
data/. Connectors here return synthetic sample data shaped like the real
tool's output — see src/ingest/connectors.py for exactly where a real API
call would go, and src/ingest/gcp_client.py for the real (unverified) GCP
integration behind VECTOR_GCP_MODE=live.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st

from agents.ingestion_agent import run_ingestion
from src.ingest.connectors import SOURCE_LABELS, VECTOR_GCP_MODE
from web.theme import brand_header

SIMPLIFIED_SOURCES = {"chronicle_secops", "threat_intel"}

st.set_page_config(page_title="External Sources — VECTOR", page_icon="🔌", layout="wide")
brand_header(
    page_title="External Sources",
    subtitle=(
        "Extensibility hook: connectors below return synthetic sample data shaped like each "
        "real tool's output. Adding a real source means writing one new fetch function in "
        "src/ingest/connectors.py — nothing else in the pipeline changes."
    ),
)
if VECTOR_GCP_MODE == "live":
    st.warning(
        "VECTOR_GCP_MODE=live — Google-native sources below will call real GCP APIs. "
        "This path is unverified (never run against a live project) — see src/ingest/gcp_client.py.",
        icon="⚠️",
    )
else:
    st.caption("Mode: **mock** (set VECTOR_GCP_MODE=live to call real GCP APIs instead — see README).")

st.divider()

st.subheader("Available Connectors")
selected = []
for source_id, label in SOURCE_LABELS.items():
    caption = " _(simplified mock — see connectors.py)_" if source_id in SIMPLIFIED_SOURCES else ""
    if st.checkbox(label + caption, value=source_id not in SIMPLIFIED_SOURCES, key=f"src_{source_id}"):
        selected.append(source_id)

run = st.button("Run Ingestion", type="primary", disabled=not selected)

if run:
    with st.spinner(f"Fetching and normalizing records from {len(selected)} source(s)..."):
        outcome = asyncio.run(run_ingestion(selected))

    st.success(f"Ingested {outcome['total_processed']} record(s).")
    st.caption(outcome["summary"])

    if outcome["results"]:
        import pandas as pd

        def _label_for(source_type: str) -> str:
            # DB source_type folds in SCC category (e.g. "gcp_scc:security_health_analytics")
            return SOURCE_LABELS.get(source_type.split(":")[0], source_type)

        rows = [
            {
                "Source": _label_for(r["source_type"]),
                "Record Type": r.get("record_type", "vulnerability"),
                "Asset": r["asset_id"],
                "Finding / CVE": r["cve_id"] or "—",
                "Vuln ID": r["vuln_id"] or "—",
                "Severity": r["severity"] or "—",
                "Normalization Rationale": r["rationale"],
            }
            for r in outcome["results"]
        ]
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        st.caption("New records appear in Asset Inventory and Vulnerability Explorer tagged with their source_type.")
