"""
web/Overview.py — VECTOR Dashboard landing page (Overview).

Streamlit multipage entrypoint. Run with:
  streamlit run web/Overview.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import pandas as pd

from web.data_access import get_summary_counts, get_prioritized_vulnerabilities
from web.theme import brand_header

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="VECTOR — Vulnerability Triage",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Header ────────────────────────────────────────────────────────────────────

brand_header(
    subtitle=(
        "AI-orchestrated vulnerability triage & remediation<br>"
        "[See README](https://github.com/Zonar-z09/AI-Agents-Capstone-Project#whats-real-vs-mocked) "
        "for what's mocked vs. real."
    )
)

# ── Metric tiles ──────────────────────────────────────────────────────────────

counts = get_summary_counts()
col1, col2, col3, col4 = st.columns(4)
col1.metric("🏢 Total Assets", counts["assets"])
col2.metric("🐛 Total CVEs", counts["cves"])
col3.metric("🚨 Open Vulnerabilities", counts["open_vulns"])
col4.metric("✅ Enriched CVEs", counts["enriched_count"],
            help="CVEs with Gemini enrichment in the write-once cache")

st.divider()

# ── Top vulnerabilities table ─────────────────────────────────────────────────

st.subheader("Top Vulnerabilities by Risk Score")
st.caption("Scored by the five-factor prioritization engine (default weights)")

vulns = get_prioritized_vulnerabilities()

if not vulns:
    st.warning("No vulnerabilities found. Run `python src/ingest/ingest_pipeline.py` first.")
    st.stop()

df = pd.DataFrame(vulns)

# Colour-code risk score
def score_color(score: float) -> str:
    if score >= 0.8:
        return "🔴"
    elif score >= 0.5:
        return "🟡"
    return "🟢"

df["risk"] = df["risk_score"].apply(score_color) + " " + df["risk_score"].astype(str)
df["internet"] = df["internet_exposed"].apply(lambda x: "🌐 Yes" if x else "No")

display_cols = {
    "risk": "Risk Score",
    "vuln_id": "Vuln ID",
    "cve_id": "CVE",
    "asset_name": "Asset",
    "environment": "Env",
    "business_tag": "Criticality",
    "internet": "Internet",
    "primary_driver": "Top Driver",
    "severity": "CVSS Severity",
}

top10 = df.head(10)[list(display_cols.keys())].rename(columns=display_cols)
st.dataframe(top10, width="stretch", hide_index=True)

if len(df) > 10:
    with st.expander(f"Show all {len(df)} vulnerabilities"):
        all_df = df[list(display_cols.keys())].rename(columns=display_cols)
        st.dataframe(all_df, width="stretch", hide_index=True)

# ── Footer ────────────────────────────────────────────────────────────────────

st.divider()
st.caption(
    "Navigate using the sidebar  •  "
    "CLI: `python vector.py run --cve CVE-XXXX`  •  "
    "Google 5-Day AI Agents Capstone"
)
