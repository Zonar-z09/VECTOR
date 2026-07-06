"""
web/pages/4_Weight_Configuration.py — Live weight configuration + ranking.

Five sliders (one per factor), live sum validation, live re-ranking.
Design rule: WARN if weights don't sum to 1.0 — do NOT silently renormalize.
(Silent renormalization contradicts the whitepaper's explicit design principle
that weights are client-configured and must sum to 1.0.)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
import pandas as pd

from src.engine.prioritization import DEFAULT_WEIGHTS
from web.data_access import get_prioritized_vulnerabilities
from web.theme import brand_header

st.set_page_config(page_title="Weight Configuration — VECTOR", page_icon="⚖️", layout="wide")
brand_header(
    page_title="Weight Configuration",
    subtitle=(
        "Adjust the five-factor weights and watch the vulnerability ranking update live. "
        "Weights must sum to 1.0 — the system warns but does not silently renormalize."
    ),
)

# ── Weight presets ─────────────────────────────────────────────────────────────

PRESETS = {
    "Default": DEFAULT_WEIGHTS,
    "Internet-Exposure Heavy": {
        "internet_exposure": 0.50,
        "environment_classification": 0.20,
        "exploit_capability": 0.15,
        "manual_tag": 0.10,
        "dependency_score": 0.05,
    },
    "CVSS-Driven": {
        "internet_exposure": 0.10,
        "environment_classification": 0.10,
        "exploit_capability": 0.60,
        "manual_tag": 0.10,
        "dependency_score": 0.10,
    },
}

col_p1, col_p2, col_p3, _ = st.columns([1, 1, 1, 3])
preset_chosen = None
with col_p1:
    if st.button("↩ Reset to Default"):
        preset_chosen = "Default"
with col_p2:
    if st.button("🌐 Internet-Exposure Heavy"):
        preset_chosen = "Internet-Exposure Heavy"
with col_p3:
    if st.button("📊 CVSS-Driven"):
        preset_chosen = "CVSS-Driven"

# Apply preset to session state
if preset_chosen:
    for k, v in PRESETS[preset_chosen].items():
        st.session_state[f"weight_{k}"] = v

# ── Slider initialisation ─────────────────────────────────────────────────────

FACTOR_LABELS = {
    "internet_exposure": "Internet Exposure",
    "environment_classification": "Environment Class",
    "exploit_capability": "Exploit Capability (CVSS)",
    "manual_tag": "Business Criticality",
    "dependency_score": "Dependency Blast Radius",
}

st.divider()
st.subheader("Factor Weights")

weights = {}
cols = st.columns(5)
for i, (key, label) in enumerate(FACTOR_LABELS.items()):
    with cols[i]:
        weights[key] = st.slider(
            label,
            min_value=0.0,
            max_value=1.0,
            step=0.05,
            key=f"weight_{key}",
            value=st.session_state.get(f"weight_{key}", DEFAULT_WEIGHTS[key]),
        )

# ── Sum validation — warn, never renormalize ──────────────────────────────────

total = round(sum(weights.values()), 4)
if abs(total - 1.0) <= 0.01:
    st.success(f"✅ Weights sum to **{total}** — valid configuration")
else:
    st.warning(
        f"⚠️ Weights sum to **{total}** (expected 1.0). "
        "Adjust the sliders until they sum to 1.0. "
        "The ranking below uses your current values as-is."
    )

# ── Live ranking table ────────────────────────────────────────────────────────

st.divider()
st.subheader("Live Vulnerability Ranking")
st.caption(f"Reranked with current weights (sum={total})")

vulns = get_prioritized_vulnerabilities(weights=weights)

rows = []
for rank, v in enumerate(vulns, 1):
    rows.append({
        "Rank": rank,
        "Risk Score": v["risk_score"],
        "CVE": v["cve_id"],
        "Asset": v["asset_name"],
        "Environment": v["environment"],
        "Criticality": v["business_tag"],
        "CVSS": v["cvss_score"],
        "Internet": "🌐" if v["internet_exposed"] else "—",
        "Top Driver": v["primary_driver"],
    })

df = pd.DataFrame(rows)
st.dataframe(df, width="stretch", hide_index=True)

# ── Weight breakdown bar ───────────────────────────────────────────────────────

st.divider()
st.subheader("Weight Distribution")
weight_df = pd.DataFrame(
    {"Factor": list(FACTOR_LABELS.values()), "Weight": list(weights.values())}
).set_index("Factor")
st.bar_chart(weight_df)
