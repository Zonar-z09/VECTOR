"""
web/pages/1_Asset_Inventory.py — Asset Inventory page.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import json
import streamlit as st
import pandas as pd

from web.data_access import get_assets
from web.theme import brand_header, ACCENT

st.set_page_config(page_title="Asset Inventory — VECTOR", page_icon="🏢", layout="wide")
brand_header(
    page_title="Asset Inventory",
    subtitle="15 synthetic assets with five-factor fields (internet exposure, environment, business tag, dependencies)",
)

# ── Filter widgets ────────────────────────────────────────────────────────────

all_assets = get_assets()
environments = sorted(set(a["environment"] for a in all_assets))
business_tags = sorted(set(a["business_tag"] for a in all_assets))

col1, col2, col3 = st.columns([2, 2, 1])
with col1:
    env_filter = st.multiselect("Environment", environments, default=[])
with col2:
    tag_filter = st.multiselect("Business Criticality", business_tags, default=[])
with col3:
    exposed_only = st.checkbox("Internet-exposed only", value=False)

# ── Apply filters — passed into get_assets, not applied post-query ────────────
filters = {}
if env_filter:
    filters["environment"] = env_filter
if tag_filter:
    filters["business_tag"] = tag_filter
if exposed_only:
    filters["internet_exposed"] = True

assets = get_assets(filters=filters if filters else None)

st.caption(f"Showing {len(assets)} of {len(all_assets)} assets")

# ── Build display dataframe ───────────────────────────────────────────────────

if not assets:
    st.info("No assets match the selected filters.")
    st.stop()

CRITICALITY_BADGE = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🟢 Low"}

rows = []
for a in assets:
    # Reuse the same dep-count parsing already in sandbox_agent._build_prompt
    try:
        dep_count = len(json.loads(a.get("dependencies_json") or "[]"))
    except Exception:
        dep_count = 0

    rows.append({
        "Asset ID": a["asset_id"],
        "Name": a["name"],
        "Type": a["type"],
        "OS": a["os"],
        "Environment": a["environment"],
        "Criticality": CRITICALITY_BADGE.get(a["business_tag"], a["business_tag"]),
        "Internet Exposed": "🌐 Yes" if a["internet_exposed"] else "No",
        "Dependencies": dep_count,
        "Patch Cadence (days)": a.get("patch_cadence_days", "N/A"),
    })

df = pd.DataFrame(rows)
st.dataframe(df, width="stretch", hide_index=True)

# ── Environment breakdown ─────────────────────────────────────────────────────

st.divider()
st.subheader("Environment Breakdown")
env_counts = pd.Series([a["environment"] for a in assets]).value_counts()
st.bar_chart(env_counts, color=ACCENT)
