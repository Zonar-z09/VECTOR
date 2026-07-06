"""
web/pages/3_Run_Pipeline.py — Interactive pipeline runner page.

Allows selecting a CVE + Asset, running enrichment (Gemini) and
sandbox validation (Ollama) with live status, and displaying results
including the scrubbing layer's redaction log.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import streamlit as st
from web.data_access import get_assets, get_enrichment_status
from src.db.database import get_db_connection
from web.theme import brand_header

st.set_page_config(page_title="Run Pipeline — VECTOR", page_icon="⚡", layout="wide")
brand_header(
    page_title="Run Pipeline",
    subtitle="Enrich a CVE via Gemini (cloud) then validate against an asset via Ollama (local)",
)

# ── Cache expensive agent instances — not query results ───────────────────────
# Per design spec: "Cache agent instances (expensive to construct), not query results."

@st.cache_resource
def get_enrichment_agent():
    from agents.enrichment_agent import EnrichmentAgent
    return EnrichmentAgent()

@st.cache_resource
def get_sandbox_agent():
    from agents.sandbox_agent import SandboxAgent
    return SandboxAgent()

# ── Dropdowns ─────────────────────────────────────────────────────────────────

conn = get_db_connection()
cve_rows = conn.execute("SELECT cve_id, description, cvss_score, severity FROM cves ORDER BY cvss_score DESC").fetchall()
asset_rows = conn.execute("SELECT asset_id, name, environment, business_tag FROM assets ORDER BY asset_id").fetchall()
conn.close()

cve_options = {r["cve_id"]: f"{r['cve_id']} (CVSS {r['cvss_score']} — {r['severity']})" for r in cve_rows}
asset_options = {r["asset_id"]: f"{r['asset_id']} — {r['name']} ({r['environment']}, {r['business_tag']})" for r in asset_rows}

col1, col2 = st.columns(2)
with col1:
    selected_cve = st.selectbox("CVE", list(cve_options.keys()), format_func=lambda k: cve_options[k])
with col2:
    selected_asset = st.selectbox("Asset", list(asset_options.keys()), format_func=lambda k: asset_options[k])

# Get CVE details for the selected CVE
cve_detail = next((dict(r) for r in cve_rows if r["cve_id"] == selected_cve), {})
asset_detail = next((dict(r) for r in asset_rows if r["asset_id"] == selected_asset), {})

# Show current enrichment status
enrich_status = get_enrichment_status(selected_cve)
if enrich_status:
    st.success(f"✅ Enrichment cached for {selected_cve} (confidence: {enrich_status.get('confidence','?')}). Running again will use the cache.")
else:
    st.info(f"⬜ {selected_cve} not yet enriched — will call Gemini API.")

st.divider()

# ── Session state for results ─────────────────────────────────────────────────

if "enrichment_result" not in st.session_state:
    st.session_state.enrichment_result = None
if "sandbox_result" not in st.session_state:
    st.session_state.sandbox_result = None

# Reset results when CVE/asset selection changes
sel_key = f"{selected_cve}::{selected_asset}"
if st.session_state.get("last_sel_key") != sel_key:
    st.session_state.enrichment_result = None
    st.session_state.sandbox_result = None
    st.session_state.last_sel_key = sel_key

# ── Stage 1: Enrichment ───────────────────────────────────────────────────────

st.subheader("Stage 1: CVE Enrichment (Gemini API)")
st.caption("Public CVE data → scrubbing layer → Gemini → structured enrichment (cached write-once)")

if st.button("🔍 Run Enrichment", type="primary"):
    agent = get_enrichment_agent()
    with st.spinner("Calling Gemini API... (cached CVEs return instantly)"):
        result = agent.enrich(
            cve_id=selected_cve,
            description=cve_detail.get("description", ""),
            cvss_score=cve_detail.get("cvss_score", 0),
        )
        st.session_state.enrichment_result = result

if st.session_state.enrichment_result:
    r = st.session_state.enrichment_result
    cache_badge = "✅ From cache" if r.get("from_cache") else "🔄 Fresh Gemini call"
    conf = r.get("confidence", "N/A")
    conf_badge = {"High": "🟢 High", "Medium": "🟡 Medium", "Low": "🔴 Low"}.get(conf, conf)

    col_a, col_b = st.columns([3, 1])
    with col_a:
        st.markdown(f"**Cache status:** {cache_badge}")
    with col_b:
        st.markdown(f"**Confidence:** {conf_badge}")

    with st.container(border=True):
        st.markdown("🔍 **Severity Context**")
        st.write(r.get("severity_context", "—"))
    with st.container(border=True):
        st.markdown("⚡ **Exploitation Intelligence**")
        st.write(r.get("exploitation_intelligence", "—"))
    with st.container(border=True):
        st.markdown("🔧 **Remediation Approach**")
        st.write(r.get("remediation_approach", "—"))

    # ── Scrubber redaction log — make the security layer visible ──────────────
    redaction_log = r.get("redaction_log", [])
    if redaction_log:
        with st.expander("🛡️ Scrubbing Layer — Redaction Log"):
            st.caption("These items were stripped from the CVE description before the cloud call:")
            st.code(str(redaction_log), language="python")
    else:
        with st.expander("🛡️ Scrubbing Layer"):
            st.caption("No sensitive patterns found in this CVE description — nothing redacted.")
            st.code("[]", language="python")

st.divider()

# ── Stage 2: Sandbox Validation ───────────────────────────────────────────────

st.subheader("Stage 2: Sandbox Validation (Ollama — local only)")
st.caption("Asset config + enrichment → Ollama qwen2.5:3b → PASS / FAIL / PARTIAL verdict (no internet)")

if st.session_state.enrichment_result is None:
    st.warning("Run Enrichment first to provide context to the sandbox agent.")
else:
    if st.button("🖥️ Run Sandbox Validation", type="secondary"):
        agent = get_sandbox_agent()
        # Fetch full asset data
        conn = get_db_connection()
        asset_row = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (selected_asset,)).fetchone()
        cve_row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (selected_cve,)).fetchone()
        conn.close()

        vulnerability = dict(cve_row) if cve_row else {"cve_id": selected_cve}
        asset = dict(asset_row) if asset_row else {"asset_id": selected_asset}

        with st.spinner("Running local model (Ollama)... this may take 15–30 seconds"):
            try:
                result = agent.validate(
                    vulnerability=vulnerability,
                    asset=asset,
                    enrichment=st.session_state.enrichment_result,
                )
                st.session_state.sandbox_result = result
            except Exception as e:
                err_msg = str(e)
                if "ConnectionError" in err_msg or "Connection refused" in err_msg:
                    st.error("❌ Ollama not reachable. Start it with: `ollama serve`")
                else:
                    st.error(f"Sandbox error: {err_msg[:120]}")

if st.session_state.sandbox_result:
    r = st.session_state.sandbox_result
    verdict = r.get("verdict", "PARTIAL")
    verdict_color = {"PASS": "green", "FAIL": "red", "PARTIAL": "orange"}.get(verdict, "gray")
    verdict_emoji = {"PASS": "✅", "FAIL": "❌", "PARTIAL": "⚠️"}.get(verdict, "❓")

    st.markdown(
        f"<h3 style='color:{verdict_color}'>{verdict_emoji} Verdict: {verdict}</h3>",
        unsafe_allow_html=True,
    )
    with st.container(border=True):
        st.markdown("**Rationale**")
        st.write(r.get("rationale", "—"))
    with st.container(border=True):
        st.markdown("**Exploitability Notes**")
        st.write(r.get("exploitability_notes", "—"))
    with st.container(border=True):
        st.markdown("**Dependency Impact**")
        st.write(r.get("dependency_impact", "—"))
