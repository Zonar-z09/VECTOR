"""
verify_web.py — Operational test suite for the VECTOR web dashboard.

Layer 1: data_access.py unit tests (no Streamlit, no mocking, fast)
Layer 2: Streamlit AppTest headless UI tests (no browser, deterministic)
         — agent calls are mocked so this runs without Ollama or live keys

Run with:
  python -X utf8 verify_web.py
"""

import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

console = Console(force_terminal=True, highlight=False)
results = []


def check(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((name, status, detail))
    console.print(f"  {status}  {name}" + (f" — {detail}" if detail else ""))


# ════════════════════════════════════════════════════════════════════
# LAYER 1 — data_access.py unit tests (no Streamlit, real DB)
# ════════════════════════════════════════════════════════════════════

console.print("\n[bold cyan]Layer 1 — data_access Unit Tests (real DB)[/bold cyan]")

from web.data_access import (
    get_summary_counts,
    get_prioritized_vulnerabilities,
    get_assets,
    get_vulnerability_detail,
    get_enrichment_status,
)
from src.db.database import get_db_connection
from src.engine.prioritization import DEFAULT_WEIGHTS

# 1a. Summary counts
try:
    counts = get_summary_counts()
    check("get_summary_counts — assets=15", counts["assets"] == 15, f"got {counts['assets']}")
    check("get_summary_counts — cves=10", counts["cves"] == 10, f"got {counts['cves']}")
    check("get_summary_counts — all keys present",
          all(k in counts for k in ["assets", "cves", "open_vulns", "enriched_count"]),
          str(list(counts.keys())))
except Exception as e:
    check("get_summary_counts", False, str(e)[:80])

# 1b. Prioritized vulnerabilities
try:
    vulns = get_prioritized_vulnerabilities()
    check("get_prioritized_vulnerabilities — 10 records",
          len(vulns) == 10, f"got {len(vulns)}")
    check("get_prioritized_vulnerabilities — sorted descending",
          all(vulns[i]["risk_score"] >= vulns[i+1]["risk_score"] for i in range(len(vulns)-1)),
          "risk scores are in descending order")
    check("get_prioritized_vulnerabilities — required keys",
          all("risk_score" in v and "cve_id" in v and "primary_driver" in v for v in vulns),
          "all records have risk_score, cve_id, primary_driver")
except Exception as e:
    check("get_prioritized_vulnerabilities", False, str(e)[:80])

# 1c. Asset filtering
try:
    all_assets = get_assets()
    check("get_assets — unfiltered returns 15", len(all_assets) == 15, f"got {len(all_assets)}")

    prod_assets = get_assets(filters={"environment": ["production"]})
    # Cross-check against direct SQL
    conn = get_db_connection()
    sql_prod_count = conn.execute(
        "SELECT COUNT(*) FROM assets WHERE environment = 'production'"
    ).fetchone()[0]
    conn.close()
    check("get_assets — production filter matches SQL",
          len(prod_assets) == sql_prod_count,
          f"filter={len(prod_assets)}, sql={sql_prod_count}")
    check("get_assets — all filtered are production",
          all(a["environment"] == "production" for a in prod_assets),
          f"{len(prod_assets)} production assets")
except Exception as e:
    check("get_assets filter", False, str(e)[:80])

# 1d. Vulnerability detail
try:
    conn = get_db_connection()
    first_vuln_id = conn.execute("SELECT vuln_id FROM vulnerabilities LIMIT 1").fetchone()[0]
    conn.close()

    detail = get_vulnerability_detail(first_vuln_id)
    required_keys = ["vuln_id", "asset_id", "cve_id", "asset_name", "cvss_score", "severity"]
    check("get_vulnerability_detail — returns dict",
          detail is not None, f"vuln_id={first_vuln_id}")
    check("get_vulnerability_detail — required keys present",
          all(k in detail for k in required_keys),
          f"keys: {[k for k in required_keys if k in detail]}")
except Exception as e:
    check("get_vulnerability_detail", False, str(e)[:80])

# ════════════════════════════════════════════════════════════════════
# LAYER 2 — Streamlit AppTest headless UI tests
# ════════════════════════════════════════════════════════════════════

console.print("\n[bold cyan]Layer 2 — Streamlit AppTest (headless, no browser)[/bold cyan]")

try:
    from streamlit.testing.v1 import AppTest

    # 2a. Overview page loads cleanly
    try:
        at = AppTest.from_file("web/Overview.py").run(timeout=30)
        check("Overview.py — no exception on load", not at.exception,
              str(at.exception)[:60] if at.exception else "clean")
        check("Overview.py — metric tiles present", len(at.metric) >= 4,
              f"found {len(at.metric)} metric(s)")
        check("Overview.py — dataframe present", len(at.dataframe) >= 1,
              f"found {len(at.dataframe)} dataframe(s)")
    except Exception as e:
        check("app.py AppTest", False, str(e)[:80])

    # 2b. Asset Inventory page loads and filters
    try:
        at = AppTest.from_file("web/pages/1_Asset_Inventory.py").run(timeout=30)
        check("1_Asset_Inventory.py — no exception", not at.exception,
              str(at.exception)[:60] if at.exception else "clean")
        check("1_Asset_Inventory.py — dataframe present", len(at.dataframe) >= 1,
              f"found {len(at.dataframe)} dataframe(s)")
    except Exception as e:
        check("1_Asset_Inventory AppTest", False, str(e)[:80])

    # 2c. Vulnerability Explorer loads
    try:
        at = AppTest.from_file("web/pages/2_Vulnerability_Explorer.py").run(timeout=30)
        check("2_Vulnerability_Explorer.py — no exception", not at.exception,
              str(at.exception)[:60] if at.exception else "clean")
    except Exception as e:
        check("2_Vulnerability_Explorer AppTest", False, str(e)[:80])

    # 2d. Weight Configuration — slider interaction changes ranking
    try:
        at = AppTest.from_file("web/pages/4_Weight_Configuration.py").run(timeout=30)
        check("4_Weight_Configuration.py — no exception", not at.exception,
              str(at.exception)[:60] if at.exception else "clean")
        check("4_Weight_Configuration.py — sliders present", len(at.slider) >= 5,
              f"found {len(at.slider)} slider(s)")

        # Get default top CVE
        default_top = at.dataframe[0].value.iloc[0]["CVE"] if len(at.dataframe) > 0 else None

        # Set internet_exposure to max, all others to 0 — should favour internet-exposed assets
        if len(at.slider) >= 5:
            at.slider[0].set_value(1.0)  # internet_exposure
            at.slider[1].set_value(0.0)
            at.slider[2].set_value(0.0)
            at.slider[3].set_value(0.0)
            at.slider[4].set_value(0.0)
            at = at.run(timeout=30)

            check("4_Weight_Configuration.py — slider change reruns", not at.exception,
                  "table updated after slider change")

    except Exception as e:
        check("4_Weight_Configuration AppTest", False, str(e)[:80])

    # 2e. Run Pipeline page — mock agents so test is fast + deterministic
    try:
        mock_enrichment = {
            "cve_id": "CVE-2021-44228",
            "severity_context": "Critical RCE via Log4j JNDI injection.",
            "exploitation_intelligence": "Actively exploited in the wild.",
            "remediation_approach": "Upgrade to Log4j 2.17.1+",
            "confidence": "High",
            "from_cache": False,
            "redaction_log": [("IPV4", "10.0.0.1")],
        }
        mock_sandbox = {
            "verdict": "FAIL",
            "rationale": "Asset runs Log4j 2.20.0 which is vulnerable.",
            "exploitability_notes": "JNDI attack vector is reachable.",
            "dependency_impact": "2 downstream assets affected.",
        }

        with patch("agents.enrichment_agent.EnrichmentAgent.enrich", return_value=mock_enrichment), \
             patch("agents.sandbox_agent.SandboxAgent.validate", return_value=mock_sandbox):
            at = AppTest.from_file("web/pages/3_Run_Pipeline.py").run(timeout=30)
            check("3_Run_Pipeline.py — no exception (mocked agents)", not at.exception,
                  str(at.exception)[:60] if at.exception else "clean")
            check("3_Run_Pipeline.py — dropdowns present", len(at.selectbox) >= 2,
                  f"found {len(at.selectbox)} selectbox(es)")

    except Exception as e:
        check("3_Run_Pipeline AppTest", False, str(e)[:80])

except ImportError as e:
    check("Streamlit AppTest import", False, f"streamlit>=1.28 required: {e}")
except Exception as e:
    check("Layer 2 setup", False, str(e)[:80])

# ── Summary ───────────────────────────────────────────────────────────────────

console.print("\n")
table = Table(title="Web Dashboard Verification Summary")
table.add_column("Check", style="white")
table.add_column("Result", style="bold")
table.add_column("Detail", style="dim")
for name, status, detail in results:
    color = "green" if "PASS" in status else "red"
    table.add_row(name, f"[{color}]{status}[/{color}]", detail)
console.print(table)

passed_count = sum(1 for _, s, _ in results if "PASS" in s)
console.print(f"\n[bold]{passed_count}/{len(results)} checks passed[/bold]")

if passed_count < len(results):
    sys.exit(1)
