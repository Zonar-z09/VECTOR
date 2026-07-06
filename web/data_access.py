"""
web/data_access.py

Thin query helpers used only by the UI layer.
This module contains ZERO business logic — no scoring, enrichment, or validation.
It only queries the DB, shapes the data, and returns it.

All scoring delegates to src/engine/prioritization.py.
All agent calls remain in the agents/ modules.
"""

import json
import sys
from pathlib import Path
from typing import Optional

# Ensure project root is on path so src/ imports resolve
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.database import get_db_connection
from src.engine.prioritization import score_vulnerability, DEFAULT_WEIGHTS


# ── Summary Counts ────────────────────────────────────────────────────────────

def get_summary_counts() -> dict:
    """Returns top-line counts for the Overview page metric tiles."""
    conn = get_db_connection()
    c = conn.cursor()
    assets = c.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    cves = c.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    open_vulns = c.execute(
        "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'"
    ).fetchone()[0]
    enriched_count = c.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0]
    conn.close()
    return {
        "assets": assets,
        "cves": cves,
        "open_vulns": open_vulns,
        "enriched_count": enriched_count,
    }


# ── Prioritized Vulnerabilities ───────────────────────────────────────────────

def get_prioritized_vulnerabilities(weights: Optional[dict] = None) -> list:
    """
    Returns all vulnerabilities scored and sorted descending by risk score.

    Wraps score_vulnerability() from src/engine/prioritization.py.
    The weights param lets the Weight Configuration page pass live slider values.
    """
    w = weights or DEFAULT_WEIGHTS
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT v.vuln_id, v.asset_id, v.cve_id, v.status,
               a.name as asset_name, a.type as asset_type,
               a.internet_exposed, a.environment, a.business_tag,
               a.dependencies_json,
               cv.cvss_score, cv.severity, cv.description
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.asset_id
        JOIN cves cv ON v.cve_id = cv.cve_id
        """
    ).fetchall()
    conn.close()

    scored = []
    for row in rows:
        d = dict(row)
        vuln = {"vuln_id": d["vuln_id"]}
        asset = {
            "asset_id": d["asset_id"],
            "internet_exposed": d["internet_exposed"],
            "environment": d["environment"],
            "business_tag": d["business_tag"],
            "dependencies_json": d["dependencies_json"],
        }
        cve = {"cve_id": d["cve_id"], "cvss_score": d["cvss_score"]}
        result = score_vulnerability(vuln, asset, cve, w)

        # Parse dep count
        try:
            dep_count = len(json.loads(d["dependencies_json"] or "[]"))
        except Exception:
            dep_count = 0

        scored.append({
            "vuln_id": d["vuln_id"],
            "asset_id": d["asset_id"],
            "asset_name": d["asset_name"],
            "cve_id": d["cve_id"],
            "cvss_score": d["cvss_score"],
            "severity": d["severity"],
            "environment": d["environment"],
            "business_tag": d["business_tag"],
            "internet_exposed": bool(d["internet_exposed"]),
            "dep_count": dep_count,
            "risk_score": round(result["final_score"], 4),
            "primary_driver": result["primary_driver"],
            "status": d["status"],
        })

    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


# ── Asset Inventory ───────────────────────────────────────────────────────────

def get_assets(filters: Optional[dict] = None) -> list:
    """
    Returns assets from the DB, optionally filtered.

    filters dict keys:
      environment: list of env strings (e.g. ['production', 'staging'])
      business_tag: list of tag strings
      internet_exposed: bool (True = only internet-exposed)
    """
    conn = get_db_connection()
    c = conn.cursor()
    rows = c.execute("SELECT * FROM assets").fetchall()
    conn.close()

    assets = []
    for row in rows:
        d = dict(row)
        try:
            dep_count = len(json.loads(d.get("dependencies_json") or "[]"))
        except Exception:
            dep_count = 0
        d["dep_count"] = dep_count
        assets.append(d)

    if not filters:
        return assets

    # Apply filters in Python (small dataset — avoids SQL injection risk with list params)
    if envs := filters.get("environment"):
        assets = [a for a in assets if a["environment"] in envs]
    if tags := filters.get("business_tag"):
        assets = [a for a in assets if a["business_tag"] in tags]
    if filters.get("internet_exposed"):
        assets = [a for a in assets if a["internet_exposed"]]

    return assets


# ── Vulnerability Detail ──────────────────────────────────────────────────────

def get_vulnerability_detail(vuln_id: str) -> Optional[dict]:
    """
    Returns a joined asset + CVE + enrichment record for one vulnerability.
    Used by the Run Pipeline page detail panel.
    """
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute(
        """
        SELECT v.vuln_id, v.asset_id, v.cve_id, v.status, v.discovered_at,
               a.name as asset_name, a.type, a.os, a.internet_exposed,
               a.environment, a.business_tag, a.dependencies_json,
               cv.cvss_score, cv.severity, cv.description, cv.published,
               e.severity_context, e.exploitation_intelligence,
               e.remediation_approach, e.confidence, e.enriched_at
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.asset_id
        JOIN cves cv ON v.cve_id = cv.cve_id
        LEFT JOIN enrichments e ON cv.cve_id = e.cve_id
        WHERE v.vuln_id = ?
        """,
        (vuln_id,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Enrichment Status ─────────────────────────────────────────────────────────

def get_enrichment_status(cve_id: str) -> Optional[dict]:
    """
    Checks the enrichments table for a CVE.
    Returns the enrichment record or None if not yet enriched.
    """
    conn = get_db_connection()
    c = conn.cursor()
    row = c.execute(
        "SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Sandbox Result ────────────────────────────────────────────────────────────

def get_sandbox_results() -> dict:
    """
    Returns a dict mapping vuln_id → sandbox verdict if any sandbox runs
    have been persisted. (For now, sandbox results are in-memory only;
    this returns an empty dict as a placeholder for future persistence.)
    """
    return {}
