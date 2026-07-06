"""
tests/test_ingestion_agent.py — unit tests for process_next_record_tool()
in agents/ingestion_agent.py.

Uses the hermetic test_db fixture (conftest.py) and mocks Ollama at the
requests.post level (same pattern as test_normalization_agent.py) — no live
Ollama, Gemini, or GCP calls. Focuses on the DB write path, since the ADK
tool-calling loop itself is already exercised live (see agents/orchestrator.py
tests for that pattern applied to the sibling sub-agents).
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import agents.ingestion_agent as ia
from src.db.database import get_db_connection


def _mock_ollama_response(text: str):
    resp = MagicMock()
    resp.json.return_value = {"response": text}
    resp.raise_for_status = MagicMock()
    return resp


@pytest.fixture(autouse=True)
def reset_ingestion_agent_sink():
    """process_next_record_tool() uses module-level globals — reset between tests."""
    ia._pending_queue = []
    ia._last_ingestion_results = []
    yield
    ia._pending_queue = []
    ia._last_ingestion_results = []


class TestRealCveReuse:
    """
    Regression test for a live-run bug: reusing a real CVE ID from a source
    (e.g. Artifact Analysis) never inserted a cves row, so the vulnerability
    silently disappeared from every INNER JOIN view (data_access.py's
    get_prioritized_vulnerabilities()). Fixed by always INSERT OR IGNORE-ing
    a cves row regardless of whether the CVE ID is real or synthetic.
    """

    def test_reused_real_cve_gets_a_cves_row(self, test_db):
        record = {
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {
                "image_uri": "registry/vector-demo/prod-payment-svc/api:1.0",
                "package": "openssl",
                "cve": "CVE-2023-0286",
                "severity": "HIGH",
            },
        }
        ia._pending_queue = [record]

        payload = json.dumps({
            "matched_asset_id": None, "new_asset_name": None,
            "environment": "production", "business_tag": "high",
            "cvss_score_estimate": 7.5, "severity": "HIGH", "rationale": "test",
        })
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(payload)):
            ia.process_next_record_tool()

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM cves WHERE cve_id = 'CVE-2023-0286'").fetchone()
        conn.close()
        assert row is not None, "reused real CVE ID must get a cves row or it silently vanishes from INNER JOIN views"

    def test_reused_real_cve_row_joins_correctly_to_vulnerabilities(self, test_db):
        record = {
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {"image_uri": "registry/x/y:1.0", "package": "openssl", "cve": "CVE-2099-0001", "severity": "HIGH"},
        }
        ia._pending_queue = [record]
        payload = json.dumps({
            "matched_asset_id": None, "new_asset_name": None,
            "environment": "production", "business_tag": "high",
            "cvss_score_estimate": 7.5, "severity": "HIGH", "rationale": "test",
        })
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(payload)):
            ia.process_next_record_tool()

        conn = get_db_connection()
        joined = conn.execute(
            "SELECT v.vuln_id FROM vulnerabilities v JOIN cves cv ON v.cve_id = cv.cve_id WHERE cv.cve_id = 'CVE-2099-0001'"
        ).fetchall()
        conn.close()
        assert len(joined) == 1

    def test_does_not_overwrite_already_seeded_real_cve(self, test_db, sample_cve):
        """INSERT OR IGNORE must not clobber a real NVD-sourced CVE already in the seed data."""
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO cves (cve_id, description, cvss_score, severity, published, raw_data, source_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sample_cve["cve_id"], sample_cve["description"], sample_cve["cvss_score"],
             sample_cve["severity"], sample_cve["published"], "{}", "synthetic_seed"),
        )
        conn.commit()
        conn.close()

        record = {
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {"image_uri": "registry/x/y:1.0", "package": "test", "cve": sample_cve["cve_id"], "severity": "LOW"},
        }
        ia._pending_queue = [record]
        payload = json.dumps({
            "matched_asset_id": None, "new_asset_name": None,
            "environment": "unknown", "business_tag": "low",
            "cvss_score_estimate": 1.0, "severity": "LOW", "rationale": "test",
        })
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(payload)):
            ia.process_next_record_tool()

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM cves WHERE cve_id = ?", (sample_cve["cve_id"],)).fetchone()
        conn.close()
        assert row["description"] == sample_cve["description"]
        assert row["source_type"] == "synthetic_seed"


class TestAssetOnlyRecords:
    def test_asset_record_type_creates_no_vulnerability_row(self, test_db):
        record = {
            "source_type": "cloud_asset_inventory",
            "record_type": "asset",
            "raw": {"display_name": "brand-new-host", "asset_type": "compute.googleapis.com/Instance"},
        }
        ia._pending_queue = [record]
        payload = json.dumps({
            "matched_asset_id": None, "new_asset_name": "brand-new-host",
            "environment": "production", "business_tag": "medium",
            "cvss_score_estimate": 0.0, "severity": "LOW", "rationale": "new asset",
        })
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(payload)):
            result = json.loads(ia.process_next_record_tool())

        assert result["processed"]["cve_id"] is None
        assert result["processed"]["vuln_id"] is None

        conn = get_db_connection()
        vuln_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        asset_row = conn.execute("SELECT * FROM assets WHERE name = 'brand-new-host'").fetchone()
        conn.close()
        assert vuln_count == 0
        assert asset_row is not None


class TestSccCategoryFoldedIntoSourceType:
    def test_gcp_scc_source_type_includes_category(self, test_db):
        record = {
            "source_type": "gcp_scc",
            "record_type": "vulnerability",
            "category": "SECURITY_HEALTH_ANALYTICS",
            "raw": {"resource_display_name": "some-asset", "description": "misconfig", "severity": "HIGH"},
        }
        ia._pending_queue = [record]
        payload = json.dumps({
            "matched_asset_id": None, "new_asset_name": "some-asset",
            "environment": "production", "business_tag": "high",
            "cvss_score_estimate": 7.0, "severity": "HIGH", "rationale": "test",
        })
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(payload)):
            result = json.loads(ia.process_next_record_tool())

        assert result["processed"]["source_type"] == "gcp_scc:security_health_analytics"


class TestQueueCompletion:
    def test_empty_queue_reports_done(self, test_db):
        ia._pending_queue = []
        result = json.loads(ia.process_next_record_tool())
        assert result["done"] is True
