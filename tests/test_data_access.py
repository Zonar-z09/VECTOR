"""
tests/test_data_access.py — unit tests for web/data_access.py

Uses the populated_db fixture (conftest.py): one asset, one CVE, one
vulnerability pairing, isolated from the real data lake.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from web.data_access import (
    get_summary_counts,
    get_prioritized_vulnerabilities,
    get_assets,
    get_vulnerability_detail,
    get_enrichment_status,
)


class TestSummaryCounts:
    def test_counts_match_populated_fixture(self, populated_db):
        counts = get_summary_counts()
        assert counts["assets"] == 1
        assert counts["cves"] == 1
        assert counts["open_vulns"] == 1
        assert counts["enriched_count"] == 0  # nothing enriched yet in this fixture

    def test_empty_db_returns_zeros(self, test_db):
        counts = get_summary_counts()
        assert counts == {"assets": 0, "cves": 0, "open_vulns": 0, "enriched_count": 0}


class TestPrioritizedVulnerabilities:
    def test_returns_scored_record_for_fixture_pairing(self, populated_db):
        results = get_prioritized_vulnerabilities()
        assert len(results) == 1
        r = results[0]
        assert r["cve_id"] == "CVE-TEST-0001"
        assert r["asset_id"] == "ASSET-TEST-01"
        assert 0.0 <= r["risk_score"] <= 1.0
        assert r["primary_driver"] in {
            "internet_exposure", "environment_classification",
            "exploit_capability", "manual_tag", "dependency_score",
        }

    def test_sorted_descending_by_risk_score(self, populated_db):
        results = get_prioritized_vulnerabilities()
        scores = [r["risk_score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_custom_weights_are_applied(self, populated_db):
        default_results = get_prioritized_vulnerabilities()
        custom_weights = {
            "internet_exposure": 0.0, "environment_classification": 0.0,
            "exploit_capability": 1.0, "manual_tag": 0.0, "dependency_score": 0.0,
        }
        custom_results = get_prioritized_vulnerabilities(weights=custom_weights)
        # cvss_score=9.8 → exploit_capability base 0.98, weight 1.0 → score should be ~0.98
        assert abs(custom_results[0]["risk_score"] - 0.98) < 0.01
        assert custom_results[0]["primary_driver"] == "exploit_capability"


class TestAssets:
    def test_returns_all_assets_unfiltered(self, populated_db):
        assets = get_assets()
        assert len(assets) == 1
        assert assets[0]["asset_id"] == "ASSET-TEST-01"
        assert assets[0]["dep_count"] == 2  # from sample_asset's 2 dependencies

    def test_filter_by_environment_matches(self, populated_db):
        assets = get_assets(filters={"environment": ["production"]})
        assert len(assets) == 1

    def test_filter_by_environment_excludes_nonmatching(self, populated_db):
        assets = get_assets(filters={"environment": ["staging"]})
        assert len(assets) == 0

    def test_filter_internet_exposed_only(self, populated_db):
        assets = get_assets(filters={"internet_exposed": True})
        assert len(assets) == 1  # sample_asset is internet-exposed

    def test_filter_by_business_tag(self, populated_db):
        assets = get_assets(filters={"business_tag": ["low"]})
        assert len(assets) == 0  # sample_asset is tagged 'critical'


class TestVulnerabilityDetail:
    def test_returns_full_joined_record(self, populated_db):
        detail = get_vulnerability_detail("VULN-TEST-0001")
        assert detail is not None
        assert detail["cve_id"] == "CVE-TEST-0001"
        assert detail["asset_id"] == "ASSET-TEST-01"
        assert detail["severity_context"] is None  # LEFT JOIN, not yet enriched

    def test_unknown_vuln_id_returns_none(self, populated_db):
        assert get_vulnerability_detail("VULN-DOES-NOT-EXIST") is None


class TestEnrichmentStatus:
    def test_not_yet_enriched_returns_none(self, populated_db):
        assert get_enrichment_status("CVE-TEST-0001") is None

    def test_enriched_cve_returns_record(self, populated_db):
        from src.db.database import get_db_connection

        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO enrichments
            (cve_id, severity_context, exploitation_intelligence,
             remediation_approach, confidence, enriched_at, raw_response)
            VALUES ('CVE-TEST-0001', 'ctx', 'intel', 'approach', 'High', '2024-01-03', '{}')
            """
        )
        conn.commit()
        conn.close()

        status = get_enrichment_status("CVE-TEST-0001")
        assert status is not None
        assert status["confidence"] == "High"
