"""
tests/test_connectors.py — unit tests for src/ingest/connectors.py

No network calls — in mock mode (the default, and the only mode these tests
exercise) every connector returns hardcoded synthetic data. Live-mode
dispatch to gcp_client.py is covered by tests/test_gcp_client.py's mocked
SDK tests, not here.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingest import connectors
from src.ingest.connectors import SOURCE_CONNECTORS, SOURCE_LABELS, fetch_all

SCC_CATEGORIES = {
    "EVENT_THREAT_DETECTION", "WEB_SECURITY_SCANNER", "CONTAINER_THREAT_DETECTION",
    "VM_THREAT_DETECTION", "SECURITY_HEALTH_ANALYTICS", "RAPID_VULNERABILITY_DETECTION",
    "SENSITIVE_ACTIONS_SERVICE",
}
GCP_LIVE_DISPATCHED_SOURCES = {
    "gcp_scc", "cloud_asset_inventory", "artifact_analysis", "cloud_dlp", "iam_recommender",
}


class TestConnectorShape:
    @pytest.mark.parametrize("source_id", list(SOURCE_CONNECTORS.keys()))
    def test_each_connector_returns_well_formed_records(self, source_id):
        records = SOURCE_CONNECTORS[source_id]()
        assert len(records) > 0
        for r in records:
            assert r["source_type"] == source_id
            assert r["record_type"] in ("asset", "vulnerability")
            assert isinstance(r["raw"], dict)
            assert len(r["raw"]) > 0

    def test_every_connector_has_a_label(self):
        assert set(SOURCE_CONNECTORS.keys()) == set(SOURCE_LABELS.keys())

    def test_nine_sources_registered(self):
        assert len(SOURCE_CONNECTORS) == 9


class TestSccUnifiedConnector:
    def test_all_seven_categories_present(self):
        records = SOURCE_CONNECTORS["gcp_scc"]()
        found = {r["category"] for r in records}
        assert found == SCC_CATEGORIES

    def test_category_matches_raw_category(self):
        for r in SOURCE_CONNECTORS["gcp_scc"]():
            assert r["category"] == r["raw"]["category"]


class TestCloudAssetInventory:
    def test_records_are_asset_type_not_vulnerability(self):
        records = SOURCE_CONNECTORS["cloud_asset_inventory"]()
        assert all(r["record_type"] == "asset" for r in records)


class TestArtifactAnalysis:
    def test_at_least_one_record_carries_a_real_looking_cve(self):
        records = SOURCE_CONNECTORS["artifact_analysis"]()
        cves = [r["raw"]["cve"] for r in records if r["raw"].get("cve")]
        assert any(c.startswith("CVE-") for c in cves)


class TestSimplifiedConnectorsAreLabeled:
    def test_chronicle_and_threat_intel_labels_flag_simplification(self):
        assert "simplified" in SOURCE_LABELS["chronicle_secops"].lower()
        assert "simplified" in SOURCE_LABELS["threat_intel"].lower()


class TestGcpModeDispatch:
    def test_default_mode_is_mock(self):
        assert connectors.VECTOR_GCP_MODE == "mock"

    def test_gcp_source_wrapper_calls_mock_fn_in_mock_mode(self):
        calls = []
        wrapped = connectors._gcp_source(lambda: calls.append("mock") or [], "nonexistent_live_fn")
        wrapped()
        assert calls == ["mock"]

    def test_gcp_source_wrapper_dispatches_to_gcp_client_in_live_mode(self, monkeypatch):
        monkeypatch.setattr(connectors, "VECTOR_GCP_MODE", "live")
        fake_gcp_client = type("FakeModule", (), {"fake_live_fn": staticmethod(lambda: ["live-result"])})
        sys.modules["src.ingest.gcp_client"] = fake_gcp_client
        try:
            wrapped = connectors._gcp_source(lambda: ["mock-result"], "fake_live_fn")
            assert wrapped() == ["live-result"]
        finally:
            del sys.modules["src.ingest.gcp_client"]


class TestFetchAll:
    def test_fetch_all_with_no_args_returns_every_source(self):
        records = fetch_all()
        found_sources = {r["source_type"] for r in records}
        assert found_sources == set(SOURCE_CONNECTORS.keys())

    def test_fetch_all_with_subset_only_returns_those_sources(self):
        records = fetch_all(["edr"])
        assert all(r["source_type"] == "edr" for r in records)

    def test_fetch_all_rejects_unknown_source(self):
        with pytest.raises(ValueError):
            fetch_all(["not_a_real_source"])
