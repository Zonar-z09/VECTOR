"""
tests/test_gcp_client.py — unit tests for src/ingest/gcp_client.py

These tests inject fake stand-ins for the google-cloud-* SDK modules into
sys.modules rather than requiring the real packages to be installed — the
same hermetic principle as the rest of this suite, and necessary here since
gcp_client.py's imports are lazy (inside each function) specifically so the
mock-mode demo path never needs these packages. This does NOT verify the
real SDKs' actual behavior (impossible without a live project — see
gcp_client.py's module docstring) — it verifies that gcp_client.py correctly
transforms whatever shape the SDK hands back into VECTOR's envelope format.
"""

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def clean_gcp_project_env(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "vector-test-project")
    monkeypatch.delenv("GCP_ORG_ID", raising=False)


@pytest.fixture
def fake_module(monkeypatch):
    """Registers a fake module at sys.modules[name] for the duration of a test."""
    installed = []

    def _install(name: str, **attrs):
        mod = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(mod, k, v)
        monkeypatch.setitem(sys.modules, name, mod)
        installed.append(name)
        return mod

    yield _install


def _import_gcp_client():
    # Import fresh each time so lazy imports inside functions re-resolve
    # against whatever fake modules the test just installed.
    import importlib
    import src.ingest.gcp_client as gcp_client
    importlib.reload(gcp_client)
    return gcp_client


class TestProjectId:
    def test_returns_env_var_when_set(self, fake_module):
        gcp_client = _import_gcp_client()
        assert gcp_client._project_id() == "vector-test-project"

    def test_raises_when_unset(self, fake_module, monkeypatch):
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
        gcp_client = _import_gcp_client()
        with pytest.raises(RuntimeError):
            gcp_client._project_id()


class TestFetchSccFindingsLive:
    def test_returns_envelope_shape_from_fake_findings(self, fake_module):
        fake_finding = MagicMock()
        fake_finding.name = "organizations/123/sources/456/findings/etd-001"
        fake_finding.category = "EVENT_THREAT_DETECTION"
        fake_finding.resource_name = "//compute.googleapis.com/projects/x/instances/prod-web-01"
        fake_finding.severity.name = "HIGH"
        fake_finding.description = "Test finding"

        fake_result = MagicMock()
        fake_result.finding = fake_finding

        fake_client = MagicMock()
        fake_client.list_findings.return_value = [fake_result]

        fake_module(
            "google.cloud.securitycenter",
            SecurityCenterClient=MagicMock(return_value=fake_client),
        )

        gcp_client = _import_gcp_client()
        records = gcp_client.fetch_scc_findings_live()

        assert len(records) == 1
        r = records[0]
        assert r["source_type"] == "gcp_scc"
        assert r["record_type"] == "vulnerability"
        assert r["category"] == "EVENT_THREAT_DETECTION"
        assert r["raw"]["finding_id"] == "etd-001"
        assert r["raw"]["severity"] == "HIGH"

    def test_uses_org_parent_when_org_id_set(self, fake_module, monkeypatch):
        monkeypatch.setenv("GCP_ORG_ID", "999")
        fake_client = MagicMock()
        fake_client.list_findings.return_value = []
        fake_module("google.cloud.securitycenter", SecurityCenterClient=MagicMock(return_value=fake_client))

        gcp_client = _import_gcp_client()
        gcp_client.fetch_scc_findings_live()

        call_kwargs = fake_client.list_findings.call_args.kwargs
        assert call_kwargs["request"]["parent"] == "organizations/999/sources/-"


class TestFetchCloudAssetInventoryLive:
    def test_returns_asset_record_type(self, fake_module):
        fake_asset = MagicMock()
        fake_asset.name = "//compute.googleapis.com/projects/x/instances/prod-web-01"
        fake_asset.asset_type = "compute.googleapis.com/Instance"
        fake_asset.resource.data = {"zone": "us-central1-a", "labels": {"env": "production"}}

        fake_client = MagicMock()
        fake_client.list_assets.return_value = [fake_asset]

        fake_asset_v1 = fake_module(
            "google.cloud.asset_v1",
            AssetServiceClient=MagicMock(return_value=fake_client),
            ContentType=MagicMock(RESOURCE="RESOURCE"),
        )

        gcp_client = _import_gcp_client()
        records = gcp_client.fetch_cloud_asset_inventory_live()

        assert len(records) == 1
        assert records[0]["record_type"] == "asset"
        assert records[0]["raw"]["display_name"] == "prod-web-01"
        assert records[0]["raw"]["labels"] == {"env": "production"}


class TestFetchIamRecommenderLive:
    def test_returns_vulnerability_record_with_recommendation_text(self, fake_module):
        fake_rec = MagicMock()
        fake_rec.name = "projects/x/locations/global/recommenders/y/recommendations/rec-001"
        fake_rec.description = "Remove unused role."

        fake_client = MagicMock()
        fake_client.list_recommendations.return_value = [fake_rec]
        fake_module("google.cloud.recommender_v1", RecommenderClient=MagicMock(return_value=fake_client))

        gcp_client = _import_gcp_client()
        records = gcp_client.fetch_iam_recommender_findings_live()

        assert len(records) == 1
        assert records[0]["source_type"] == "iam_recommender"
        assert records[0]["raw"]["recommendation"] == "Remove unused role."
        # Documented limitation — see gcp_client.py's UNVERIFIED note
        assert records[0]["raw"]["current_role"] is None
