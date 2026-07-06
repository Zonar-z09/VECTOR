"""
tests/conftest.py — shared pytest fixtures.

Central idea: src/db/database.py reads a module-level DB_PATH constant fresh
on every get_db_connection() call, so patching that constant per-test (via
monkeypatch) gives full test isolation from the real vulnerability_lake.db
without any changes to production code.
"""

import sys
import json
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db import database as db_module


@pytest.fixture
def anyio_backend():
    """Runs @pytest.mark.anyio async tests on the asyncio backend (anyio plugin is already installed)."""
    return "asyncio"


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """
    Points src.db.database at an isolated temp SQLite file for the duration
    of the test, and initializes the schema. Never touches the real data lake.
    """
    db_path = tmp_path / "test_vulnerability_lake.db"
    monkeypatch.setattr(db_module, "DB_PATH", db_path)
    db_module.init_db()
    yield db_path


@pytest.fixture
def sample_asset():
    return {
        "asset_id": "ASSET-TEST-01",
        "name": "test-web-01",
        "type": "web_server",
        "os": "Ubuntu 22.04",
        "internet_exposed": True,
        "environment": "production",
        "business_tag": "critical",
        "patch_cadence_days": 30,
        "dependencies": ["ASSET-TEST-02", "ASSET-TEST-03"],
    }


@pytest.fixture
def sample_cve():
    return {
        "cve_id": "CVE-TEST-0001",
        "description": "Test remote code execution vulnerability in test-lib.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2024-01-01",
    }


@pytest.fixture
def populated_db(test_db, sample_asset, sample_cve):
    """
    test_db plus one asset, one CVE, and one vulnerability pairing inserted —
    for tests that need to exercise joins (data_access.py, playbook_agent.py).
    """
    conn = db_module.get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO assets
        (asset_id, name, type, os, internet_exposed, environment, business_tag,
         patch_cadence_days, dependencies_json, raw_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample_asset["asset_id"], sample_asset["name"], sample_asset["type"],
            sample_asset["os"], sample_asset["internet_exposed"], sample_asset["environment"],
            sample_asset["business_tag"], sample_asset["patch_cadence_days"],
            json.dumps(sample_asset["dependencies"]), json.dumps(sample_asset),
        ),
    )
    cursor.execute(
        """
        INSERT INTO cves (cve_id, description, cvss_score, severity, published, raw_data)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            sample_cve["cve_id"], sample_cve["description"], sample_cve["cvss_score"],
            sample_cve["severity"], sample_cve["published"], json.dumps(sample_cve),
        ),
    )
    cursor.execute(
        """
        INSERT INTO vulnerabilities (vuln_id, asset_id, cve_id, status, discovered_at)
        VALUES (?, ?, ?, 'open', '2024-01-02T00:00:00Z')
        """,
        ("VULN-TEST-0001", sample_asset["asset_id"], sample_cve["cve_id"]),
    )
    conn.commit()
    conn.close()
    return test_db
