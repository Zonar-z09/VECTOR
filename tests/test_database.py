"""
tests/test_database.py — unit tests for src/db/database.py

Uses the test_db fixture (conftest.py) — never touches the real data lake.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.database import get_db_connection


EXPECTED_TABLES = {"assets", "cves", "vulnerabilities", "enrichments"}

EXPECTED_COLUMNS = {
    "assets": {
        "asset_id", "name", "type", "os", "internet_exposed", "environment",
        "business_tag", "patch_cadence_days", "dependencies_json", "raw_data", "source_type",
    },
    "cves": {"cve_id", "description", "cvss_score", "severity", "published", "raw_data", "source_type"},
    "vulnerabilities": {"vuln_id", "asset_id", "cve_id", "status", "discovered_at", "source_type"},
    "enrichments": {
        "cve_id", "severity_context", "exploitation_intelligence",
        "remediation_approach", "confidence", "enriched_at", "raw_response",
    },
}


def _table_columns(conn, table_name):
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


class TestSchema:
    def test_all_expected_tables_exist(self, test_db):
        conn = get_db_connection()
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        conn.close()
        assert EXPECTED_TABLES.issubset(tables)

    def test_table_columns_match_expected(self, test_db):
        conn = get_db_connection()
        for table, expected_cols in EXPECTED_COLUMNS.items():
            assert _table_columns(conn, table) == expected_cols, f"mismatch in {table}"
        conn.close()

    def test_init_db_is_idempotent(self, test_db):
        # Calling init_db() twice must not raise or drop existing data.
        from src.db.database import init_db
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO cves (cve_id, description, cvss_score, severity, published, raw_data) "
            "VALUES ('CVE-IDEMPOTENT', 'x', 5.0, 'MEDIUM', '2024-01-01', '{}')"
        )
        conn.commit()
        conn.close()

        init_db()  # second call — should be a no-op on existing tables/rows

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM cves WHERE cve_id = 'CVE-IDEMPOTENT'").fetchone()
        conn.close()
        assert row is not None


class TestConnection:
    def test_row_factory_allows_dict_style_access(self, test_db):
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO cves (cve_id, description, cvss_score, severity, published, raw_data) "
            "VALUES ('CVE-ROWFACTORY', 'desc', 7.0, 'HIGH', '2024-01-01', '{}')"
        )
        conn.commit()
        row = conn.execute("SELECT * FROM cves WHERE cve_id = 'CVE-ROWFACTORY'").fetchone()
        conn.close()
        assert row["cve_id"] == "CVE-ROWFACTORY"
        assert dict(row)["severity"] == "HIGH"
