"""
Database setup for the unified data lake (VECTOR).
"""

import sqlite3
import json
from pathlib import Path

DB_DIR = Path(__file__).parent.parent.parent / "data"
DB_PATH = DB_DIR / "vulnerability_lake.db"

def get_db_connection():
    """Returns a SQLite connection to the data lake."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Assets table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            name TEXT,
            type TEXT,
            os TEXT,
            internet_exposed BOOLEAN,
            environment TEXT,
            business_tag TEXT,
            patch_cadence_days INTEGER,
            dependencies_json TEXT, -- Store list as JSON
            raw_data TEXT,
            source_type TEXT DEFAULT 'synthetic_seed'
        )
    """)

    # CVEs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            severity TEXT,
            published TEXT,
            raw_data TEXT,
            source_type TEXT DEFAULT 'synthetic_seed'
        )
    """)

    # Vulnerabilities table (Asset + CVE mapping)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id TEXT PRIMARY KEY,
            asset_id TEXT,
            cve_id TEXT,
            status TEXT DEFAULT 'open',
            discovered_at TEXT,
            source_type TEXT DEFAULT 'synthetic_seed',
            FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        )
    """)

    # Migration: add source_type to any pre-existing DB file created before
    # this column existed (CREATE TABLE IF NOT EXISTS above is a no-op on an
    # already-created table, so ALTER TABLE is needed for upgrades in place).
    for table in ("assets", "cves", "vulnerabilities"):
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN source_type TEXT DEFAULT 'synthetic_seed'")
        except sqlite3.OperationalError:
            pass  # column already exists

    # Enrichments table — write-once cache (Pillar 2b)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS enrichments (
            cve_id TEXT PRIMARY KEY,
            severity_context TEXT,
            exploitation_intelligence TEXT,
            remediation_approach TEXT,
            confidence TEXT,
            enriched_at TEXT,
            raw_response TEXT
        )
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
