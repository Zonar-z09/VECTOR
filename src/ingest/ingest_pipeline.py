"""
Ingests mock asset inventory and real CVE IDs into the unified data lake.
Also creates synthetic vulnerability pairings for testing the engine.
"""

import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
import sys

# Ensure src module is discoverable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.database import get_db_connection, init_db

DATA_DIR = Path(__file__).parent.parent.parent / "data"

def load_assets(conn):
    assets_file = DATA_DIR / "assets.json"
    if not assets_file.exists():
        print(f"Error: {assets_file} not found.")
        return []
    
    data = json.loads(assets_file.read_text())
    assets = data.get("assets", [])
    
    cursor = conn.cursor()
    for a in assets:
        cursor.execute("""
            INSERT OR REPLACE INTO assets
            (asset_id, name, type, os, internet_exposed, environment, business_tag, patch_cadence_days, dependencies_json, raw_data, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a["asset_id"],
            a["name"],
            a["type"],
            a["os"],
            a["internet_exposed"],
            a["environment"],
            a["business_tag"],
            a["patch_cadence_days"],
            json.dumps(a.get("dependencies", [])),
            json.dumps(a),
            "synthetic_seed"
        ))
    
    conn.commit()
    print(f"Loaded {len(assets)} assets.")
    return assets

def load_cves(conn):
    cves_file = DATA_DIR / "cve_seed_list.json"
    if not cves_file.exists():
        print(f"Error: {cves_file} not found.")
        return []
    
    data = json.loads(cves_file.read_text())
    cves = data.get("cves", [])
    
    cursor = conn.cursor()
    for c in cves:
        cursor.execute("""
            INSERT OR REPLACE INTO cves
            (cve_id, description, cvss_score, severity, published, raw_data, source_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            c["cve_id"],
            c["description"],
            c["cvss_score"],
            c["severity"],
            c["published"],
            json.dumps(c),
            "synthetic_seed"
        ))
    
    conn.commit()
    print(f"Loaded {len(cves)} CVEs.")
    return cves

def generate_synthetic_vulnerabilities(conn, assets, cves):
    """Generates 10 random pairings between assets and cves."""
    if not assets or not cves:
        return
    
    cursor = conn.cursor()
    # Clear existing synthetic data for a clean run
    cursor.execute("DELETE FROM vulnerabilities")
    
    # We want 10 synthetic vulnerabilities
    vuln_count = 10
    
    ts = datetime.now(timezone.utc).isoformat()
    
    print(f"Generating {vuln_count} synthetic vulnerabilities...")
    
    # Ensure reproducibility for tests if needed, but random is fine for this demo
    random.seed(42)
    
    for i in range(vuln_count):
        asset = random.choice(assets)
        cve = random.choice(cves)
        vuln_id = f"VULN-{uuid.uuid4().hex[:8].upper()}"
        
        cursor.execute("""
            INSERT INTO vulnerabilities (vuln_id, asset_id, cve_id, discovered_at, source_type)
            VALUES (?, ?, ?, ?, ?)
        """, (vuln_id, asset["asset_id"], cve["cve_id"], ts, "synthetic_seed"))
    
    conn.commit()
    print("Done generating synthetic vulnerabilities.")

def main():
    print("Initializing database...")
    init_db()
    conn = get_db_connection()
    
    assets = load_assets(conn)
    cves = load_cves(conn)
    generate_synthetic_vulnerabilities(conn, assets, cves)
    
    conn.close()
    print("Ingestion complete.")

if __name__ == "__main__":
    main()
