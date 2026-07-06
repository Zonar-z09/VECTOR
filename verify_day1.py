"""
verify_day1.py — Run all Day 1 verification checks.

Checks:
  1. Ingestion / Database: SQLite DB exists and contains data.
  2. Prioritization Engine: Engine outputs a deterministic score with an explainable breakdown.
  3. MCP Server: Day 1 tools (get_asset_inventory, get_vulnerability_record, create_ticket) are callable.
"""

import os
import sys
import asyncio
import json
import sqlite3
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console(force_terminal=True, highlight=False)

results = []

def check(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((name, status, detail))
    console.print(f"  {status}  {name}" + (f" — {detail}" if detail else ""))

# ── 1. Ingestion & Database ───────────────────────────────────────────────────

console.print("\n[bold cyan]1. Ingestion & Database (SQLite)[/bold cyan]")
try:
    db_path = Path("data/vulnerability_lake.db")
    if not db_path.exists():
        check("Database File", False, f"{db_path} does not exist.")
    else:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM assets")
        asset_count = cursor.fetchone()[0]
        check("Assets Ingestion", asset_count > 0, f"Loaded {asset_count} assets")
        
        cursor.execute("SELECT COUNT(*) FROM cves")
        cve_count = cursor.fetchone()[0]
        check("CVEs Ingestion", cve_count > 0, f"Loaded {cve_count} CVEs")
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]
        check("Synthetic Vulnerabilities", vuln_count > 0, f"Generated {vuln_count} pairings")
        
        conn.close()
except Exception as e:
    check("Database Verification", False, str(e)[:80])

# ── 2. Prioritization Engine ──────────────────────────────────────────────────

console.print("\n[bold cyan]2. Prioritization Engine (Five-Factor Model)[/bold cyan]")
try:
    # Set up a mock vulnerability for testing the engine directly
    from src.engine.prioritization import score_vulnerability
    
    mock_vuln = {"vuln_id": "VULN-TEST"}
    mock_asset = {
        "asset_id": "ASSET-TEST",
        "internet_exposed": True,
        "environment": "production",
        "business_tag": "critical",
        "dependencies_json": "[\"ASSET-002\", \"ASSET-003\"]"
    }
    mock_cve = {
        "cve_id": "CVE-TEST",
        "cvss_score": 10.0
    }
    
    res = score_vulnerability(mock_vuln, mock_asset, mock_cve)
    
    has_score = "final_score" in res and isinstance(res["final_score"], float)
    has_breakdown = "breakdown" in res and "internet_exposure" in res["breakdown"]
    has_driver = "primary_driver" in res
    
    if has_score and has_breakdown and has_driver:
        check("Engine Execution", True, f"Score: {res['final_score']}, Driver: {res['primary_driver']}")
    else:
        check("Engine Execution", False, "Missing required output fields in score result")
except Exception as e:
    check("Engine Execution", False, str(e)[:80])

# ── 3. MCP Server ─────────────────────────────────────────────────────────────

console.print("\n[bold cyan]3. MCP Server (Day 1 Tools)[/bold cyan]")

async def test_mcp():
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        
        server_params = StdioServerParameters(
            command="python",
            args=[str(Path("mcp_server/day1_server.py"))],
        )
        
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                
                # Check get_asset_inventory
                res1 = await session.call_tool("get_asset_inventory", {})
                assets = json.loads(res1.content[0].text)
                check("MCP: get_asset_inventory", len(assets) > 0, f"Returned {len(assets)} assets")
                
                # Check get_vulnerability_record
                res2 = await session.call_tool("get_vulnerability_record", {})
                vulns = json.loads(res2.content[0].text)
                check("MCP: get_vulnerability_record", len(vulns) > 0, f"Returned {len(vulns)} vulnerabilities")
                
                # Check create_ticket
                if vulns:
                    test_id = vulns[0].get("vuln_id", "TEST-123")
                    res3 = await session.call_tool("create_ticket", {"vuln_id": test_id})
                    ticket = json.loads(res3.content[0].text)
                    check("MCP: create_ticket", ticket.get("status") == "success", f"Created {ticket.get('ticket_id')}")
                else:
                    check("MCP: create_ticket", False, "No vulnerabilities found to ticket")
                    
    except Exception as e:
        check("MCP Server Execution", False, str(e)[:80])

asyncio.run(test_mcp())

# ── Summary ───────────────────────────────────────────────────────────────────

console.print("\n")
table = Table(title="Day 1 Verification Summary")
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
