"""
Day 1 MCP Server.

Exposes tools:
  - get_asset_inventory
  - get_vulnerability_record
  - create_ticket (stub)

Run: python mcp_server/day1_server.py
"""

import json
import asyncio
import sqlite3
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types as mcp_types

app = Server("vulnerability-intel-server-day1")
DB_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "vulnerability_lake.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    return [
        mcp_types.Tool(
            name="get_asset_inventory",
            description="Returns all assets in the inventory.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        mcp_types.Tool(
            name="get_vulnerability_record",
            description="Returns vulnerability details given a specific vuln_id, cve_id, or asset_id.",
            inputSchema={
                "type": "object", 
                "properties": {
                    "vuln_id": {"type": "string", "description": "Specific vulnerability mapping ID"},
                    "cve_id": {"type": "string", "description": "CVE ID (e.g. CVE-2024-3094)"},
                    "asset_id": {"type": "string", "description": "Asset ID (e.g. ASSET-001)"}
                }
            },
        ),
        mcp_types.Tool(
            name="create_ticket",
            description="Creates a remediation ticket (stub).",
            inputSchema={
                "type": "object", 
                "properties": {
                    "vuln_id": {"type": "string", "description": "Vulnerability ID to ticket"}
                }, 
                "required": ["vuln_id"]
            },
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[mcp_types.TextContent]:
    if name == "get_asset_inventory":
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets")
            rows = cursor.fetchall()
            conn.close()
            assets = [dict(row) for row in rows]
            return [mcp_types.TextContent(type="text", text=json.dumps(assets, indent=2))]
        except Exception as e:
            return [mcp_types.TextContent(type="text", text=f"Error reading DB: {e}")]

    elif name == "get_vulnerability_record":
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            vuln_id = arguments.get("vuln_id")
            cve_id = arguments.get("cve_id")
            asset_id = arguments.get("asset_id")
            
            query = """
                SELECT v.vuln_id, v.status, v.discovered_at, 
                       a.asset_id, a.name as asset_name, a.environment, a.business_tag, a.internet_exposed,
                       c.cve_id, c.description, c.cvss_score, c.severity
                FROM vulnerabilities v
                JOIN assets a ON v.asset_id = a.asset_id
                JOIN cves c ON v.cve_id = c.cve_id
                WHERE 1=1
            """
            params = []
            if vuln_id:
                query += " AND v.vuln_id = ?"
                params.append(vuln_id)
            if cve_id:
                query += " AND v.cve_id = ?"
                params.append(cve_id)
            if asset_id:
                query += " AND v.asset_id = ?"
                params.append(asset_id)
                
            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()
            results = [dict(row) for row in rows]
            return [mcp_types.TextContent(type="text", text=json.dumps(results, indent=2))]
        except Exception as e:
            return [mcp_types.TextContent(type="text", text=f"Error reading DB: {e}")]

    elif name == "create_ticket":
        vuln_id = arguments.get("vuln_id")
        if not vuln_id:
            return [mcp_types.TextContent(type="text", text="Error: vuln_id is required")]
        # Stub logic
        ticket_id = f"TICK-8492-{vuln_id.split('-')[-1]}" if '-' in vuln_id else "TICK-8492"
        res = {"status": "success", "ticket_id": ticket_id, "message": f"Ticket created for {vuln_id}"}
        return [mcp_types.TextContent(type="text", text=json.dumps(res, indent=2))]

    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    print("Starting Day 1 MCP server on stdio...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
