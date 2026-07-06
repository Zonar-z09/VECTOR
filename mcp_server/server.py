"""
MCP Server — Day 0 verification check.

Exposes two tools:
  - ping: returns a pong with a timestamp
  - get_asset_count: returns the number of assets in the synthetic inventory

Run:  python mcp_server/server.py
Test: python mcp_server/test_client.py
"""

import json
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types as mcp_types


# ── Server setup ─────────────────────────────────────────────────────────────

app = Server("vulnerability-intel-server")

DATA_DIR = Path(__file__).parent.parent / "data"


@app.list_tools()
async def list_tools() -> list[mcp_types.Tool]:
    return [
        mcp_types.Tool(
            name="ping",
            description="Health check — returns a pong with a UTC timestamp.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        mcp_types.Tool(
            name="get_asset_count",
            description="Returns the number of assets in the synthetic inventory.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        mcp_types.Tool(
            name="get_cve_seeds",
            description="Returns the seed list of CVE IDs for enrichment.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[mcp_types.TextContent]:
    if name == "ping":
        ts = datetime.now(timezone.utc).isoformat()
        return [mcp_types.TextContent(type="text", text=f"pong — {ts}")]

    elif name == "get_asset_count":
        assets_file = DATA_DIR / "assets.json"
        if assets_file.exists():
            assets = json.loads(assets_file.read_text())
            count = len(assets.get("assets", []))
        else:
            count = 0
        return [mcp_types.TextContent(type="text", text=str(count))]

    elif name == "get_cve_seeds":
        cve_file = DATA_DIR / "cve_seed_list.json"
        if cve_file.exists():
            data = json.loads(cve_file.read_text())
            return [mcp_types.TextContent(type="text", text=json.dumps(data, indent=2))]
        return [mcp_types.TextContent(type="text", text="[]")]

    else:
        raise ValueError(f"Unknown tool: {name}")


# ── Entry point ───────────────────────────────────────────────────────────────

async def main():
    print("Starting MCP vulnerability-intel-server on stdio...")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
