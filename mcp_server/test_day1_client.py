"""
MCP test client for Day 1 Server.
Calls the get_asset_inventory, get_vulnerability_record, and create_ticket tools.
"""

import asyncio
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test_day1_mcp_server():
    print("=== Day 1 MCP Server Test ===")

    server_params = StdioServerParameters(
        command="python",
        args=[str(Path(__file__).parent / "day1_server.py")],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List tools
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"Available tools: {tool_names}")

            # Call get_asset_inventory
            print("\n--- Calling get_asset_inventory ---")
            result = await session.call_tool("get_asset_inventory", {})
            assets = json.loads(result.content[0].text)
            print(f"Returned {len(assets)} assets.")
            if assets:
                print(f"First asset: {assets[0]['asset_id']} - {assets[0]['name']}")

            # Call get_vulnerability_record
            print("\n--- Calling get_vulnerability_record (no params) ---")
            result2 = await session.call_tool("get_vulnerability_record", {})
            vulns = json.loads(result2.content[0].text)
            print(f"Returned {len(vulns)} vulnerability records.")
            
            if vulns:
                test_vuln_id = vulns[0]['vuln_id']
                print(f"\n--- Calling get_vulnerability_record (vuln_id={test_vuln_id}) ---")
                result3 = await session.call_tool("get_vulnerability_record", {"vuln_id": test_vuln_id})
                vuln_record = json.loads(result3.content[0].text)
                print(f"Returned {len(vuln_record)} record(s).")
                print(f"Details: {vuln_record[0]['cve_id']} on {vuln_record[0]['asset_name']}")

                # Call create_ticket
                print(f"\n--- Calling create_ticket (vuln_id={test_vuln_id}) ---")
                result4 = await session.call_tool("create_ticket", {"vuln_id": test_vuln_id})
                ticket_info = json.loads(result4.content[0].text)
                print(f"Response: {ticket_info}")

            print("\n✅ Day 1 MCP server: PASSED")

if __name__ == "__main__":
    asyncio.run(test_day1_mcp_server())
