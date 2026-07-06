"""
MCP test client — Day 0 verification.
Calls the ping and get_asset_count tools and prints results.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def test_mcp_server():
    print("=== MCP Server Test ===")

    server_params = StdioServerParameters(
        command="python",
        args=[str(Path(__file__).parent / "server.py")],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List tools
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"Available tools: {tool_names}")

            # Call ping
            result = await session.call_tool("ping", {})
            print(f"ping → {result.content[0].text}")

            # Call get_asset_count
            result = await session.call_tool("get_asset_count", {})
            print(f"get_asset_count → {result.content[0].text} assets")

            print("✅ MCP server: PASSED")


if __name__ == "__main__":
    asyncio.run(test_mcp_server())
