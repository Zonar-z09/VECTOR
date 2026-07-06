"""
verify_day0.py — Run all Day 0 verification checks.

Checks:
  1. NVD API key returns a real CVE record
  2. Claude API responds
  3. Ollama model answers a prompt locally
  4. MCP server starts and responds to ping tool call
  5. ADK hello-world agent runs (requires valid GOOGLE_API_KEY)
"""

import os
import sys
import subprocess
import asyncio
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()
console = Console()

results = []


def check(name: str, passed: bool, detail: str = ""):
    status = "✅ PASS" if passed else "❌ FAIL"
    results.append((name, status, detail))
    console.print(f"  {status}  {name}" + (f" — {detail}" if detail else ""))


# ── 1. NVD API ────────────────────────────────────────────────────────────────

console.print("\n[bold cyan]1. NVD API[/bold cyan]")
nvd_key = os.getenv("NVD_API_KEY", "")
try:
    r = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2024-6387"},
        headers={"apiKey": nvd_key} if nvd_key else {},
        timeout=15,
    )
    if r.status_code == 200:
        data = r.json()
        cve_id = data["vulnerabilities"][0]["cve"]["id"]
        check("NVD API — live CVE fetch", True, f"Fetched {cve_id}")
    else:
        check("NVD API — live CVE fetch", False, f"HTTP {r.status_code} (key may not be activated yet)")
except Exception as e:
    check("NVD API — live CVE fetch", False, str(e)[:80])


# ── 2. Claude API ─────────────────────────────────────────────────────────────

console.print("\n[bold cyan]2. Claude API (Anthropic)[/bold cyan]")
ant_key = os.getenv("ANTHROPIC_API_KEY", "")
try:
    import anthropic
    client = anthropic.Anthropic(api_key=ant_key)
    msg = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=20,
        messages=[{"role": "user", "content": "Reply with only: verified"}],
    )
    reply = msg.content[0].text.strip().lower()
    check("Claude API", "verified" in reply, f"Response: {reply}")
except Exception as e:
    check("Claude API", False, str(e)[:80])


# ── 3. Ollama local model ─────────────────────────────────────────────────────

console.print("\n[bold cyan]3. Ollama — qwen2.5:3b[/bold cyan]")
try:
    r = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "qwen2.5:3b", "prompt": "Reply with only the single word: verified", "stream": False},
        timeout=120,
    )
    if r.status_code == 200:
        reply = r.json().get("response", "").strip()
        check("Ollama qwen2.5:3b", bool(reply), f"Response: {reply[:60]}")
    else:
        check("Ollama qwen2.5:3b", False, f"HTTP {r.status_code} — is Ollama running?")
except requests.exceptions.ConnectionError:
    check("Ollama qwen2.5:3b", False, "Cannot connect to localhost:11434 — start Ollama first")
except Exception as e:
    check("Ollama qwen2.5:3b", False, str(e)[:80])


# ── 4. MCP server ─────────────────────────────────────────────────────────────

console.print("\n[bold cyan]4. MCP Server[/bold cyan]")

async def test_mcp():
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        from pathlib import Path

        server_params = StdioServerParameters(
            command="python",
            args=[str(Path("mcp_server/server.py"))],
        )
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("ping", {})
                return True, result.content[0].text
    except Exception as e:
        return False, str(e)[:80]

passed, detail = asyncio.run(test_mcp())
check("MCP server — ping tool", passed, detail)


# ── 5. ADK agent ──────────────────────────────────────────────────────────────

console.print("\n[bold cyan]5. Google ADK Agent[/bold cyan]")
google_key = os.getenv("GOOGLE_API_KEY", "")
if not google_key:
    check("ADK hello-world agent", False, "GOOGLE_API_KEY not set in .env")
else:
    try:
        from agents.hello_adk import run_hello_world
        response = run_hello_world()
        check("ADK hello-world agent", bool(response), f"Response: {response[:60]}")
    except Exception as e:
        check("ADK hello-world agent", False, str(e)[:80])


# ── Summary ───────────────────────────────────────────────────────────────────

console.print("\n")
table = Table(title="Day 0 Verification Summary")
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
