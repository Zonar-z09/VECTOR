"""
vector.py — Root-level CLI entry point for the VECTOR pipeline.

This is the Agent Skills (CLI) checkpoint for Day 3.

Usage examples:
  python vector.py run --cve CVE-2021-44228
  python vector.py run --cve CVE-2024-6387 --asset ASSET-001
  python vector.py run --top 5
  python vector.py run --top 3 --auto-approve
  python vector.py status
"""

import sys
from pathlib import Path

# Ensure project root is on the path so all imports resolve correctly
sys.path.insert(0, str(Path(__file__).parent))

from cli.main import cli

if __name__ == "__main__":
    cli()
