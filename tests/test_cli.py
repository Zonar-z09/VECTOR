"""
tests/test_cli.py — unit tests for cli/main.py (the Agent Skills / CLI surface)

agents.full_pipeline.run_full_pipeline is mocked out — these tests verify
CLI argument wiring and output formatting, not the pipeline itself (that's
covered by test_playbook_agent.py, test_enrichment_agent.py, and
test_sandbox_agent.py individually, plus the live verify_day3.py suite).
"""

import sys
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.main import cli


class TestHelp:
    def test_top_level_help(self):
        result = CliRunner().invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_run_help(self):
        result = CliRunner().invoke(cli, ["run", "--help"])
        assert result.exit_code == 0
        assert "--cve" in result.output
        assert "--top" in result.output
        assert "--auto-approve" in result.output


class TestStatusCommand:
    def test_status_runs_without_crashing(self):
        # Depends on the real data/assets.json and data/cve_seed_list.json
        # fixture files being present (checked into the repo) — this is a
        # light smoke test, not a hermetic unit test of file contents.
        result = CliRunner().invoke(cli, ["status"])
        assert result.exit_code == 0


class TestRunCommandArgumentWiring:
    def test_no_cve_and_no_top_shows_hint_without_running_pipeline(self):
        with patch("agents.full_pipeline.run_full_pipeline") as mock_run:
            result = CliRunner().invoke(cli, ["run"])
        mock_run.assert_not_called()
        assert "Hint" in result.output

    def test_cve_flag_passed_through_correctly(self):
        with patch("agents.full_pipeline.run_full_pipeline", return_value=[]) as mock_run:
            CliRunner().invoke(cli, ["run", "--cve", "CVE-2021-44228", "--auto-approve"])
        mock_run.assert_called_once_with(
            cve_id="CVE-2021-44228", asset_id=None, top_n=None, auto_approve=True,
        )

    def test_cve_and_asset_passed_through_correctly(self):
        with patch("agents.full_pipeline.run_full_pipeline", return_value=[]) as mock_run:
            CliRunner().invoke(
                cli, ["run", "--cve", "CVE-2024-6387", "--asset", "ASSET-001"]
            )
        mock_run.assert_called_once_with(
            cve_id="CVE-2024-6387", asset_id="ASSET-001", top_n=None, auto_approve=False,
        )

    def test_top_flag_passed_through_correctly(self):
        with patch("agents.full_pipeline.run_full_pipeline", return_value=[]) as mock_run:
            CliRunner().invoke(cli, ["run", "--top", "5"])
        mock_run.assert_called_once_with(
            cve_id=None, asset_id=None, top_n=5, auto_approve=False,
        )


class TestRunCommandOutputSummary:
    def test_summary_counts_delivered_and_rejected(self):
        fake_results = [
            {"status": "delivered", "cve_id": "CVE-1", "asset_id": "ASSET-1", "ticket_id": "TICK-1"},
            {"status": "rejected", "cve_id": "CVE-2", "asset_id": "ASSET-2"},
        ]
        with patch("agents.full_pipeline.run_full_pipeline", return_value=fake_results):
            result = CliRunner().invoke(cli, ["run", "--top", "2", "--auto-approve"])
        assert "1 delivered, 1 rejected" in result.output
        assert "TICK-1" in result.output
