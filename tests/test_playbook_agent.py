"""
tests/test_playbook_agent.py — unit tests for agents/playbook_agent.py

Uses the populated_db fixture (conftest.py) for the asset/CVE lookup, and
mocks builtins.input for the human-gate paths.
"""

import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.playbook_agent import PlaybookAgent

ENRICHMENT = {
    "severity_context": "Critical, widely exploited.",
    "exploitation_intelligence": "Active exploitation observed.",
    "remediation_approach": "Upgrade to patched version.",
    "confidence": "High",
}
SANDBOX_RESULT = {
    "verdict": "FAIL",
    "rationale": "Vulnerable software confirmed present.",
    "dependency_impact": "2 downstream services affected.",
}


@pytest.fixture
def agent():
    return PlaybookAgent()


class TestMissingRecords:
    def test_unknown_asset_returns_error(self, populated_db, agent):
        result = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-DOES-NOT-EXIST",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        assert result["status"] == "error"

    def test_unknown_cve_returns_error(self, populated_db, agent):
        result = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-DOES-NOT-EXIST", asset_id="ASSET-TEST-01",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        assert result["status"] == "error"


class TestAutoApprove:
    def test_auto_approve_skips_input_and_delivers(self, populated_db, agent):
        with patch("builtins.input") as mock_input:
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
            )
        mock_input.assert_not_called()
        assert result["status"] == "delivered"
        assert result["ticket_id"] is not None


class TestHumanGate:
    def test_approval_creates_ticket(self, populated_db, agent):
        with patch("builtins.input", return_value="y"):
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=False,
            )
        assert result["status"] == "delivered"
        assert re.match(r"TICK-\d+-0001", result["ticket_id"])

    def test_yes_variants_accepted(self, populated_db, agent):
        with patch("builtins.input", return_value="yes"):
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=False,
            )
        assert result["status"] == "delivered"

    def test_rejection_blocks_ticket_creation(self, populated_db, agent):
        with patch("builtins.input", return_value="n"):
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=False,
            )
        assert result["status"] == "rejected"
        assert "ticket_id" not in result

    def test_empty_input_defaults_to_reject(self, populated_db, agent):
        with patch("builtins.input", return_value=""):
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=False,
            )
        assert result["status"] == "rejected"

    def test_keyboard_interrupt_treated_as_reject(self, populated_db, agent):
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = agent.run(
                vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
                enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=False,
            )
        assert result["status"] == "rejected"


class TestReportContents:
    def test_report_has_expected_fields(self, populated_db, agent):
        result = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        for key in (
            "vuln_id", "cve_id", "asset_id", "asset_name", "risk_score",
            "primary_driver", "score_breakdown", "enrichment", "sandbox_verdict",
            "sandbox_rationale", "dependency_impact", "status", "assembled_at",
        ):
            assert key in result

    def test_risk_score_reflects_five_factor_engine(self, populated_db, agent):
        # sample_asset/sample_cve fixtures are high-risk on every factor —
        # score should reflect that, not just be present.
        result = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        assert result["risk_score"] > 0.9

    def test_ticket_ids_increment_across_calls(self, populated_db, agent):
        r1 = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        r2 = agent.run(
            vuln_id="VULN-TEST-0001", cve_id="CVE-TEST-0001", asset_id="ASSET-TEST-01",
            enrichment=ENRICHMENT, sandbox_result=SANDBOX_RESULT, auto_approve=True,
        )
        assert r1["ticket_id"] != r2["ticket_id"]
