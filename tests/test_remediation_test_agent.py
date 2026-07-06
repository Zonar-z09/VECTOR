"""
tests/test_remediation_test_agent.py — unit tests for agents/remediation_test_agent.py

requests.post is fully mocked — no running Ollama instance required.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.remediation_test_agent import RemediationTestAgent, VALID_VERDICTS, NOT_APPLICABLE


TEST_VULN = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI injection RCE.",
    "cvss_score": 10.0,
}
TEST_ASSET = {
    "asset_id": "ASSET-005",
    "name": "prod-payment-svc",
    "os": "Ubuntu 22.04",
    "environment": "production",
    "business_tag": "critical",
    "dependencies_json": '["ASSET-003", "ASSET-006"]',
}
TEST_ENRICHMENT = {"remediation_approach": "Upgrade log4j to 2.20.0 or later."}
EXPLOITABLE_SANDBOX_RESULT = {"verdict": "FAIL", "rationale": "log4j 2.x present and reachable."}


def _mock_ollama_response(text: str):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": text}
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


@pytest.fixture
def agent():
    return RemediationTestAgent()


class TestSkipCondition:
    def test_pass_verdict_skips_without_calling_ollama(self, agent):
        with patch("agents.remediation_test_agent.requests.post") as mock_post:
            result = agent.test_remediation(
                TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, {"verdict": "PASS", "rationale": "not reachable"}
            )
        mock_post.assert_not_called()
        assert result["remediation_verdict"] == NOT_APPLICABLE

    def test_partial_verdict_also_skips(self, agent):
        with patch("agents.remediation_test_agent.requests.post") as mock_post:
            result = agent.test_remediation(
                TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, {"verdict": "PARTIAL", "rationale": "unclear"}
            )
        mock_post.assert_not_called()
        assert result["remediation_verdict"] == NOT_APPLICABLE

    def test_missing_sandbox_result_defaults_to_skip(self, agent):
        with patch("agents.remediation_test_agent.requests.post") as mock_post:
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, sandbox_result=None)
        mock_post.assert_not_called()
        assert result["remediation_verdict"] == NOT_APPLICABLE

    def test_fail_verdict_does_call_ollama(self, agent):
        payload = {
            "remediation_verdict": "CLEAN_FIX", "rationale": "fixed",
            "validated_steps": "upgrade", "dependency_impact": "none",
        }
        with patch(
            "agents.remediation_test_agent.requests.post",
            return_value=_mock_ollama_response(json.dumps(payload)),
        ) as mock_post:
            agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        mock_post.assert_called_once()


class TestVerdictParsing:
    def test_clean_fix_parsed_directly(self, agent):
        payload = {
            "remediation_verdict": "CLEAN_FIX",
            "rationale": "Upgrading resolves the JNDI lookup vector entirely.",
            "validated_steps": "1. Upgrade log4j to 2.20.0  2. Restart service",
            "dependency_impact": "No impact on ASSET-003 or ASSET-006.",
        }
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "CLEAN_FIX"
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["asset_id"] == "ASSET-005"

    def test_breaks_dependency_verdict(self, agent):
        payload = {
            "remediation_verdict": "BREAKS_DEPENDENCY", "rationale": "Downstream service pins old API.",
            "validated_steps": "Coordinate with ASSET-006 owner first.", "dependency_impact": "ASSET-006 breaks.",
        }
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "BREAKS_DEPENDENCY"

    def test_json_wrapped_in_extra_text_is_extracted(self, agent):
        payload = {
            "remediation_verdict": "PARTIAL_FIX", "rationale": "reduces risk",
            "validated_steps": "apply workaround", "dependency_impact": "none",
        }
        raw = f"My analysis: {json.dumps(payload)} — done."
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "PARTIAL_FIX"

    def test_unparseable_response_falls_back_to_keyword_scan(self, agent):
        raw = "This fix looks like it FAILED to resolve the issue."
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "FAILED"

    def test_result_always_has_valid_verdict_or_not_applicable(self, agent):
        raw = "garbage output with no structure"
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] in VALID_VERDICTS


class TestConnectionHandling:
    def test_ollama_unreachable_returns_partial_fix_with_hint(self, agent):
        with patch(
            "agents.remediation_test_agent.requests.post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "PARTIAL_FIX"
        assert "ollama serve" in result["rationale"]


class TestPromptContent:
    def test_proposed_fix_included_in_prompt(self, agent):
        payload = {"remediation_verdict": "CLEAN_FIX", "rationale": "x", "validated_steps": "y", "dependency_impact": "z"}
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))) as mock_post:
            agent.test_remediation(TEST_VULN, TEST_ASSET, TEST_ENRICHMENT, EXPLOITABLE_SANDBOX_RESULT)

        sent_prompt = mock_post.call_args.kwargs["json"]["prompt"]
        assert "Upgrade log4j to 2.20.0 or later." in sent_prompt
        assert "ASSET-003" in sent_prompt  # dependency list surfaced

    def test_missing_enrichment_does_not_raise(self, agent):
        payload = {"remediation_verdict": "FAILED", "rationale": "no fix available", "validated_steps": "n/a", "dependency_impact": "n/a"}
        with patch("agents.remediation_test_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.test_remediation(TEST_VULN, TEST_ASSET, enrichment=None, sandbox_result=EXPLOITABLE_SANDBOX_RESULT)
        assert result["remediation_verdict"] == "FAILED"
