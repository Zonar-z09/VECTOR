"""
tests/test_sandbox_agent.py — unit tests for agents/sandbox_agent.py

requests.post is fully mocked — these tests never require a running Ollama
instance and never make a real network call.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.sandbox_agent import SandboxAgent, VALID_VERDICTS


TEST_VULN = {
    "cve_id": "CVE-2021-44228",
    "description": "Apache Log4j2 JNDI injection RCE.",
    "cvss_score": 10.0,
    "severity": "CRITICAL",
}
TEST_ASSET = {
    "asset_id": "ASSET-005",
    "name": "prod-payment-svc",
    "type": "microservice",
    "os": "Ubuntu 22.04",
    "software": ["java/17.0.7", "log4j/2.20.0"],
    "internet_exposed": False,
    "environment": "production",
    "business_tag": "critical",
    "dependencies_json": '["ASSET-003", "ASSET-006"]',
}


def _mock_ollama_response(text: str, status_code=200):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"response": text}
    mock_resp.raise_for_status = MagicMock()
    if status_code != 200:
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
    return mock_resp


@pytest.fixture
def agent():
    return SandboxAgent()


class TestValidJsonVerdict:
    def test_direct_json_response_parsed(self, agent):
        payload = {
            "verdict": "FAIL",
            "rationale": "Vulnerable log4j version is present and reachable.",
            "exploitability_notes": "JNDI lookup is enabled.",
            "dependency_impact": "2 downstream services affected.",
        }
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.validate(TEST_VULN, TEST_ASSET)

        assert result["verdict"] == "FAIL"
        assert result["cve_id"] == "CVE-2021-44228"
        assert result["asset_id"] == "ASSET-005"


class TestFallbackParsing:
    def test_json_embedded_in_extra_text(self, agent):
        payload = {
            "verdict": "PASS", "rationale": "Not reachable.",
            "exploitability_notes": "n/a", "dependency_impact": "none",
        }
        raw = f"Based on my analysis: {json.dumps(payload)} — that's my conclusion."
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.validate(TEST_VULN, TEST_ASSET)
        assert result["verdict"] == "PASS"

    def test_unparseable_text_falls_back_to_keyword_scan(self, agent):
        raw = "This looks like a FAIL case to me, the software is clearly present."
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.validate(TEST_VULN, TEST_ASSET)
        assert result["verdict"] == "FAIL"

    def test_no_recognizable_verdict_defaults_to_partial(self, agent):
        raw = "I'm not entirely sure about this configuration."
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.validate(TEST_VULN, TEST_ASSET)
        assert result["verdict"] == "PARTIAL"

    def test_result_always_has_valid_verdict(self, agent):
        raw = "garbage output with no structure"
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.validate(TEST_VULN, TEST_ASSET)
        assert result["verdict"] in VALID_VERDICTS


class TestConnectionHandling:
    def test_ollama_unreachable_returns_partial_with_hint(self, agent):
        with patch(
            "agents.sandbox_agent.requests.post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            result = agent.validate(TEST_VULN, TEST_ASSET)

        assert result["verdict"] == "PARTIAL"
        assert "ollama serve" in result["rationale"]

    def test_unexpected_exception_does_not_crash(self, agent):
        with patch("agents.sandbox_agent.requests.post", side_effect=ValueError("boom")):
            result = agent.validate(TEST_VULN, TEST_ASSET)
        assert result["verdict"] == "PARTIAL"


class TestPromptBuilding:
    def test_missing_optional_fields_do_not_raise(self, agent):
        minimal_asset = {"asset_id": "ASSET-MIN"}
        minimal_vuln = {"cve_id": "CVE-MIN"}
        payload = {"verdict": "PARTIAL", "rationale": "insufficient data",
                   "exploitability_notes": "n/a", "dependency_impact": "n/a"}
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.validate(minimal_vuln, minimal_asset)
        assert result["verdict"] == "PARTIAL"

    def test_calls_ollama_with_correct_model(self, agent):
        payload = {"verdict": "PASS", "rationale": "ok", "exploitability_notes": "n/a", "dependency_impact": "n/a"}
        with patch("agents.sandbox_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))) as mock_post:
            agent.validate(TEST_VULN, TEST_ASSET)

        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["json"]["model"] == "qwen2.5:3b"
        assert mock_post.call_args.args[0] == "http://localhost:11434/api/generate"
