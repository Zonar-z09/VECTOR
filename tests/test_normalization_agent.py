"""
tests/test_normalization_agent.py — unit tests for agents/normalization_agent.py

requests.post is fully mocked — these tests never require a running Ollama
instance and never make a real network call. Mirrors tests/test_sandbox_agent.py.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.normalization_agent import NormalizationAgent, VALID_SEVERITIES, match_known_asset

TEST_RECORD = {
    "source_type": "edr",
    "record_type": "vulnerability",
    "raw": {"hostname": "prod-web-01", "detection_name": "Suspicious child process", "severity": "MEDIUM"},
}
TEST_KNOWN_ASSETS = [{"asset_id": "ASSET-001", "name": "prod-web-01"}]


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
    return NormalizationAgent()


class TestValidJsonResult:
    def test_direct_json_response_parsed(self, agent):
        payload = {
            "matched_asset_id": "ASSET-001",
            "new_asset_name": None,
            "environment": "production",
            "business_tag": "critical",
            "cvss_score_estimate": 6.5,
            "severity": "MEDIUM",
            "rationale": "Hostname matches ASSET-001 directly.",
        }
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)

        assert result["matched_asset_id"] == "ASSET-001"
        assert result["severity"] == "MEDIUM"
        assert result["cvss_score_estimate"] == 6.5


class TestFallbackParsing:
    def test_json_embedded_in_extra_text(self, agent):
        payload = {
            "matched_asset_id": None, "new_asset_name": "new-host",
            "environment": "unknown", "business_tag": "medium",
            "cvss_score_estimate": 5.0, "severity": "LOW", "rationale": "no match",
        }
        raw = f"Here is my analysis: {json.dumps(payload)} — done."
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(raw)):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        # Severity comes from the connector's own raw.severity ("MEDIUM" on
        # TEST_RECORD) by design, not the LLM's guess ("LOW") — see
        # match_known_asset()'s docstring for why.
        assert result["severity"] == "MEDIUM"

    def test_unparseable_text_falls_back_to_defaults(self, agent):
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response("garbage, no structure")):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["severity"] in VALID_SEVERITIES
        # Deterministic name matching still finds ASSET-001 (hostname
        # "prod-web-01" exactly matches) even though the LLM's own text was
        # garbage — this is the whole point of match_known_asset().
        assert result["matched_asset_id"] == "ASSET-001"

    def test_invalid_environment_coerced_to_unknown(self, agent):
        payload = {
            "matched_asset_id": "ASSET-001", "new_asset_name": None,
            "environment": "not_a_real_env", "business_tag": "medium",
            "cvss_score_estimate": 5.0, "severity": "HIGH", "rationale": "x",
        }
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["environment"] == "unknown"


class TestDeterministicOverrides:
    """
    Regression tests for a live-run bug: qwen2.5:3b's free-text rationale
    correctly identified the right asset while its own matched_asset_id
    field came back null, and it returned "HIGH" severity regardless of the
    connector's actual severity. match_known_asset() + the raw.severity
    passthrough in normalize() fix both — these assert the fix, not just
    the model's (untrustworthy) opinion.
    """

    def test_llm_null_match_overridden_by_exact_hostname_match(self, agent):
        payload = {
            "matched_asset_id": None, "new_asset_name": "some-new-host",
            "environment": "production", "business_tag": "high",
            "cvss_score_estimate": 7.0, "severity": "HIGH",
            "rationale": "hostname prod-web-01 matches ASSET-001 but I'm not filling the field",
        }
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["matched_asset_id"] == "ASSET-001"

    def test_llm_severity_ignored_when_raw_has_its_own(self, agent):
        payload = {
            "matched_asset_id": "ASSET-001", "new_asset_name": None,
            "environment": "production", "business_tag": "high",
            "cvss_score_estimate": 9.0, "severity": "HIGH",  # LLM says HIGH
            "rationale": "x",
        }
        # TEST_RECORD's raw.severity is "MEDIUM" — that must win.
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["severity"] == "MEDIUM"

    def test_fuzzy_token_match_finds_asset_with_different_naming(self, agent):
        record = {
            "source_type": "code_scan",
            "record_type": "vulnerability",
            "raw": {"repo": "payments-service", "message": "hardcoded secret", "severity": "HIGH"},
        }
        known_assets = [{"asset_id": "ASSET-005", "name": "prod-payment-svc"}]
        assert match_known_asset(record["raw"], known_assets) == "ASSET-005"

    def test_generic_word_service_does_not_cause_false_positive(self):
        """
        Regression: a live run matched "payments-service" to "prod-auth-service"
        (ASSET-004) on the shared generic word "service" instead of the real
        intended match "prod-payment-svc" (ASSET-005) on "payment(s)".
        """
        raw = {"repo": "payments-service", "message": "hardcoded secret", "severity": "HIGH"}
        known_assets = [
            {"asset_id": "ASSET-004", "name": "prod-auth-service"},
            {"asset_id": "ASSET-005", "name": "prod-payment-svc"},
        ]
        assert match_known_asset(raw, known_assets) == "ASSET-005"

    def test_no_match_returns_none_and_llms_new_asset_name_is_kept(self, agent):
        record = {
            "source_type": "code_scan",
            "record_type": "vulnerability",
            "raw": {"repo": "totally-unrelated-repo", "message": "issue", "severity": "LOW"},
        }
        payload = {
            "matched_asset_id": None, "new_asset_name": "totally-unrelated-repo",
            "environment": "unknown", "business_tag": "medium",
            "cvss_score_estimate": 4.0, "severity": "LOW", "rationale": "no known asset matches",
        }
        with patch("agents.normalization_agent.requests.post", return_value=_mock_ollama_response(json.dumps(payload))):
            result = agent.normalize(record, TEST_KNOWN_ASSETS)
        assert result["matched_asset_id"] is None
        assert result["new_asset_name"] == "totally-unrelated-repo"


class TestConnectionHandling:
    def test_ollama_unreachable_returns_safe_defaults(self, agent):
        with patch(
            "agents.normalization_agent.requests.post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["severity"] == "MEDIUM"
        assert "ollama serve" in result["rationale"]

    def test_unexpected_exception_does_not_crash(self, agent):
        with patch("agents.normalization_agent.requests.post", side_effect=ValueError("boom")):
            result = agent.normalize(TEST_RECORD, TEST_KNOWN_ASSETS)
        assert result["severity"] in VALID_SEVERITIES
