"""
tests/test_enrichment_agent.py — unit tests for agents/enrichment_agent.py

The Gemini client is fully mocked — these tests never make a real API call
and never require a real GOOGLE_API_KEY. DB isolation comes from the
test_db fixture (conftest.py).
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.enrichment_agent import EnrichmentAgent
from src.db.database import get_db_connection


def _mock_gemini_response(payload: dict):
    """Builds a fake genai response object shaped like the real SDK's response."""
    resp = MagicMock()
    resp.text = json.dumps(payload)
    return resp


VALID_PAYLOAD = {
    "severity_context": "Critical RCE, widely exploited.",
    "exploitation_intelligence": "Actively exploited in the wild.",
    "remediation_approach": "Upgrade to version 2.20.0 or later.",
    "confidence": "High",
}


@pytest.fixture
def agent(test_db):
    """EnrichmentAgent with a fully mocked Gemini client."""
    with patch("agents.enrichment_agent.genai.Client") as MockClient:
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        a = EnrichmentAgent()
        a._mock_client = mock_client  # stash for assertions in tests
        yield a


class TestCacheMiss:
    def test_calls_gemini_and_returns_result(self, agent):
        agent._mock_client.models.generate_content.return_value = _mock_gemini_response(VALID_PAYLOAD)

        result = agent.enrich("CVE-2021-44228", "Log4j JNDI injection RCE.", 10.0)

        agent._mock_client.models.generate_content.assert_called_once()
        assert result["from_cache"] is False
        assert result["confidence"] == "High"
        assert result["severity_context"] == VALID_PAYLOAD["severity_context"]

    def test_writes_to_cache(self, agent, test_db):
        agent._mock_client.models.generate_content.return_value = _mock_gemini_response(VALID_PAYLOAD)
        agent.enrich("CVE-2021-44228", "Log4j JNDI injection RCE.", 10.0)

        conn = get_db_connection()
        row = conn.execute(
            "SELECT * FROM enrichments WHERE cve_id = 'CVE-2021-44228'"
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["confidence"] == "High"


class TestCacheHit:
    def test_second_call_does_not_call_gemini_again(self, agent):
        agent._mock_client.models.generate_content.return_value = _mock_gemini_response(VALID_PAYLOAD)

        r1 = agent.enrich("CVE-2021-44228", "desc", 10.0)
        r2 = agent.enrich("CVE-2021-44228", "desc", 10.0)

        agent._mock_client.models.generate_content.assert_called_once()  # not twice
        assert r1["from_cache"] is False
        assert r2["from_cache"] is True
        assert r1["severity_context"] == r2["severity_context"]

    def test_pre_seeded_cache_skips_api_call_entirely(self, agent, test_db):
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO enrichments
            (cve_id, severity_context, exploitation_intelligence,
             remediation_approach, confidence, enriched_at, raw_response)
            VALUES ('CVE-PRESEEDED', 'ctx', 'intel', 'fix', 'Medium', '2024-01-01', '{}')
            """
        )
        conn.commit()
        conn.close()

        result = agent.enrich("CVE-PRESEEDED", "irrelevant", 5.0)

        agent._mock_client.models.generate_content.assert_not_called()
        assert result["from_cache"] is True
        assert result["confidence"] == "Medium"


class TestResponseParsing:
    def test_json_wrapped_in_extra_text_is_extracted(self, agent):
        resp = MagicMock()
        resp.text = f"Here is the analysis:\n{json.dumps(VALID_PAYLOAD)}\nHope that helps."
        agent._mock_client.models.generate_content.return_value = resp

        result = agent.enrich("CVE-WRAPPED", "desc", 7.0)
        assert result["confidence"] == "High"
        assert result["remediation_approach"] == VALID_PAYLOAD["remediation_approach"]

    def test_completely_unparseable_response_falls_back_gracefully(self, agent):
        resp = MagicMock()
        resp.text = "I cannot provide a structured answer for this one."
        agent._mock_client.models.generate_content.return_value = resp

        result = agent.enrich("CVE-UNPARSEABLE", "desc", 3.0)
        assert result["confidence"] == "Low"
        assert result["from_cache"] is False  # still completes, just low-confidence


class TestScrubbingIntegration:
    def test_description_is_scrubbed_before_reaching_gemini(self, agent):
        agent._mock_client.models.generate_content.return_value = _mock_gemini_response(VALID_PAYLOAD)

        agent.enrich(
            "CVE-SCRUB-TEST",
            "Vulnerable service running at 192.168.10.5 on db.internal",
            8.0,
        )

        sent_prompt = agent._mock_client.models.generate_content.call_args.kwargs["contents"]
        assert "192.168.10.5" not in sent_prompt
        assert "db.internal" not in sent_prompt
        assert "[REDACTED_IPV4]" in sent_prompt
        assert "[REDACTED_INTERNAL_HOSTNAME]" in sent_prompt
