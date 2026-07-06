"""
tests/test_ticketing.py — unit tests for src/integrations/ticketing.py

_call_mcp_create_ticket (the raw stdio-client round trip) is mocked here —
that mechanism is already covered live by mcp_server/test_day1_client.py
and verify_day1.py (7/7, already verified). These tests cover this module's
OWN logic: the approval gate, backend dispatch, and payload formatting.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.ticketing import (
    create_ticket,
    format_jira_payload,
    format_servicenow_payload,
    format_generic_webhook_payload,
    _priority_from_score,
    TICKET_BACKENDS,
)

DEMO_REPORT = {
    "cve_id": "CVE-2021-44228",
    "asset_id": "ASSET-005",
    "risk_score": 0.92,
    "sandbox_verdict": "FAIL",
    "sandbox_rationale": "log4j 2.x present and reachable.",
    "enrichment": {"remediation_approach": "Upgrade to log4j 2.20.0+"},
}


class TestPriorityMapping:
    def test_critical_threshold(self):
        assert _priority_from_score(0.95) == "Critical"

    def test_high_threshold(self):
        assert _priority_from_score(0.6) == "High"

    def test_medium_threshold(self):
        assert _priority_from_score(0.3) == "Medium"

    def test_low_threshold(self):
        assert _priority_from_score(0.05) == "Low"


class TestPayloadFormatters:
    def test_jira_payload_shape(self):
        payload = format_jira_payload("VULN-001", DEMO_REPORT, "TICK-8493-001")
        assert payload["backend"] == "jira"
        assert payload["key"] == "TICK-8493-001"
        assert payload["fields"]["priority"] == "Critical"
        assert "CVE-2021-44228" in payload["fields"]["summary"]

    def test_servicenow_payload_shape(self):
        payload = format_servicenow_payload("VULN-001", DEMO_REPORT, "TICK-8493-001")
        assert payload["backend"] == "servicenow"
        assert payload["sys_id"] == "TICK-8493-001"
        assert payload["cmdb_ci"] == "ASSET-005"

    def test_webhook_payload_shape(self):
        payload = format_generic_webhook_payload("VULN-001", DEMO_REPORT, "TICK-8493-001")
        assert payload["event"] == "vulnerability.remediation_ticket_created"
        assert payload["ticket_id"] == "TICK-8493-001"
        assert payload["data"]["cve_id"] == "CVE-2021-44228"

    def test_all_registered_backends_are_callable(self):
        for name, formatter in TICKET_BACKENDS.items():
            result = formatter("VULN-001", DEMO_REPORT, "TICK-TEST")
            assert isinstance(result, dict)


class TestApprovalGate:
    @pytest.mark.anyio
    async def test_unapproved_raises_and_never_calls_mcp(self):
        with patch(
            "src.integrations.ticketing._call_mcp_create_ticket", new_callable=AsyncMock
        ) as mock_mcp:
            with pytest.raises(ValueError, match="approved=True"):
                await create_ticket("VULN-001", DEMO_REPORT, backend="jira", approved=False)
        mock_mcp.assert_not_called()

    @pytest.mark.anyio
    async def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown ticket backend"):
            await create_ticket("VULN-001", DEMO_REPORT, backend="carrier-pigeon", approved=True)


class TestCreateTicket:
    @pytest.mark.anyio
    async def test_approved_jira_ticket_created(self):
        with patch(
            "src.integrations.ticketing._call_mcp_create_ticket",
            new_callable=AsyncMock,
            return_value={"status": "success", "ticket_id": "TICK-8493-001", "message": "ok"},
        ) as mock_mcp:
            result = await create_ticket("VULN-001", DEMO_REPORT, backend="jira", approved=True)

        mock_mcp.assert_called_once_with("VULN-001")
        assert result["status"] == "success"
        assert result["ticket_id"] == "TICK-8493-001"
        assert result["backend"] == "jira"
        assert result["payload"]["fields"]["priority"] == "Critical"

    @pytest.mark.anyio
    async def test_mcp_failure_raises_runtime_error(self):
        with patch(
            "src.integrations.ticketing._call_mcp_create_ticket",
            new_callable=AsyncMock,
            return_value={"status": "error", "message": "vuln_id is required"},
        ):
            with pytest.raises(RuntimeError, match="MCP create_ticket failed"):
                await create_ticket("VULN-001", DEMO_REPORT, backend="jira", approved=True)

    @pytest.mark.anyio
    async def test_different_backends_produce_different_payload_shapes(self):
        with patch(
            "src.integrations.ticketing._call_mcp_create_ticket",
            new_callable=AsyncMock,
            return_value={"status": "success", "ticket_id": "TICK-8493-001", "message": "ok"},
        ):
            jira_result = await create_ticket("VULN-001", DEMO_REPORT, backend="jira", approved=True)
            snow_result = await create_ticket("VULN-001", DEMO_REPORT, backend="servicenow", approved=True)

        assert set(jira_result["payload"].keys()) != set(snow_result["payload"].keys())
        assert jira_result["ticket_id"] == snow_result["ticket_id"] == "TICK-8493-001"
