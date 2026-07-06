"""
agents/sandbox_agent.py

Sandbox / Validation Agent — Local tier (Ollama qwen2.5:3b ONLY).

Given a vulnerability + mock asset config, reasons about exploitability and
dependency impact. Returns a PASS / FAIL / PARTIAL verdict with rationale.

ARCHITECTURAL RULE: This agent NEVER makes external API calls.
It ONLY communicates with localhost:11434 (Ollama).
This is the core AI-architecture story: cloud for public CVE data,
local model for anything touching sensitive asset configuration.
"""

import json
import re
import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
VALID_VERDICTS = {"PASS", "FAIL", "PARTIAL"}


class SandboxAgent:
    """
    Local-only validation agent using Ollama.
    No external API calls. Ever.
    """

    def _build_prompt(self, vulnerability: dict, asset: dict, enrichment: dict = None) -> str:
        """Builds a structured prompt for the local model."""

        software_list = asset.get("software", asset.get("raw_data", "{}"))
        if isinstance(software_list, str):
            try:
                raw = json.loads(software_list)
                software_list = raw.get("software", [])
            except Exception:
                software_list = []

        enrich_context = ""
        if enrichment:
            enrich_context = f"""
Enrichment Intelligence:
- Severity Context: {enrichment.get('severity_context', 'N/A')}
- Known Exploitation: {enrichment.get('exploitation_intelligence', 'N/A')}
"""

        prompt = f"""You are a cybersecurity sandbox validator running entirely offline.
Analyze this vulnerability and asset configuration and return a structured JSON verdict.

=== VULNERABILITY ===
CVE ID: {vulnerability.get('cve_id', 'Unknown')}
CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
Severity: {vulnerability.get('severity', 'N/A')}
Description: {vulnerability.get('description', 'N/A')}
{enrich_context}
=== ASSET CONFIGURATION ===
Asset ID: {asset.get('asset_id', 'Unknown')}
Asset Name: {asset.get('name', 'Unknown')}
Asset Type: {asset.get('type', 'Unknown')}
OS: {asset.get('os', 'Unknown')}
Installed Software: {json.dumps(software_list)}
Internet Exposed: {asset.get('internet_exposed', False)}
Environment: {asset.get('environment', 'Unknown')}
Business Tag: {asset.get('business_tag', 'Unknown')}
Dependency Count: {len(json.loads(asset.get('dependencies_json', '[]')) if isinstance(asset.get('dependencies_json'), str) else asset.get('dependencies', []))}

=== TASK ===
Return ONLY a valid JSON object with exactly these fields:
{{
  "verdict": "FAIL",
  "rationale": "Short explanation of why this asset is or is not exploitable",
  "exploitability_notes": "Is the vulnerable software present? Is the attack vector reachable?",
  "dependency_impact": "How many downstream assets could be affected if this is exploited?"
}}

Verdict must be exactly one of: PASS (not exploitable), FAIL (exploitable), PARTIAL (unclear/conditional).
Return only the JSON. No markdown fences."""

        return prompt

    def _call_ollama(self, prompt: str) -> str:
        """Calls Ollama local API. Raises on connection failure."""
        response = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()

    def _parse_verdict(self, raw: str) -> dict:
        """Parses JSON from Ollama response with fallback."""
        # Try direct parse
        try:
            parsed = json.loads(raw)
            if parsed.get("verdict") in VALID_VERDICTS:
                return parsed
        except json.JSONDecodeError:
            pass

        # Try to extract JSON block
        match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', raw, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                if parsed.get("verdict") in VALID_VERDICTS:
                    return parsed
            except json.JSONDecodeError:
                pass

        # Fallback: extract verdict keyword from text
        verdict = "PARTIAL"
        for v in VALID_VERDICTS:
            if v in raw.upper():
                verdict = v
                break

        return {
            "verdict": verdict,
            "rationale": raw[:300],
            "exploitability_notes": "Could not parse structured response from local model.",
            "dependency_impact": "Unknown.",
        }

    def validate(self, vulnerability: dict, asset: dict, enrichment: dict = None) -> dict:
        """
        Validates exploitability of a CVE against an asset.

        Args:
            vulnerability: dict with cve_id, description, cvss_score, severity
            asset: dict with asset config (from DB row or assets.json)
            enrichment: optional enrichment from EnrichmentAgent

        Returns:
            dict with verdict, rationale, exploitability_notes, dependency_impact
        """
        cve_id = vulnerability.get("cve_id", "unknown")
        asset_id = asset.get("asset_id", "unknown")
        print(f"\n[SandboxAgent] Validating {cve_id} on {asset_id} (LOCAL ONLY)...")

        prompt = self._build_prompt(vulnerability, asset, enrichment)

        try:
            raw = self._call_ollama(prompt)
            result = self._parse_verdict(raw)
        except requests.exceptions.ConnectionError:
            result = {
                "verdict": "PARTIAL",
                "rationale": "Ollama server not reachable at localhost:11434. Start with: ollama serve",
                "exploitability_notes": "N/A",
                "dependency_impact": "N/A",
            }
        except Exception as e:
            result = {
                "verdict": "PARTIAL",
                "rationale": f"Local model error: {str(e)[:100]}",
                "exploitability_notes": "N/A",
                "dependency_impact": "N/A",
            }

        result["cve_id"] = cve_id
        result["asset_id"] = asset_id
        print(f"  [Sandbox] Verdict: {result['verdict']}")

        return result


if __name__ == "__main__":
    agent = SandboxAgent()
    test_vuln = {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI injection allowing remote code execution.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
    }
    test_asset = {
        "asset_id": "ASSET-005",
        "name": "prod-payment-svc",
        "type": "microservice",
        "os": "Ubuntu 22.04",
        "software": ["java/17.0.7", "spring-boot/3.1.2", "log4j/2.20.0"],
        "internet_exposed": False,
        "environment": "production",
        "business_tag": "critical",
        "dependencies_json": '["ASSET-003", "ASSET-006"]',
    }
    result = agent.validate(test_vuln, test_asset)
    print(json.dumps(result, indent=2))
