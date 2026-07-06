"""
agents/remediation_test_agent.py

Remediation Test Agent — Local tier (Ollama qwen2.5:3b ONLY).

Runs AFTER SandboxAgent, and only when SandboxAgent found the vulnerability
exploitable (verdict == "FAIL"). Takes the EnrichmentAgent's proposed fix
(remediation_approach) and reasons about whether applying it to THIS specific
asset would actually resolve the vulnerability, and whether it would break
anything the asset depends on.

ARCHITECTURAL RULE: This agent NEVER makes external API calls, same
contract as SandboxAgent — it only communicates with localhost:11434.
Asset-specific reasoning (exact software versions, exact dependency list)
is exactly the class of data that must stay local per the whitepaper's
dual-AI architecture.

This is the piece that upgrades VECTOR from "AI suggests a fix" to
"AI suggests AND tests a fix" — the whitepaper's closed-loop verification
principle, and the most concrete demonstration of the sandbox lifecycle's
Stage 3 (remediation path selection) + Stage 4 (sandbox simulation).
"""

import json
import re
import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
VALID_VERDICTS = {"CLEAN_FIX", "PARTIAL_FIX", "FAILED", "BREAKS_DEPENDENCY"}
NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationTestAgent:
    """
    Local-only remediation testing agent using Ollama.
    No external API calls. Ever. Same contract as SandboxAgent.
    """

    def _skip_result(self, cve_id: str, asset_id: str, sandbox_verdict: str) -> dict:
        """
        Builds the NOT_APPLICABLE result for vulnerabilities that SandboxAgent
        did not flag as exploitable — no reason to test a remediation for
        something that isn't exploitable in this environment.
        """
        return {
            "cve_id": cve_id,
            "asset_id": asset_id,
            "remediation_verdict": NOT_APPLICABLE,
            "rationale": (
                f"Skipped — SandboxAgent verdict was '{sandbox_verdict}', not FAIL. "
                "Remediation testing only runs on confirmed-exploitable findings."
            ),
            "validated_steps": "",
            "dependency_impact": "",
        }

    def _build_prompt(self, vulnerability: dict, asset: dict, enrichment: dict, sandbox_result: dict) -> str:
        """Builds a structured prompt for the local model."""

        deps_raw = asset.get("dependencies_json", asset.get("dependencies", "[]"))
        try:
            deps = json.loads(deps_raw) if isinstance(deps_raw, str) else deps_raw
        except Exception:
            deps = []

        proposed_fix = (enrichment or {}).get("remediation_approach", "No proposed fix available.")

        prompt = f"""You are a cybersecurity remediation validator running entirely offline.
A vulnerability has already been confirmed exploitable on this asset by a separate sandbox
validation step. Your job is to test whether the PROPOSED remediation actually resolves it
on THIS specific asset, and whether it would break anything the asset depends on.

=== VULNERABILITY ===
CVE ID: {vulnerability.get('cve_id', 'Unknown')}
CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
Description: {vulnerability.get('description', 'N/A')}

=== SANDBOX EXPLOITABILITY RESULT (already confirmed exploitable) ===
Rationale: {sandbox_result.get('rationale', 'N/A')}

=== PROPOSED REMEDIATION (from cloud enrichment) ===
{proposed_fix}

=== ASSET CONFIGURATION ===
Asset ID: {asset.get('asset_id', 'Unknown')}
Asset Name: {asset.get('name', 'Unknown')}
OS: {asset.get('os', 'Unknown')}
Environment: {asset.get('environment', 'Unknown')}
Business Criticality: {asset.get('business_tag', 'Unknown')}
Dependent Systems: {json.dumps(deps)}

=== TASK ===
Return ONLY a valid JSON object with exactly these fields:
{{
  "remediation_verdict": "CLEAN_FIX",
  "rationale": "Short explanation of whether the fix resolves the vulnerability on this asset",
  "validated_steps": "Concrete, ordered remediation steps a human engineer would follow in production",
  "dependency_impact": "What happens to the {len(deps)} dependent system(s) if this fix is applied"
}}

remediation_verdict must be exactly one of:
  CLEAN_FIX          — the fix fully resolves the vulnerability with no side effects
  PARTIAL_FIX        — the fix reduces risk but does not fully close the exploit path
  FAILED              — the fix does not resolve the vulnerability on this asset
  BREAKS_DEPENDENCY   — the fix resolves the vulnerability but would break a dependent system

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

    def _parse_result(self, raw: str) -> dict:
        """Parses JSON from Ollama response with fallback, mirroring SandboxAgent's approach."""
        try:
            parsed = json.loads(raw)
            if parsed.get("remediation_verdict") in VALID_VERDICTS:
                return parsed
        except json.JSONDecodeError:
            pass

        match = re.search(r'\{[^{}]*"remediation_verdict"[^{}]*\}', raw, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                if parsed.get("remediation_verdict") in VALID_VERDICTS:
                    return parsed
            except json.JSONDecodeError:
                pass

        verdict = "PARTIAL_FIX"
        for v in VALID_VERDICTS:
            if v in raw.upper():
                verdict = v
                break

        return {
            "remediation_verdict": verdict,
            "rationale": raw[:300],
            "validated_steps": "Could not parse structured response from local model.",
            "dependency_impact": "Unknown.",
        }

    def test_remediation(
        self,
        vulnerability: dict,
        asset: dict,
        enrichment: dict = None,
        sandbox_result: dict = None,
    ) -> dict:
        """
        Tests whether the proposed remediation resolves the vulnerability on
        this specific asset.

        Skip condition: only runs if sandbox_result['verdict'] == 'FAIL'.
        Any other sandbox verdict (PASS, PARTIAL) returns NOT_APPLICABLE
        without calling the local model at all.

        Args:
            vulnerability: dict with cve_id, description, cvss_score
            asset: dict with asset config (from DB row or assets.json)
            enrichment: output from EnrichmentAgent (used for remediation_approach)
            sandbox_result: output from SandboxAgent (gates whether this runs)

        Returns:
            dict with remediation_verdict, rationale, validated_steps, dependency_impact
        """
        cve_id = vulnerability.get("cve_id", "unknown")
        asset_id = asset.get("asset_id", "unknown")
        sandbox_result = sandbox_result or {}
        sandbox_verdict = sandbox_result.get("verdict", "PARTIAL")

        if sandbox_verdict != "FAIL":
            print(f"\n[RemediationTestAgent] Skipping {cve_id} on {asset_id} — "
                  f"sandbox verdict was '{sandbox_verdict}', not exploitable.")
            return self._skip_result(cve_id, asset_id, sandbox_verdict)

        print(f"\n[RemediationTestAgent] Testing remediation for {cve_id} on {asset_id} (LOCAL ONLY)...")

        prompt = self._build_prompt(vulnerability, asset, enrichment or {}, sandbox_result)

        try:
            raw = self._call_ollama(prompt)
            result = self._parse_result(raw)
        except requests.exceptions.ConnectionError:
            result = {
                "remediation_verdict": "PARTIAL_FIX",
                "rationale": "Ollama server not reachable at localhost:11434. Start with: ollama serve",
                "validated_steps": "N/A",
                "dependency_impact": "N/A",
            }
        except Exception as e:
            result = {
                "remediation_verdict": "PARTIAL_FIX",
                "rationale": f"Local model error: {str(e)[:100]}",
                "validated_steps": "N/A",
                "dependency_impact": "N/A",
            }

        result["cve_id"] = cve_id
        result["asset_id"] = asset_id
        print(f"  [RemediationTest] Verdict: {result['remediation_verdict']}")

        return result


if __name__ == "__main__":
    agent = RemediationTestAgent()
    test_vuln = {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 JNDI injection allowing remote code execution.",
        "cvss_score": 10.0,
    }
    test_asset = {
        "asset_id": "ASSET-005",
        "name": "prod-payment-svc",
        "os": "Ubuntu 22.04",
        "environment": "production",
        "business_tag": "critical",
        "dependencies_json": '["ASSET-003", "ASSET-006"]',
    }
    test_enrichment = {"remediation_approach": "Upgrade log4j to 2.20.0 or later; set log4j2.formatMsgNoLookups=true as a workaround."}
    test_sandbox_result = {"verdict": "FAIL", "rationale": "log4j 2.x present and reachable via user-controlled input."}

    result = agent.test_remediation(test_vuln, test_asset, test_enrichment, test_sandbox_result)
    print(json.dumps(result, indent=2))

    # Skip-condition demo
    skip_result = agent.test_remediation(
        test_vuln, test_asset, test_enrichment, {"verdict": "PASS", "rationale": "not reachable"}
    )
    print(json.dumps(skip_result, indent=2))
