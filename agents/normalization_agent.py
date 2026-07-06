"""
agents/normalization_agent.py

Normalization Agent — Local tier (Ollama qwen2.5:3b ONLY), same architectural
rule as agents/sandbox_agent.py.

Given one raw record from an external source connector (src/ingest/connectors.py
— code-scan/SAST, EDR, Google SCC Event Threat Detection, Google SCC Web
Security Scanner), reasons about which existing asset it belongs to (or that
it's a new asset), and estimates the five-factor fields the rest of the
pipeline needs (environment, business_tag, cvss_score, severity).

ARCHITECTURAL RULE: This agent NEVER makes external API calls. It ONLY
communicates with localhost:11434 (Ollama). Source records describe internal
hosts, repos, and cloud resources — the same class of "sensitive asset
configuration" data that sandbox_agent.py already keeps off the cloud.
"""

import json
import re
import sys
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_ENVIRONMENTS = {"production", "staging", "development", "unknown"}
VALID_BUSINESS_TAGS = {"critical", "high", "medium", "low"}

# Generic tokens ignored when fuzzy-matching asset names — too common to be
# meaningful evidence of a match on their own (e.g. "prod" appears in most
# asset names, so it can't tell "prod-web-01" apart from "prod-db-primary").
# "service"/"services" caused a real false-positive: a "payments-service"
# repo finding matched "prod-auth-service" (ASSET-004) on the shared word
# "service" instead of "prod-payment-svc" (ASSET-005) on "payment(s)".
_GENERIC_TOKENS = {"prod", "svc", "web", "the", "and", "server", "service", "services"}


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[-_\s.]+", s.lower()) if len(t) >= 3}


def _extract_candidate_names(raw: dict) -> list[str]:
    """Pulls whichever identifying strings a raw connector record has."""
    candidates = []
    for key in ("hostname", "repo", "resource_display_name", "display_name"):
        if raw.get(key):
            candidates.append(str(raw[key]))
    if raw.get("vulnerable_url"):
        match = re.search(r"://([^/]+)", raw["vulnerable_url"])
        if match:
            candidates.append(match.group(1).split(".")[0])
    if raw.get("image_uri"):
        # e.g. ".../vector-demo/prod-payment-svc/api:1.4.2" -> "prod-payment-svc"
        parts = raw["image_uri"].split("/")
        if len(parts) >= 2:
            candidates.append(parts[-2])
    return candidates


def match_known_asset(raw: dict, known_assets: list[dict]) -> str | None:
    """
    Deterministic asset matching — NOT left to the local model's judgment.

    A live test run found the model's free-text rationale correctly
    identified the right asset ("payments-service... matches prod-payment-svc")
    while its own matched_asset_id field came back null — the same class of
    reliability gap already documented for cross-agent ID handoffs
    (see agents/orchestrator.py's _current_target design note). Exact/substring/
    fuzzy-token name matching is a lookup, not a judgment call, so it belongs
    in Python, not in the LLM's structured output.
    """
    candidates = _extract_candidate_names(raw)
    if not candidates:
        return None

    # Pass 1: exact or substring match on the raw asset name.
    for asset in known_assets:
        name = asset["name"].lower()
        for c in candidates:
            cl = c.lower()
            if cl == name or cl in name or name in cl:
                return asset["asset_id"]

    # Pass 2: fuzzy token overlap (handles "payments-service" vs "prod-payment-svc").
    candidate_tokens = set()
    for c in candidates:
        candidate_tokens |= _tokens(c)
    candidate_tokens -= _GENERIC_TOKENS
    for asset in known_assets:
        name_tokens = _tokens(asset["name"]) - _GENERIC_TOKENS
        for nt in name_tokens:
            for ct in candidate_tokens:
                if nt in ct or ct in nt:
                    return asset["asset_id"]

    return None


class NormalizationAgent:
    """
    Local-only normalization agent using Ollama.
    No external API calls. Ever.
    """

    def _build_prompt(self, record: dict, known_assets: list[dict]) -> str:
        """Builds a structured prompt for the local model."""
        asset_list = "\n".join(f"- {a['asset_id']}: {a['name']}" for a in known_assets) or "(none)"

        prompt = f"""You are a cybersecurity data-normalization analyst running entirely offline.
A finding was pulled from an external security tool. Map it onto the existing
asset inventory and estimate standard risk fields, returning ONLY a JSON object.

=== SOURCE ===
Source type: {record.get('source_type', 'unknown')}
Record type: {record.get('record_type', 'unknown')}
Raw finding: {json.dumps(record.get('raw', {}))}

=== KNOWN ASSETS (asset_id: name) ===
{asset_list}

=== TASK ===
Decide which known asset this finding belongs to, by matching hostnames, repo
names, or resource names in the raw finding against asset names above (fuzzy
matching is fine, e.g. "prod-payment-svc" matches repo "payments-service").
If no known asset matches, set matched_asset_id to null and propose a new_asset_name.

Return ONLY a valid JSON object with exactly these fields:
{{
  "matched_asset_id": "ASSET-001" or null,
  "new_asset_name": "short-asset-name" or null,
  "environment": "production",
  "business_tag": "high",
  "cvss_score_estimate": 7.5,
  "severity": "HIGH",
  "rationale": "One sentence explaining the match and estimate"
}}

environment must be exactly one of: production, staging, development, unknown.
business_tag must be exactly one of: critical, high, medium, low.
severity must be exactly one of: CRITICAL, HIGH, MEDIUM, LOW.
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
        """Parses JSON from Ollama response with fallback."""
        try:
            parsed = json.loads(raw)
            if parsed.get("severity") in VALID_SEVERITIES:
                return self._coerce(parsed)
        except json.JSONDecodeError:
            pass

        match = re.search(r'\{[^{}]*"severity"[^{}]*\}', raw, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
                if parsed.get("severity") in VALID_SEVERITIES:
                    return self._coerce(parsed)
            except json.JSONDecodeError:
                pass

        # Fallback: no matched asset, conservative defaults
        return {
            "matched_asset_id": None,
            "new_asset_name": None,
            "environment": "unknown",
            "business_tag": "medium",
            "cvss_score_estimate": 5.0,
            "severity": "MEDIUM",
            "rationale": f"Could not parse structured response from local model: {raw[:150]}",
        }

    def _coerce(self, parsed: dict) -> dict:
        """Fills in safe defaults for any missing/invalid fields."""
        parsed.setdefault("matched_asset_id", None)
        parsed.setdefault("new_asset_name", None)
        if parsed.get("environment") not in VALID_ENVIRONMENTS:
            parsed["environment"] = "unknown"
        if parsed.get("business_tag") not in VALID_BUSINESS_TAGS:
            parsed["business_tag"] = "medium"
        try:
            parsed["cvss_score_estimate"] = float(parsed.get("cvss_score_estimate", 5.0))
        except (TypeError, ValueError):
            parsed["cvss_score_estimate"] = 5.0
        parsed.setdefault("rationale", "")
        return parsed

    def normalize(self, record: dict, known_assets: list[dict]) -> dict:
        """
        Normalizes one raw connector record against the known asset inventory.

        Args:
            record: {"source_type", "record_type", "raw"} envelope from
                src/ingest/connectors.py
            known_assets: list of {"asset_id", "name"} dicts

        Returns:
            dict with matched_asset_id, new_asset_name, environment,
            business_tag, cvss_score_estimate, severity, rationale
        """
        print(f"\n[NormalizationAgent] Normalizing {record.get('source_type')} record (LOCAL ONLY)...")

        prompt = self._build_prompt(record, known_assets)

        try:
            raw = self._call_ollama(prompt)
            result = self._parse_result(raw)
        except requests.exceptions.ConnectionError:
            result = {
                "matched_asset_id": None,
                "new_asset_name": None,
                "environment": "unknown",
                "business_tag": "medium",
                "cvss_score_estimate": 5.0,
                "severity": "MEDIUM",
                "rationale": "Ollama server not reachable at localhost:11434. Start with: ollama serve",
            }
        except Exception as e:
            result = {
                "matched_asset_id": None,
                "new_asset_name": None,
                "environment": "unknown",
                "business_tag": "medium",
                "cvss_score_estimate": 5.0,
                "severity": "MEDIUM",
                "rationale": f"Local model error: {str(e)[:100]}",
            }

        # Deterministic overrides — see match_known_asset()'s docstring for why
        # asset matching is not left to the model. Severity is likewise taken
        # straight from the source when the connector already provides one
        # (all four current connectors do); the model's severity estimate is
        # only used as a fallback for sources that don't carry their own.
        raw = record.get("raw", {})
        deterministic_match = match_known_asset(raw, known_assets)
        if deterministic_match:
            result["matched_asset_id"] = deterministic_match

        raw_severity = str(raw.get("severity", "")).upper()
        if raw_severity in VALID_SEVERITIES:
            result["severity"] = raw_severity

        print(f"  [Normalization] matched_asset_id={result['matched_asset_id']} severity={result['severity']}")
        return result


if __name__ == "__main__":
    agent = NormalizationAgent()
    test_record = {
        "source_type": "edr",
        "record_type": "vulnerability",
        "raw": {
            "hostname": "prod-web-01",
            "detection_name": "Suspicious child process spawned by nginx worker",
            "severity": "MEDIUM",
        },
    }
    test_known_assets = [{"asset_id": "ASSET-001", "name": "prod-web-01"}]
    result = agent.normalize(test_record, test_known_assets)
    print(json.dumps(result, indent=2))
