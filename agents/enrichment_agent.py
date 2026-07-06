"""
agents/enrichment_agent.py

Enrichment Agent — Cloud tier (Gemini API).

Takes a CVE ID → scrubs the description → calls Gemini → returns structured
enrichment (severity context, exploitation intelligence, remediation approach,
confidence tag). Implements write-once caching: if the CVE is already in the
enrichments table, the cached result is returned immediately.

This agent NEVER sees raw asset data — only public CVE information.

Note: this is a plain synchronous class, used directly by the standalone
"Run Pipeline" Streamlit page for its single-agent demo. The live pipeline's
Enrichment step instead goes through a genuine ADK sub-agent (see
agents/orchestrator.py) — that sub-agent's own gemini-2.5-flash reasoning
does the CVE analysis directly via typed tool-call arguments, rather than
parsing free-text JSON the way this standalone class does.
"""

import os
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from google import genai
from dotenv import load_dotenv

from src.db.database import get_db_connection, init_db
from src.security.scrubber import scrub

load_dotenv()

GEMINI_MODEL = "gemini-2.5-flash"


class EnrichmentAgent:
    """Cloud-based CVE enrichment agent using Gemini."""

    def __init__(self):
        api_key = os.getenv("GOOGLE_API_KEY", "")
        self.client = genai.Client(api_key=api_key)
        # Ensure DB schema is up to date
        init_db()

    def _get_cached(self, cve_id: str) -> dict | None:
        """Returns cached enrichment if it exists, else None."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM enrichments WHERE cve_id = ?", (cve_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {
                "cve_id": row["cve_id"],
                "severity_context": row["severity_context"],
                "exploitation_intelligence": row["exploitation_intelligence"],
                "remediation_approach": row["remediation_approach"],
                "confidence": row["confidence"],
                "enriched_at": row["enriched_at"],
                "from_cache": True,
            }
        return None

    def _write_cache(self, cve_id: str, result: dict, raw_response: str):
        """Writes enrichment to cache (write-once — will not overwrite)."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR IGNORE INTO enrichments
            (cve_id, severity_context, exploitation_intelligence,
             remediation_approach, confidence, enriched_at, raw_response)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                result.get("severity_context", ""),
                result.get("exploitation_intelligence", ""),
                result.get("remediation_approach", ""),
                result.get("confidence", "Medium"),
                datetime.now(timezone.utc).isoformat(),
                raw_response,
            ),
        )
        conn.commit()
        conn.close()

    def _call_gemini(self, cve_id: str, description: str, cvss_score: float) -> dict:
        """Calls Gemini with a scrubbed CVE description and parses structured JSON."""

        # ── Scrub before sending to cloud ────────────────────────────────────
        scrubbed_desc, redactions = scrub(description)
        if redactions:
            print(f"  [Scrubber] Redacted {len(redactions)} item(s) before cloud call: "
                  f"{[r[0] for r in redactions]}")

        prompt = f"""You are a cybersecurity analyst. Analyze this CVE and return a JSON object.

CVE ID: {cve_id}
CVSS Score: {cvss_score}
Description: {scrubbed_desc}

Return ONLY a valid JSON object with exactly these fields:
{{
  "severity_context": "2-3 sentences explaining the real-world severity and attack surface",
  "exploitation_intelligence": "Is this known to be exploited in the wild? Any known PoC?",
  "remediation_approach": "Concrete remediation steps (patch version, workaround, mitigation)",
  "confidence": "High or Medium or Low — based on how well-understood this CVE is"
}}

Return only the JSON. No markdown, no explanation, no code fences."""

        response = self.client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )

        raw = response.text.strip()

        # Parse JSON — with fallback for minor formatting issues
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            import re
            match = re.search(r'\{.*\}', raw, re.DOTALL)
            if match:
                parsed = json.loads(match.group())
            else:
                parsed = {
                    "severity_context": raw[:300],
                    "exploitation_intelligence": "Could not parse structured response.",
                    "remediation_approach": "See CVE advisory for details.",
                    "confidence": "Low",
                }

        return parsed, raw, redactions

    def enrich(self, cve_id: str, description: str, cvss_score: float) -> dict:
        """
        Main enrichment method.

        Returns cached result on repeated calls (write-once caching).
        """
        print(f"\n[EnrichmentAgent] Processing {cve_id}...")

        # ── Cache hit ─────────────────────────────────────────────────────────
        cached = self._get_cached(cve_id)
        if cached:
            print(f"  [Cache] HIT — returning cached enrichment (from_cache=True)")
            # Cache hits have no redaction log (scrubbing already happened on first call)
            cached["redaction_log"] = []
            return cached

        # ── Cache miss — call Gemini ───────────────────────────────────────────
        print(f"  [Cache] MISS — calling Gemini API...")
        parsed, raw, redactions = self._call_gemini(cve_id, description, cvss_score)

        result = {
            "cve_id": cve_id,
            "severity_context": parsed.get("severity_context", ""),
            "exploitation_intelligence": parsed.get("exploitation_intelligence", ""),
            "remediation_approach": parsed.get("remediation_approach", ""),
            "confidence": parsed.get("confidence", "Medium"),
            "from_cache": False,
            # redaction_log is additive — existing callers that ignore it are unaffected
            "redaction_log": redactions,
        }

        # ── Write once ───────────────────────────────────────────────────────
        self._write_cache(cve_id, result, raw)
        print(f"  [Cache] Written to store. Confidence: {result['confidence']}")

        return result


if __name__ == "__main__":
    agent = EnrichmentAgent()
    # Test with Log4Shell
    r1 = agent.enrich(
        "CVE-2021-44228",
        "Apache Log4j2 JNDI injection allowing remote code execution. Affects billions of Java applications.",
        10.0
    )
    print("\nFirst call (from_cache):", r1["from_cache"])
    r2 = agent.enrich(
        "CVE-2021-44228",
        "Apache Log4j2 JNDI injection allowing remote code execution. Affects billions of Java applications.",
        10.0
    )
    print("Second call (from_cache):", r2["from_cache"])
    assert r2["from_cache"] is True, "Write-once cache not working!"
    print("Write-once cache: VERIFIED")
