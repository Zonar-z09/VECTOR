"""
tests/test_prioritization.py — unit tests for src/engine/prioritization.py

Pure-function module. Complements the existing tests/test_scoring.py
(which exercises the engine against real seeded DB data with rich output);
this file covers the individual factor functions and edge cases in isolation.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.engine.prioritization import (
    calculate_internet_exposure,
    calculate_environment_classification,
    calculate_exploit_capability,
    calculate_manual_tag,
    calculate_dependency_score,
    score_vulnerability,
    DEFAULT_WEIGHTS,
)


class TestInternetExposure:
    def test_exposed_returns_1(self):
        assert calculate_internet_exposure({"internet_exposed": True}) == 1.0

    def test_not_exposed_returns_0(self):
        assert calculate_internet_exposure({"internet_exposed": False}) == 0.0


class TestEnvironmentClassification:
    def test_production(self):
        assert calculate_environment_classification({"environment": "production"}) == 1.0

    def test_staging(self):
        assert calculate_environment_classification({"environment": "staging"}) == 0.5

    def test_development(self):
        assert calculate_environment_classification({"environment": "development"}) == 0.2

    def test_unknown_environment_defaults_to_0(self):
        assert calculate_environment_classification({"environment": "sandbox"}) == 0.0

    def test_case_insensitive(self):
        assert calculate_environment_classification({"environment": "PRODUCTION"}) == 1.0

    def test_missing_environment_key(self):
        assert calculate_environment_classification({}) == 0.0


class TestExploitCapability:
    def test_max_cvss(self):
        assert calculate_exploit_capability({"cvss_score": 10.0}) == 1.0

    def test_mid_cvss(self):
        assert calculate_exploit_capability({"cvss_score": 5.0}) == 0.5

    def test_zero_cvss(self):
        assert calculate_exploit_capability({"cvss_score": 0.0}) == 0.0

    def test_missing_cvss_defaults_to_0(self):
        assert calculate_exploit_capability({}) == 0.0

    def test_out_of_range_high_is_clamped(self):
        # Defensive: CVSS should never exceed 10, but the function must not
        # silently produce a score > 1.0 if bad data slips through.
        assert calculate_exploit_capability({"cvss_score": 15.0}) == 1.0

    def test_negative_is_clamped(self):
        assert calculate_exploit_capability({"cvss_score": -3.0}) == 0.0


class TestManualTag:
    def test_critical(self):
        assert calculate_manual_tag({"business_tag": "critical"}) == 1.0

    def test_high(self):
        assert calculate_manual_tag({"business_tag": "high"}) == 0.8

    def test_medium(self):
        assert calculate_manual_tag({"business_tag": "medium"}) == 0.5

    def test_low(self):
        assert calculate_manual_tag({"business_tag": "low"}) == 0.2

    def test_unrecognized_tag_defaults_to_0(self):
        assert calculate_manual_tag({"business_tag": "experimental"}) == 0.0


class TestDependencyScore:
    def test_two_or_more_deps(self):
        assert calculate_dependency_score({"dependencies_json": '["A", "B"]'}) == 1.0

    def test_one_dep(self):
        assert calculate_dependency_score({"dependencies_json": '["A"]'}) == 0.5

    def test_zero_deps(self):
        assert calculate_dependency_score({"dependencies_json": "[]"}) == 0.2

    def test_missing_field_defaults_to_zero_deps(self):
        assert calculate_dependency_score({}) == 0.2

    def test_malformed_json_does_not_raise(self):
        assert calculate_dependency_score({"dependencies_json": "{not valid json"}) == 0.2

    def test_already_a_list_not_a_string(self):
        # ingest_pipeline stores this as a JSON string, but the function should
        # tolerate being handed an already-parsed list too.
        assert calculate_dependency_score({"dependencies_json": ["A", "B", "C"]}) == 1.0


class TestScoreVulnerability:
    def _make_case(self, **overrides):
        vuln = {"vuln_id": "VULN-001"}
        asset = {
            "asset_id": "ASSET-001",
            "internet_exposed": True,
            "environment": "production",
            "business_tag": "critical",
            "dependencies_json": '["A", "B"]',
        }
        cve = {"cve_id": "CVE-TEST", "cvss_score": 9.8}
        asset.update(overrides.pop("asset", {}))
        cve.update(overrides.pop("cve", {}))
        return vuln, asset, cve

    def test_max_risk_case_scores_near_1(self):
        vuln, asset, cve = self._make_case()
        result = score_vulnerability(vuln, asset, cve)
        assert result["final_score"] > 0.95

    def test_minimal_risk_case_scores_near_0(self):
        vuln, asset, cve = self._make_case(
            asset={"internet_exposed": False, "environment": "development",
                   "business_tag": "low", "dependencies_json": "[]"},
            cve={"cvss_score": 0.0},
        )
        result = score_vulnerability(vuln, asset, cve)
        assert result["final_score"] <= 0.1  # exactly 0.10 for this all-minimum case

    def test_determinism(self):
        vuln, asset, cve = self._make_case()
        r1 = score_vulnerability(vuln, asset, cve)
        r2 = score_vulnerability(vuln, asset, cve)
        assert r1["final_score"] == r2["final_score"]
        assert r1["primary_driver"] == r2["primary_driver"]

    def test_default_weights_sum_to_one(self):
        assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 1e-9

    def test_custom_weights_change_ranking(self):
        vuln, asset, cve = self._make_case(cve={"cvss_score": 1.0})  # low exploit capability
        default_result = score_vulnerability(vuln, asset, cve)

        internet_heavy = {
            "internet_exposure": 0.9, "environment_classification": 0.025,
            "exploit_capability": 0.025, "manual_tag": 0.025, "dependency_score": 0.025,
        }
        heavy_result = score_vulnerability(vuln, asset, cve, weights=internet_heavy)

        # Same inputs, different weights → different score, both deterministic.
        assert heavy_result["final_score"] != default_result["final_score"]
        assert heavy_result["primary_driver"] == "internet_exposure"

    def test_output_contains_expected_keys(self):
        vuln, asset, cve = self._make_case()
        result = score_vulnerability(vuln, asset, cve)
        assert set(result.keys()) == {
            "vuln_id", "asset_id", "cve_id", "final_score", "primary_driver", "breakdown",
        }
        assert set(result["breakdown"].keys()) == {
            "internet_exposure", "environment_classification",
            "exploit_capability", "manual_tag", "dependency_score",
        }

    def test_weights_not_summing_to_one_is_not_validated_by_engine(self):
        # The engine itself is intentionally agnostic about weight sums —
        # sum validation is the Weight Configuration UI page's job (it warns,
        # never silently renormalizes). This test documents that contract so
        # a future change to either side doesn't silently drift.
        vuln, asset, cve = self._make_case()
        bad_weights = {"internet_exposure": 0.5, "environment_classification": 0.5,
                        "exploit_capability": 0.5, "manual_tag": 0.5, "dependency_score": 0.5}
        result = score_vulnerability(vuln, asset, cve, weights=bad_weights)
        assert result["final_score"] > 1.0  # engine does not clamp or validate
