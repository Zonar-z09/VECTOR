"""
Five-factor prioritization engine.
Calculates risk scores for vulnerabilities based on asset and CVE context.
"""

import json

# Default weights summing to 1.0
DEFAULT_WEIGHTS = {
    "internet_exposure": 0.25,
    "environment_classification": 0.20,
    "exploit_capability": 0.25,
    "manual_tag": 0.20,
    "dependency_score": 0.10
}

def calculate_internet_exposure(asset):
    return 1.0 if asset["internet_exposed"] else 0.0

def calculate_environment_classification(asset):
    env = asset.get("environment", "").lower()
    if env == "production":
        return 1.0
    elif env == "staging":
        return 0.5
    elif env == "development":
        return 0.2
    return 0.0

def calculate_exploit_capability(cve):
    # Normalize CVSS score (0-10) to 0-1 range
    score = cve.get("cvss_score", 0.0)
    return min(max(score / 10.0, 0.0), 1.0)

def calculate_manual_tag(asset):
    tag = asset.get("business_tag", "").lower()
    if tag == "critical":
        return 1.0
    elif tag == "high":
        return 0.8
    elif tag == "medium":
        return 0.5
    elif tag == "low":
        return 0.2
    return 0.0

def calculate_dependency_score(asset):
    # Retrieve dependencies (parsed JSON list or empty string)
    deps_raw = asset.get("dependencies_json", "[]")
    try:
        deps = json.loads(deps_raw) if isinstance(deps_raw, str) else deps_raw
    except:
        deps = []
        
    count = len(deps)
    if count >= 2:
        return 1.0
    elif count == 1:
        return 0.5
    return 0.2

def score_vulnerability(vuln, asset, cve, weights=None):
    """
    Scores a vulnerability based on the five-factor model.
    Returns a dictionary containing the final score and a breakdown of factors.
    """
    w = weights if weights else DEFAULT_WEIGHTS
    
    # Calculate unweighted base scores (0-1) for each factor
    f1_base = calculate_internet_exposure(asset)
    f2_base = calculate_environment_classification(asset)
    f3_base = calculate_exploit_capability(cve)
    f4_base = calculate_manual_tag(asset)
    f5_base = calculate_dependency_score(asset)
    
    # Apply weights
    f1_weighted = f1_base * w.get("internet_exposure", 0.0)
    f2_weighted = f2_base * w.get("environment_classification", 0.0)
    f3_weighted = f3_base * w.get("exploit_capability", 0.0)
    f4_weighted = f4_base * w.get("manual_tag", 0.0)
    f5_weighted = f5_base * w.get("dependency_score", 0.0)
    
    final_score = sum([f1_weighted, f2_weighted, f3_weighted, f4_weighted, f5_weighted])
    
    # Identify which factor drove the score most
    weighted_scores = {
        "internet_exposure": f1_weighted,
        "environment_classification": f2_weighted,
        "exploit_capability": f3_weighted,
        "manual_tag": f4_weighted,
        "dependency_score": f5_weighted
    }
    primary_driver = max(weighted_scores, key=weighted_scores.get)
    
    return {
        "vuln_id": vuln["vuln_id"],
        "asset_id": asset["asset_id"],
        "cve_id": cve["cve_id"],
        "final_score": round(final_score, 4),
        "primary_driver": primary_driver,
        "breakdown": {
            "internet_exposure": {"base": f1_base, "weighted": f1_weighted},
            "environment_classification": {"base": f2_base, "weighted": f2_weighted},
            "exploit_capability": {"base": f3_base, "weighted": f3_weighted},
            "manual_tag": {"base": f4_base, "weighted": f4_weighted},
            "dependency_score": {"base": f5_base, "weighted": f5_weighted}
        }
    }
