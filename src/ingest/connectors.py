"""
src/ingest/connectors.py

Pluggable external-source connector registry — the extensibility hook for
ingesting assets/vulnerabilities from real tools (code-scanning/SAST, EDR,
Google Security Command Center) instead of only the static seed files in
data/.

WHY THIS IS MOCKED, LIKE src/integrations/ticketing.py's backend formatters:
Each fetch_* function below returns a small set of synthetic sample records,
shaped like what the real tool's API actually returns, with a comment
showing exactly where the real API call would replace the synthetic data.
No live credentials or network calls happen here. This mirrors the same
"pluggable backend, one clear seam for a real integration" pattern already
used for ticketing (Jira/ServiceNow/webhook) — SOURCE_CONNECTORS is the
ingestion-side equivalent of TICKET_BACKENDS.

Each record returned has a common envelope so agents/ingestion_agent.py can
process any source without source-specific branching:
  {
    "source_type": "code_scan" | "edr" | "gcp_scc" | "cloud_asset_inventory" | "artifact_analysis",
    "record_type": "asset" | "vulnerability",
    "raw": {...source-native fields...},
  }

WHY gcp_scc IS ONE CONNECTOR, NOT ONE PER DETECTOR:
Google Security Command Center's detectors (Event Threat Detection, Web
Security Scanner, Container Threat Detection, VM Threat Detection, Security
Health Analytics, Rapid Vulnerability Detection, Sensitive Actions Service)
all write to ONE underlying Findings API
(securitycenter.projects().sources().findings().list(), filterable by a
`category` field) — they are not separate APIs. fetch_scc_findings() below
returns records tagged with `category`, matching that real shape, instead of
pretending each detector is its own integration.

MOCK VS LIVE: set VECTOR_GCP_MODE=live (default "mock") to dispatch the 5
GCP-native connectors (gcp_scc, cloud_asset_inventory, artifact_analysis,
cloud_dlp, iam_recommender) to src/ingest/gcp_client.py's real API calls
instead of the synthetic functions below — see that module's docstring for
required IAM roles/env vars and its explicit "unverified" disclaimer.
chronicle_secops and threat_intel have no live counterpart (see their
docstrings for why) and always return mock data.
"""

import os

VECTOR_GCP_MODE = os.environ.get("VECTOR_GCP_MODE", "mock")


def _gcp_source(mock_fn, live_attr_name):
    """
    Wraps a mock connector so it dispatches to gcp_client.py's real
    implementation when VECTOR_GCP_MODE=live. gcp_client's GCP client
    libraries are imported lazily (inside gcp_client.py itself) so a
    machine without them installed can still run the mock-mode demo.
    """
    def _call():
        if VECTOR_GCP_MODE == "live":
            from src.ingest import gcp_client
            return getattr(gcp_client, live_attr_name)()
        return mock_fn()
    return _call


def fetch_code_scan_findings() -> list[dict]:
    """
    Simulates a SAST / repo-scanning tool (e.g. Semgrep, CodeQL, Snyk Code).
    # Real integration would call e.g. requests.get(f"{SNYK_API}/orgs/{org}/projects/{id}/issues", headers=auth)
    """
    return [
        {
            "source_type": "code_scan",
            "record_type": "vulnerability",
            "raw": {
                "repo": "payments-service",
                "file": "src/payments/webhook_handler.py",
                "line": 88,
                "rule_id": "python.jwt.security.hardcoded-jwt-secret",
                "message": "Hardcoded JWT signing secret found in source.",
                "severity": "HIGH",
                "cve": None,
            },
        },
        {
            "source_type": "code_scan",
            "record_type": "vulnerability",
            "raw": {
                "repo": "web-frontend",
                "file": "server/render.py",
                "line": 214,
                "rule_id": "python.flask.security.audit.debug-enabled",
                "message": "Flask app running with debug=True in production config.",
                "severity": "MEDIUM",
                "cve": None,
            },
        },
    ]


def fetch_edr_alerts() -> list[dict]:
    """
    Simulates an EDR/endpoint tool (e.g. CrowdStrike Falcon, SentinelOne).
    # Real integration would call e.g. requests.get(f"{CROWDSTRIKE_API}/detects/queries/detects/v1", headers=auth)
    """
    return [
        {
            "source_type": "edr",
            "record_type": "vulnerability",
            "raw": {
                "hostname": "prod-web-01",
                "agent_id": "edr-8f3a21",
                "detection_name": "Suspicious child process spawned by nginx worker",
                "severity": "MEDIUM",
                "os": "Ubuntu 22.04",
                "process": "curl",
            },
        },
        {
            "source_type": "edr",
            "record_type": "vulnerability",
            "raw": {
                "hostname": "dev-build-server",
                "agent_id": "edr-1c77b0",
                "detection_name": "Outdated agent — endpoint missing 3 patch cycles",
                "severity": "LOW",
                "os": "Ubuntu 22.04",
                "process": None,
            },
        },
    ]


def fetch_scc_findings() -> list[dict]:
    """
    Simulates Google Security Command Center's unified Findings API across
    all 7 detector categories. Real SCC findings share one record shape
    (finding_id, category, resource_display_name, severity, description)
    regardless of which detector produced them — see this module's docstring
    for why that means one connector, not one per detector.
    # Real integration would call the SCC Findings API:
    # securitycenter.projects().sources().findings().list(
    #     parent=f"organizations/{org}/sources/-", filter=f'category="{category}"')
    """
    findings = [
        # Event Threat Detection
        ("etd-finding-0417", "EVENT_THREAT_DETECTION", "prod-api-gateway", "HIGH",
         "Anomalous IAM role grant detected on a production resource."),
        ("etd-finding-0512", "EVENT_THREAT_DETECTION", "prod-backup-storage", "CRITICAL",
         "Large outbound data transfer detected from a storage resource."),
        # Web Security Scanner
        ("wss-finding-0091", "WEB_SECURITY_SCANNER", "prod-web-01", "HIGH",
         "Reflected XSS vulnerability found on the login page."),
        ("wss-finding-0104", "WEB_SECURITY_SCANNER", "staging-web-01", "MEDIUM",
         "Outdated client-side library with known vulnerabilities detected."),
        # Container Threat Detection
        ("ctd-finding-0033", "CONTAINER_THREAT_DETECTION", "prod-k8s-control-plane", "CRITICAL",
         "Suspicious binary execution detected inside a running GKE container."),
        # VM Threat Detection
        ("vmtd-finding-0027", "VM_THREAT_DETECTION", "prod-vpn-gateway", "HIGH",
         "Cryptocurrency mining process detected on a Compute Engine instance."),
        # Security Health Analytics (misconfiguration scanning)
        ("sha-finding-0158", "SECURITY_HEALTH_ANALYTICS", "prod-backup-storage", "HIGH",
         "Cloud Storage bucket is publicly accessible (allUsers has read access)."),
        ("sha-finding-0162", "SECURITY_HEALTH_ANALYTICS", "prod-auth-service", "MEDIUM",
         "Service account has an overly broad project-level IAM role instead of a scoped one."),
        # Rapid Vulnerability Detection
        ("rvd-finding-0071", "RAPID_VULNERABILITY_DETECTION", "prod-monitoring", "HIGH",
         "Admin interface reachable without authentication on a public IP."),
        # Sensitive Actions Service
        ("sas-finding-0009", "SENSITIVE_ACTIONS_SERVICE", "prod-payment-svc", "MEDIUM",
         "New service account key created for a production-tagged resource outside change window."),
    ]
    return [
        {
            "source_type": "gcp_scc",
            "record_type": "vulnerability",
            "category": category,
            "raw": {
                "finding_id": finding_id,
                "category": category,
                "resource_display_name": resource,
                "severity": severity,
                "description": description,
            },
        }
        for finding_id, category, resource, severity, description in findings
    ]


def fetch_cloud_asset_inventory() -> list[dict]:
    """
    Simulates Cloud Asset Inventory — the real asset-metadata source of
    truth (what resources exist and how they're configured), as opposed to
    a findings/vulnerability feed. First connector to emit record_type
    "asset" records.
    # Real integration would call e.g.:
    # asset_client.list_assets(request={"parent": f"projects/{project}", "asset_types": [...]})
    """
    return [
        {
            "source_type": "cloud_asset_inventory",
            "record_type": "asset",
            "raw": {
                "resource_name": "//compute.googleapis.com/projects/vector-demo/zones/us-central1-a/instances/prod-web-01",
                "asset_type": "compute.googleapis.com/Instance",
                "display_name": "prod-web-01",
                "project": "vector-demo",
                "location": "us-central1-a",
                "labels": {"env": "production"},
                "public_ip": True,
            },
        },
        {
            "source_type": "cloud_asset_inventory",
            "record_type": "asset",
            "raw": {
                "resource_name": "//sqladmin.googleapis.com/projects/vector-demo/instances/prod-analytics-db",
                "asset_type": "sqladmin.googleapis.com/Instance",
                "display_name": "prod-analytics-db",
                "project": "vector-demo",
                "location": "us-central1",
                "labels": {"env": "production", "team": "data"},
                "public_ip": False,
            },
        },
    ]


def fetch_artifact_analysis() -> list[dict]:
    """
    Simulates Artifact Analysis (Container Scanning) — vulnerability
    scanning of container images in Artifact Registry. The real GCP-native
    equivalent of fetch_code_scan_findings(), and unlike the other mocks
    here, its findings often carry a genuine CVE ID.
    # Real integration would call e.g.:
    # grafeas_client.list_occurrences(parent=f"projects/{project}",
    #     filter='kind="VULNERABILITY"')
    """
    return [
        {
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {
                "image_uri": "us-central1-docker.pkg.dev/vector-demo/prod-payment-svc/api:1.4.2",
                "package": "openssl",
                "installed_version": "1.1.1k",
                "fixed_version": "1.1.1w",
                "cve": "CVE-2023-0286",
                "severity": "HIGH",
            },
        },
        {
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {
                "image_uri": "us-central1-docker.pkg.dev/vector-demo/prod-web-01/nginx:1.24.0",
                "package": "libcurl",
                "installed_version": "7.81.0",
                "fixed_version": "7.88.1",
                "cve": None,
                "severity": "MEDIUM",
            },
        },
    ]


def fetch_cloud_dlp_findings() -> list[dict]:
    """
    Simulates Sensitive Data Protection (Cloud DLP) — data classification
    and exposure findings.
    # Real integration would call e.g.:
    # dlp_client.list_findings(request={"parent": f"projects/{project}/locations/{loc}"})
    """
    return [
        {
            "source_type": "cloud_dlp",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-backup-storage",
                "info_type": "CREDIT_CARD_NUMBER",
                "likelihood": "VERY_LIKELY",
                "severity": "HIGH",
                "description": "Unmasked credit card numbers found in an object without encryption-at-rest policy.",
            },
        },
        {
            "source_type": "cloud_dlp",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-db-primary",
                "info_type": "US_SOCIAL_SECURITY_NUMBER",
                "likelihood": "LIKELY",
                "severity": "CRITICAL",
                "description": "Sensitive PII detected in a table without column-level access controls.",
            },
        },
    ]


def fetch_iam_recommender_findings() -> list[dict]:
    """
    Simulates IAM Recommender / Policy Intelligence — over-privileged
    access findings.
    # Real integration would call e.g.:
    # recommender_client.list_recommendations(parent=f"projects/{project}/locations/global/recommenders/google.iam.policy.Recommender")
    """
    return [
        {
            "source_type": "iam_recommender",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-auth-service",
                "recommendation": "Remove unused 'roles/editor' grant — no activity in the last 90 days.",
                "current_role": "roles/editor",
                "recommended_role": "roles/iam.serviceAccountUser",
                "severity": "MEDIUM",
            },
        },
        {
            "source_type": "iam_recommender",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-k8s-control-plane",
                "recommendation": "Service account has project-owner role; scope down to GKE-specific roles.",
                "current_role": "roles/owner",
                "recommended_role": "roles/container.admin",
                "severity": "HIGH",
            },
        },
    ]


def fetch_chronicle_secops_events() -> list[dict]:
    """
    SIMPLIFIED MOCK — Google Security Operations (Chronicle) is fundamentally
    different from every other connector here: it's a SIEM you query (UDM
    search) or stream telemetry into, not a bounded list of discrete
    findings. Forcing it into this module's fetch_*() -> list[dict] shape is
    a deliberate simplification for demo purposes, not a realistic
    representation of how Chronicle is actually integrated. A genuine
    integration would poll or stream via the Chronicle API's UDM search /
    event streaming endpoints, not a one-shot "list of events" call.
    # Real integration would call e.g.:
    # chronicle_client.legacy_search_udm_events(request={"query": "...", "time_range": {...}})
    """
    return [
        {
            "source_type": "chronicle_secops",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-api-gateway",
                "udm_event_type": "NETWORK_CONNECTION",
                "rule_name": "Repeated auth failures followed by successful login",
                "severity": "HIGH",
                "description": "Correlated telemetry suggests a successful credential-stuffing attempt.",
            },
        },
    ]


def fetch_threat_intel_iocs() -> list[dict]:
    """
    SIMPLIFIED MOCK — VirusTotal and Mandiant threat intelligence are
    indicator/campaign-centric (file hashes, malicious URLs, actor TTPs),
    not asset-bound findings. Real usage means checking whether an indicator
    you already have (a hash, a URL) appears in their intelligence — it does
    not mean these products hand you a list of findings against your asset
    inventory. The asset attribution below is FABRICATED for demo purposes
    (asserting "this indicator was observed on this asset") to fit the
    shared connector shape — that fabricated step is exactly what a real
    integration would need custom correlation logic to do honestly (e.g.
    matching a VirusTotal hash hit against your own EDR process telemetry).
    # Real integration would call e.g.:
    # requests.get(f"{VT_API}/api/v3/files/{file_hash}", headers=auth)
    """
    return [
        {
            "source_type": "threat_intel",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": "prod-web-01",
                "indicator_type": "FILE_HASH",
                "indicator_value": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "source": "VirusTotal",
                "detections": "34/72 engines",
                "severity": "HIGH",
                "description": "A file hash observed on this host matches a known malware sample.",
            },
        },
    ]


SOURCE_CONNECTORS = {
    "code_scan": fetch_code_scan_findings,
    "edr": fetch_edr_alerts,
    "gcp_scc": _gcp_source(fetch_scc_findings, "fetch_scc_findings_live"),
    "cloud_asset_inventory": _gcp_source(fetch_cloud_asset_inventory, "fetch_cloud_asset_inventory_live"),
    "artifact_analysis": _gcp_source(fetch_artifact_analysis, "fetch_artifact_analysis_live"),
    "cloud_dlp": _gcp_source(fetch_cloud_dlp_findings, "fetch_cloud_dlp_findings_live"),
    "iam_recommender": _gcp_source(fetch_iam_recommender_findings, "fetch_iam_recommender_findings_live"),
    "chronicle_secops": fetch_chronicle_secops_events,
    "threat_intel": fetch_threat_intel_iocs,
}

SOURCE_LABELS = {
    "code_scan": "Code Review / Repo Scanner (SAST)",
    "edr": "EDR / Endpoint Protection",
    "gcp_scc": "Google Security Command Center (all categories)",
    "cloud_asset_inventory": "Google Cloud Asset Inventory",
    "artifact_analysis": "Google Artifact Analysis (Container Scanning)",
    "cloud_dlp": "Google Sensitive Data Protection (Cloud DLP)",
    "iam_recommender": "Google IAM Recommender / Policy Intelligence",
    "chronicle_secops": "Google Security Operations (Chronicle) — simplified",
    "threat_intel": "Threat Intel (VirusTotal / Mandiant) — simplified",
}


def fetch_all(sources: list[str] | None = None) -> list[dict]:
    """
    Fetches raw records from the given source ids (or all sources if None),
    tagged with the common envelope described in the module docstring.
    """
    ids = sources or list(SOURCE_CONNECTORS.keys())
    records = []
    for source_id in ids:
        if source_id not in SOURCE_CONNECTORS:
            raise ValueError(f"Unknown source '{source_id}'. Choose from: {list(SOURCE_CONNECTORS)}")
        records.extend(SOURCE_CONNECTORS[source_id]())
    return records


if __name__ == "__main__":
    import json
    print(json.dumps(fetch_all(), indent=2))
