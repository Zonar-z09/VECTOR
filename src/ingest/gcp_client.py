"""
src/ingest/gcp_client.py

Real GCP integration — the deployment hook for someone running VECTOR
against their own GCP project/org instead of the synthetic connectors in
connectors.py.

═══════════════════════════════════════════════════════════════════════════
HONESTY NOTE — READ BEFORE TRUSTING THIS CODE
═══════════════════════════════════════════════════════════════════════════
This module has NEVER been run against a live GCP project. There is no GCP
project available in the environment this was built in. Every function here
is written against the documented request/response shapes of the official
Google client libraries as of mid-2026, but "matches the docs" is not the
same guarantee as "tested end-to-end" — every other piece of VECTOR's
ingestion path (the connectors, the normalization agent's deterministic
overrides) was built, run, and fixed against real output before being called
done. This module has not had that chance.

Treat this as a reference implementation to adapt and verify, not a
verified integration. If you deploy this, expect to debug field names,
enum values, and pagination against your actual project before it works.

Scope: this covers the GCP-native services reachable with standard project
IAM roles and the official Google client libraries — Security Command
Center, Cloud Asset Inventory, Artifact Analysis, Cloud DLP, IAM Recommender.
It deliberately does NOT cover Chronicle/SecOps (separate product/API,
different auth model) or VirusTotal/Mandiant (separate API keys, not GCP
IAM) — connectors.py keeps those two as mocks only; see that module's
docstrings for why.
═══════════════════════════════════════════════════════════════════════════

Every function below returns the same envelope shape as its mock
counterpart in connectors.py, so agents/ingestion_agent.py never needs to
know which mode it's running in.
"""

import os


def _project_id() -> str:
    project_id = os.environ.get("GCP_PROJECT_ID")
    if not project_id:
        raise RuntimeError("GCP_PROJECT_ID is not set — required for live GCP ingestion.")
    return project_id


def fetch_scc_findings_live() -> list[dict]:
    """
    Real Security Command Center Findings API call, across all categories.

    Requires GCP_ORG_ID (org-level SCC access) or GCP_PROJECT_ID (project-
    level SCC, narrower coverage) and roles/securitycenter.findingsViewer.

    UNVERIFIED: finding.resource_name is the full resource path
    (e.g. "//compute.googleapis.com/projects/x/zones/y/instances/z"), not a
    human-readable display name — real deployments will likely want to
    cross-reference it against Cloud Asset Inventory's resource_name to get
    a display_name that match_known_asset() can actually use. This function
    passes resource_name through as-is; that cross-reference is NOT
    implemented here and would need to be added before this is genuinely
    useful against a live project.
    """
    from google.cloud import securitycenter

    org_id = os.environ.get("GCP_ORG_ID")
    if org_id:
        parent = f"organizations/{org_id}/sources/-"
    else:
        parent = f"projects/{_project_id()}/sources/-"

    client = securitycenter.SecurityCenterClient()
    records = []
    for result in client.list_findings(request={"parent": parent}):
        finding = result.finding
        severity = finding.severity.name if hasattr(finding.severity, "name") else str(finding.severity)
        records.append({
            "source_type": "gcp_scc",
            "record_type": "vulnerability",
            "category": finding.category,
            "raw": {
                "finding_id": finding.name.rsplit("/", 1)[-1],
                "category": finding.category,
                "resource_display_name": finding.resource_name,
                "severity": severity,
                "description": finding.description,
            },
        })
    return records


def fetch_cloud_asset_inventory_live() -> list[dict]:
    """
    Real Cloud Asset Inventory call — lists resource metadata for the
    project. Requires GCP_PROJECT_ID and roles/cloudasset.viewer.

    UNVERIFIED: labels/public_ip extraction depends on asset.resource.data,
    whose shape varies per asset_type (a Compute instance's data looks
    nothing like a Cloud SQL instance's). The parsing below is a best-effort
    default that will not correctly populate labels/public_ip for most
    asset types without per-type handling — flagged rather than silently
    wrong.
    """
    from google.cloud import asset_v1

    client = asset_v1.AssetServiceClient()
    parent = f"projects/{_project_id()}"
    records = []
    for asset in client.list_assets(request={"parent": parent, "content_type": asset_v1.ContentType.RESOURCE}):
        data = dict(asset.resource.data) if asset.resource and asset.resource.data else {}
        records.append({
            "source_type": "cloud_asset_inventory",
            "record_type": "asset",
            "raw": {
                "resource_name": asset.name,
                "asset_type": asset.asset_type,
                "display_name": asset.name.rsplit("/", 1)[-1],
                "project": _project_id(),
                "location": data.get("zone") or data.get("region") or data.get("location"),
                "labels": data.get("labels", {}),
                "public_ip": bool(data.get("natIP") or data.get("ipAddress")),
            },
        })
    return records


def fetch_artifact_analysis_live() -> list[dict]:
    """
    Real Artifact Analysis (Container Scanning) call via the Grafeas API.
    Requires GCP_PROJECT_ID and roles/containeranalysis.occurrences.viewer.

    UNVERIFIED: vulnerability.package_issue is a repeated field (an
    occurrence can list multiple affected packages) — this takes only the
    first one for simplicity, matching the one-package-per-record shape the
    mock/DB path expects. A real deployment ingesting high volume would
    likely want to fan this out into one record per package_issue instead.
    """
    from google.cloud.devtools import containeranalysis_v1

    client = containeranalysis_v1.ContainerAnalysisClient()
    grafeas_client = client.get_grafeas_client()
    parent = f"projects/{_project_id()}"
    records = []
    for occ in grafeas_client.list_occurrences(parent=parent, filter='kind="VULNERABILITY"'):
        vuln = occ.vulnerability
        issue = vuln.package_issue[0] if vuln.package_issue else None
        cve = vuln.short_description if vuln.short_description.startswith("CVE-") else None
        records.append({
            "source_type": "artifact_analysis",
            "record_type": "vulnerability",
            "raw": {
                "image_uri": occ.resource_uri,
                "package": issue.affected_package if issue else None,
                "installed_version": getattr(issue.affected_version, "name", None) if issue else None,
                "fixed_version": getattr(issue.fixed_version, "name", None) if issue else None,
                "cve": cve,
                "severity": vuln.effective_severity.name if vuln.effective_severity else "MEDIUM",
            },
        })
    return records


def fetch_cloud_dlp_findings_live() -> list[dict]:
    """
    Real Cloud DLP call. Requires GCP_PROJECT_ID and roles/dlp.reader.

    UNVERIFIED, AND A REAL SHAPE MISMATCH TO FLAG: unlike SCC's flat
    findings list, DLP findings are scoped to individual inspection jobs —
    there's no single "list all findings" call. This lists recent completed
    jobs and pulls their inspect_details.result.info_type_stats, which
    gives counts per info_type rather than one row per finding the way
    every other connector here does. The record shape below approximates
    "one record per (job, info_type)" to fit the envelope, which is a
    coarser grain than SCC/Artifact Analysis findings — noted rather than
    hidden.
    """
    from google.cloud import dlp_v2

    client = dlp_v2.DlpServiceClient()
    parent = f"projects/{_project_id()}/locations/global"
    records = []
    for job in client.list_dlp_jobs(request={"parent": parent, "filter": "state=DONE"}):
        result = getattr(job.inspect_details, "result", None)
        if not result:
            continue
        for stat in result.info_type_stats:
            records.append({
                "source_type": "cloud_dlp",
                "record_type": "vulnerability",
                "raw": {
                    "resource_display_name": job.name.rsplit("/", 1)[-1],
                    "info_type": stat.info_type.name,
                    "likelihood": "LIKELY",  # per-finding likelihood isn't in job-level stats; approximated
                    "severity": "HIGH" if stat.count > 0 else "LOW",
                    "description": f"{stat.count} instance(s) of {stat.info_type.name} found.",
                },
            })
    return records


def fetch_iam_recommender_findings_live() -> list[dict]:
    """
    Real IAM Recommender call. Requires GCP_PROJECT_ID and
    roles/recommender.iamViewer.

    UNVERIFIED: current_role/recommended_role extraction from
    rec.content.operation_groups is non-trivial (nested operation objects,
    not flat fields) — left as None here rather than guessed at. The
    recommendation description text itself is reliable; the structured
    role fields are not populated by this implementation.
    """
    from google.cloud import recommender_v1

    client = recommender_v1.RecommenderClient()
    parent = f"projects/{_project_id()}/locations/global/recommenders/google.iam.policy.Recommender"
    records = []
    for rec in client.list_recommendations(request={"parent": parent}):
        records.append({
            "source_type": "iam_recommender",
            "record_type": "vulnerability",
            "raw": {
                "resource_display_name": rec.name.rsplit("/", 1)[-1],
                "recommendation": rec.description,
                "current_role": None,
                "recommended_role": None,
                "severity": "MEDIUM",
            },
        })
    return records
