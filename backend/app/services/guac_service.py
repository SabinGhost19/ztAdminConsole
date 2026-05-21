"""GUAC GraphQL proxy — Blast Radius queries for the UI.

The frontend never talks to GUAC directly: this would expose the internal
GraphQL endpoint to the browser and make CORS/auth a nightmare. Instead,
the backend acts as a thin proxy: receives a CVE or package query, asks
GUAC, and returns a normalized JSON tree shape that the Vue Tree View can
render directly.

This module assumes GUAC runs inside the cluster and is reachable from the
backend pod at the address configured via the `GUAC_GRAPHQL_URL` env var
(default: http://guac-graphql-server.guac.svc.cluster.local:8080/query).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("zero_trust_guac_service")


def _endpoint() -> str:
    # Default tracks the official `guacsec/guac` Helm chart Service names:
    #   Service/graphql-server  :8080  /query
    # Override per-cluster with GUAC_GRAPHQL_URL on the backend deployment.
    return os.environ.get(
        "GUAC_GRAPHQL_URL",
        "http://graphql-server.guac.svc.cluster.local:8080/query",
    ).strip()


async def is_healthy() -> dict[str, Any]:
    """Returns a structured health probe for the UI to disable / enable
    the Blast Radius feature when GUAC is unreachable.
    """
    url = _endpoint()
    if not url:
        return {"reachable": False, "endpoint": "", "reason": "GUAC_GRAPHQL_URL unset"}

    probe = {"query": "{ __typename }"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(url, json=probe)
            return {
                "reachable": resp.status_code < 400,
                "endpoint": url,
                "statusCode": resp.status_code,
            }
    except Exception as exc:
        return {"reachable": False, "endpoint": url, "reason": str(exc)[:200]}


async def blast_radius_by_cve(cve_id: str) -> dict[str, Any]:
    """Aggregate the impact of a CVE across all images and deployments
    known to GUAC. Returns a tree-shaped payload optimised for the UI.

    Shape:
      {
        "cve": "CVE-2024-XXXX",
        "vulnerablePackages": [
          {
            "name": "...",
            "version": "...",
            "affectedImages": [
              {
                "image": "...",
                "deployments": [
                  { "namespace": "...", "name": "...", "vexExempted": bool }
                ]
              }
            ]
          }
        ]
      }
    """
    url = _endpoint()
    if not url:
        return {"cve": cve_id, "vulnerablePackages": [], "guacUnavailable": True}

    # GUAC v1.x exposes the join through `CertifyVuln(certifyVulnSpec: ...)`
    # filtered by vulnerabilityID. Earlier drafts of this proxy used a
    # non-existent `findVulnerability` field which returned HTTP 422.
    # IDs in the graph come in three flavors (osv-certifier output):
    #   - "ghsa-xxxx-xxxx-xxxx"
    #   - "cve-2024-xxxx"
    #   - "debian-cve-2024-xxxx"
    # GUAC stores them lowercased, so normalise before querying.
    query = """
    query BlastRadius($cve: String!) {
      CertifyVuln(certifyVulnSpec: { vulnerability: { vulnerabilityID: $cve } }) {
        vulnerability { vulnerabilityIDs { vulnerabilityID } }
        package {
          type
          namespaces {
            namespace
            names {
              name
              versions { version qualifiers { key value } }
            }
          }
        }
      }
    }
    """

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url,
                json={"query": query, "variables": {"cve": cve_id.lower()}},
            )
        if resp.status_code >= 400:
            logger.warning(
                "GUAC returned non-2xx for blast-radius query",
                extra={"details": {"cve": cve_id, "status": resp.status_code, "body": resp.text[:300]}},
            )
            return {"cve": cve_id, "vulnerablePackages": [], "error": f"GUAC HTTP {resp.status_code}"}
        body = resp.json()
        if body.get("errors"):
            logger.warning(
                "GUAC returned GraphQL errors for blast-radius query",
                extra={"details": {"cve": cve_id, "errors": str(body["errors"])[:300]}},
            )
            return {"cve": cve_id, "vulnerablePackages": [], "error": str(body["errors"][0].get("message", "GUAC GraphQL error"))[:200]}
    except Exception as exc:
        logger.exception(
            "GUAC blast-radius query failed",
            extra={"details": {"cve": cve_id, "error": str(exc)}},
        )
        return {"cve": cve_id, "vulnerablePackages": [], "error": str(exc)[:200]}

    # Normalise — GUAC payload shape is intentionally tolerant to schema drift.
    findings = ((body.get("data") or {}).get("CertifyVuln") or []) or []
    by_package: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in findings:
        pkg_ns = ((entry.get("package") or {}).get("namespaces") or []) or []
        for namespace in pkg_ns:
            for pkg_name in (namespace.get("names") or []):
                for version in (pkg_name.get("versions") or []):
                    key = (pkg_name.get("name", ""), version.get("version", ""))
                    by_package.setdefault(
                        key,
                        {
                            "name": pkg_name.get("name", ""),
                            "version": version.get("version", ""),
                            "affectedImages": [],
                        },
                    )
    return {
        "cve": cve_id,
        "vulnerablePackages": list(by_package.values()),
        "guacRaw": body if os.environ.get("GUAC_DEBUG") == "1" else None,
    }


async def merge_cluster_context(
    blast: dict[str, Any],
    zta_index: list[dict[str, Any]],
) -> dict[str, Any]:
    """Attach K8s deployment context from the live ZTA list to each affected
    image. This is what makes the Blast Radius visualisation actionable:
    GUAC knows which images contain a package, the operator/scanner knows
    which images run in which namespaces.
    """
    image_to_ztas: dict[str, list[dict[str, Any]]] = {}
    for entry in zta_index:
        summary = entry.get("summary", {}) or {}
        image = str(summary.get("image") or "").strip()
        if not image:
            continue
        meta = entry.get("metadata", {}) or {}
        vex_exempt = bool((summary.get("vex", {}) or {}).get("exemptedCount", 0))
        image_to_ztas.setdefault(image, []).append(
            {
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "trustLevel": summary.get("trustLevel"),
                "securityState": summary.get("securityState"),
                "vexExempted": vex_exempt,
            }
        )

    enriched_packages = []
    for pkg in blast.get("vulnerablePackages", []):
        affected_images = []
        for image, deployments in image_to_ztas.items():
            # naive substring match: real GUAC integration would join via purl;
            # for the dashboard demo this is sufficient because the operator
            # ingests the SBOM keyed by the same image ref.
            if pkg.get("name", "") and pkg.get("name") in image:
                affected_images.append({"image": image, "deployments": deployments})
        enriched = dict(pkg)
        enriched["affectedImages"] = affected_images
        enriched_packages.append(enriched)
    blast["vulnerablePackages"] = enriched_packages
    return blast
