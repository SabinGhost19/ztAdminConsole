"""GUAC proxy endpoints (Blast Radius + health probe).

The UI calls these endpoints; they shield the browser from direct GraphQL
access to the internal GUAC service. All endpoints are read-only and
require the same SECURITY_READ permission used by other observability
routes (sca_routes, integrity_routes).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Any, Dict

from app.security.identity import Identity, require_permission
from app.security import permissions as perm
from app.services import guac_service, zta_service

router = APIRouter()


@router.get("/health", response_model=Dict[str, Any])
async def guac_health(
    _identity: Identity = Depends(require_permission(perm.P_SECURITY_READ)),
) -> Dict[str, Any]:
    """Lets the UI decide whether to enable the Blast Radius button."""
    return await guac_service.is_healthy()


@router.get("/vulnerabilities", response_model=Dict[str, Any])
async def list_vulnerabilities(
    _identity: Identity = Depends(require_permission(perm.P_SECURITY_READ)),
) -> Dict[str, Any]:
    """List every vulnerability ID known to the GUAC graph.

    The UI uses this to populate the "pick a vulnerability" autocomplete
    so auditors don't have to memorise GHSA/debian-cve strings. Sorted by
    affected-package count descending (so the highest-impact CVEs surface
    first), with a `family` hint for grouping (`GHSA`, `Debian`, `CVE`...).
    """
    return await guac_service.list_known_vulnerabilities()


@router.get("/blast-radius", response_model=Dict[str, Any])
async def blast_radius(
    cve: str = Query(..., description="Vulnerability ID (CVE-…, GHSA-…, debian-cve-…)"),
    enrich_cluster: bool = Query(True, description="Atașează context K8s din ZTA list"),
    _identity: Identity = Depends(require_permission(perm.P_SECURITY_READ)),
) -> Dict[str, Any]:
    """Run a Blast Radius query against GUAC and return a tree-shaped JSON
    ready to be rendered by the Vue Tree View component.

    With `enrich_cluster=true` (default), each vulnerable package gets its
    `affectedImages` populated by traversing GUAC's `IsDependency` graph —
    only OCI images whose SBOM declares the vulnerable package land there.
    The frontend uses an `affectedImages.deployments.length > 0` test as
    the "in cluster" signal for the toggle filter, so the response always
    carries the full package list (filtering happens client-side to keep
    the M/N counter honest).

    Errors are surfaced softly: the response always contains
    `vulnerablePackages` (possibly empty) plus an `error` or
    `guacUnavailable` flag so the UI can render a friendly empty state.
    """
    # osv-certifier emits identifiers in three shapes; accept all of them.
    # GUAC stores them lowercased internally, so the regex is lenient
    # on case and the service layer downcases before the GraphQL call.
    import re
    if not cve or not re.match(r"^(cve|ghsa|debian-cve|osv|rhsa|alas|gms)-", cve.strip(), re.IGNORECASE):
        raise HTTPException(
            status_code=400,
            detail="vuln id must look like CVE-…, GHSA-…, or debian-cve-…",
        )

    result = await guac_service.blast_radius_by_cve(cve.strip())
    if enrich_cluster:
        try:
            zta_index = await zta_service.list_zta_applications()
        except Exception:
            zta_index = []
        result = await guac_service.merge_cluster_context(result, zta_index)
    return result
