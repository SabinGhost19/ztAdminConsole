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


@router.get("/blast-radius", response_model=Dict[str, Any])
async def blast_radius(
    cve: str = Query(..., description="Identificator CVE (ex: CVE-2024-1234)"),
    enrich_cluster: bool = Query(True, description="Atașează context K8s din ZTA list"),
    _identity: Identity = Depends(require_permission(perm.P_SECURITY_READ)),
) -> Dict[str, Any]:
    """Run a Blast Radius query against GUAC and return a tree-shaped JSON
    ready to be rendered by the Vue Tree View component.

    Errors are surfaced softly: the response always contains
    `vulnerablePackages` (possibly empty) plus an `error` or
    `guacUnavailable` flag so the UI can render a friendly empty state.
    """
    if not cve or not cve.upper().startswith("CVE-"):
        raise HTTPException(status_code=400, detail="cve must look like CVE-YYYY-NNNN")

    result = await guac_service.blast_radius_by_cve(cve.strip())
    if enrich_cluster:
        try:
            zta_index = await zta_service.list_zta_applications()
        except Exception:
            zta_index = []
        result = await guac_service.merge_cluster_context(result, zta_index)
    return result
