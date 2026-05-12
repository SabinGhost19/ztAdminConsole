"""HTTP routes for the Break-Glass / eBPF Honeypot module."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.security.identity import Identity, current_user, require_permission
from app.security import permissions as perm
from app.services.breakglass_service import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    get_service,
)
from app.core.k8s_client import get_k8s_client

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class IssueTokenIn(BaseModel):
    node: str = Field(..., description="Target node name (will be enforced as JWT audience)")
    reason: str = Field(default="", description="Free-form justification for the audit log")
    ttl_seconds: int = Field(
        default=DEFAULT_TTL_SECONDS,
        ge=60,
        le=MAX_TTL_SECONDS,
        description="Requested token lifetime in seconds",
    )


class IssueTokenOut(BaseModel):
    jti: str
    node: str
    requester: str
    approver: str
    reason: str
    ttl_seconds: int
    issued_at: str
    expires_at: str
    state: str
    token: str


class SessionOut(BaseModel):
    jti: str
    node: str
    requester: str
    approver: str
    reason: str
    ttl_seconds: int
    issued_at: str
    expires_at: str
    state: str
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None


class AuditEventIn(BaseModel):
    """Loose schema. The agent forwards the kernel ringbuf record verbatim."""

    event: Optional[str] = None
    ts_ns: Optional[int] = None
    pid: Optional[int] = None
    tgid: Optional[int] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    action: Optional[str] = None
    dev: Optional[int] = None
    ino: Optional[int] = None
    path: Optional[str] = None
    comm: Optional[str] = None
    pcomm: Optional[str] = None
    node: Optional[str] = None

    class Config:
        extra = "allow"


# ---------------------------------------------------------------------------
# Token / session management
# ---------------------------------------------------------------------------
@router.post("/sessions", response_model=IssueTokenOut, summary="Issue break-glass JWT")
async def issue_token(
    payload: IssueTokenIn,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_ISSUE)),
) -> IssueTokenOut:
    requester = identity.email
    svc = get_service()
    try:
        sess = svc.issue_token(
            node=payload.node,
            requester=requester,
            approver=requester,
            reason=payload.reason,
            ttl_seconds=payload.ttl_seconds,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    out = sess.to_dict(include_token=True)
    return IssueTokenOut(**out)


@router.get("/sessions", response_model=Dict[str, Any], summary="List sessions")
async def list_sessions(
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    return {"status": "success", "sessions": get_service().list_sessions()}


@router.get("/sessions/{jti}", response_model=SessionOut, summary="Get session by jti")
async def get_session(
    jti: str,
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> SessionOut:
    sess = get_service().get_session(jti)
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    return SessionOut(**sess)


@router.delete("/sessions/{jti}", response_model=Dict[str, Any], summary="Revoke session")
async def revoke_session(
    jti: str,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_REVOKE)),
) -> Dict[str, Any]:
    sess = get_service().revoke_session(jti, identity.email)
    if not sess:
        raise HTTPException(status_code=404, detail="session not found")
    return {"status": "success", "session": sess.to_dict()}


# ---------------------------------------------------------------------------
# Agent ingress (DaemonSet pushes here)
# ---------------------------------------------------------------------------
@router.post("/audit", summary="Ingest audit event from agent")
async def ingest_audit(payload: AuditEventIn) -> Dict[str, Any]:
    get_service().ingest_audit(payload.dict(exclude_none=False))
    return {"status": "ok"}


@router.post("/heartbeat", summary="Ingest heartbeat from agent")
async def ingest_heartbeat(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be an object")
    get_service().ingest_heartbeat(payload)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Read-only views for the dashboard
# ---------------------------------------------------------------------------
@router.get("/audit", summary="List audit events")
async def list_audit(
    limit: int = 200,
    node: Optional[str] = None,
    action: Optional[str] = None,
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    items = get_service().list_audit(limit=limit, node=node, action=action)
    return {"status": "success", "events": items, "count": len(items)}


@router.get("/nodes", summary="List node agents")
async def list_nodes(
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    return {"status": "success", "nodes": get_service().list_heartbeats()}


@router.get("/analytics", summary="Aggregated analytics")
async def analytics(
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    return {"status": "success", "analytics": get_service().analytics()}


@router.get("/public-key", summary="Expose Ed25519 public key (PEM)")
async def public_key(
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    return {
        "status": "success",
        "format": "PEM",
        "public_key": get_service().public_key_pem(),
    }


@router.get("/policies", summary="List NodeProtectionPolicy CRD resources")
async def list_policies(
    _identity: Identity = Depends(require_permission(perm.P_BREAKGLASS_READ)),
) -> Dict[str, Any]:
    try:
        k8s_client = get_k8s_client()
        policies = await get_service().list_policies(k8s_client)
        return {"status": "success", "policies": policies}
    except Exception as exc:
        return {"status": "error", "detail": str(exc), "policies": []}
