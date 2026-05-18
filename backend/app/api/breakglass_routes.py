"""HTTP routes for the Break-Glass / eBPF Honeypot module."""

from __future__ import annotations

import logging
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

logger = logging.getLogger("zero_trust_backend.breakglass")

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
    # email claim may be absent when Keycloak token scope is "openid groups"
    # (missing "email" scope or mapper not configured); fall back to
    # preferred_username then sub so the endpoint never returns 400 for a
    # successfully-authenticated user.
    requester = identity.email or identity.preferred_username or identity.subject
    import logging as _log
    _log.getLogger("zero_trust_backend.breakglass").info(
        "issue_token: requester=%r node=%r ttl=%s",
        requester, payload.node, payload.ttl_seconds,
    )
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
async def ingest_audit(payload: AuditEventIn, request: Request) -> Dict[str, Any]:
    ev = payload.dict(exclude_none=False)
    node = ev.get("node") or request.headers.get("X-Forwarded-Node", "unknown")
    action = ev.get("action", "?")
    path = ev.get("path", "?")
    comm = ev.get("comm", "?")
    pid = ev.get("pid", "?")
    logger.info(
        "audit ingest: node=%s action=%s path=%s comm=%s pid=%s",
        node, action, path, comm, pid,
    )
    get_service().ingest_audit(ev)
    return {"status": "ok"}


@router.post("/heartbeat", summary="Ingest heartbeat from agent")
async def ingest_heartbeat(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be an object")
    node = payload.get("node") or request.headers.get("X-Forwarded-Node", "unknown")
    policies = payload.get("policies_loaded", "?")
    mode = payload.get("mode", "?")
    version = payload.get("version", "?")
    fwd = (payload.get("audit_forwarder") or {})
    fwd_url = fwd.get("url", "disabled")
    fwd_dropped = fwd.get("dropped", 0)
    fwd_err = fwd.get("last_err", "")
    logger.info(
        "heartbeat: node=%s mode=%s policies=%s version=%s forwarder_url=%s dropped=%s last_err=%r",
        node, mode, policies, version, fwd_url, fwd_dropped, fwd_err,
    )
    if fwd_dropped and int(fwd_dropped) > 0:
        logger.warning("heartbeat: node=%s has %s dropped audit events", node, fwd_dropped)
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
        policies = await get_service().list_policies()
        return {"status": "success", "policies": policies}
    except Exception as exc:
        return {"status": "error", "detail": str(exc), "policies": []}
