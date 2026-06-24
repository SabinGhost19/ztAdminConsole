import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from typing import Any, AsyncIterator, Dict, List

from pydantic import BaseModel, Field

logger = logging.getLogger("zero_trust_jit_routes")

from app.services import jit_service
from app.services.jit_admin_service import get_jit_analytics, get_jit_policies, update_jit_policies
from app.services import k8s_jit_service
from app.services.jit_kubeconfig import build_jit_kubeconfig
from app.middleware.errors import ZeroTrustException
from app.security.identity import current_user, require_permission, require_any_permission, Identity
from app.security import permissions as perm

router = APIRouter()

class JitCreateIn(BaseModel):
    namespace: str = Field("default", title="Numele namespace-ului destinație")
    role: str = Field(..., title="Rolul JIT cerut")
    # Kubernetes TokenRequest API requires spec.expirationSeconds >= 600 (10 minutes)
    duration: int = Field(60, ge=10, le=120)
    # Operator-facing justification for the access (audit trail). Persisted to
    # spec.reason on the JITAccessRequest CRD instead of a hardcoded placeholder.
    reason: str = Field("", title="Justificarea cererii (audit trail)", max_length=512)


class AntiAbuseIn(BaseModel):
    maxActiveSessions: int = Field(1, ge=1)
    cooldownMinutes: int = Field(15, ge=0)
    maxRequestsPerDay: int = Field(5, ge=1)
    maxDurationMinutes: int = Field(120, ge=5)


class JitPoliciesIn(BaseModel):
    blockedUsers: list[str] = Field(default_factory=list)
    antiAbuse: AntiAbuseIn = Field(default_factory=AntiAbuseIn)

def _owner_of(item: Dict[str, Any]) -> str:
    summary = item.get("summary", {}) or {}
    return str(summary.get("developerId") or "").strip().lower()


def _filter_user_visible(items: List[Dict[str, Any]], email: str) -> List[Dict[str, Any]]:
    """Hide orphan entries (unknown owner) and sessions that don't belong to this user."""
    scoped = (email or "").strip().lower()
    return [
        item for item in items
        if _owner_of(item) and _owner_of(item) != "unknown" and _owner_of(item) == scoped
    ]


@router.get("/sessions", response_model=List[Dict[str, Any]])
async def get_all_jit_requests(
    request: Request,
    identity: Identity = Depends(require_any_permission(perm.P_JIT_READ, perm.P_JIT_READ_LIMITED)),
):
    items = await jit_service.list_jit_requests()
    if perm.P_JIT_READ not in identity.permissions:
        items = _filter_user_visible(items, identity.email or "")
    return items


@router.get("/my-requests", response_model=List[Dict[str, Any]])
async def get_my_jit_requests(
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_READ_OWN)),
):
    """Return only the JIT requests that belong to the calling user."""
    all_items = await jit_service.list_jit_requests()
    return _filter_user_visible(all_items, identity.email or "")


@router.get("/analytics", response_model=Dict[str, Any])
async def get_jit_anti_abuse_analytics(
    identity: Identity = Depends(require_any_permission(perm.P_JIT_READ, perm.P_JIT_READ_LIMITED)),
) -> Dict[str, Any]:
    scope_email = None if perm.P_JIT_READ in identity.permissions else identity.email
    return await get_jit_analytics(user_email=scope_email)


@router.get("/policies", response_model=Dict[str, Any])
async def get_jit_policy_config(
    _identity: Identity = Depends(require_any_permission(perm.P_JIT_READ, perm.P_JIT_READ_LIMITED)),
) -> Dict[str, Any]:
    return await get_jit_policies()


@router.put("/policies", response_model=Dict[str, Any])
async def update_jit_policy_config(
    data: JitPoliciesIn,
    _identity: Identity = Depends(require_permission(perm.P_JIT_POLICY_WRITE)),
) -> Dict[str, Any]:
    return await update_jit_policies(
        {
            "blockedUsers": data.blockedUsers,
            "antiAbuse": data.antiAbuse.model_dump(),
        }
    )

@router.post("/request", response_model=Dict[str, Any])
async def create_jit_session(
    data: JitCreateIn,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_REQUEST)),
):
    import uuid

    name = f"jit-{uuid.uuid4().hex[:6]}"

    user_label = identity.email or identity.preferred_username or identity.subject or "unknown"
    res = await jit_service.create_jit_request(
        namespace=data.namespace,
        name=name,
        user_email=user_label,
        duration=data.duration,
        role=data.role,
        reason=data.reason,
        requires_approval=True,
    )
    return res


@router.post("/request/{namespace}/{name}/approve", response_model=Dict[str, Any])
async def approve_jit_request_endpoint(
    namespace: str,
    name: str,
    identity: Identity = Depends(require_permission(perm.P_JIT_APPROVE)),
) -> Dict[str, Any]:
    """Approve a PENDING_APPROVAL JIT CRD. The operator picks up the status change and provisions the token."""
    approver = identity.email or identity.preferred_username or identity.subject or "unknown"
    payload = await jit_service.approve_jit_request(namespace=namespace, name=name, approver_email=approver)
    return {"status": "success", "approvedBy": approver, "request": payload.get("metadata", {}).get("name")}


@router.get("/request/{namespace}/{name}", response_model=Dict[str, Any])
async def get_jit_request_single(
    namespace: str,
    name: str,
    request: Request,
    _identity: Identity = Depends(require_permission(perm.P_JIT_READ_OWN)),
):
    """Fetch a single JITAccessRequest CRD by namespace/name."""
    try:
        res = await k8s_jit_service.get_jit_request(namespace=namespace, name=name)
        return {"status": "success", "request": res}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"JIT request not found: {e}")


@router.get("/request/{namespace}/{name}/kubeconfig")
async def download_jit_kubeconfig(
    namespace: str,
    name: str,
    identity: Identity = Depends(
        require_any_permission(perm.P_JIT_READ, perm.P_JIT_READ_LIMITED, perm.P_JIT_READ_OWN)
    ),
):
    """Return a self-contained kubeconfig (server + CA + token, NO client cert) for an
    ACTIVE JIT session, so the developer authenticates as the temporary ServiceAccount
    instead of accidentally falling back to their admin client certificate."""
    try:
        item = await k8s_jit_service.get_jit_request(namespace=namespace, name=name)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"JIT request not found: {e}")

    summary = item.get("summary", {}) or {}

    # Non-admins (without P_JIT_READ) may only download their own session.
    if perm.P_JIT_READ not in identity.permissions:
        owner = str(summary.get("developerId") or "").strip().lower()
        if not owner or owner != (identity.email or "").strip().lower():
            raise HTTPException(status_code=403, detail="Not your JIT session")

    if not summary.get("tokenIssued") or str(summary.get("state") or "").upper() != "ACTIVE":
        raise HTTPException(status_code=409, detail="JIT token not ready for this session")

    try:
        body = build_jit_kubeconfig(summary)
    except ValueError as e:
        raise HTTPException(status_code=503, detail=str(e))

    return Response(
        content=body,
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="jit-{name}.yaml"'},
    )


@router.delete("/revoke/{namespace}/{name}")
async def revoke_jit_session(
    namespace: str,
    name: str,
    request: Request,
    _identity: Identity = Depends(require_permission(perm.P_JIT_REVOKE)),
):
    await jit_service.revoke_jit_access(namespace, name)
    return {"status": "success", "message": f"{name} a fost revocat cu succes."}


_DISMISSIBLE_STATES = {"EXPIRED", "REVOKED", "TAMPERED", "REJECTED", "RATE_LIMITED", "QUOTA_EXCEEDED"}


@router.delete("/request/{namespace}/{name}")
async def dismiss_jit_request(
    namespace: str,
    name: str,
    identity: Identity = Depends(require_any_permission(perm.P_JIT_REVOKE, perm.P_JIT_READ_OWN, perm.P_JIT_READ_LIMITED)),
):
    """Delete a completed JIT CRD (cleanup). Non-admins can only dismiss their own
    EXPIRED/REVOKED entries; users with P_JIT_REVOKE can dismiss any state."""
    item = await k8s_jit_service.get_jit_request(namespace=namespace, name=name)
    summary = item.get("summary", {}) or {}
    state = str(summary.get("state") or "").upper()
    owner = str(summary.get("developerId") or "").strip().lower()
    is_admin = perm.P_JIT_REVOKE in identity.permissions
    is_owner = bool(owner) and owner == (identity.email or "").strip().lower()
    if not is_admin:
        if not is_owner:
            raise HTTPException(status_code=403, detail="Not the owner of this JIT request.")
        if state not in _DISMISSIBLE_STATES:
            raise HTTPException(status_code=409, detail=f"Only completed sessions can be dismissed (current: {state}).")
    await jit_service.revoke_jit_access(namespace, name)
    return {"status": "success", "message": f"{name} a fost șters din listă."}


@router.get("/sessions/aggregate", response_model=Dict[str, Any])
async def aggregate_jit_sessions(
    request: Request,
    _identity: Identity = Depends(require_permission(perm.P_JIT_READ)),
):
    """Return aggregated sessions: operator CRD sessions and web JIT sessions from state DB."""
    from app.core.state_db import list_state_by_type

    # CRD-backed sessions
    crd_sessions = await jit_service.list_jit_requests()

    # Web JIT sessions stored in state_db
    web_sessions = list_state_by_type("web_jit_session")

    return {"status": "success", "crd_sessions": crd_sessions, "web_sessions": web_sessions}

# --- Web Ingress JIT Extensions ---

from app.services.keycloak_service import grant_jit_access as kc_grant, revoke_jit_access as kc_revoke
from app.core.state_db import write_state, read_state, delete_state
from datetime import datetime, timedelta, timezone

@router.get("/namespaces", response_model=Dict[str, Any])
async def list_k8s_namespaces(
    _identity: Identity = Depends(require_permission(perm.P_JIT_REQUEST)),
):
    """List all namespaces available for JIT access targeting."""
    from app.core.k8s import get_core_api
    try:
        core = get_core_api()
        ns_list = await core.list_namespace()
        namespaces = sorted(ns.metadata.name for ns in ns_list.items)
    except Exception:
        namespaces = ["default"]
    return {"status": "success", "namespaces": namespaces}


class WebJitCreateIn(BaseModel):
    app_name: str = Field(..., title="Numele aplicatiei web (ex: demo-api)")
    duration: int = Field(60, ge=5, le=480, title="Durata accesului web in minute")

@router.post("/web/request", response_model=Dict[str, Any])
async def create_web_jit_session(
    data: WebJitCreateIn,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_REQUEST)),
):
    email = identity.email

    success = kc_grant(email, data.app_name)
    if not success:
        raise HTTPException(status_code=500, detail="Eroare la adaugarea utilizatorului in Keycloak JIT group.")

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=data.duration)
    cache_key = f"webjit:{email}:{data.app_name}"

    write_state(
        cache_key=cache_key,
        payload={"email": email, "app_name": data.app_name, "expires_at": expires_at.isoformat()},
        state_type="web_jit_session",
        namespace="global",
        resource_name=str(data.app_name),
    )

    return {"status": "success", "message": f"Acces web pentru {data.app_name} a fost grantat temporar.", "expires_at": expires_at.isoformat()}

@router.delete("/web/revoke/{app_name}")
async def revoke_web_jit_session(
    app_name: str,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_REQUEST)),
):
    email = identity.email
    cache_key = f"webjit:{email}:{app_name}"

    success = kc_revoke(email, app_name)
    if success:
        delete_state(cache_key)

    return {"status": "success", "message": f"Acces web revocat manual pentru {app_name}."}

from app.core.k8s import get_networking_api
from app.services.keycloak_service import _get_admin

@router.get("/web/apps", response_model=Dict[str, Any])
async def list_web_apps(
    _identity: Identity = Depends(require_permission(perm.P_APPS_READ)),
):
    net = get_networking_api()
    ingresses = await net.list_ingress_for_all_namespaces()
    apps = []
    for item in ingresses.items:
        apps.append({
            "name": item.metadata.name,
            "namespace": item.metadata.namespace,
            "host": item.spec.rules[0].host if item.spec.rules else "unknown"
        })
    return {"status": "success", "apps": apps}

@router.get("/iam/users", response_model=Dict[str, Any])
async def list_iam_users(
    _identity: Identity = Depends(require_permission(perm.P_IAM_READ)),
):
    try:
        admin = _get_admin()
        users = admin.get_users()
        return {"status": "success", "users": users}
    except Exception as exc:
        raise ZeroTrustException(
            error_code="KEYCLOAK_LIST_USERS_FAILED",
            message="Nu pot lista utilizatorii din Keycloak.",
            technical_details=str(exc),
            component="KEYCLOAK_ADMIN",
            action_required="Verifica client credentials si conectivitatea la Keycloak.",
        )

# --- Phase 4b: IAM Groups Management ---

class GroupCreateIn(BaseModel):
    name: str = Field(..., title="Numelul grupului (ex: jit-access-database)")
    description: str = Field("", title="Descrierea grupului")


class GroupUpdateIn(BaseModel):
    name: str | None = Field(None, title="Nume nou pentru grup")
    description: str | None = Field(None, title="Descriere noua pentru grup")


class UserStatusIn(BaseModel):
    enabled: bool = Field(..., title="Activeaza sau dezactiveaza utilizatorul")

class UserGroupAssignIn(BaseModel):
    group_id: str = Field(..., title="ID-ul grupului")

@router.get("/iam/groups", response_model=Dict[str, Any])
async def list_iam_groups(
    _identity: Identity = Depends(require_permission(perm.P_IAM_READ)),
):
    """List all groups in the realm"""
    from app.services.keycloak_service import list_all_groups
    groups = list_all_groups()
    return {"status": "success", "groups": groups}

@router.post("/iam/groups", response_model=Dict[str, Any])
async def create_iam_group(
    data: GroupCreateIn,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Create a new group in Keycloak"""
    from app.services.keycloak_service import create_group_keycloak
    group_id = create_group_keycloak(data.name, data.description)
    return {"status": "success", "group_id": group_id, "name": data.name}


@router.put("/iam/groups/{group_id}", response_model=Dict[str, Any])
async def update_iam_group(
    group_id: str,
    data: GroupUpdateIn,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Update group name/description"""
    from app.services.keycloak_service import update_group_keycloak
    success = update_group_keycloak(group_id, data.name, data.description)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found or update failed")
    return {"status": "success", "group_id": group_id}


@router.delete("/iam/groups/{group_id}", response_model=Dict[str, Any])
async def delete_iam_group(
    group_id: str,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Delete group by ID"""
    from app.services.keycloak_service import delete_group_keycloak
    success = delete_group_keycloak(group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found or delete failed")
    return {"status": "success", "group_id": group_id}

@router.get("/iam/users/{user_id}/groups", response_model=Dict[str, Any])
async def list_user_groups(
    user_id: str,
    _identity: Identity = Depends(require_permission(perm.P_IAM_READ)),
):
    """List all groups a user belongs to"""
    from app.services.keycloak_service import get_user_groups
    groups = get_user_groups(user_id)
    return {"status": "success", "groups": groups}

@router.put("/iam/users/{user_id}/groups/{group_id}", response_model=Dict[str, Any])
async def add_user_to_group(
    user_id: str,
    group_id: str,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Add a user to a group"""
    from app.services.keycloak_service import add_user_to_group_keycloak
    success = add_user_to_group_keycloak(user_id, group_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add user to group")
    return {"status": "success", "message": f"User {user_id} added to group {group_id}"}

@router.delete("/iam/users/{user_id}/groups/{group_id}", response_model=Dict[str, Any])
async def remove_user_from_group(
    user_id: str,
    group_id: str,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Remove a user from a group"""
    from app.services.keycloak_service import remove_user_from_group_keycloak
    success = remove_user_from_group_keycloak(user_id, group_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove user from group")
    return {"status": "success", "message": f"User {user_id} removed from group {group_id}"}


@router.put("/iam/users/{user_id}/status", response_model=Dict[str, Any])
async def update_iam_user_status(
    user_id: str,
    data: UserStatusIn,
    _identity: Identity = Depends(require_permission(perm.P_IAM_WRITE)),
):
    """Enable/disable a user in Keycloak"""
    from app.services.keycloak_service import update_user_status_keycloak
    success = update_user_status_keycloak(user_id, data.enabled)
    if not success:
        raise HTTPException(status_code=404, detail="User not found or update failed")
    return {"status": "success", "user_id": user_id, "enabled": data.enabled}

# --- Phase 5: JIT Sessions State Machine ---

class JitSessionState(BaseModel):
    session_id: str
    user_email: str
    app_name: str
    state: str  # "PENDING" | "ACTIVE" | "EXPIRED" | "REVOKED"
    requested_at: str  # ISO timestamp
    expires_at: str    # ISO timestamp
    approved_by: str = None  # admin email who approved
    reason: str = None  # revocation reason

@router.get("/sessions/state", response_model=Dict[str, Any])
async def list_jit_sessions_state(
    request: Request,
    _identity: Identity = Depends(require_permission(perm.P_JIT_READ)),
):
    """List all active JIT sessions with their state"""
    from app.services.jit_state_service import get_active_sessions
    sessions = get_active_sessions()
    return {"status": "success", "sessions": sessions}

@router.post("/sessions/{session_id}/approve", response_model=Dict[str, Any])
async def approve_jit_session(
    session_id: str,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_APPROVE)),
):
    """Approve a PENDING JIT session"""
    from app.services.jit_state_service import approve_session
    success = approve_session(session_id, identity.email)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or not in PENDING state")
    return {"status": "success", "message": f"Session {session_id} approved"}

@router.delete("/sessions/{session_id}/revoke", response_model=Dict[str, Any])
async def revoke_jit_session_explicit(
    session_id: str,
    request: Request,
    identity: Identity = Depends(require_permission(perm.P_JIT_REVOKE)),
):
    """Revoke an active JIT session"""
    from app.services.jit_state_service import revoke_session_explicit
    success = revoke_session_explicit(session_id, identity.email)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already expired")
    return {"status": "success", "message": f"Session {session_id} revoked"}

@router.get("/sessions/stats", response_model=Dict[str, Any])
async def get_jit_sessions_stats(
    _identity: Identity = Depends(require_permission(perm.P_JIT_READ)),
):
    """Get statistics on JIT sessions"""
    from app.services.jit_state_service import get_session_stats
    stats = get_session_stats()
    return {"status": "success", "stats": stats}

# --- Phase 6: Real-time SSE stream of JIT CRD changes ---

async def _jit_event_stream(identity: Identity) -> AsyncIterator[str]:
    """Polls /jit/sessions every 2s, emits SSE event when the visible snapshot changes."""
    last_snapshot: str | None = None
    keepalive_ticks = 0
    try:
        while True:
            try:
                items = await jit_service.list_jit_requests()
                if perm.P_JIT_READ not in identity.permissions:
                    items = _filter_user_visible(items, identity.email or "")
                # Compact fingerprint per session — name+state+tokenIssued+expiresAt+approved
                fingerprint = [
                    {
                        "name": (i.get("metadata", {}) or {}).get("name"),
                        "namespace": (i.get("metadata", {}) or {}).get("namespace"),
                        "state": (i.get("summary", {}) or {}).get("state"),
                        "tokenIssued": (i.get("summary", {}) or {}).get("tokenIssued"),
                        "expiresAt": (i.get("summary", {}) or {}).get("expiresAt"),
                        "approved": ((i.get("status", {}) or {}).get("approved")),
                    }
                    for i in items
                ]
                snapshot = json.dumps(fingerprint, sort_keys=True)
                if snapshot != last_snapshot:
                    last_snapshot = snapshot
                    yield f"event: jit.snapshot\ndata: {json.dumps(items)}\n\n"
                    keepalive_ticks = 0
                else:
                    keepalive_ticks += 1
                    if keepalive_ticks >= 15:  # ~30s heartbeat
                        yield ": keepalive\n\n"
                        keepalive_ticks = 0
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("SSE stream tick failed: %s", exc)
                yield f"event: jit.error\ndata: {json.dumps({'message': str(exc)})}\n\n"
            await asyncio.sleep(2)
    except asyncio.CancelledError:
        logger.info("SSE stream cancelled for %s", identity.email)
        return


@router.get("/stream")
async def stream_jit_events(
    identity: Identity = Depends(require_any_permission(perm.P_JIT_READ, perm.P_JIT_READ_LIMITED, perm.P_JIT_READ_OWN)),
) -> StreamingResponse:
    """Server-Sent Events stream of JIT request changes, scoped to the caller's permissions."""
    return StreamingResponse(
        _jit_event_stream(identity),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
