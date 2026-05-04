from fastapi import APIRouter, HTTPException, Request
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from app.services import jit_service
from app.services.jit_admin_service import get_jit_analytics, get_jit_policies, update_jit_policies
from app.services import k8s_jit_service
from app.middleware.errors import ZeroTrustException

router = APIRouter()

class JitCreateIn(BaseModel):
    namespace: str = Field("default", title="Numele namespace-ului destinație")
    role: str = Field(..., title="Rolul JIT cerut")
    duration: int = Field(60, ge=5, le=120)


class AntiAbuseIn(BaseModel):
    maxActiveSessions: int = Field(1, ge=1)
    cooldownMinutes: int = Field(15, ge=0)
    maxRequestsPerDay: int = Field(5, ge=1)
    maxDurationMinutes: int = Field(120, ge=5)


class JitPoliciesIn(BaseModel):
    blockedUsers: list[str] = Field(default_factory=list)
    antiAbuse: AntiAbuseIn = Field(default_factory=AntiAbuseIn)

@router.get("/sessions", response_model=List[Dict[str, Any]])
async def get_all_jit_requests(request: Request):
    items = await jit_service.list_jit_requests()
    return items


@router.get("/analytics", response_model=Dict[str, Any])
async def get_jit_anti_abuse_analytics() -> Dict[str, Any]:
    return await get_jit_analytics()


@router.get("/policies", response_model=Dict[str, Any])
async def get_jit_policy_config() -> Dict[str, Any]:
    return await get_jit_policies()


@router.put("/policies", response_model=Dict[str, Any])
async def update_jit_policy_config(data: JitPoliciesIn) -> Dict[str, Any]:
    return await update_jit_policies(
        {
            "blockedUsers": data.blockedUsers,
            "antiAbuse": data.antiAbuse.model_dump(),
        }
    )

@router.post("/request", response_model=Dict[str, Any])
async def create_jit_session(data: JitCreateIn, request: Request):
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="Header-ul de identitate X-Forwarded-Email lipsește. Acces interzis.")

    import uuid

    name = f"jit-{uuid.uuid4().hex[:6]}"

    res = await jit_service.create_jit_request(
        namespace=data.namespace,
        name=name,
        user_email=email,
        duration=data.duration,
        role=data.role
    )
    return res


@router.get("/request/{namespace}/{name}", response_model=Dict[str, Any])
async def get_jit_request_single(namespace: str, name: str, request: Request):
    """Fetch a single JITAccessRequest CRD by namespace/name."""
    try:
        res = await k8s_jit_service.get_jit_request(namespace=namespace, name=name)
        return {"status": "success", "request": res}
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"JIT request not found: {e}")

@router.delete("/revoke/{namespace}/{name}")
async def revoke_jit_session(namespace: str, name: str, request: Request):
    await jit_service.revoke_jit_access(namespace, name)
    return {"status": "success", "message": f"{name} a fost revocat cu succes."}


@router.get("/sessions/aggregate", response_model=Dict[str, Any])
async def aggregate_jit_sessions(request: Request):
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

class WebJitCreateIn(BaseModel):
    app_name: str = Field(..., title="Numele aplicatiei web (ex: demo-api)")
    duration: int = Field(60, ge=5, le=480, title="Durata accesului web in minute")

@router.post("/web/request", response_model=Dict[str, Any])
async def create_web_jit_session(data: WebJitCreateIn, request: Request):
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="Missing X-Forwarded-Email header.")

    success = kc_grant(email, data.app_name)
    if not success:
        raise HTTPException(status_code=500, detail="Eroare la adaugarea utilizatorului in Keycloak JIT group.")

    # Inregistram expirarea
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
async def revoke_web_jit_session(app_name: str, request: Request):
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="Header lipsa.")

    cache_key = f"webjit:{email}:{app_name}"
    
    success = kc_revoke(email, app_name)
    if success:
        delete_state(cache_key)
        
    return {"status": "success", "message": f"Acces web revocat manual pentru {app_name}."}

from app.core.k8s import get_networking_api
from app.services.keycloak_service import _get_admin

@router.get("/web/apps", response_model=Dict[str, Any])
async def list_web_apps():
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
async def list_iam_users():
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
async def list_iam_groups():
    """List all groups in the realm"""
    from app.services.keycloak_service import list_all_groups
    groups = list_all_groups()
    return {"status": "success", "groups": groups}

@router.post("/iam/groups", response_model=Dict[str, Any])
async def create_iam_group(data: GroupCreateIn):
    """Create a new group in Keycloak"""
    from app.services.keycloak_service import create_group_keycloak
    group_id = create_group_keycloak(data.name, data.description)
    return {"status": "success", "group_id": group_id, "name": data.name}


@router.put("/iam/groups/{group_id}", response_model=Dict[str, Any])
async def update_iam_group(group_id: str, data: GroupUpdateIn):
    """Update group name/description"""
    from app.services.keycloak_service import update_group_keycloak
    success = update_group_keycloak(group_id, data.name, data.description)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found or update failed")
    return {"status": "success", "group_id": group_id}


@router.delete("/iam/groups/{group_id}", response_model=Dict[str, Any])
async def delete_iam_group(group_id: str):
    """Delete group by ID"""
    from app.services.keycloak_service import delete_group_keycloak
    success = delete_group_keycloak(group_id)
    if not success:
        raise HTTPException(status_code=404, detail="Group not found or delete failed")
    return {"status": "success", "group_id": group_id}

@router.get("/iam/users/{user_id}/groups", response_model=Dict[str, Any])
async def list_user_groups(user_id: str):
    """List all groups a user belongs to"""
    from app.services.keycloak_service import get_user_groups
    groups = get_user_groups(user_id)
    return {"status": "success", "groups": groups}

@router.put("/iam/users/{user_id}/groups/{group_id}", response_model=Dict[str, Any])
async def add_user_to_group(user_id: str, group_id: str):
    """Add a user to a group"""
    from app.services.keycloak_service import add_user_to_group_keycloak
    success = add_user_to_group_keycloak(user_id, group_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add user to group")
    return {"status": "success", "message": f"User {user_id} added to group {group_id}"}

@router.delete("/iam/users/{user_id}/groups/{group_id}", response_model=Dict[str, Any])
async def remove_user_from_group(user_id: str, group_id: str):
    """Remove a user from a group"""
    from app.services.keycloak_service import remove_user_from_group_keycloak
    success = remove_user_from_group_keycloak(user_id, group_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove user from group")
    return {"status": "success", "message": f"User {user_id} removed from group {group_id}"}


@router.put("/iam/users/{user_id}/status", response_model=Dict[str, Any])
async def update_iam_user_status(user_id: str, data: UserStatusIn):
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
async def list_jit_sessions_state(request: Request):
    """List all active JIT sessions with their state"""
    from app.services.jit_state_service import get_active_sessions
    sessions = get_active_sessions()
    return {"status": "success", "sessions": sessions}

@router.post("/sessions/{session_id}/approve", response_model=Dict[str, Any])
async def approve_jit_session(session_id: str, request: Request):
    """Approve a PENDING JIT session (admin only)"""
    approver = request.headers.get("X-Forwarded-Email")
    from app.services.jit_state_service import approve_session
    success = approve_session(session_id, approver)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or not in PENDING state")
    return {"status": "success", "message": f"Session {session_id} approved"}

@router.delete("/sessions/{session_id}/revoke", response_model=Dict[str, Any])
async def revoke_jit_session_explicit(session_id: str, request: Request):
    """Revoke an active JIT session"""
    revoker = request.headers.get("X-Forwarded-Email")
    from app.services.jit_state_service import revoke_session_explicit
    success = revoke_session_explicit(session_id, revoker)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found or already expired")
    return {"status": "success", "message": f"Session {session_id} revoked"}

@router.get("/sessions/stats", response_model=Dict[str, Any])
async def get_jit_sessions_stats():
    """Get statistics on JIT sessions"""
    from app.services.jit_state_service import get_session_stats
    stats = get_session_stats()
    return {"status": "success", "stats": stats}