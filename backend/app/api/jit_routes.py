from fastapi import APIRouter, HTTPException, Request
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from app.services import jit_service
from app.services.jit_admin_service import get_jit_analytics, get_jit_policies, update_jit_policies

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

@router.delete("/revoke/{namespace}/{name}")
async def revoke_jit_session(namespace: str, name: str, request: Request):
    await jit_service.revoke_jit_access(namespace, name)
    return {"status": "success", "message": f"{name} a fost revocat cu succes."}

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
    admin = _get_admin()
    users = admin.get_users()
    return {"status": "success", "users": users}