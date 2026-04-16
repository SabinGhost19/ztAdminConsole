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