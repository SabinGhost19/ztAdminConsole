from fastapi import APIRouter, Request, HTTPException
from typing import List, Dict, Any
from app.services import jit_service

router = APIRouter()

# Schema de request pt JIT
from pydantic import BaseModel, Field

class JitCreateIn(BaseModel):
    namespace: str = Field("default", title="Numele namespace-ului destinație")
    role: str = Field(..., title="Rolul JIT cerut")
    duration: int = Field(60, ge=5, le=120)

@router.get("/sessions", response_model=List[Dict[str, Any]])
async def get_all_jit_requests(request: Request):
    """
    Folosește clientul K8s Async pentru a interoga CustomObjectsApi 
    și returnează array-ul de sesiuni convertit pentru UI.
    """
    items = await jit_service.list_jit_requests()
    return items

@router.post("/request", response_model=Dict[str, Any])
async def create_jit_session(data: JitCreateIn, request: Request):
    """
    Mock-ul proxy Oauth2 a validat X-Forwarded-Email la intrare. 
    Trimitem CRD-ul de JITAccessRequest în Kubernetes.
    """
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="Header-ul de identitate X-Forwarded-Email lipsește. Acces interzis.")
    
    # Generăm un nume Random K8s-compliant
    import uuid
    name = f"jit-{uuid.uuid4().hex[:6]}"
    
    # Aici aruncă ApiException 403 dacă user-ului nu-i e permis din via OPA sau un Policy Kyverno validation
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
    """
    Tabelul din UI (Kill Switch) trimite un DELETE pentru a șterge 
    complet CRD-ul curent, ceea ce va invoca logica `kopf.on.delete` a JIT Operator-ului 
    care va trage după sine Token-ul și RoleBinding-ul temporal.
    """
    await jit_service.revoke_jit_access(namespace, name)
    return {"status": "success", "message": f"{name} a fost revocat cu succes."}