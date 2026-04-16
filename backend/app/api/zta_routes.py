from fastapi import APIRouter, HTTPException, Request
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from app.services import zta_service

router = APIRouter()


class PolicyRefIn(BaseModel):
    name: str


class ZtaCreateIn(BaseModel):
    name: str = Field(..., title="Numele CRD-ului ZTA")
    namespace: str = Field("default", title="Namespace-ul aplicației")
    labels: Dict[str, str] = Field(default_factory=dict, title="Metadate ZTA")
    annotations: Dict[str, str] = Field(default_factory=dict, title="Anotări ZTA")
    image: str = Field(..., title="Imaginea containerului")
    replicas: int = Field(1, ge=1, title="Numărul de replici")
    securityPolicyRef: PolicyRefIn = Field(..., title="Referința explicită către SupplyChainAttestation")
    networkZeroTrust: Dict[str, Any] = Field(default_factory=dict, title="Politicile de ingress/egress zero trust")
    wafConfig: Dict[str, Any] = Field(default_factory=dict, title="Configurația WAF")
    runtimeSecurity: Dict[str, Any] = Field(default_factory=dict, title="Configurația runtime security")

@router.get("/", response_model=List[Dict[str, Any]])
async def list_zta_applications(request: Request):
    return await zta_service.list_zta_applications()

@router.post("/", response_model=Dict[str, Any])
async def create_zta_application(data: ZtaCreateIn, request: Request):
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="X-Forwarded-Email missing. Access interzis.")

    res = await zta_service.create_zta_application(
        namespace=data.namespace,
        name=data.name,
        user_email=email,
        labels=data.labels,
        annotations=data.annotations,
        image=data.image,
        replicas=data.replicas,
        security_policy_ref=data.securityPolicyRef.model_dump(exclude_none=True),
        network_zero_trust=data.networkZeroTrust,
        waf_config=data.wafConfig,
        runtime_security=data.runtimeSecurity,
    )
    return res

@router.delete("/{namespace}/{name}")
async def delete_zta_application(namespace: str, name: str, request: Request):
    await zta_service.delete_zta_application(namespace, name)
    return {"status": "success", "message": f"{name} șters cu succes. ZTA Operator reconciliază rețeaua."}