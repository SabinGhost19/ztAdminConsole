from fastapi import APIRouter, Header
from pydantic import BaseModel, Field
from typing import Any, Dict, List

from app.services.sca_service import list_sca_policies, create_sca_policy, delete_sca_policy

router = APIRouter()

class ScaCreateIn(BaseModel):
    name: str = Field(..., title="Numele politicii SCA")
    sourceValidation: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    vulnerabilityPolicy: Dict[str, Any] = Field(default_factory=dict)
    sbomPolicy: Dict[str, Any] = Field(default_factory=dict)
    policyBinding: Dict[str, Any] = Field(default_factory=dict)
    strictManifestHash: Dict[str, Any] = Field(default_factory=dict)
    runtimeEnforcement: Dict[str, Any] = Field(default_factory=dict)

@router.get("/")
async def get_all_scas():
    return await list_sca_policies()

@router.post("/")
async def create_sca(
    payload: ScaCreateIn,
    x_forwarded_email: str = Header(None, alias="X-Forwarded-Email")
):
    owner = x_forwarded_email or "admin@licenta.ro"
    res = await create_sca_policy(
        name=payload.name,
        user_email=owner,
        source_validation=payload.sourceValidation,
        provenance=payload.provenance,
        vulnerability_policy=payload.vulnerabilityPolicy,
        sbom_policy=payload.sbomPolicy,
        policy_binding=payload.policyBinding,
        strict_manifest_hash=payload.strictManifestHash,
        runtime_enforcement=payload.runtimeEnforcement,
    )
    return {"status": "created", "resource": res}

@router.delete("/{name}")
async def remove_sca(name: str):
    await delete_sca_policy(name)
    return {"status": "deleted"}
