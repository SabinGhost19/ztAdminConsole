from fastapi import APIRouter, Header, Depends
from pydantic import BaseModel, Field
from typing import List, Optional
from app.services.sca_service import list_sca_policies, create_sca_policy, delete_sca_policy

router = APIRouter()

class ScaCreateIn(BaseModel):
    name: str
    zta_name: str
    zta_namespace: str
    trusted_issuers: List[str]
    enforce_sbom: bool = True
    on_policy_drift: str = "Isolate"

@router.get("/")
async def get_all_scas():
    # Extrage direct resuresele SupplyChainAttestation
    return await list_sca_policies()

@router.post("/")
async def create_sca(
    payload: ScaCreateIn,
    x_forwarded_email: str = Header(None, alias="X-Forwarded-Email")
):
    owner = x_forwarded_email or "admin@licenta.ro"
    res = await create_sca_policy(
        name=payload.name,
        zta_name=payload.zta_name,
        zta_namespace=payload.zta_namespace,
        trusted_issuers=payload.trusted_issuers,
        enforce_sbom=payload.enforce_sbom,
        on_policy_drift=payload.on_policy_drift,
        user_email=owner
    )
    return {"status": "created", "resource": res}

@router.delete("/{name}")
async def remove_sca(name: str):
    await delete_sca_policy(name)
    return {"status": "deleted"}
