from fastapi import APIRouter, HTTPException, Request
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from app.services import zts_service

router = APIRouter()


class RefIn(BaseModel):
    name: str
    namespace: str | None = None


class WorkloadRefIn(BaseModel):
    kind: str
    name: str
    namespace: str | None = None


class SecretStoreRefIn(BaseModel):
    kind: str = "ClusterSecretStore"
    name: str = "vault-backend"


class ZtsCreateIn(BaseModel):
    name: str = Field(..., title="Numele resursei ZeroTrustSecret", max_length=63)
    namespace: str = Field("default", title="Locația de target")
    applicationRef: RefIn = Field(..., title="Referința către ZeroTrustApplication")
    targetWorkload: WorkloadRefIn = Field(..., title="Workload-ul unde se injectează secretul")
    secretStoreRef: SecretStoreRefIn = Field(default_factory=SecretStoreRefIn, title="Referința către Secret Store")
    targetSecretName: str = Field(..., title="Numele Secretului target generat în cluster")
    secretData: Dict[str, Any] = Field(..., title="Maparea secretelor remote către workload")
    zeroTrustConditions: Dict[str, Any] = Field(default_factory=dict, title="Condiții de trust gating")
    lifecycle: Dict[str, Any] = Field(default_factory=dict, title="Lifecycle și rotație")

@router.get("/", response_model=List[Dict[str, Any]])
async def list_zts_secrets(request: Request):
    return await zts_service.list_zts_secrets()

@router.post("/", response_model=Dict[str, Any])
async def create_zts_secret(data: ZtsCreateIn, request: Request):
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="X-Forwarded-Email missing. Access interzis.")

    res = await zts_service.create_zts_secret(
        namespace=data.namespace,
        name=data.name,
        user_email=email,
        application_ref=data.applicationRef.model_dump(exclude_none=True),
        target_workload=data.targetWorkload.model_dump(exclude_none=True),
        secret_store_ref=data.secretStoreRef.model_dump(exclude_none=True),
        target_secret_name=data.targetSecretName,
        secret_data=data.secretData,
        zero_trust_conditions=data.zeroTrustConditions,
        lifecycle=data.lifecycle,
    )
    return res

@router.delete("/{namespace}/{name}")
async def delete_zts_secret(namespace: str, name: str, request: Request):
    await zts_service.delete_zts_secret(namespace, name)
    return {"status": "success", "message": f"{name} a fost șters! Toate referințele Vault delegate sunt curățate."}