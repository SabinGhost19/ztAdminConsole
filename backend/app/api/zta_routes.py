from fastapi import APIRouter, Request, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.services import zta_service

router = APIRouter()

class ZtaCreateIn(BaseModel):
    name: str = Field(..., title="Numele CRD-ului ZTA")
    namespace: str = Field("default", title="Locația de target")
    labels: Dict[str, str] = Field(default_factory=dict, title="Metadate ZTA")
    ingress_host: str = Field(..., title="Adresa host pentru Ingress Route")
    image: str = Field(..., title="Imaginea Docker mapată la ZeroTrustApplication")
    networkPolicy: Dict[str, Any] = Field(default_factory=dict, title="Ingress / Egress eBPF Rules pentru ZTA Operator")

@router.get("/", response_model=List[Dict[str, Any]])
async def list_zta_applications(request: Request):
    """
    Citește prin API Kubernetes (async) toate obiectele ZeroTrustApplication (ZTA).
    """
    return await zta_service.list_zta_applications()

@router.post("/", response_model=Dict[str, Any])
async def create_zta_application(data: ZtaCreateIn, request: Request):
    """
    Declanșatorul Operatorului ZTA. 
    Generează CRD-ul de K8s, ceea ce forțează operatorul Pythonic să aloce resursele.
    """
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        raise HTTPException(status_code=401, detail="X-Forwarded-Email missing. Access interzis.")
    
    # Interogarea funcției din serviciu care pasează modelul JSON explicit la apiserver
    res = await zta_service.create_zta_application(
        namespace=data.namespace,
        name=data.name,
        user_email=email,
        labels=data.labels,
        ingress_host=data.ingress_host,
        policy_rules=data.networkPolicy,
        image=data.image
    )
    return res

@router.delete("/{namespace}/{name}")
async def delete_zta_application(namespace: str, name: str, request: Request):
    """
    Șterge resursa declarativă. Operatorul Kubernetes se ocupă de Garbare Collection (OwnerReferences).
    """
    await zta_service.delete_zta_application(namespace, name)
    return {"status": "success", "message": f"{name} șters cu succes. ZTA Operator reconciliază rețeaua."}