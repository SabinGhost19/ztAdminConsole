from fastapi import APIRouter, Request, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.services import zts_service
from app.middleware.errors import ZeroTrustException

router = APIRouter()

class ZtsCreateIn(BaseModel):
    name: str = Field(..., title="Numele resursei ZeroTrustSecret", max_length=63)
    namespace: str = Field("default", title="Locația de target")
    vault_path: str = Field(..., title="Calea în HashiCorp Vault")
    target_secret: str = Field(..., title="Numele Secretului target generat în cluster")
    rotation_interval: str = Field("1h", title="Interval de rotație (ex. '15m', '1h')")

@router.get("/", response_model=List[Dict[str, Any]])
async def list_zts_secrets(request: Request):
    """
    Lista completă a obiectelor ZeroTrustSecret pe toți namespaces (if admin) sau a celor autorizate.
    Erorile sunt complet gestionate în ZTS Service și prinse de Middleware-ul Global FastAPI.
    """
    return await zts_service.list_zts_secrets()

@router.post("/", response_model=Dict[str, Any])
async def create_zts_secret(data: ZtsCreateIn, request: Request):
    """
    Acțiune: Declansază operatorul ZTA să investigheze policy/semnăturile unei aplicații destinație.
    Doar dacă Operatorul lasă cererea să treacă, va emite un 'ExternalSecret' care cere efectiv de la Vault secretul via ESO.
    """
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        trace_id = request.headers.get("X-Request-ID", "N/A")
        # Eșec grav, proxy-ul a scăpat header-ul (nu ar trebui să se întâmple cu OAuth2).
        raise ZeroTrustException(
            error_code="MISSING_IDENTITY_ZTS",
            message="Cererea pentru noul secret ZTS nu poate fi validată criptografic pentru că lipsește identitatea ta.",
            technical_details="FastAPI MIddleware / Router nu a găsit 'X-Forwarded-Email' în header.",
            component="API_OAUTH2_PROXY",
            trace_id=trace_id,
            action_required="Autentificati-vă prin IAP (Identity-Aware Proxy)."
        )
    
    res = await zts_service.create_zts_secret(
        namespace=data.namespace,
        name=data.name,
        user_email=email,
        vault_path=data.vault_path,
        target_secret=data.target_secret,
        rotation_interval=data.rotation_interval
    )
    return res

@router.delete("/{namespace}/{name}")
async def delete_zts_secret(namespace: str, name: str, request: Request):
    """
    Prin ștergerea acestei resurse, Operatorul ZTA va face curățenie (Garbage Collector) 
    inclusiv pe obiectele ExternalSecret din spate. Toate secretele expuse în memorie se revoca/scurg.
    """
    await zts_service.delete_zts_secret(namespace, name)
    return {"status": "success", "message": f"{name} a fost șters! Toate referințele Vault delegate sunt curățate."}