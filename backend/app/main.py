from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from app.core.k8s import init_k8s
from app.middleware.errors import global_exception_handler
from app.api import jit_routes, zta_routes, zts_routes, sca_routes, drift_routes
from app.models.jit import APIErrorDetails
import uuid

app = FastAPI(
    title="Zero-Trust Kubernetes Dashboard Backend",
    description="Backend API communicare directă cu resursele Custom (CRDs) JIT, ZTA, ZTS",
    version="1.0.0"
)

# Adaugă middleware-ul de erori logic curat
app.add_exception_handler(Exception, global_exception_handler)

@app.middleware("http")
async def require_identity_header(request: Request, call_next):
    # Domiciliat temporar deschis: bypass complet de autentificare (până când OIDC va fi reactivat)
    # Totuși, injectăm o identitate de mock pentru componentele JIT care se bazează pe acest email
    email = request.headers.get("X-Forwarded-Email", "admin@devsecops.licenta.ro")
    
    # Suprascriem headers-urile temporar
    from starlette.datastructures import MutableHeaders
    new_headers = MutableHeaders(request.headers)
    new_headers["X-Forwarded-Email"] = email
    request._headers = new_headers
    request.scope.update(headers=request.headers.raw)

    response = await call_next(request)
    return response

@app.on_event("startup")
async def startup_event():
    # Inițializează clientul k8s async la pornirea serverului.
    await init_k8s()

@app.get("/api/v1/health", tags=["System"])
async def health_check():
    return {"status": "ok"}

@app.get("/api/v1/auth/me", tags=["System"])
async def get_current_user(request: Request):
    email = request.headers.get("X-Forwarded-Email", "admin@devsecops.licenta.ro")
    return {"email": email, "roles": ["admin"]}

app.include_router(jit_routes.router, prefix="/api/v1/jit", tags=["JIT Access Module"])
app.include_router(zta_routes.router, prefix="/api/v1/zta", tags=["ZTA Controller Module"])
app.include_router(zts_routes.router, prefix="/api/v1/zts", tags=["Zero-Trust Secret Delegation"])
app.include_router(sca_routes.router, prefix="/api/v1/sca", tags=["Supply Chain Attestations"])
app.include_router(drift_routes.router, prefix="/api/v1/drift", tags=["ZTA Drift Analyzer"])