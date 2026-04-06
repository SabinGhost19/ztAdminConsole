from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from app.core.k8s import init_k8s
from app.middleware.errors import global_exception_handler
from app.api import jit_routes, zta_routes, zts_routes
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
    # Skip pentry docs
    if request.url.path.startswith("/docs") or request.url.path.startswith("/openapi.json"):
        return await call_next(request)
        
    email = request.headers.get("X-Forwarded-Email")
    if not email:
        trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        err = APIErrorDetails(
            error_code="IDENTITY_MISSING",
            message="Acces respins. Identitatea utilizatorului nu a putut fi extrasă.",
            technical_details="Header-ul 'X-Forwarded-Email' injectat de Identity-Aware Proxy (Keycloak) lipsește.",
            component="API_GATEWAY",
            trace_id=trace_id,
            action_required="Asigurați-vă că accesați interfața prin proxy-ul de securitate."
        )
        return JSONResponse(status_code=401, content=err.model_dump())
    
    response = await call_next(request)
    return response

@app.on_event("startup")
async def startup_event():
    # Inițializează clientul k8s async la pornirea serverului.
    await init_k8s()

app.include_router(jit_routes.router, prefix="/api/v1/jit", tags=["JIT Access Module"])
app.include_router(zta_routes.router, prefix="/api/v1/zta", tags=["ZTA Controller Module"])
app.include_router(zts_routes.router, prefix="/api/v1/zts", tags=["Zero-Trust Secret Delegation"])