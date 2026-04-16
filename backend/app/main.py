import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.core.k8s import init_k8s
from app.core.logging import configure_logging
from app.middleware.errors import global_exception_handler
from app.api import drift_routes, integrity_routes, jit_routes, overview_routes, sca_routes, system_routes, zta_routes, zts_routes

configure_logging()
logger = logging.getLogger("zero_trust_backend")

app = FastAPI(
    title="Zero-Trust Kubernetes Dashboard Backend",
    description="Backend API communicare directă cu resursele Custom (CRDs) JIT, ZTA, ZTS",
    version="1.0.0"
)

# Adaugă middleware-ul de erori logic curat
app.add_exception_handler(Exception, global_exception_handler)

@app.middleware("http")
async def require_identity_header(request: Request, call_next):
    trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.trace_id = trace_id
    start_time = time.perf_counter()

    # Domiciliat temporar deschis: bypass complet de autentificare (până când OIDC va fi reactivat)
    # Totuși, injectăm o identitate de mock pentru componentele JIT care se bazează pe acest email
    email = request.headers.get("X-Forwarded-Email", "admin@devsecops.licenta.ro")
    
    # Suprascriem headers-urile temporar
    from starlette.datastructures import MutableHeaders
    new_headers = MutableHeaders(request.headers)
    new_headers["X-Forwarded-Email"] = email
    new_headers["X-Request-ID"] = trace_id
    request._headers = new_headers
    request.scope.update(headers=request.headers.raw)

    logger.info(
        f"[{trace_id}] Incoming request {request.method} {request.url.path}",
        extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "details": {"query": dict(request.query_params)}},
    )

    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    response.headers["X-Request-ID"] = trace_id
    logger.info(
        f"[{trace_id}] Completed {request.method} {request.url.path} -> {response.status_code} in {duration_ms}ms",
        extra={
            "trace_id": trace_id,
            "path": request.url.path,
            "method": request.method,
            "status_code": response.status_code,
            "details": {"durationMs": duration_ms},
        },
    )
    return response

@app.on_event("startup")
async def startup_event():
    # Inițializează clientul k8s async la pornirea serverului.
    logger.info("Initializing Kubernetes async client")
    await init_k8s()
    logger.info("Kubernetes async client initialized successfully")

@app.get("/api/v1/health", tags=["System"])
async def health_check():
    return {"status": "ok", "component": "backend", "logging": "enabled"}

@app.get("/api/v1/auth/me", tags=["System"])
async def get_current_user(request: Request):
    email = request.headers.get("X-Forwarded-Email", "admin@devsecops.licenta.ro")
    return {"email": email, "roles": ["admin"]}

app.include_router(jit_routes.router, prefix="/api/v1/jit", tags=["JIT Access Module"])
app.include_router(zta_routes.router, prefix="/api/v1/zta", tags=["ZTA Controller Module"])
app.include_router(zts_routes.router, prefix="/api/v1/zts", tags=["Zero-Trust Secret Delegation"])
app.include_router(sca_routes.router, prefix="/api/v1/sca", tags=["Supply Chain Attestations"])
app.include_router(drift_routes.router, prefix="/api/v1/drift", tags=["ZTA Drift Analyzer"])
app.include_router(overview_routes.router, prefix="/api/v1/overview", tags=["Cluster Security Pulse"])
app.include_router(integrity_routes.router, prefix="/api/v1/integrity", tags=["Software Integrity"])
app.include_router(system_routes.router, prefix="/api/v1/system", tags=["Observability"])