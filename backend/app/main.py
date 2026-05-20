import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.core.k8s import close_k8s, init_k8s
from app.core.logging import configure_logging
from app.core.state_db import close_state_db, init_state_db
from app.middleware.errors import global_exception_handler
from app.api import (
    auth_routes,
    breakglass_routes,
    drift_routes,
    guac_routes,
    integrity_routes,
    jit_routes,
    overview_routes,
    sca_routes,
    system_routes,
    zta_routes,
    zts_routes,
)
from app.security.identity import get_auth_config, optional_identity_with_error

configure_logging()
logger = logging.getLogger("zero_trust_backend")

app = FastAPI(
    title="Zero-Trust Kubernetes Dashboard Backend",
    description="Backend API communicare directă cu resursele Custom (CRDs) JIT, ZTA, ZTS",
    version="1.0.0"
)

# Adaugă middleware-ul de erori logic curat
app.add_exception_handler(Exception, global_exception_handler)

# Routes that may be reached without a valid Bearer token. Anything else
# requires authentication via the require_identity middleware below, which
# itself defers the verdict to FastAPI dependencies (so individual routes
# can opt out by being on this list).
## (method, path-or-prefix) tuples. Method "*" matches any verb. Trailing
## "/*" means "any subpath".  Order matters: first match wins.
PUBLIC_ROUTES = (
    ("*", "/api/v1/health"),
    ("*", "/api/v1/auth/config"),
    ("*", "/api/v1/auth/permissions"),
    # Agent-side ingestion endpoints. Authenticated separately via the
    # optional bearer token configured in the ebpf-honeypot Helm chart
    # (auditForwarder.bearerTokenSecret).
    ("POST", "/api/v1/breakglass/audit"),
    ("POST", "/api/v1/breakglass/heartbeat"),
    ("*", "/docs"),
    ("*", "/docs/*"),
    ("*", "/openapi.json"),
    ("*", "/redoc"),
    ("*", "/redoc/*"),
)


def _is_public(method: str, path: str) -> bool:
    method = method.upper()
    for m, pattern in PUBLIC_ROUTES:
        if m != "*" and m != method:
            continue
        if pattern.endswith("/*"):
            base = pattern[:-2]
            if path == base or path.startswith(base + "/"):
                return True
        else:
            if path == pattern:
                return True
    return False


@app.middleware("http")
async def require_identity_header(request: Request, call_next):
    trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.trace_id = trace_id
    start_time = time.perf_counter()

    cfg = get_auth_config()
    path = request.url.path

    # Resolve identity once. For public routes we still try (so handlers
    # can know the caller if they want to), but failures are ignored.
    identity, auth_error_reason = optional_identity_with_error(request)

    if not identity and not _is_public(request.method, path) and not cfg.bypass:
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
        has_bearer_header = bool(auth_header and auth_header.lower().startswith("bearer "))
        # Fail fast with a structured 401; the SPA will redirect to login.
        logger.info(
            f"[{trace_id}] 401 unauthenticated for {request.method} {path}: {auth_error_reason or 'unknown'}",
            extra={
                "trace_id": trace_id,
                "path": path,
                "method": request.method,
                "details": {
                    "hasAuthorizationHeader": bool(auth_header),
                    "hasBearerPrefix": has_bearer_header,
                    "authErrorReason": auth_error_reason or "unknown",
                },
            },
        )
        return JSONResponse(
            status_code=401,
            content={
                "error_code": "UNAUTHENTICATED",
                "message": "Authentication required.",
                "trace_id": trace_id,
                "request_path": path,
                "request_method": request.method,
            },
            headers={"X-Request-ID": trace_id},
        )

    # For backward-compat with routes that still read X-Forwarded-Email,
    # propagate the email from the verified identity. Defence-in-depth:
    # we OVERWRITE any pre-existing X-Forwarded-Email header coming from
    # the client because Keycloak is now the only source of truth.
    from starlette.datastructures import MutableHeaders
    new_headers = MutableHeaders(request.headers)
    new_headers["X-Request-ID"] = trace_id
    if identity:
        new_headers["X-Forwarded-Email"] = identity.email
    elif cfg.bypass:
        new_headers["X-Forwarded-Email"] = cfg.bypass_email
    elif "X-Forwarded-Email" in new_headers:
        # No identity but header set client-side: drop it (anti-spoof).
        del new_headers["X-Forwarded-Email"]
    request._headers = new_headers
    request.scope.update(headers=request.headers.raw)

    logger.info(
        f"[{trace_id}] Incoming request {request.method} {path} (auth={'yes' if identity else 'public'})",
        extra={"trace_id": trace_id, "path": path, "method": request.method,
               "details": {"query": dict(request.query_params),
                           "user": (identity.email if identity else None),
                           "groups": (identity.groups if identity else None)}},
    )

    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    response.headers["X-Request-ID"] = trace_id
    logger.info(
        f"[{trace_id}] Completed {request.method} {path} -> {response.status_code} in {duration_ms}ms",
        extra={
            "trace_id": trace_id,
            "path": path,
            "method": request.method,
            "status_code": response.status_code,
            "details": {"durationMs": duration_ms},
        },
    )
    return response

import asyncio
from datetime import datetime, timezone
from app.services.keycloak_service import revoke_jit_access as kc_revoke
from app.core.state_db import list_state_by_type, delete_state as _delete_state

background_tasks = set()

async def jit_gc_task():
    while True:
        try:
            now = datetime.now(timezone.utc)
            for session in list_state_by_type("web_jit_session"):
                expires_at_str = session.get("expires_at")
                if not expires_at_str:
                    continue
                if now >= datetime.fromisoformat(expires_at_str):
                    email = session.get("email", "")
                    app_name = session.get("app_name", "")
                    cache_key = f"webjit:{email}:{app_name}"
                    logger.info(f"Web JIT session {cache_key} expired. Revoking...")
                    kc_revoke(email, app_name)
                    _delete_state(cache_key)
        except Exception as e:
            logger.error(f"Eroare in JIT GC task: {e}")

        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    # Inițializează clientul k8s async la pornirea serverului.
    logger.info("Initializing Kubernetes async client")
    await init_k8s()
    init_state_db()
    logger.info("Initialized in-memory SQLite state cache")

    from app.services.breakglass_service import configure_from_env
    configure_from_env()
    logger.info("Break-glass service configured")

    # Initialize background scheduler for periodic tasks
    from app.core.background_tasks import init_background_scheduler
    init_background_scheduler()
    
    logger.info("Kubernetes async client initialized successfully")
    
    # Start garbage collection background task
    task = asyncio.create_task(jit_gc_task())
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Closing Kubernetes async client")
    await close_k8s()
    close_state_db()
    logger.info("Closed in-memory SQLite state cache")
    
    # Shutdown background scheduler
    from app.core.background_tasks import shutdown_background_scheduler
    shutdown_background_scheduler()
    
    logger.info("Kubernetes async client closed successfully")

@app.get("/api/v1/health", tags=["System"])
async def health_check():
    return {"status": "ok", "component": "backend", "logging": "enabled"}

from fastapi import Depends as _Depends
from app.security.identity import require_permission as _req
from app.security import permissions as _p

app.include_router(auth_routes.router, prefix="/api/v1/auth", tags=["Authentication"])
# /jit and /breakglass routers carry their own per-route guards because the
# permissions diverge inside the router (read vs write vs revoke).
app.include_router(jit_routes.router, prefix="/api/v1/jit", tags=["JIT Access Module"])
app.include_router(
    zta_routes.router,
    prefix="/api/v1/zta",
    tags=["ZTA Controller Module"],
    dependencies=[_Depends(_req(_p.P_APPS_READ))],
)
app.include_router(
    zts_routes.router,
    prefix="/api/v1/zts",
    tags=["Zero-Trust Secret Delegation"],
    dependencies=[_Depends(_req(_p.P_SECRETS_READ))],
)
app.include_router(
    sca_routes.router,
    prefix="/api/v1/sca",
    tags=["Supply Chain Attestations"],
    dependencies=[_Depends(_req(_p.P_SCA_READ))],
)
app.include_router(
    drift_routes.router,
    prefix="/api/v1/drift",
    tags=["ZTA Drift Analyzer"],
    dependencies=[_Depends(_req(_p.P_SECURITY_READ))],
)
app.include_router(
    overview_routes.router,
    prefix="/api/v1/overview",
    tags=["Cluster Security Pulse"],
    dependencies=[_Depends(_req(_p.P_OVERVIEW_READ))],
)
app.include_router(
    integrity_routes.router,
    prefix="/api/v1/integrity",
    tags=["Software Integrity"],
    dependencies=[_Depends(_req(_p.P_SECURITY_READ))],
)
app.include_router(
    system_routes.router,
    prefix="/api/v1/system",
    tags=["Observability"],
    dependencies=[_Depends(_req(_p.P_SECURITY_READ))],
)
app.include_router(
    guac_routes.router,
    prefix="/api/v1/guac",
    tags=["GUAC Knowledge Graph"],
    dependencies=[_Depends(_req(_p.P_SECURITY_READ))],
)
app.include_router(breakglass_routes.router, prefix="/api/v1/breakglass", tags=["Break-Glass / eBPF Honeypot"])