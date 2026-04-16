import uuid
import logging
from datetime import datetime, timezone
from typing import Any
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi import HTTPException
from starlette.responses import JSONResponse
from kubernetes_asyncio.client.exceptions import ApiException
from pydantic import ValidationError
from app.models.jit import APIErrorDetails

logger = logging.getLogger("zero_trust_error_handler")

# ================================
# EXCEPTII COSTUM PENTRU LOGICĂ
# ================================
class ZeroTrustException(Exception):
    def __init__(self, error_code: str, message: str, technical_details: str, component: str, action_required: str):
        self.error_code = error_code
        self.message = message
        self.technical_details = technical_details
        self.component = component
        self.action_required = action_required


def _error_payload(
    request: Request,
    trace_id: str,
    *,
    error_code: str,
    message: str,
    technical_details: str,
    component: str,
    action_required: str,
    status_code: int,
    error_type: str,
    details: dict[str, Any] | None = None,
) -> APIErrorDetails:
    return APIErrorDetails(
        error_code=error_code,
        message=message,
        technical_details=technical_details,
        component=component,
        trace_id=trace_id,
        action_required=action_required,
        status_code=status_code,
        request_method=request.method,
        request_path=request.url.path,
        timestamp=datetime.now(timezone.utc).isoformat(),
        error_type=error_type,
        details=details,
    )

async def global_exception_handler(request: Request, exc: Exception):
    trace_id = request.headers.get("X-Request-ID", getattr(request.state, "trace_id", str(uuid.uuid4())))
    
    # Prinde Pydantic Validation Error (Input gresit form ZTA/JIT builder)
    if isinstance(exc, (ValidationError, RequestValidationError)):
        detail_items = exc.errors() if hasattr(exc, "errors") else []
        err = _error_payload(
            request,
            trace_id,
            error_code="VALIDATION_ERROR",
            message="Datele formularului sunt invalide și au fost respinse de backend.",
            technical_details=str(exc),
            component="BACKEND_API",
            action_required="Verifică datele introduse conform validării.",
            status_code=422,
            error_type=type(exc).__name__,
            details={"validationErrors": detail_items},
        )
        logger.warning(
            f"[{trace_id}] Validation Error: {exc}",
            extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "status_code": 422, "details": detail_items},
        )
        return JSONResponse(status_code=422, content=err.model_dump())

    if isinstance(exc, HTTPException):
        err = _error_payload(
            request,
            trace_id,
            error_code=f"HTTP_{exc.status_code}",
            message=str(exc.detail),
            technical_details=str(exc.detail),
            component="FASTAPI_ROUTER",
            action_required="Verifică parametrii cererii și reîncearcă.",
            status_code=exc.status_code,
            error_type=type(exc).__name__,
        )
        logger.warning(
            f"[{trace_id}] HTTPException [{exc.status_code}]: {exc.detail}",
            extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "status_code": exc.status_code},
        )
        return JSONResponse(status_code=exc.status_code, content=err.model_dump())

    # Prinde erorile Kyverno / Kubernetes API aruncate de kubernetes-asyncio
    if isinstance(exc, ApiException):
        details = {
            "reason": exc.reason,
            "status": exc.status,
            "body": exc.body,
            "headers": dict(exc.headers or {}),
        }
        # 403 Forbidden = de obicei blocat de Admission Controller (Kyverno / OPA) 
        err = _error_payload(
            request,
            trace_id,
            error_code=f"K8S_API_ERROR_{exc.status}",
            message=f"Kubernetes API a respins cererea (Cod: {exc.status})." if exc.status != 403 else "Acțiunea dvs. a fost blocată de un policy intern (Kyverno).",
            technical_details=exc.reason or "N/A",
            component="K8S_API_SERVER",
            action_required="Contactați SecOps sau verificați atestările Cosign/Trivy.",
            status_code=exc.status,
            error_type=type(exc).__name__,
            details=details,
        )
        # Loghează detaliul complet pentru observabilitate (body conține Kyverno reject reason)
        logger.error(
            f"[{trace_id}] K8S ApiException [{exc.status}]: {exc.body}",
            extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "status_code": exc.status, "details": details},
        )
        
        return JSONResponse(status_code=exc.status, content=err.model_dump())
    
    # Prinde logica internă ZeroTrust (Business Logic de la operatori)
    if isinstance(exc, ZeroTrustException):
        err = _error_payload(
            request,
            trace_id,
            error_code=exc.error_code,
            message=exc.message,
            technical_details=exc.technical_details,
            component=exc.component,
            action_required=exc.action_required,
            status_code=400,
            error_type=type(exc).__name__,
        )
        logger.warning(
            f"[{trace_id}] ZeroTrust [{exc.component}]: {exc.technical_details}",
            extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "status_code": 400, "details": {"component": exc.component}},
        )
        return JSONResponse(status_code=400, content=err.model_dump())

    # Eroare generică nespecificată (Fatal)
    err = _error_payload(
        request,
        trace_id,
        error_code="INTERNAL_FATAL_ERROR",
        message="A apărut o eroare internă severă la procesarea cererii.",
        technical_details=str(exc),
        component="FASTAPI_CORE",
        action_required="Deschideți un tichet IT/SecOps cu acest trace_id atașat.",
        status_code=500,
        error_type=type(exc).__name__,
    )
    logger.exception(
        f"[{trace_id}] Fatal Error 500: {exc}",
        extra={"trace_id": trace_id, "path": request.url.path, "method": request.method, "status_code": 500},
    )
    return JSONResponse(status_code=500, content=err.model_dump())
