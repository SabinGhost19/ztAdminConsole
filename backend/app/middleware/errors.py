import uuid
import logging
from typing import Any
from fastapi import Request
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

async def global_exception_handler(request: Request, exc: Exception):
    trace_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    
    # Prinde Pydantic Validation Error (Input gresit form ZTA/JIT builder)
    if isinstance(exc, ValidationError):
        err = APIErrorDetails(
            error_code="VALIDATION_ERROR",
            message="Datele formularului sunt invalide și au fost respinse de backend.",
            technical_details=str(exc),
            component="BACKEND_API",
            trace_id=trace_id,
            action_required="Verifică datele introduse conform validării."
        )
        logger.warning(f"[{trace_id}] Validation Error: {exc}")
        return JSONResponse(status_code=422, content=err.model_dump())

    # Prinde erorile Kyverno / Kubernetes API aruncate de kubernetes-asyncio
    if isinstance(exc, ApiException):
        # 403 Forbidden = de obicei blocat de Admission Controller (Kyverno / OPA) 
        err = APIErrorDetails(
            error_code=f"K8S_API_ERROR_{exc.status}",
            message=f"Kubernetes API a respins cererea (Cod: {exc.status})." if exc.status != 403 else "Acțiunea dvs. a fost blocată de un policy intern (Kyverno).",
            technical_details=exc.reason or "N/A",
            component="K8S_API_SERVER",
            trace_id=trace_id,
            action_required="Contactați SecOps sau verificați atestările Cosign/Trivy."
        )
        # Loghează detaliul complet pentru observabilitate (body conține Kyverno reject reason)
        logger.error(f"[{trace_id}] K8S ApiException [{exc.status}]: {exc.body}")
        
        return JSONResponse(status_code=exc.status, content=err.model_dump())
    
    # Prinde logica internă ZeroTrust (Business Logic de la operatori)
    if isinstance(exc, ZeroTrustException):
        err = APIErrorDetails(
            error_code=exc.error_code,
            message=exc.message,
            technical_details=exc.technical_details,
            component=exc.component,
            trace_id=trace_id,
            action_required=exc.action_required
        )
        logger.warning(f"[{trace_id}] ZeroTrust [{exc.component}]: {exc.technical_details}")
        return JSONResponse(status_code=400, content=err.model_dump())

    # Eroare generică nespecificată (Fatal)
    err = APIErrorDetails(
        error_code="INTERNAL_FATAL_ERROR",
        message="A apărut o eroare internă severă la procesarea cererii.",
        technical_details=str(exc),
        component="FASTAPI_CORE",
        trace_id=trace_id,
        action_required="Deschideți un tichet IT/SecOps cu acest trace_id atașat."
    )
    logger.exception(f"[{trace_id}] Fatal Error 500: {exc}")
    return JSONResponse(status_code=500, content=err.model_dump())
