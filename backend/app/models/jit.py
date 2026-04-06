from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

# ====================
# MODELE ERORI API
# ====================
class APIErrorDetails(BaseModel):
    error_code: str
    message: str
    technical_details: str
    component: str
    trace_id: str
    action_required: str

# ====================
# MODELE JIT CRD
# ====================
class JITAccessRequestSpec(BaseModel):
    targetNamespace: str
    role: str
    durationMinutes: int
    reason: Optional[str] = None

class JITAccessRequestStatus(BaseModel):
    state: str = "PENDING"
    expiresAt: Optional[str] = None
    temporaryToken: Optional[str] = None
    temporaryServiceAccount: Optional[str] = None
    roleBindingName: Optional[str] = None

class JITAccessRequest(BaseModel):
    apiVersion: str = "devsecops.licenta.ro/v1alpha1"
    kind: str = "JITAccessRequest"
    metadata: Dict[str, Any]
    spec: JITAccessRequestSpec
    status: Optional[JITAccessRequestStatus] = None