from kubernetes_asyncio import client
import logging
from app.models.jit import JITAccessRequest, JITAccessRequestSpec
from app.middleware.errors import ZeroTrustException

logger = logging.getLogger("zero_trust_jit_service")

# Constante pt CRD-ul JIT
CRD_GROUP = "devsecops.licenta.ro"
CRD_VERSION = "v1alpha1"
CRD_PLURAL = "jitaccessrequests"

async def list_jit_requests(namespace: str = "") -> list:
    """Interoghează clusterul K8s folosind CustomObjectsApi pentru starea JIT-urilor."""
    api = client.CustomObjectsApi()
    
    try:
        if namespace:
            res = await api.list_namespaced_custom_object(
                group=CRD_GROUP, version=CRD_VERSION, namespace=namespace, plural=CRD_PLURAL
            )
        else:
            res = await api.list_cluster_custom_object(
                group=CRD_GROUP, version=CRD_VERSION, plural=CRD_PLURAL
            )
        return res.get("items", [])
    except Exception as e:
        logger.error(f"Eroare listare JIT Request CRDs: {e}")
        raise e

async def create_jit_request(namespace: str, name: str, user_email: str, duration: int, role: str) -> dict:
    """Creează un JIT CRD în Kubernetes. Operatorul va reacționa dintr-un watcher la acest manifest."""
    api = client.CustomObjectsApi()
    
    # Formăm corpul resursei conform CRD-ului
    manifest = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "JITAccessRequest",
        "metadata": {
            "name": name,
            "annotations": {
                "jit.devsecops/user": user_email
            }
        },
        "spec": {
            "targetNamespace": namespace,
            "role": role,
            "durationMinutes": duration,
            "reason": f"Requested via UI by {user_email}"
        }
    }
    
    res = await api.create_namespaced_custom_object(
        group=CRD_GROUP,
        version=CRD_VERSION,
        namespace=namespace,
        plural=CRD_PLURAL,
        body=manifest
    )
    return res

async def revoke_jit_access(namespace: str, name: str):
    """
    Kill Switch (Revocare Forțată): Funcționează prin ștergerea directă a CRD-ului sau
    prin aplicarea unui PATCH `status.state=REVOKED`. Aici ștergem resursa,
    ceea ce va forța operatorul (cu un on.delete) să steargă RoleBinding-ul.
    """
    api = client.CustomObjectsApi()
    
    try:
        await api.delete_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural=CRD_PLURAL,
            name=name
        )
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ZeroTrustException(
                error_code="JIT_NOT_FOUND",
                message="Sesiunea JIT nu a putut fi găsită pentru revocare.",
                technical_details=f"JITRequest {name} în {namespace} este deja șters sau invalid.",
                component="JIT_OPERATOR",
                action_required="Reîncărcați tabelul (Refresh) sau raportați o problemă State Mismatch."
            )
        raise e