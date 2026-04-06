from kubernetes_asyncio import client
import logging
from app.middleware.errors import ZeroTrustException

logger = logging.getLogger("zero_trust_zta_service")

# Constante pt CRD-ul ZTA
CRD_GROUP = "devsecops.licenta.ro"
CRD_VERSION = "v1"
CRD_PLURAL = "zerotrustapplications"

async def list_zta_applications(namespace: str = "") -> list:
    """Interoghează clusterul K8s pentru starea curentă a aplicațiilor Zero Trust."""
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
        logger.error(f"Eroare listare ZTA CRDs: {e}")
        raise e

async def create_zta_application(namespace: str, name: str, user_email: str, labels: dict, ingress_host: str, policy_rules: dict, image: str) -> dict:
    """Creează un ZTA CRD în Kubernetes, semnalând ZTA Operator să genereze politicile eBPF/Network."""
    api = client.CustomObjectsApi()
    
    manifest = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "ZeroTrustApplication",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "zta.devsecops/creator": user_email
            },
            "labels": labels
        },
        "spec": {
            "ingress": {
                "host": ingress_host
            },
            "image": image,
            "networkPolicy": policy_rules
        }
    }
    
    try:
        res = await api.create_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural=CRD_PLURAL,
            body=manifest
        )
        return res
    except client.exceptions.ApiException as e:
        if e.status == 409:
            raise ZeroTrustException(
                error_code="ZTA_CONFLICT",
                message=f"Aplicația ZTA {name} există deja.",
                technical_details="K8s reportat HTTP 409 Conflict. Numele CRD-ului e duplicat.",
                component="ZTA_OPERATOR",
                action_required="Alegeți un nume unic sau folosiți edit/patch."
            )
        raise e

async def delete_zta_application(namespace: str, name: str):
    """
    Șterge declarația ZTA, trimițând un trigger către operatorul ZTA care 
    va retrage regulile Cilium NetworkPolicies / Ingress-urile asociate.
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
                error_code="ZTA_NOT_FOUND",
                message="Sistemul ZTA nu a putut fi găsit.",
                technical_details=f"ZTA {name} în {namespace} nu există.",
                component="ZTA_OPERATOR",
                action_required="Reîncărcați lista."
            )
        raise e
