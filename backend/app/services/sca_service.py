from kubernetes_asyncio import client
import logging
from app.middleware.errors import ZeroTrustException

logger = logging.getLogger("zero_trust_sca_service")

# Constante pt CRD-ul SCA
CRD_GROUP = "devsecops.licenta.ro"
CRD_VERSION = "v1"
CRD_PLURAL = "supplychainattestations"

async def list_sca_policies(namespace: str = "") -> list:
    """Interoghează clusterul K8s pentru starea curentă a politicilor Supply Chain Attestation (SCA/nw)."""
    api = client.CustomObjectsApi()
    
    try:
        if namespace:
            # Although SCA is Cluster scoped in yaml, the kubernetes client might treat it as Cluster scope.
            # Wait, `scope: Cluster` means we should always use `list_cluster_custom_object`.
            pass
        res = await api.list_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural=CRD_PLURAL
        )
        return res.get("items", [])
    except Exception as e:
        logger.error(f"Eroare listare SCA CRDs: {e}")
        raise e

async def create_sca_policy(name: str, zta_name: str, zta_namespace: str, trusted_issuers: list, enforce_sbom: bool, on_policy_drift: str, user_email: str) -> dict:
    """Creează un SCA CRD în Kubernetes."""
    api = client.CustomObjectsApi()
    
    manifest = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "SupplyChainAttestation",
        "metadata": {
            "name": name,
            "annotations": {
                "sca.devsecops/creator": user_email
            }
        },
        "spec": {
            "target": {
                "ztaName": zta_name,
                "ztaNamespace": zta_namespace
            },
            "sourceValidation": {
                "enforceCosign": True,
                "trustedIssuers": trusted_issuers
            },
            "sbomPolicy": {
                "enforceSBOM": enforce_sbom,
                "forbiddenPackages": []
            },
            "runtimeEnforcement": {
                "enabled": True,
                "onPolicyDrift": on_policy_drift
            }
        }
    }
    
    try:
        res = await api.create_cluster_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            plural=CRD_PLURAL,
            body=manifest
        )
        return res
    except client.exceptions.ApiException as e:
        if e.status == 409:
            raise ZeroTrustException(
                error_code="SCA_CONFLICT",
                message=f"Politica SCA {name} există deja.",
                technical_details="K8s reportat HTTP 409 Conflict. Numele CRD-ului e duplicat.",
                component="SCA_OPERATOR",
                action_required="Alegeți un nume unic sau folosiți edit/patch."
            )
        raise e

async def delete_sca_policy(name: str):
    """
    Șterge o politică SCA.
    """
    api = client.CustomObjectsApi()
    try:
        await api.delete_cluster_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            plural=CRD_PLURAL,
            name=name
        )
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ZeroTrustException(
                error_code="SCA_NOT_FOUND",
                message="Politica SCA nu a putut fi găsită.",
                technical_details=f"SCA {name} nu există la nivel de cluster.",
                component="SCA_OPERATOR",
                action_required="Reîncărcați lista."
            )
        raise e
