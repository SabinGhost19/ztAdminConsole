import logging

from kubernetes_asyncio import client

from app.middleware.errors import ZeroTrustException
from app.services.k8s_scanner import ZTA_PLURAL, scanner
from app.services.serializers import serialize_zta_resource

logger = logging.getLogger("zero_trust_zta_service")

async def list_zta_applications(namespace: str = "") -> list:
    try:
        logger.info("Listing ZTA applications", extra={"details": {"namespace": namespace or None}})
        items = await scanner.list_custom_resources(plural=ZTA_PLURAL, namespace=namespace or None)
        serialized = [serialize_zta_resource(item) for item in items]
        logger.info("Listed ZTA applications successfully", extra={"details": {"namespace": namespace or None, "count": len(serialized)}})
        return serialized
    except Exception as e:
        logger.exception(f"Eroare listare ZTA CRDs: {e}", extra={"details": {"namespace": namespace or None}})
        raise e

async def create_zta_application(
    namespace: str,
    name: str,
    user_email: str,
    labels: dict,
    annotations: dict,
    image: str,
    replicas: int,
    security_policy_ref: dict,
    network_zero_trust: dict,
    waf_config: dict,
    runtime_security: dict,
) -> dict:
    logger.info(
        "Creating ZTA application",
        extra={"details": {"namespace": namespace, "name": name, "image": image, "replicas": replicas, "securityPolicyRef": security_policy_ref}},
    )
    manifest = {
        "apiVersion": "devsecops.licenta.ro/v1",
        "kind": "ZeroTrustApplication",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "zta.devsecops/creator": user_email,
                **annotations,
            },
            "labels": labels,
        },
        "spec": {
            "image": image,
            "replicas": replicas,
            "securityPolicyRef": security_policy_ref,
            "networkZeroTrust": network_zero_trust,
            "wafConfig": waf_config,
            "runtimeSecurity": runtime_security,
        },
    }

    try:
        payload = await scanner.create_custom_resource(
            plural=ZTA_PLURAL,
            namespace=namespace,
            body=manifest,
        )
        logger.info("Created ZTA application successfully", extra={"details": {"namespace": namespace, "name": name, "image": image}})
        return payload
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed creating ZTA application {namespace}/{name}", extra={"details": {"namespace": namespace, "name": name, "status": e.status, "image": image}})
        if e.status == 409:
            raise ZeroTrustException(
                error_code="ZTA_CONFLICT",
                message=f"Aplicația ZTA {name} există deja.",
                technical_details="K8s reportat HTTP 409 Conflict. Numele CRD-ului e duplicat.",
                component="ZTA_OPERATOR",
                action_required="Alegeți un nume unic sau folosiți edit/patch."
            )
        raise e

async def trigger_zta_reconcile(namespace: str, name: str, user_email: str) -> dict:
    """Force the ZTA operator to re-evaluate a resource by patching a
    benign annotation. Used by the dashboard's "Re-Evaluate" button so the
    user can recover from a stale Failed_SupplyChain or Degraded state
    without manually deleting and recreating the ZTA.

    kopf watches the spec field but also picks up arbitrary metadata
    changes — patching `zta.devsecops/reconciled-at` is enough to wake it.
    """
    from datetime import datetime, timezone

    patch_body = {
        "metadata": {
            "annotations": {
                "zta.devsecops/reconciled-at": datetime.now(timezone.utc).isoformat(),
                "zta.devsecops/reconciled-by": user_email,
            }
        }
    }
    try:
        logger.info("Triggering ZTA reconcile", extra={"details": {"namespace": namespace, "name": name, "user": user_email}})
        from app.services.k8s_scanner import GROUP, VERSION
        from app.core.k8s import get_custom_api
        api = get_custom_api()
        payload = await api.patch_namespaced_custom_object(
            group=GROUP, version=VERSION, namespace=namespace,
            plural=ZTA_PLURAL, name=name, body=patch_body,
        )
        logger.info("Triggered ZTA reconcile successfully", extra={"details": {"namespace": namespace, "name": name}})
        return payload
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ZeroTrustException(
                error_code="ZTA_NOT_FOUND",
                message="ZTA-ul nu există — nu poate fi re-evaluat.",
                technical_details=f"ZTA {name} în {namespace} nu există.",
                component="ZTA_OPERATOR",
                action_required="Reîncărcați lista de aplicații."
            )
        raise


async def delete_zta_application(namespace: str, name: str):
    """
    Șterge declarația ZTA, trimițând un trigger către operatorul ZTA care 
    va retrage regulile Cilium NetworkPolicies / Ingress-urile asociate.
    """
    try:
        logger.info("Deleting ZTA application", extra={"details": {"namespace": namespace, "name": name}})
        await scanner.delete_custom_resource(plural=ZTA_PLURAL, namespace=namespace, name=name)
        logger.info("Deleted ZTA application successfully", extra={"details": {"namespace": namespace, "name": name}})
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed deleting ZTA application {namespace}/{name}", extra={"details": {"namespace": namespace, "name": name, "status": e.status}})
        if e.status == 404:
            raise ZeroTrustException(
                error_code="ZTA_NOT_FOUND",
                message="Sistemul ZTA nu a putut fi găsit.",
                technical_details=f"ZTA {name} în {namespace} nu există.",
                component="ZTA_OPERATOR",
                action_required="Reîncărcați lista."
            )
        raise e
