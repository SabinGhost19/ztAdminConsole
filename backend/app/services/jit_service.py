import logging

from kubernetes_asyncio import client

from app.middleware.errors import ZeroTrustException
from app.services.k8s_scanner import JIT_PLURAL, scanner
from app.services.serializers import serialize_jit_request

logger = logging.getLogger("zero_trust_jit_service")

async def list_jit_requests(namespace: str = "") -> list:
    try:
        logger.info("Listing JIT requests", extra={"details": {"namespace": namespace or None}})
        items = await scanner.list_custom_resources(plural=JIT_PLURAL, namespace=namespace or None)
        serialized = [serialize_jit_request(item) for item in items]
        logger.info("Listed JIT requests successfully", extra={"details": {"namespace": namespace or None, "count": len(serialized)}})
        return serialized
    except Exception as e:
        logger.exception(f"Eroare listare JIT Request CRDs: {e}", extra={"details": {"namespace": namespace or None}})
        raise e

async def create_jit_request(namespace: str, name: str, user_email: str, duration: int, role: str) -> dict:
    logger.info(
        "Creating JIT request",
        extra={"details": {"namespace": namespace, "name": name, "user": user_email, "duration": duration, "role": role}},
    )
    manifest = {
        "apiVersion": "devsecops.licenta.ro/v1",
        "kind": "JITAccessRequest",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "jit.devsecops/user": user_email
            }
        },
        "spec": {
            "developerId": user_email,
            "targetNamespace": namespace,
            "requestedRole": role,
            "duration": f"{duration}m",
            "reason": f"Requested via UI by {user_email}"
        }
    }
    payload = await scanner.create_custom_resource(
        plural=JIT_PLURAL,
        namespace=namespace,
        body=manifest,
    )
    logger.info("Created JIT request successfully", extra={"details": {"namespace": namespace, "name": name, "user": user_email}})
    return payload

async def revoke_jit_access(namespace: str, name: str):
    """
    Kill Switch (Revocare Forțată): Funcționează prin ștergerea directă a CRD-ului sau
    prin aplicarea unui PATCH `status.state=REVOKED`. Aici ștergem resursa,
    ceea ce va forța operatorul (cu un on.delete) să steargă RoleBinding-ul.
    """
    try:
        logger.info("Revoking JIT access", extra={"details": {"namespace": namespace, "name": name}})
        await scanner.delete_custom_resource(plural=JIT_PLURAL, namespace=namespace, name=name)
        logger.info("Revoked JIT access successfully", extra={"details": {"namespace": namespace, "name": name}})
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed revoking JIT access {namespace}/{name}", extra={"details": {"namespace": namespace, "name": name, "status": e.status}})
        if e.status == 404:
            raise ZeroTrustException(
                error_code="JIT_NOT_FOUND",
                message="Sesiunea JIT nu a putut fi găsită pentru revocare.",
                technical_details=f"JITRequest {name} în {namespace} este deja șters sau invalid.",
                component="JIT_OPERATOR",
                action_required="Reîncărcați tabelul (Refresh) sau raportați o problemă State Mismatch."
            )
        raise e