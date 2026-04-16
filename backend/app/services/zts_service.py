import logging

from kubernetes_asyncio import client

from app.middleware.errors import ZeroTrustException
from app.services.k8s_scanner import ZTS_PLURAL, scanner
from app.services.serializers import serialize_zts_resource

logger = logging.getLogger("zero_trust_zts_service")

async def list_zts_secrets(namespace: str = "") -> list:
    try:
        logger.info("Listing ZTS secrets", extra={"details": {"namespace": namespace or None}})
        items = await scanner.list_custom_resources(plural=ZTS_PLURAL, namespace=namespace or None)
        serialized = [serialize_zts_resource(item) for item in items]
        logger.info("Listed ZTS secrets successfully", extra={"details": {"namespace": namespace or None, "count": len(serialized)}})
        return serialized
    except Exception as e:
        logger.exception(f"Eroare listare ZTS CRDs: {e}", extra={"details": {"namespace": namespace or None}})
        raise ZeroTrustException(
            error_code="ZTS_FETCH_FAILED",
            message="Nu s-au putut prelua secretele Zero-Trust din cluster.",
            technical_details=str(e),
            component="ZTS_SERVICE",
            action_required="Verificați conexiunea la API Server sau permisiunile RBAC."
        )

async def create_zts_secret(
    namespace: str,
    name: str,
    user_email: str,
    application_ref: dict,
    target_workload: dict,
    secret_store_ref: dict,
    target_secret_name: str,
    secret_data: dict,
    zero_trust_conditions: dict,
    lifecycle: dict,
) -> dict:
    logger.info(
        "Creating ZTS secret declaration",
        extra={"details": {"namespace": namespace, "name": name, "user": user_email, "applicationRef": application_ref, "targetSecretName": target_secret_name}},
    )
    manifest = {
        "apiVersion": "devsecops.licenta.ro/v1",
        "kind": "ZeroTrustSecret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "zts.devsecops/requester": user_email
            }
        },
        "spec": {
            "applicationRef": application_ref,
            "targetWorkload": target_workload,
            "secretStoreRef": secret_store_ref,
            "targetSecretName": target_secret_name,
            "secretData": secret_data,
            "zeroTrustConditions": zero_trust_conditions,
            "lifecycle": lifecycle,
        }
    }

    try:
        payload = await scanner.create_custom_resource(
            plural=ZTS_PLURAL,
            namespace=namespace,
            body=manifest,
        )
        logger.info("Created ZTS secret declaration successfully", extra={"details": {"namespace": namespace, "name": name, "targetSecretName": target_secret_name}})
        return payload
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed creating ZTS secret {namespace}/{name}", extra={"details": {"namespace": namespace, "name": name, "status": e.status, "targetSecretName": target_secret_name}})
        if e.status == 409:
            raise ZeroTrustException(
                error_code="ZTS_CONFLICT",
                message=f"Secretul Zero-Trust '{name}' a fost deja declarat în namespace-ul '{namespace}'.",
                technical_details="K8s API a raportat HTTP 409 Conflict. Resursa există.",
                component="ZTS_SERVICE",
                action_required="Modificați numele secretului sau asigurați-vă că folosiți ruta de actualizare."
            )
        elif e.status == 403:
            raise ZeroTrustException(
                error_code="ZTS_FORBIDDEN",
                message="Dashboard-ul nu are permisiuni să creeze ZeroTrustSecrets.",
                technical_details=f"Verificați RoleBinding-ul pentru ServicAccount. {e.reason}",
                component="RBAC_ENFORCER",
                action_required="Aplicați Helm chart-ul cu RBAC-ul actualizat."
            )
        else:
             raise ZeroTrustException(
                error_code="ZTS_CREATION_FAILED",
                message="Eroare necunoscută la comunicarea cu K8s API.",
                technical_details=str(e.body),
                component="ZTS_SERVICE",
                action_required="Investigați mesajul de eroare brut din K8s."
            )

async def delete_zts_secret(namespace: str, name: str):
    """
    Șterge cererea ZTS. Operatorul ZTA (sau owner references) se va ocupa de Garbage Collection pentru ExternalSecret-ul generat.
    """
    try:
        logger.info("Deleting ZTS secret declaration", extra={"details": {"namespace": namespace, "name": name}})
        await scanner.delete_custom_resource(plural=ZTS_PLURAL, namespace=namespace, name=name)
        logger.info("Deleted ZTS secret declaration successfully", extra={"details": {"namespace": namespace, "name": name}})
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed deleting ZTS secret {namespace}/{name}", extra={"details": {"namespace": namespace, "name": name, "status": e.status}})
        if e.status == 404:
            raise ZeroTrustException(
                error_code="ZTS_NOT_FOUND",
                message=f"Secretul ZTS '{name}' nu există pentru a fi șters.",
                technical_details=f"ZTS {name} în {namespace} nu a generat niciun match.",
                component="ZTS_SERVICE",
                action_required="Reîncărcați lista de secrete din UI."
            )
        raise ZeroTrustException(
            error_code="ZTS_DELETION_FAILED",
            message="Eroare la ștergerea resurselor de secret din cluster.",
            technical_details=str(e.body),
            component="ZTS_SERVICE",
            action_required="Forțați ștergerea prin kubectl sau investigați starea Finalizer-ului."
        )
