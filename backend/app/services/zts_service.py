from kubernetes_asyncio import client
import logging
from app.middleware.errors import ZeroTrustException

logger = logging.getLogger("zero_trust_zts_service")

# Constante pt CRD-ul ZTS
CRD_GROUP = "devsecops.licenta.ro"
CRD_VERSION = "v1"
CRD_PLURAL = "zerotrustsecrets"

async def list_zts_secrets(namespace: str = "") -> list:
    """Interoghează clusterul K8s pentru starea curentă a ZeroTrustSecrets."""
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
        logger.error(f"Eroare listare ZTS CRDs: {e}")
        # Ridicăm o eroare formatată pentru Global Exception Handler
        raise ZeroTrustException(
            error_code="ZTS_FETCH_FAILED",
            message="Nu s-au putut prelua secretele Zero-Trust din cluster.",
            technical_details=str(e),
            component="ZTS_SERVICE",
            action_required="Verificați conexiunea la API Server sau permisiunile RBAC."
        )

async def create_zts_secret(namespace: str, name: str, user_email: str, vault_path: str, target_secret: str, rotation_interval: str = "1h") -> dict:
    """Creează cererea ZTS. Operatorul ZTA va prelua CRD-ul, va face verificări de supply-chain și va delega la External Secrets Operator (ESO)."""
    api = client.CustomObjectsApi()
    
    manifest = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "ZeroTrustSecret",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "zts.devsecops/requester": user_email
            }
        },
        "spec": {
            "vaultPath": vault_path,
            "targetSecretName": target_secret,
            "rotationInterval": rotation_interval,
            "validationPolicy": "strict" # Forțează operatorul să valideze identitatea
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
