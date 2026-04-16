import logging

from kubernetes_asyncio import client

from app.middleware.errors import ZeroTrustException
from app.services.k8s_scanner import SCA_PLURAL, scanner
from app.services.serializers import serialize_sca_resource

logger = logging.getLogger("zero_trust_sca_service")

async def list_sca_policies(namespace: str = "") -> list:
    try:
        logger.info("Listing SCA policies")
        items = await scanner.list_custom_resources(plural=SCA_PLURAL, cluster_scoped=True)
        serialized = [serialize_sca_resource(item) for item in items]
        logger.info("Listed SCA policies successfully", extra={"details": {"count": len(serialized)}})
        return serialized
    except Exception as e:
        logger.exception(f"Eroare listare SCA CRDs: {e}")
        raise e

async def create_sca_policy(
    name: str,
    user_email: str,
    source_validation: dict,
    provenance: dict,
    vulnerability_policy: dict,
    sbom_policy: dict,
    policy_binding: dict,
    strict_manifest_hash: dict,
    runtime_enforcement: dict,
) -> dict:
    logger.info(
        "Creating SCA policy",
        extra={"details": {"name": name, "user": user_email, "trustedIssuers": source_validation.get("trustedIssuers", []), "trustedRepositories": provenance.get("trustedRepositories", []), "minSlsaLevel": provenance.get("minSlsaLevel")}},
    )
    manifest = {
        "apiVersion": "devsecops.licenta.ro/v1",
        "kind": "SupplyChainAttestation",
        "metadata": {
            "name": name,
            "annotations": {
                "sca.devsecops/creator": user_email
            }
        },
        "spec": {
            "sourceValidation": source_validation,
            "provenance": provenance,
            "vulnerabilityPolicy": vulnerability_policy,
            "sbomPolicy": sbom_policy,
            "policyBinding": policy_binding,
            "strictManifestHash": strict_manifest_hash,
            "runtimeEnforcement": runtime_enforcement,
        }
    }

    try:
        payload = await scanner.create_custom_resource(
            plural=SCA_PLURAL,
            cluster_scoped=True,
            body=manifest,
        )
        logger.info("Created SCA policy successfully", extra={"details": {"name": name, "user": user_email}})
        return payload
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed creating SCA policy {name}", extra={"details": {"name": name, "status": e.status}})
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
    try:
        logger.info("Deleting SCA policy", extra={"details": {"name": name}})
        await scanner.delete_custom_resource(plural=SCA_PLURAL, cluster_scoped=True, name=name)
        logger.info("Deleted SCA policy successfully", extra={"details": {"name": name}})
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed deleting SCA policy {name}", extra={"details": {"name": name, "status": e.status}})
        if e.status == 404:
            raise ZeroTrustException(
                error_code="SCA_NOT_FOUND",
                message="Politica SCA nu a putut fi găsită.",
                technical_details=f"SCA {name} nu există la nivel de cluster.",
                component="SCA_OPERATOR",
                action_required="Reîncărcați lista."
            )
        raise e
