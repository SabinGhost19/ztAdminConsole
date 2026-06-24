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

def _build_sca_spec(
    source_validation: dict,
    provenance: dict,
    vulnerability_policy: dict,
    sbom_policy: dict,
    policy_binding: dict,
    strict_manifest_hash: dict,
    slsa_provenance_policy: dict,
    open_vex_policy: dict,
    security_scan_policy: dict,
    custom_rules: list,
    runtime_enforcement: dict,
) -> dict:
    return {
        "sourceValidation": source_validation,
        "provenance": provenance,
        "vulnerabilityPolicy": vulnerability_policy,
        "sbomPolicy": sbom_policy,
        "policyBinding": policy_binding,
        "strictManifestHash": strict_manifest_hash,
        "slsaProvenancePolicy": slsa_provenance_policy,
        "openVexPolicy": open_vex_policy,
        "securityScanPolicy": security_scan_policy,
        "customRules": custom_rules,
        "runtimeEnforcement": runtime_enforcement,
    }


async def create_sca_policy(
    name: str,
    user_email: str,
    source_validation: dict,
    provenance: dict,
    vulnerability_policy: dict,
    sbom_policy: dict,
    policy_binding: dict,
    strict_manifest_hash: dict,
    slsa_provenance_policy: dict,
    open_vex_policy: dict,
    security_scan_policy: dict,
    custom_rules: list,
    runtime_enforcement: dict,
) -> dict:
    logger.info(
        "Creating SCA policy",
        extra={"details": {"name": name, "user": user_email, "trustedIssuers": source_validation.get("trustedIssuers", []), "trustedRepositories": provenance.get("trustedRepositories", []), "minSlsaLevel": provenance.get("minSlsaLevel"), "customRules": len(custom_rules or [])}},
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
        "spec": _build_sca_spec(
            source_validation, provenance, vulnerability_policy, sbom_policy,
            policy_binding, strict_manifest_hash, slsa_provenance_policy,
            open_vex_policy, security_scan_policy, custom_rules, runtime_enforcement,
        ),
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

async def update_sca_policy(
    name: str,
    user_email: str,
    source_validation: dict,
    provenance: dict,
    vulnerability_policy: dict,
    sbom_policy: dict,
    policy_binding: dict,
    strict_manifest_hash: dict,
    slsa_provenance_policy: dict,
    open_vex_policy: dict,
    security_scan_policy: dict,
    custom_rules: list,
    runtime_enforcement: dict,
) -> dict:
    """Update an existing cluster-scoped SCA via optimistic-concurrency replace
    (mirror of zts_service.update_zts_secret)."""
    logger.info("Updating SCA policy", extra={"details": {"name": name, "user": user_email, "customRules": len(custom_rules or [])}})
    try:
        current = await scanner.get_custom_resource(plural=SCA_PLURAL, cluster_scoped=True, name=name)
    except client.exceptions.ApiException as e:
        if e.status == 404:
            raise ZeroTrustException(
                error_code="SCA_NOT_FOUND",
                message=f"Politica SCA '{name}' nu există pentru a fi actualizată.",
                technical_details=f"SCA {name} nu există la nivel de cluster.",
                component="SCA_OPERATOR",
                action_required="Reîncărcați lista de politici.",
            )
        raise

    meta = current.setdefault("metadata", {})
    merged_annotations = meta.get("annotations", {}) or {}
    merged_annotations.setdefault("sca.devsecops/creator", user_email)
    meta["annotations"] = merged_annotations
    current["spec"] = _build_sca_spec(
        source_validation, provenance, vulnerability_policy, sbom_policy,
        policy_binding, strict_manifest_hash, slsa_provenance_policy,
        open_vex_policy, security_scan_policy, custom_rules, runtime_enforcement,
    )

    try:
        payload = await scanner.replace_custom_resource(plural=SCA_PLURAL, cluster_scoped=True, name=name, body=current)
        logger.info("Updated SCA policy successfully", extra={"details": {"name": name}})
        return payload
    except client.exceptions.ApiException as e:
        logger.exception(f"Failed updating SCA policy {name}", extra={"details": {"name": name, "status": e.status}})
        if e.status == 409:
            raise ZeroTrustException(
                error_code="SCA_CONFLICT",
                message=f"Politica SCA {name} a fost modificată concurent.",
                technical_details="HTTP 409 Conflict (resourceVersion). Reîncărcați și reîncercați.",
                component="SCA_OPERATOR",
                action_required="Reîncărcați lista și reaplicați modificările.",
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
