from __future__ import annotations

import logging
import os
from typing import Any

from kubernetes_asyncio import client

from app.core.k8s import get_core_api
from app.middleware.errors import ZeroTrustException
from app.services.provenance_revalidation import RevalidationError, revalidate_vbbi
from app.services.k8s_scanner import SCA_PLURAL, ZTA_PLURAL, ZTS_PLURAL, scanner
from app.services.serializers import serialize_sca_resource, serialize_zta_resource, serialize_zts_resource

TALON_NAMESPACE = os.getenv("TALON_NAMESPACE", "falco-talon")
TALON_CONFIGMAP_NAME = os.getenv("TALON_CONFIGMAP_NAME", "falco-talon-rules")
TALON_CONFIGMAP_KEY = os.getenv("TALON_CONFIGMAP_KEY", "rules.yaml")
logger = logging.getLogger("zero_trust_integrity_service")


def _build_integrity_ledger(application: dict[str, Any], policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    status = application.get("status", {}) or {}
    summary = application.get("summary", {}) or {}
    provenance = status.get("provenance", {}) or {}
    hmac_chain = provenance.get("hmacChain", {}) or {}
    merkle = provenance.get("merkle", {}) or {}
    voucher_required = bool(((policy or {}).get("summary", {}) or {}).get("requireVoucher", False))
    has_verified_at = bool(provenance.get("verifiedAt"))

    return [
        {
            "id": "voucher",
            "title": "Voucher Presence",
            "status": "verified" if has_verified_at else ("required" if voucher_required else "optional"),
            "details": provenance.get("reason") or "Voucher status derived from ZeroTrustApplication provenance status.",
        },
        {
            "id": "hmac-chain",
            "title": "HMAC Chain",
            "status": "verified" if hmac_chain.get("verified") else ("pending" if voucher_required else "not-enabled"),
            "details": {
                "provider": hmac_chain.get("provider"),
                "steps": hmac_chain.get("steps"),
                "finalVoucher": hmac_chain.get("finalVoucher"),
            },
        },
        {
            "id": "merkle-root",
            "title": "Merkle Root",
            "status": "verified" if merkle.get("verified") else ("pending" if voucher_required else "not-enabled"),
            "details": merkle,
        },
        {
            "id": "policy-gate",
            "title": "Policy Gate",
            "status": "verified" if summary.get("trustLevel") == "Verified" else "blocked",
            "details": {
                "trustLevel": summary.get("trustLevel"),
                "securityState": summary.get("securityState"),
                "violations": summary.get("violations", []),
            },
        },
    ]


def _build_trust_cascade(application: dict[str, Any], policy: dict[str, Any] | None, secrets: list[dict[str, Any]]) -> dict[str, Any]:
    policy_name = ((application.get("spec", {}) or {}).get("securityPolicyRef", {}) or {}).get("name")
    trust_level = ((application.get("summary", {}) or {}).get("trustLevel") or "Untrusted")
    return {
        "source": {
            "type": "policy",
            "name": policy_name,
            "ready": policy is not None,
        },
        "application": {
            "name": application.get("metadata", {}).get("name"),
            "namespace": application.get("metadata", {}).get("namespace"),
            "trustLevel": trust_level,
            "securityState": (application.get("summary", {}) or {}).get("securityState"),
        },
        "secrets": [
            {
                "name": item.get("metadata", {}).get("name"),
                "phase": item.get("summary", {}).get("phase"),
                "targetSecretName": item.get("summary", {}).get("targetSecretName"),
            }
            for item in secrets
        ],
        "blocked": trust_level != "Verified",
    }


def _build_sbom_tree(attestations: dict[str, Any]) -> list[dict[str, Any]]:
    packages = attestations.get("sbomPackages", []) or []
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in packages:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "unknown")).strip() or "unknown"
        version = str(item.get("versionInfo", item.get("version", "unknown"))).strip() or "unknown"
        purl = str(item.get("purl", "")).strip()
        ecosystem = "generic"
        if purl.startswith("pkg:"):
            ecosystem = purl.split("/", 1)[0].replace("pkg:", "")
        groups.setdefault(ecosystem, []).append({
            "name": name,
            "version": version,
            "purl": purl,
        })
    return [
        {"ecosystem": ecosystem, "packages": sorted(entries, key=lambda item: item["name"])}
        for ecosystem, entries in sorted(groups.items(), key=lambda item: item[0])
    ]


def _build_vulnerability_heatmap(application: dict[str, Any], policy: dict[str, Any] | None) -> dict[str, Any]:
    details = (application.get("status", {}) or {}).get("details", {}) or {}
    threshold = ((policy or {}).get("summary", {}) or {}).get("maxAllowedSeverity")
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    severity_counts = details.get("severityCounts", {}) or {}
    for key in counts:
        counts[key] = int(severity_counts.get(key, severity_counts.get(key.lower(), 0)) or 0)
    highest = str(details.get("highest", details.get("severity", ""))).upper().strip()
    if highest in counts and sum(counts.values()) == 0:
        counts[highest] = 1
    return {
        "counts": counts,
        "highest": highest or "NONE",
        "threshold": threshold,
        "failOnFixable": ((policy or {}).get("summary", {}) or {}).get("failOnFixable", False),
        "details": details,
    }


def _build_sanction_history(application: dict[str, Any], policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    status = application.get("status", {}) or {}
    summary = application.get("summary", {}) or {}
    runtime = ((policy or {}).get("summary", {}) or {})
    history: list[dict[str, Any]] = []
    if summary.get("provenanceVerifiedAt"):
        history.append({
            "kind": "provenance",
            "action": "Verified",
            "timestamp": summary.get("provenanceVerifiedAt"),
            "message": "Provenance-Enforcer marked the workload as verified.",
        })
    for violation in status.get("activeViolations", []) or []:
        history.append({
            "kind": "violation",
            "action": runtime.get("onPolicyDrift", "Alert"),
            "timestamp": status.get("lastVerified") or application.get("metadata", {}).get("createdAt"),
            "message": str(violation),
        })
    if status.get("securityState") and status.get("securityState") not in {"Compliant", "PendingProvenance"}:
        history.append({
            "kind": "security-state",
            "action": status.get("securityState"),
            "timestamp": status.get("lastVerified") or application.get("metadata", {}).get("createdAt"),
            "message": status.get("lastError") or "Security state changed due to operator enforcement.",
        })
    return history


async def _build_runtime_forensics(application: dict[str, Any]) -> dict[str, Any]:
    metadata = application.get("metadata", {}) or {}
    spec = application.get("spec", {}) or {}
    namespace = str(metadata.get("namespace", "default"))
    name = str(metadata.get("name", ""))
    local_configmap_name = f"falco-rule-{name}"
    expected_rule_name = f"Unauthorized_Write_{namespace}_{name}".replace("-", "_")
    core = get_core_api()

    local_rule = None
    talon_rules = None
    try:
        logger.info("Reading local Falco rule ConfigMap", extra={"details": {"namespace": namespace, "name": local_configmap_name}})
        local_cm = await core.read_namespaced_config_map(name=local_configmap_name, namespace=namespace)
        local_rule = (local_cm.data or {}).get("custom_rule.yaml")
    except client.exceptions.ApiException:
        local_rule = None

    try:
        logger.info("Reading Talon ConfigMap", extra={"details": {"namespace": TALON_NAMESPACE, "name": TALON_CONFIGMAP_NAME, "key": TALON_CONFIGMAP_KEY}})
        talon_cm = await core.read_namespaced_config_map(name=TALON_CONFIGMAP_NAME, namespace=TALON_NAMESPACE)
        talon_rules = (talon_cm.data or {}).get(TALON_CONFIGMAP_KEY)
    except client.exceptions.ApiException:
        talon_rules = None

    return {
        "allowedPaths": ((spec.get("runtimeSecurity", {}) or {}).get("allowedPaths", []) or []),
        "localFalcoRuleConfigMap": local_configmap_name,
        "localRulePresent": bool(local_rule),
        "localRuleSnippet": local_rule,
        "talonNamespace": TALON_NAMESPACE,
        "talonConfigMapName": TALON_CONFIGMAP_NAME,
        "talonRuleReference": expected_rule_name,
        "talonRulePresent": bool(talon_rules and expected_rule_name in talon_rules),
        "talonRulesSnippet": talon_rules,
    }


def _build_placeholder_ledger(provenance: dict[str, Any]) -> list[dict[str, Any]]:
    hmac_chain = provenance.get("hmacChain", {}) or {}
    step_count = int(hmac_chain.get("steps", 0) or 0)
    return [
        {
            "id": f"step-{index}",
            "label": f"Step {index}",
            "position": index,
            "verified": bool(hmac_chain.get("verified", False)),
            "metadataHash": None,
            "hmacResult": None,
        }
        for index in range(1, step_count + 1)
    ]


def _build_placeholder_merkle(provenance: dict[str, Any]) -> list[list[dict[str, Any]]]:
    merkle = provenance.get("merkle", {}) or {}
    leaf_count = int(merkle.get("leafCount", 0) or 0)
    if leaf_count <= 0:
        return []
    return [[{"hash": f"leaf-{index}", "label": f"Leaf {index}"} for index in range(1, leaf_count + 1)]]


async def _build_revalidation(application: dict[str, Any], policy: dict[str, Any] | None, force_oci: bool = False) -> dict[str, Any]:
    spec = application.get("spec", {}) or {}
    status = application.get("status", {}) or {}
    provenance = status.get("provenance", {}) or {}
    summary = (policy or {}).get("summary", {}) or {}

    base = {
        "status": "cached" if provenance.get("verifiedAt") else "pending",
        "voucherPolicy": {
            "repository": provenance.get("repository"),
            "slsaLevel": provenance.get("slsaLevel"),
            "stepCount": provenance.get("stepCount"),
            "subjectVerified": provenance.get("subjectVerified"),
            "statementType": provenance.get("statementType"),
        },
        "hmacChain": provenance.get("hmacChain", {}) or {},
        "merkle": provenance.get("merkle", {}) or {},
        "buildContext": {},
        "ledgerNodes": _build_placeholder_ledger(provenance),
        "merkleLevels": _build_placeholder_merkle(provenance),
        "fetch": {
            "status": "not-requested" if not force_oci else "failed",
            "reason": provenance.get("reason", "no-oci-revalidation-attempt"),
        },
        "vaultMetadata": {
            "hmacMode": provenance.get("hmacMode"),
            "verifiedAt": provenance.get("verifiedAt"),
            "note": "Dashboard reads provenance metadata from ZTA status; Vault transit revalidation requires operator-side keys.",
        },
    }

    if not force_oci:
        logger.info("Using cached integrity revalidation data", extra={"details": {"application": application.get("metadata", {}).get("name"), "namespace": application.get("metadata", {}).get("namespace")}})
        return base

    trusted_issuers = ((policy or {}).get("summary", {}) or {}).get("trustedIssuers", []) or []
    try:
        logger.info(
            "Starting OCI integrity revalidation",
            extra={"details": {"application": application.get("metadata", {}).get("name"), "namespace": application.get("metadata", {}).get("namespace"), "image": str(spec.get("image", "")).strip(), "trustedIssuers": trusted_issuers}},
        )
        revalidated = revalidate_vbbi(
            image=str(spec.get("image", "")).strip(),
            trusted_issuers=[str(item).strip() for item in trusted_issuers if str(item).strip()],
            min_slsa_level=int(summary.get("minSlsaLevel", 0) or 0),
            trusted_repositories=[str(item).strip() for item in (summary.get("trustedRepositories", []) or []) if str(item).strip()],
            enforce_hmac_chain=bool(summary.get("enforceHmacChain", True)),
        )
        base.update(revalidated)
        base["vaultMetadata"]["note"] = "Dashboard performed OCI-based revalidation using cosign and local shared-secret settings."
        logger.info("Completed OCI integrity revalidation", extra={"details": {"application": application.get("metadata", {}).get("name"), "namespace": application.get("metadata", {}).get("namespace"), "status": base.get("status")}})
        return base
    except RevalidationError as exc:
        base["status"] = "failed"
        base["fetch"] = {"status": "failed", "reason": str(exc)}
        logger.warning(f"OCI integrity revalidation failed: {exc}", extra={"details": {"application": application.get("metadata", {}).get("name"), "namespace": application.get("metadata", {}).get("namespace"), "image": str(spec.get("image", "")).strip()}})
        return base


async def _collect_integrity_payload(namespace: str, name: str, force_oci: bool = False) -> dict[str, Any]:
    logger.info("Collecting integrity payload", extra={"details": {"namespace": namespace, "name": name, "forceOci": force_oci}})
    try:
        raw_application = await scanner.get_custom_resource(
            plural=ZTA_PLURAL,
            namespace=namespace,
            name=name,
        )
    except client.exceptions.ApiException as exc:
        if exc.status == 404:
            return {}
        raise

    application = serialize_zta_resource(raw_application)
    policy_name = (((raw_application.get("spec", {}) or {}).get("securityPolicyRef", {}) or {}).get("name") or "").strip()
    policy = None
    if policy_name:
        try:
            raw_policy = await scanner.get_custom_resource(
                plural=SCA_PLURAL,
                name=policy_name,
                cluster_scoped=True,
            )
            policy = serialize_sca_resource(raw_policy)
        except client.exceptions.ApiException as exc:
            if exc.status != 404:
                raise
            logger.warning("Referenced SCA policy not found during integrity collection", extra={"details": {"namespace": namespace, "name": name, "policyName": policy_name}})

    raw_secrets = await scanner.list_custom_resources(plural=ZTS_PLURAL, namespace=namespace)
    related_secrets = []
    for item in raw_secrets:
        application_ref = ((item.get("spec", {}) or {}).get("applicationRef", {}) or {})
        if application_ref.get("name") == name and str(application_ref.get("namespace", namespace) or namespace) == namespace:
            related_secrets.append(serialize_zts_resource(item))

    attestations = (application.get("status", {}) or {}).get("attestations", {})
    payload = {
        "application": application,
        "policy": policy,
        "secretBindings": related_secrets,
        "integrityLedger": _build_integrity_ledger(application, policy),
        "trustCascade": _build_trust_cascade(application, policy, related_secrets),
        "attestations": attestations,
        "provenance": (application.get("status", {}) or {}).get("provenance", {}),
        "revalidation": await _build_revalidation(application, policy, force_oci=force_oci),
        "sbomTree": _build_sbom_tree(attestations),
        "vulnerabilityHeatmap": _build_vulnerability_heatmap(application, policy),
        "sanctionHistory": _build_sanction_history(application, policy),
        "runtimeForensics": await _build_runtime_forensics(application),
    }
    logger.info(
        "Collected integrity payload successfully",
        extra={"details": {"namespace": namespace, "name": name, "policyBound": bool(policy), "secretBindings": len(related_secrets), "sbomPackages": len(attestations.get("sbomPackages", []) or []), "sanctions": len(payload["sanctionHistory"])}})
    return payload


async def list_integrity_applications() -> list[dict[str, Any]]:
    logger.info("Listing integrity-capable applications")
    raw_apps = await scanner.list_custom_resources(plural=ZTA_PLURAL)
    serialized = [serialize_zta_resource(item) for item in raw_apps]
    logger.info("Listed integrity-capable applications successfully", extra={"details": {"count": len(serialized)}})
    return serialized


async def get_application_integrity(namespace: str, name: str) -> dict[str, Any]:
    logger.info("Fetching application integrity", extra={"details": {"namespace": namespace, "name": name}})
    return await _collect_integrity_payload(namespace, name, force_oci=False)


async def revalidate_application_integrity(namespace: str, name: str) -> dict[str, Any]:
    logger.info("Revalidating application integrity", extra={"details": {"namespace": namespace, "name": name}})
    payload = await _collect_integrity_payload(namespace, name, force_oci=True)
    if not payload:
        raise ZeroTrustException(
            error_code="ZTA_NOT_FOUND",
            message="ZeroTrustApplication nu există pentru revalidare.",
            technical_details=f"{namespace}/{name}",
            component="INTEGRITY_ENGINE",
            action_required="Selectează o aplicație validă.",
        )
    return payload