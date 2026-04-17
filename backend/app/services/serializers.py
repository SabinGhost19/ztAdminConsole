from __future__ import annotations

from typing import Any


def _metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata", {}) or {}
    return {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "uid": metadata.get("uid"),
        "createdAt": metadata.get("creation_timestamp") or metadata.get("creationTimestamp"),
        "labels": metadata.get("labels", {}) or {},
        "annotations": metadata.get("annotations", {}) or {},
    }


def serialize_jit_request(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    return {
        "metadata": _metadata(item),
        "spec": spec,
        "status": status,
        "summary": {
            "developerId": spec.get("developerId"),
            "targetNamespace": spec.get("targetNamespace"),
            "requestedRole": spec.get("requestedRole"),
            "duration": spec.get("duration"),
            "reason": spec.get("reason"),
            "state": status.get("state", "PENDING"),
            "expiresAt": status.get("expiresAt"),
            "message": status.get("message"),
            "sessionId": status.get("sessionId"),
        },
    }


def serialize_zta_resource(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    policy_ref = (spec.get("securityPolicyRef", {}) or {}).get("name")
    active_violations = status.get("activeViolations", []) or []
    provenance = status.get("provenance", {}) or {}
    last_error = str(status.get("lastError", "") or "").strip()
    expected_infra_hash = str((((status.get("attestations", {}) or {}).get("expectedInfraHash", "")) or "")).strip()
    computed_infra_hash = str((((status.get("attestations", {}) or {}).get("computedInfraHash", "")) or "")).strip()
    has_hash_mismatch = bool(
        expected_infra_hash
        and computed_infra_hash
        and expected_infra_hash.lower().removeprefix("sha256:") != computed_infra_hash.lower().removeprefix("sha256:")
    )
    return {
        "metadata": _metadata(item),
        "spec": spec,
        "status": status,
        "summary": {
            "image": spec.get("image"),
            "replicas": spec.get("replicas", 1),
            "securityPolicyRef": policy_ref,
            "phase": status.get("phase", "Pending"),
            "trustLevel": status.get("trustLevel", "Untrusted"),
            "securityState": status.get("securityState", "Unknown"),
            "lastVerified": status.get("lastVerified"),
            "violations": active_violations,
            "hasViolations": bool(active_violations),
            "lastError": last_error,
            "hasErrors": bool(last_error),
            "expectedInfraHash": expected_infra_hash,
            "computedInfraHash": computed_infra_hash,
            "hasHashMismatch": has_hash_mismatch,
            "provenanceVerifiedAt": provenance.get("verifiedAt"),
            "provenanceRequired": provenance.get("required", False),
        },
    }


def serialize_zts_resource(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    application_ref = spec.get("applicationRef", {}) or {}
    target_workload = spec.get("targetWorkload", {}) or {}
    lifecycle = spec.get("lifecycle", {}) or {}
    return {
        "metadata": _metadata(item),
        "spec": spec,
        "status": status,
        "summary": {
            "applicationRef": application_ref,
            "targetWorkload": target_workload,
            "targetSecretName": status.get("targetSecretName") or spec.get("targetSecretName"),
            "phase": status.get("phase", "Pending"),
            "lastRotationChecksum": status.get("lastRotationChecksum"),
            "refreshInterval": lifecycle.get("refreshInterval", "10m"),
            "onUpdateAction": lifecycle.get("onUpdateAction", "RollingRestart"),
        },
    }


def serialize_sca_resource(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec", {}) or {}
    source_validation = spec.get("sourceValidation", {}) or {}
    provenance = spec.get("provenance", {}) or {}
    vulnerability_policy = spec.get("vulnerabilityPolicy", {}) or {}
    runtime = spec.get("runtimeEnforcement", {}) or {}
    sbom_policy = spec.get("sbomPolicy", {}) or {}
    return {
        "metadata": _metadata(item),
        "spec": spec,
        "summary": {
            "enforceCosign": source_validation.get("enforceCosign", True),
            "trustedIssuers": source_validation.get("trustedIssuers", []) or [],
            "requireVoucher": provenance.get("requireVoucher", False),
            "enforceHmacChain": provenance.get("enforceHmacChain", True),
            "minSlsaLevel": provenance.get("minSlsaLevel", 0),
            "trustedRepositories": provenance.get("trustedRepositories", []) or [],
            "maxAllowedSeverity": vulnerability_policy.get("maxAllowedSeverity"),
            "failOnFixable": vulnerability_policy.get("failOnFixable", False),
            "enforceSBOM": sbom_policy.get("enforceSBOM", True),
            "forbiddenPackages": sbom_policy.get("forbiddenPackages", []) or [],
            "onPolicyDrift": runtime.get("onPolicyDrift", "Isolate"),
            "onVulnerabilityFound": runtime.get("onVulnerabilityFound", "Alert"),
        },
    }