from __future__ import annotations

import os
import re

from typing import Any


def _unique_preserve_order(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _summarize_error_text(message: str) -> str:
    text = str(message or "").strip()
    if not text:
        return ""

    if "manifest spec hash mismatch against expected_infra_hash" in text:
        return "Manifest hash mismatch against attested expected_infra_hash."

    status_match = re.search(r"\((\d{3})\)", text)
    reason_match = re.search(r"Reason:\s*([^\n]+)", text)
    body_match = re.search(r"HTTP response body:\s*([^\n]+)", text)
    if status_match and reason_match:
        body = body_match.group(1).strip() if body_match else ""
        summary = f"Kubernetes API error {status_match.group(1)} {reason_match.group(1).strip()}"
        if body:
          summary += f": {body}"
        return summary

    return text.splitlines()[0].strip()


def _error_category(message: str) -> str:
    text = str(message or "").strip()
    if not text:
        return ""
    if "manifest spec hash mismatch" in text:
        return "Manifest Mismatch"
    if "VulnerabilityPolicy" in text or "trivy" in text.lower():
        return "Compliance Failure"
    if "Reason: Not Found" in text or "404" in text:
        return "Provisioning Error"
    return "Verification Failure"


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
    token = status.get("temporaryToken")
    target_ns = spec.get("targetNamespace", "")
    sa = status.get("temporaryServiceAccount")
    # Isolate from the caller's kubeconfig: a plain `kubectl --token=...` over an admin
    # kubeconfig is ignored (client cert wins), so the command must drop the local creds.
    # The downloadable kubeconfig is the primary path; this is a quick one-liner fallback.
    _apiserver = os.getenv("JIT_EXTERNAL_APISERVER", "").strip() or "<API_SERVER_URL>"
    command_to_use = (
        f"kubectl --kubeconfig=/dev/null --server={_apiserver} "
        f"--insecure-skip-tls-verify=true --token='{token}' -n {target_ns} get pods"
        if token and target_ns
        else None
    )
    requires_approval = bool(spec.get("requiresApproval", True))
    default_state = "PENDING_APPROVAL" if requires_approval else "PENDING"
    return {
        "metadata": _metadata(item),
        "spec": spec,
        "status": status,
        "summary": {
            "developerId": spec.get("developerId"),
            "targetNamespace": target_ns,
            "requestedRole": spec.get("requestedRole"),
            "duration": spec.get("duration"),
            "reason": spec.get("reason"),
            "state": status.get("state") or default_state,
            "expiresAt": status.get("expiresAt"),
            "message": status.get("message"),
            "sessionId": status.get("sessionId"),
            "temporaryToken": token,
            "temporaryServiceAccount": sa,
            "commandToUse": command_to_use,
            "tokenIssued": bool(status.get("tokenIssued", False)),
            "requiresApproval": requires_approval,
            "approved": bool(status.get("approved", False)),
            "approvedBy": status.get("approvedBy"),
            "approvedAt": status.get("approvedAt"),
        },
    }


def serialize_zta_resource(item: dict[str, Any]) -> dict[str, Any]:
    spec = item.get("spec", {}) or {}
    status = item.get("status", {}) or {}
    policy_ref = (spec.get("securityPolicyRef", {}) or {}).get("name")
    active_violations = _unique_preserve_order(status.get("activeViolations", []) or [])
    provenance = status.get("provenance", {}) or {}
    last_error = str(status.get("lastError", "") or "").strip()
    last_error_summary = _summarize_error_text(last_error)
    attestations = status.get("attestations", {}) or {}
    expected_infra_hash = str((attestations.get("expectedInfraHash", "")) or "").strip()
    computed_infra_hash = str((attestations.get("computedInfraHash", "")) or "").strip()
    has_hash_mismatch = bool(
        expected_infra_hash
        and computed_infra_hash
        and expected_infra_hash.lower().removeprefix("sha256:") != computed_infra_hash.lower().removeprefix("sha256:")
    )

    # New surfaces (RFC 6962 Merkle v2, OpenVEX, CEL, audit-mode, async GUAC).
    security_state = str(status.get("securityState", "Unknown") or "Unknown")
    is_audit_alert = security_state.lower() == "alert"
    voucher = (provenance.get("voucher", {}) or {})
    merkle_tree = (voucher.get("merkle_tree", {}) or {}) if isinstance(voucher, dict) else {}
    merkle_version = int(merkle_tree.get("version", 1) or 1) if merkle_tree else int(
        (provenance.get("merkle", {}) or {}).get("merkleVersion", 1) or 1
    )
    merkle_algorithm = str(
        merkle_tree.get("algorithm")
        or (provenance.get("merkle", {}) or {}).get("merkleAlgorithm")
        or "plain-sha256"
    )
    build_context = (voucher.get("build_context", {}) or {}) if isinstance(voucher, dict) else {}
    hmac_chain_predicate = (voucher.get("hmac_chain", {}) or {}) if isinstance(voucher, dict) else {}

    vex_statements = attestations.get("vexStatements", []) or []
    vex_exempted = attestations.get("vexExempted", []) or []
    cel_evaluations = attestations.get("celEvaluations", []) or []

    # OSS security-scan attestation (gitleaks/checkov/semgrep aggregate).
    verifications = status.get("verifications", {}) or {}
    security_scan_verif = verifications.get("securityScan", {}) or {}
    security_scan_summary = attestations.get("securityScanSummary", {}) or {}
    security_scan_findings = attestations.get("securityScanFindings", []) or []
    security_scan = {
        "verified": bool(security_scan_verif.get("passed", False)),
        "reason": str(security_scan_verif.get("reason", "") or ""),
        "gating": str(attestations.get("securityScanGating", "") or ""),
        "commit": str(attestations.get("securityScanCommit", "") or ""),
        "completedAt": security_scan_verif.get("completedAt"),
        "secretsTotal": security_scan_verif.get("secretsTotal", 0),
        "iacHighest": security_scan_verif.get("iacHighest", "NONE"),
        "sastHighest": security_scan_verif.get("sastHighest", "NONE"),
        "findingsCount": security_scan_verif.get(
            "findingsCount", len(security_scan_findings) if isinstance(security_scan_findings, list) else 0
        ),
        "summary": security_scan_summary,
        "findings": security_scan_findings,
        "enforced": bool(security_scan_verif),
    }

    guac_ingestion = {
        "status": str(status.get("guacIngestionStatus", "") or ""),
        "message": str(status.get("guacIngestionMessage", "") or ""),
        "completedAt": status.get("guacIngestionCompletedAt"),
    }

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
            "securityState": security_state,
            "isAuditAlert": is_audit_alert,
            "lastVerified": status.get("lastVerified"),
            "violations": active_violations,
            "hasViolations": bool(active_violations),
            "lastError": last_error,
            "lastErrorSummary": last_error_summary,
            "errorCategory": _error_category(last_error),
            "hasErrors": bool(last_error),
            "expectedInfraHash": expected_infra_hash,
            "computedInfraHash": computed_infra_hash,
            "hasHashMismatch": has_hash_mismatch,
            "provenanceVerifiedAt": provenance.get("verifiedAt"),
            "provenanceRequired": provenance.get("required", False),
            "merkle": {
                "version": merkle_version,
                "algorithm": merkle_algorithm,
                "rfc6962": merkle_version >= 2 or merkle_algorithm == "rfc6962-sha256",
                "rootHash": merkle_tree.get("root_hash")
                or (provenance.get("merkle", {}) or {}).get("computedRoot"),
                "leafCount": (
                    len(merkle_tree.get("leaves", []) or [])
                    if merkle_tree.get("leaves") is not None
                    else (provenance.get("merkle", {}) or {}).get("leafCount")
                ),
            },
            "voucher": {
                "buildContext": build_context,
                "hmacChainProvider": hmac_chain_predicate.get("provider"),
                "slsaLevel": build_context.get("slsa_level") or provenance.get("slsaLevel"),
                "repository": build_context.get("repository") or provenance.get("repository"),
            },
            "vex": {
                "statements": vex_statements,
                "exemptedCveIds": vex_exempted,
                "exemptedCount": len(vex_exempted),
            },
            "celEvaluations": cel_evaluations,
            "guacIngestion": guac_ingestion,
            "securityScan": security_scan,
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
    strict_manifest_hash = spec.get("strictManifestHash", {}) or {}
    custom_rules = spec.get("customRules", []) or []
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
            "strictManifestHash": {
                "enabled": bool(strict_manifest_hash.get("enabled", False)),
                "enforcementAction": str(strict_manifest_hash.get("enforcementAction", "Reject") or "Reject"),
                "isAuditMode": str(strict_manifest_hash.get("enforcementAction", "") or "").lower() == "alert",
            },
            "customRules": [
                {
                    "name": str(rule.get("name", "") or ""),
                    "description": str(rule.get("description", "") or ""),
                    "expression": str(rule.get("expression", "") or ""),
                    "action": str(rule.get("action", "Deny") or "Deny"),
                }
                for rule in custom_rules
                if isinstance(rule, dict)
            ],
            "customRulesCount": len(custom_rules),
        },
    }