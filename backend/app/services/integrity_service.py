from __future__ import annotations

import logging
import os
from typing import Any

from kubernetes_asyncio import client

from app.core.k8s import get_core_api
from app.middleware.errors import ZeroTrustException
from app.services.state_cache import get_integrity_snapshot_record, set_integrity_snapshot
from app.services.provenance_revalidation import RevalidationError, revalidate_vbbi
from app.services.k8s_scanner import SCA_PLURAL, ZTA_PLURAL, ZTS_PLURAL, scanner
from app.services.serializers import serialize_sca_resource, serialize_zta_resource, serialize_zts_resource

TALON_NAMESPACE = os.getenv("TALON_NAMESPACE", "falco-talon")
TALON_CONFIGMAP_NAME = os.getenv("TALON_CONFIGMAP_NAME", "falco-talon-rules")
TALON_CONFIGMAP_KEY = os.getenv("TALON_CONFIGMAP_KEY", "rules.yaml")
logger = logging.getLogger("zero_trust_integrity_service")


def _with_cache_details(payload: dict[str, Any], cache_record: dict[str, Any] | None) -> dict[str, Any]:
    if cache_record is None:
        return payload

    response = dict(payload)
    response["_cache"] = {
        "cacheKey": cache_record.get("cacheKey"),
        "stateType": cache_record.get("stateType"),
        "stateVersion": cache_record.get("stateVersion"),
        "status": cache_record.get("status"),
        "fingerprint": cache_record.get("fingerprint"),
        "metadata": cache_record.get("metadata", {}),
        "updatedAt": cache_record.get("updatedAt"),
        "accessedAt": cache_record.get("accessedAt"),
    }
    return response


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


def _aggregate_messages(values: list[Any]) -> list[dict[str, Any]]:
    ordered_counts: dict[str, int] = {}
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        ordered_counts[normalized] = ordered_counts.get(normalized, 0) + 1
    return [{"message": message, "count": count} for message, count in ordered_counts.items()]


def _build_integrity_ledger(application: dict[str, Any], policy: dict[str, Any] | None) -> list[dict[str, Any]]:
    status = application.get("status", {}) or {}
    summary = application.get("summary", {}) or {}
    provenance = status.get("provenance", {}) or {}
    hmac_chain = provenance.get("hmacChain", {}) or {}
    merkle = provenance.get("merkle", {}) or {}
    voucher_required = bool(((policy or {}).get("summary", {}) or {}).get("requireVoucher", False))
    has_verified_at = bool(provenance.get("verifiedAt"))
    summarized_error = summary.get("lastErrorSummary") or summary.get("lastError")
    ledger = [
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
            "status": "error" if summary.get("lastError") else ("verified" if summary.get("trustLevel") == "Verified" else "blocked"),
            "details": {
                "trustLevel": summary.get("trustLevel"),
                "securityState": summary.get("securityState"),
                "violations": _aggregate_messages(summary.get("violations", [])),
                "lastError": summarized_error,
            },
        },
    ]

    expected_hash = str(summary.get("expectedInfraHash", "") or "").strip()
    computed_hash = str(summary.get("computedInfraHash", "") or "").strip()
    if expected_hash or computed_hash:
        ledger.append(
            {
                "id": "manifest-hash",
                "title": "Manifest Hash",
                "status": "error" if summary.get("hasHashMismatch") else "verified",
                "details": {
                    "expected": expected_hash,
                    "computed": computed_hash,
                    "mismatch": bool(summary.get("hasHashMismatch")),
                },
            }
        )

    if summary.get("lastError"):
        ledger.insert(
            0,
            {
                "id": "operator-error",
                "title": summary.get("errorCategory") or "Verification Failure",
                "status": "error",
                "details": summarized_error,
            },
        )

    return ledger


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
    active_violations = _unique_preserve_order((application.get("status", {}) or {}).get("activeViolations", []) or [])
    threshold = ((policy or {}).get("summary", {}) or {}).get("maxAllowedSeverity")
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    severity_counts = details.get("severityCounts", {}) or {}
    for key in counts:
        counts[key] = int(severity_counts.get(key, severity_counts.get(key.lower(), 0)) or 0)
    highest = str(details.get("highest", details.get("severity", ""))).upper().strip()
    if highest in counts and sum(counts.values()) == 0:
        counts[highest] = 1

    # Fallback for alert-only Trivy outputs where severityCounts is absent in status.details.
    if sum(counts.values()) == 0:
        threshold_upper = str(threshold or "HIGH").upper().strip()
        if "trivy-fixable-vulnerability-found" in " ".join(active_violations).lower():
            inferred = threshold_upper if threshold_upper in counts else "HIGH"
            counts[inferred] = 1
            highest = highest or inferred

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
            "severity": "success",
            "timestamp": summary.get("provenanceVerifiedAt"),
            "message": "Provenance-Enforcer marked the workload as verified.",
        })
    for entry in _aggregate_messages(status.get("activeViolations", []) or []):
        message = entry["message"]
        count = int(entry["count"])
        history.append({
            "kind": "violation",
            "action": runtime.get("onPolicyDrift", "Alert"),
            "severity": "error",
            "timestamp": status.get("lastVerified") or application.get("metadata", {}).get("createdAt"),
            "message": f"{message} (x{count})" if count > 1 else message,
        })
    if status.get("securityState") and status.get("securityState") not in {"Compliant", "PendingProvenance"}:
        history.append({
            "kind": "security-state",
            "action": status.get("securityState"),
            "severity": "error",
            "timestamp": status.get("lastVerified") or application.get("metadata", {}).get("createdAt"),
            "message": summary.get("lastErrorSummary") or status.get("lastError") or "Security state changed due to operator enforcement.",
        })
    deduped_history: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in history:
        key = (str(item.get("kind", "")), str(item.get("action", "")), str(item.get("message", "")))
        if key in seen:
            continue
        seen.add(key)
        deduped_history.append(item)
    return deduped_history


def _build_provisioning_plan(application: dict[str, Any]) -> list[dict[str, Any]]:
    spec = application.get("spec", {}) or {}
    network = spec.get("networkZeroTrust", {}) or {}
    ingress = network.get("ingressAllowedFrom", []) or []
    egress = network.get("egressAllowedTo", []) or []
    has_waf = bool(spec.get("wafConfig", {}))
    has_runtime = bool(spec.get("runtimeSecurity", {}))

    return [
        {
            "id": "deployment",
            "title": "Kubernetes Deployment",
            "kind": "apps/v1 Deployment",
            "enabled": True,
            "reason": "Always created for ZeroTrustApplication workload.",
        },
        {
            "id": "service",
            "title": "Kubernetes Service",
            "kind": "v1 Service",
            "enabled": True,
            "reason": "Always created for service discovery and traffic exposure.",
        },
        {
            "id": "networkpolicy",
            "title": "Microsegmentation Policy",
            "kind": "networking.k8s.io/v1 NetworkPolicy",
            "enabled": bool(ingress or egress),
            "reason": "Created only if ingress/egress constraints are declared in networkZeroTrust.",
        },
        {
            "id": "authorizationpolicy",
            "title": "Istio AuthorizationPolicy",
            "kind": "security.istio.io AuthorizationPolicy",
            "enabled": has_waf,
            "reason": "Created only when wafConfig is present.",
        },
        {
            "id": "wasmplugin",
            "title": "Istio WasmPlugin (Coraza)",
            "kind": "extensions.istio.io WasmPlugin",
            "enabled": has_waf,
            "reason": "Created only when wafConfig is present.",
        },
        {
            "id": "falco-rule-configmap",
            "title": "Falco Rule ConfigMap",
            "kind": "v1 ConfigMap",
            "enabled": has_runtime,
            "reason": "Created only when runtimeSecurity is present.",
        },
        {
            "id": "talon-patch",
            "title": "Talon Runtime Rule Patch",
            "kind": "Falco Talon ConfigMap patch",
            "enabled": has_runtime,
            "reason": "Patched only when runtimeSecurity is present.",
        },
    ]


def _build_reconcile_flow(application: dict[str, Any], policy: dict[str, Any] | None, provisioning_plan: list[dict[str, Any]]) -> dict[str, Any]:
    summary = application.get("summary", {}) or {}
    status = application.get("status", {}) or {}
    phase = str(summary.get("phase", "Pending") or "Pending")
    trust_level = str(summary.get("trustLevel", "Untrusted") or "Untrusted")
    security_state = str(summary.get("securityState", "Unknown") or "Unknown")
    has_error = bool(summary.get("lastError"))
    hash_mismatch = bool(summary.get("hasHashMismatch"))
    provenance_required = bool(((status.get("provenance", {}) or {}).get("required", False)) or (((policy or {}).get("summary", {}) or {}).get("requireVoucher", False)))

    def _stage_status(stage_id: str) -> str:
        if stage_id == "manifest":
            return "success"

        if stage_id == "provenance":
            if not provenance_required:
                return "skipped"
            if trust_level == "Verified":
                return "success"
            if trust_level == "UntrustedProvenance":
                return "failed"
            if phase in {"Pending", "Validating"}:
                return "running"
            return "pending"

        if stage_id == "supply-chain":
            if phase == "Validating":
                return "running"
            if phase == "Failed_SupplyChain":
                return "failed"
            if security_state == "Alert":
                return "warning"
            if trust_level == "Verified":
                return "success"
            return "pending"

        if stage_id == "attestation":
            if hash_mismatch:
                return "failed"
            if summary.get("expectedInfraHash") or summary.get("computedInfraHash"):
                return "success"
            return "pending"

        if stage_id == "resource-plan":
            return "success"

        if stage_id == "provisioning":
            if has_error and phase in {"Degraded", "Failed_SupplyChain"}:
                return "failed"
            if phase == "Provisioning":
                return "running"
            if phase in {"Running", "Degraded"}:
                return "success"
            return "pending"

        if stage_id == "runtime":
            runtime_enabled = any(item.get("id") == "falco-rule-configmap" and item.get("enabled") for item in provisioning_plan)
            if not runtime_enabled:
                return "skipped"
            if has_error and phase in {"Degraded", "Failed_SupplyChain"}:
                return "failed"
            if phase == "Provisioning":
                return "running"
            return "success" if phase in {"Running", "Degraded"} else "pending"

        if stage_id == "ready":
            if phase in {"Failed_SupplyChain"}:
                return "failed"
            if security_state == "Alert":
                return "warning"
            if phase == "Running" and trust_level == "Verified":
                return "success"
            if phase == "Running":
                return "warning"
            if phase == "Provisioning":
                return "running"
            return "pending"

        return "pending"

    stages = [
        {"id": "manifest", "title": "Manifest Accepted", "description": "ZeroTrustApplication parsed and admitted."},
        {"id": "provenance", "title": "Provenance Gate", "description": "VBBI voucher, HMAC chain, and Merkle verification."},
        {"id": "supply-chain", "title": "Supply-Chain Scan", "description": "Cosign + Trivy policy checks."},
        {"id": "attestation", "title": "Attestation Binding", "description": "SCA policy matching and manifest hash validation."},
        {"id": "resource-plan", "title": "Resource Planning", "description": "Determine optional Istio/Falco/Talon resources from manifest."},
        {"id": "provisioning", "title": "Provisioning", "description": "Apply Deployment, Service, and optional resources."},
        {"id": "runtime", "title": "Runtime Enforcement", "description": "Configure Falco/Talon runtime controls if enabled."},
        {"id": "ready", "title": "Operational State", "description": "Final security state exposed to dashboard."},
    ]

    # User-facing waiting messages shown under spinning stages so the user
    # understands why a step is taking time (reduces anxiety vs. silent spin).
    last_error = str(summary.get("lastError") or "").strip()
    waiting_messages = {
        "provenance": (
            "Waiting for CI/CD pipeline to issue a VBBI voucher (status.trustLevel ≠ Verified)."
            if security_state != "WaitingForPolicy" else
            "Waiting for the referenced SupplyChainAttestation to be created in the cluster."
        ),
        "supply-chain": "Running cosign verify + trivy image scan (up to 5 minutes for large images).",
        "provisioning": "Applying Deployment, Service, NetworkPolicy and optional Istio/Falco resources.",
    }
    # If the operator reported WaitingForPolicy state, the provenance stage
    # is not the right place — bubble that message up to the supply-chain stage.
    if security_state == "WaitingForPolicy" and last_error:
        waiting_messages["supply-chain"] = last_error

    decorated = []
    active = None
    for stage in stages:
        status_value = _stage_status(stage["id"])
        if active is None and status_value == "running":
            active = stage["id"]
        stage_payload = {**stage, "status": status_value}
        if status_value == "running" and stage["id"] in waiting_messages:
            stage_payload["message"] = waiting_messages[stage["id"]]
        subtasks = _build_stage_subtasks(
            stage["id"], status_value, application, policy, provisioning_plan,
            phase=phase, trust_level=trust_level, security_state=security_state,
            last_error=last_error,
        )
        if subtasks:
            stage_payload["subtasks"] = subtasks
        decorated.append(stage_payload)

    return {
        "phase": phase,
        "trustLevel": trust_level,
        "securityState": security_state,
        "activeStage": active,
        "stages": decorated,
    }


_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE")


def _max_severity_from_counts(counts: dict[str, Any]) -> str:
    """Highest non-zero severity bucket present in a severityCounts dict."""
    if not isinstance(counts, dict):
        return ""
    for sev in _SEVERITY_ORDER:
        try:
            if int(counts.get(sev, counts.get(sev.lower(), 0)) or 0) > 0:
                return sev
        except (TypeError, ValueError):
            continue
    return ""


def _severity_from_reason(text: str) -> str:
    """Pull a severity hint out of an error/violation message as a fallback."""
    upper = (text or "").upper()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in upper:
            return sev
    return ""


def _build_stage_subtasks(
    stage_id: str,
    stage_status: str,
    application: dict[str, Any],
    policy: dict[str, Any] | None,
    provisioning_plan: list[dict[str, Any]],
    *,
    phase: str,
    trust_level: str,
    security_state: str,
    last_error: str,
) -> list[dict[str, Any]]:
    """Granular forensics breakdown shown when the user clicks a stage node.

    Surfaces *why* a high-level step failed (e.g. "Cosign ok but Trivy
    found a CRITICAL CVE") so the dashboard becomes a diagnostic tool
    rather than a binary pass/fail display.
    """
    err = last_error.lower()
    status = application.get("status", {}) or {}
    summary = application.get("summary", {}) or {}
    attestations = status.get("attestations", {}) or {}
    details = status.get("details", {}) or {}
    verifications = status.get("verifications", {}) or {}
    policy_summary = (policy or {}).get("summary", {}) or {}
    past_supply_chain = phase in {"Provisioning", "Running", "Degraded"}

    def _verif_subtask(key: str, *, legacy_status: str, legacy_detail: str) -> dict[str, Any]:
        """Prefer the structured status.verifications.<key> entry written
        by the operator; fall back to legacy regex-derived status."""
        entry = verifications.get(key) if isinstance(verifications, dict) else None
        if isinstance(entry, dict) and ("passed" in entry):
            return {
                "status": "success" if bool(entry.get("passed")) else "failed",
                "detail": str(entry.get("reason") or "") or legacy_detail,
            }
        return {"status": legacy_status, "detail": legacy_detail}

    if stage_id == "supply-chain":
        # Cosign keyless verification
        if "cosign" in err and ("verification" in err or "verify" in err or "signature" in err):
            cosign_legacy = ("failed", "Signature verification failed against all trusted issuers.")
        elif past_supply_chain or security_state == "Alert":
            cosign_legacy = ("success", "Image signature valid (keyless OIDC via GitHub Actions).")
        elif phase == "Validating":
            cosign_legacy = ("running", "Verifying signature against trusted OIDC identities...")
        else:
            cosign_legacy = ("pending", "Awaiting supply-chain scan.")
        cosign = _verif_subtask("cosign", legacy_status=cosign_legacy[0], legacy_detail=cosign_legacy[1])

        # Trivy vulnerability scan — prefer status.verifications.trivy if present.
        trivy_entry = verifications.get("trivy") if isinstance(verifications, dict) else None
        if isinstance(trivy_entry, dict) and "passed" in trivy_entry:
            if bool(trivy_entry.get("passed")):
                highest = trivy_entry.get("highest") or details.get("highest", "NONE")
                trivy = {"status": "success", "detail": f"No vulnerabilities above policy threshold (highest found: {highest})."}
            else:
                trivy = {"status": "failed", "detail": str(trivy_entry.get("reason") or "Trivy policy violation.")}
        elif "trivy-threshold-exceeded" in err:
            highest = details.get("highest", "?")
            threshold = details.get("threshold", "?")
            trivy = {"status": "failed", "detail": f"Found {highest} severity vulnerability — policy threshold is {threshold}."}
        elif "trivy-fixable" in err:
            trivy = {"status": "failed", "detail": "Fixable vulnerabilities detected (failOnFixable=true blocks deploy)."}
        elif "trivy-scan-failed" in err:
            trivy = {"status": "failed", "detail": "Trivy scanner returned non-zero exit code."}
        elif security_state == "Alert":
            # Derive highest severity from multiple sources: explicit
            # `status.details.highest`, then `severityCounts`, then the
            # violation reason string as a last resort. Avoids the bare "?"
            # we used to show when the operator overwrote details on a
            # follow-up reconcile.
            highest = (
                str(details.get("highest", "") or "").strip()
                or _max_severity_from_counts(details.get("severityCounts") or {})
                or _severity_from_reason(" ".join(str(v) for v in (status.get("activeViolations") or [])))
                or "above threshold"
            )
            threshold = str(details.get("threshold", "") or "").strip() or (policy_summary.get("maxAllowedSeverity") or "policy threshold")
            trivy = {
                "status": "warning",
                "detail": f"Vulnerabilities above threshold present (highest: {highest}, threshold: {threshold}) — runtimeEnforcement.onVulnerabilityFound=Alert allows deploy with warning.",
            }
        elif past_supply_chain:
            highest = details.get("highest", "NONE")
            trivy = {"status": "success", "detail": f"No vulnerabilities above policy threshold (highest found: {highest})."}
        elif cosign["status"] == "running":
            trivy = {"status": "pending", "detail": "Awaiting cosign to pass."}
        elif phase == "Validating":
            trivy = {"status": "running", "detail": "Scanning image for CVEs via Trivy..."}
        else:
            trivy = {"status": "pending", "detail": "Awaiting supply-chain scan."}

        return [
            {"id": "cosign", "title": "Cosign Keyless Verification", **cosign},
            {"id": "trivy", "title": "Trivy Vulnerability Scan", **trivy},
        ]

    if stage_id == "attestation":
        out = []
        resolved = str(attestations.get("resolvedImage", "")).strip()
        out.append({
            "id": "digest",
            "title": "Image Digest Resolution",
            "status": "success" if resolved else ("running" if phase == "Validating" else "pending"),
            "detail": (resolved[:80] + "...") if len(resolved) > 80 else (resolved or "cosign triangulate <image>"),
        })
        if bool(policy_summary.get("enforceSBOM")):
            sbom_packages = attestations.get("sbomPackages", []) or []
            sbom_digest = attestations.get("sbomDigest", "")
            out.append({
                "id": "sbom",
                "title": "SBOM Attestation",
                "status": "success" if sbom_digest else ("running" if phase == "Validating" else "pending"),
                "detail": f"{len(sbom_packages)} packages attested" if sbom_digest else "Awaiting verify-attestation spdxjson",
            })
        policy_digest = attestations.get("policyDigest", "")
        if policy_summary.get("requireVoucher") or policy_digest:
            out.append({
                "id": "policy-attestation",
                "title": "Custom ZTA Policy Attestation",
                "status": "success" if policy_digest else ("running" if phase == "Validating" else "pending"),
                "detail": f"sha256:{policy_digest[:24]}..." if policy_digest else "Awaiting verify-attestation custom-zta-policy/v1",
            })
        expected = str(summary.get("expectedInfraHash", "") or "").strip()
        computed = str(summary.get("computedInfraHash", "") or "").strip()
        hash_mismatch = bool(summary.get("hasHashMismatch"))
        if expected or computed:
            out.append({
                "id": "manifest-hash",
                "title": "Manifest Hash Match",
                "status": "failed" if hash_mismatch else "success",
                "detail": (
                    f"MISMATCH — expected={expected[:16]}... computed={computed[:16]}..."
                    if hash_mismatch else
                    f"Match — sha256:{(computed or expected)[:24]}..."
                ),
            })
        # SLSA v1.0 provenance — only surfaced if the operator recorded an
        # entry under status.verifications.slsaProvenance (enforced via SCA
        # slsaProvenancePolicy.enforceSlsa). Otherwise hidden so we don't
        # show a fake "pending" line for clusters that don't require SLSA.
        slsa_entry = verifications.get("slsaProvenance") if isinstance(verifications, dict) else None
        if isinstance(slsa_entry, dict) and "passed" in slsa_entry:
            out.append({
                "id": "slsa-provenance",
                "title": "SLSA v1.0 Provenance",
                "status": "success" if bool(slsa_entry.get("passed")) else "failed",
                "detail": str(slsa_entry.get("reason") or "") or (
                    f"builder={slsa_entry.get('builderId', '')} buildType={slsa_entry.get('buildType', '')}"
                ),
            })
        openvex_entry = verifications.get("openvex") if isinstance(verifications, dict) else None
        if isinstance(openvex_entry, dict) and "passed" in openvex_entry:
            out.append({
                "id": "openvex",
                "title": "OpenVEX Signed Attestation",
                "status": "success" if bool(openvex_entry.get("passed")) else "failed",
                "detail": str(openvex_entry.get("reason") or "") or (
                    f"{openvex_entry.get('statementCount', 0)} statements"
                ),
            })
        return out

    if stage_id == "provisioning":
        if phase == "Running":
            base = "success"
        elif phase == "Provisioning":
            base = "running"
        elif phase in {"Degraded", "Failed_SupplyChain"} and last_error:
            base = "failed"
        else:
            base = "pending"
        return [
            {
                "id": item["id"],
                "title": item["title"],
                "status": "skipped" if not item.get("enabled") else base,
                "detail": item.get("kind", "") + (" — " + str(item.get("reason", "")) if item.get("reason") else ""),
            }
            for item in provisioning_plan
        ]

    if stage_id == "provenance":
        provenance = status.get("provenance", {}) or {}
        hmac = provenance.get("hmacChain", {}) or {}
        merkle = provenance.get("merkle", {}) or {}
        out: list[dict[str, Any]] = []
        voucher_ts = provenance.get("verifiedAt")
        if trust_level == "UntrustedProvenance":
            voucher_status, voucher_detail = "failed", str(provenance.get("reason") or "Provenance verification rejected by enforcer.")
        elif voucher_ts:
            voucher_status, voucher_detail = "success", f"Voucher verified at {voucher_ts}"
        elif stage_status == "running":
            voucher_status, voucher_detail = "running", "Waiting for Provenance-Enforcer to mark trustLevel=Verified"
        else:
            voucher_status, voucher_detail = "pending", "No voucher issued yet"
        out.append({"id": "voucher", "title": "VBBI Voucher Presence", "status": voucher_status, "detail": voucher_detail})
        if hmac:
            out.append({
                "id": "hmac",
                "title": "HMAC Chain",
                "status": "success" if hmac.get("verified") else "pending",
                "detail": f"{hmac.get('steps', 0)} CI/CD steps verified" if hmac.get("verified") else "Awaiting hmac chain validation",
            })
        if merkle:
            out.append({
                "id": "merkle",
                "title": "Merkle Root",
                "status": "success" if merkle.get("verified") else "pending",
                "detail": f"leafCount={merkle.get('leafCount', 0)} root={(merkle.get('root') or '')[:16]}..." if merkle.get("verified") else "Awaiting merkle validation",
            })
        return out

    if stage_id == "runtime":
        runtime_enabled = any(item.get("id") == "falco-rule-configmap" and item.get("enabled") for item in provisioning_plan)
        if not runtime_enabled:
            return [{"id": "runtime-disabled", "title": "Runtime Enforcement", "status": "skipped", "detail": "spec.runtimeSecurity not declared — Falco/Talon resources skipped."}]
        return [
            {"id": "falco-rule", "title": "Falco Custom Rule ConfigMap", "status": "success" if phase in {"Running", "Degraded"} else ("running" if phase == "Provisioning" else "pending"), "detail": f"falco-rule-{summary.get('image', 'app')[:30]}"},
            {"id": "talon-patch", "title": "Falco Talon Rule Patch", "status": "success" if phase in {"Running", "Degraded"} else ("running" if phase == "Provisioning" else "pending"), "detail": "Patched falco-talon-rules ConfigMap"},
        ]

    return []


async def _build_runtime_forensics(application: dict[str, Any]) -> dict[str, Any]:
    metadata = application.get("metadata", {}) or {}
    spec = application.get("spec", {}) or {}
    status = application.get("status", {}) or {}
    namespace = str(metadata.get("namespace", "default"))
    name = str(metadata.get("name", ""))
    local_configmap_name = f"falco-rule-{name}"
    expected_rule_name = f"Unauthorized_Write_{namespace}_{name}".replace("-", "_")
    core = get_core_api()

    local_rule = None
    talon_rules = None
    talon_cm_missing = False
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
    except client.exceptions.ApiException as exc:
        talon_rules = None
        if int(getattr(exc, "status", 0) or 0) == 404:
            talon_cm_missing = True

    # Pull the operator-authored status block. When the operator hits a
    # missing Falco/Talon stack at provisioning time, it sets
    # status.runtimeEnforcement.{installed:false, missing:[...]}. We pass
    # that through verbatim so the UI can render an informational banner
    # distinct from "rule expected but not patched".
    runtime_enforcement = status.get("runtimeEnforcement", {}) or {}
    requested = bool(spec.get("runtimeSecurity"))
    # Heuristic fallback for older operators that don't write the field.
    if "installed" not in runtime_enforcement:
        if requested and talon_cm_missing:
            runtime_enforcement = {
                "requested": True,
                "installed": False,
                "talonRulePatched": False,
                "missing": [f"ConfigMap {TALON_NAMESPACE}/{TALON_CONFIGMAP_NAME}"],
                "reason": "Talon ConfigMap not found (Falco/Talon Helm charts not installed).",
            }
        else:
            runtime_enforcement = {
                "requested": requested,
                "installed": None,
                "talonRulePatched": bool(talon_rules and expected_rule_name in talon_rules),
                "missing": [],
                "reason": "",
            }

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
        # New: structured Falco/Talon infrastructure availability info.
        "infrastructure": {
            "requested": bool(runtime_enforcement.get("requested", requested)),
            "installed": runtime_enforcement.get("installed"),
            "missing": list(runtime_enforcement.get("missing", []) or []),
            "reason": str(runtime_enforcement.get("reason", "") or ""),
            "talonRulePatched": bool(runtime_enforcement.get("talonRulePatched", False)),
        },
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
    provisioning_plan = _build_provisioning_plan(application)
    payload = {
        "application": application,
        "policy": policy,
        "secretBindings": related_secrets,
        "integrityLedger": _build_integrity_ledger(application, policy),
        "trustCascade": _build_trust_cascade(application, policy, related_secrets),
        "reconcileFlow": _build_reconcile_flow(application, policy, provisioning_plan),
        "provisioningPlan": provisioning_plan,
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

    # Always fetch fresh K8s state so the dashboard reflects operator progress
    # in real time and correctly handles delete+recreate of the same ZTA name.
    payload = await _collect_integrity_payload(namespace, name, force_oci=False)
    if payload:
        set_integrity_snapshot(namespace, name, payload)
        cached_record = get_integrity_snapshot_record(namespace, name)
        return _with_cache_details(payload, cached_record)

    return _with_cache_details({}, None)


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
    set_integrity_snapshot(namespace, name, payload)
    return _with_cache_details(payload, get_integrity_snapshot_record(namespace, name))