from __future__ import annotations

from collections import Counter
import logging
from typing import Any

from app.services.k8s_scanner import JIT_PLURAL, SCA_PLURAL, ZTA_PLURAL, ZTS_PLURAL, scanner
from app.services.serializers import (
    serialize_jit_request,
    serialize_sca_resource,
    serialize_zta_resource,
    serialize_zts_resource,
)

logger = logging.getLogger("zero_trust_overview_service")


def _status_from_bool(value: bool) -> str:
    return "healthy" if value else "degraded"


def _extract_pod_health(pod: dict[str, Any]) -> dict[str, Any]:
    metadata = pod.get("metadata", {}) or {}
    status = pod.get("status", {}) or {}
    container_statuses = status.get("container_statuses", []) or status.get("containerStatuses", []) or []
    ready = sum(1 for item in container_statuses if item.get("ready"))
    total = len(container_statuses)
    restarts = sum(int(item.get("restart_count", item.get("restartCount", 0)) or 0) for item in container_statuses)
    healthy = total > 0 and ready == total and str(status.get("phase", "Unknown")) == "Running"
    return {
        "podName": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "phase": status.get("phase", "Unknown"),
        "readyContainers": ready,
        "totalContainers": total,
        "restartCount": restarts,
        "healthy": healthy,
        "status": _status_from_bool(healthy),
    }


def _build_operator_health(pods: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = [
        ("jit-access", "JIT Access Operator"),
        ("zta-operator", "ZTA/ZTS Operator"),
        ("provenance-enforcer", "Provenance Enforcer"),
        ("external-secrets", "External Secrets"),
    ]
    results: list[dict[str, Any]] = []
    for needle, title in groups:
        matches = [pod for pod in pods if needle in str((pod.get("metadata", {}) or {}).get("name", ""))]
        if not matches:
            results.append({
                "name": title,
                "status": "unknown",
                "healthy": False,
                "pods": [],
            })
            continue
        pod_health = [_extract_pod_health(pod) for pod in matches]
        healthy = all(item["healthy"] for item in pod_health)
        results.append({
            "name": title,
            "status": _status_from_bool(healthy),
            "healthy": healthy,
            "pods": pod_health,
        })
    return results


def _build_recent_events(
    ztas: list[dict[str, Any]],
    ztss: list[dict[str, Any]],
    jits: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for item in ztas:
        metadata = item["metadata"]
        summary = item["summary"]
        status = item["status"]
        if summary["hasViolations"]:
            events.append({
                "kind": "zta-violation",
                "resource": metadata["name"],
                "namespace": metadata["namespace"],
                "severity": "high",
                "message": "; ".join(summary["violations"]),
                "timestamp": metadata["createdAt"],
            })
        if status.get("lastError"):
            events.append({
                "kind": "zta-error",
                "resource": metadata["name"],
                "namespace": metadata["namespace"],
                "severity": "high",
                "message": status.get("lastError"),
                "timestamp": metadata["createdAt"],
            })
    for item in ztss:
        metadata = item["metadata"]
        status = item["status"]
        if status.get("lastError"):
            events.append({
                "kind": "zts-error",
                "resource": metadata["name"],
                "namespace": metadata["namespace"],
                "severity": "medium",
                "message": status.get("lastError"),
                "timestamp": metadata["createdAt"],
            })
    for item in jits:
        metadata = item["metadata"]
        summary = item["summary"]
        state = str(summary.get("state", "PENDING")).upper()
        if state not in {"APPROVED", "ACTIVE", "EXPIRED"}:
            events.append({
                "kind": "jit-state",
                "resource": metadata["name"],
                "namespace": metadata["namespace"],
                "severity": "medium",
                "message": summary.get("message") or f"JIT request is {state}",
                "timestamp": metadata["createdAt"],
            })
    events.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return events[:25]


async def get_cluster_overview() -> dict[str, Any]:
    logger.info("Building cluster overview payload")
    raw_ztas = await scanner.list_custom_resources(plural=ZTA_PLURAL)
    raw_ztss = await scanner.list_custom_resources(plural=ZTS_PLURAL)
    raw_scas = await scanner.list_custom_resources(plural=SCA_PLURAL, cluster_scoped=True)
    raw_jits = await scanner.list_custom_resources(plural=JIT_PLURAL)
    raw_pods = await scanner.list_pods()

    ztas = [serialize_zta_resource(item) for item in raw_ztas]
    ztss = [serialize_zts_resource(item) for item in raw_ztss]
    scas = [serialize_sca_resource(item) for item in raw_scas]
    jits = [serialize_jit_request(item) for item in raw_jits]

    trust_counter = Counter(item["summary"].get("trustLevel", "Untrusted") for item in ztas)
    phase_counter = Counter(item["summary"].get("phase", "Pending") for item in ztas)
    jit_counter = Counter(item["summary"].get("state", "PENDING") for item in jits)
    verified = trust_counter.get("Verified", 0)
    total = len(ztas)
    trust_score = round((verified / total) * 100, 2) if total else 0.0

    payload = {
        "summary": {
            "applications": total,
            "verifiedApplications": verified,
            "degradedApplications": sum(1 for item in ztas if item["summary"].get("securityState") not in {"Compliant", "PendingProvenance"}),
            "secretBindings": len(ztss),
            "supplyChainPolicies": len(scas),
            "jitRequests": len(jits),
        },
        "trustScore": {
            "value": trust_score,
            "verified": verified,
            "total": total,
            "distribution": dict(trust_counter),
        },
        "ztaPhases": dict(phase_counter),
        "jitStates": dict(jit_counter),
        "operatorHealth": _build_operator_health(raw_pods),
        "recentEvents": _build_recent_events(ztas, ztss, jits),
    }
    logger.info("Built cluster overview payload successfully", extra={"details": {"applications": total, "verified": verified, "degraded": payload["summary"]["degradedApplications"], "jitRequests": payload["summary"]["jitRequests"], "recentEvents": len(payload["recentEvents"])}})
    return payload