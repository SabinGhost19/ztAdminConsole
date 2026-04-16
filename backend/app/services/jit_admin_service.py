from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any

from kubernetes_asyncio import client

from app.core.k8s import get_core_api
from app.middleware.errors import ZeroTrustException
from app.services.k8s_scanner import JIT_PLURAL, scanner
from app.services.serializers import serialize_jit_request

JIT_POLICIES_CONFIGMAP = os.getenv("JIT_POLICIES_CONFIGMAP", "jit-security-policies")
JIT_POLICIES_NAMESPACE = os.getenv("JIT_POLICIES_NAMESPACE", "jit-system")
logger = logging.getLogger("zero_trust_jit_admin_service")


async def _resolve_policy_configmap() -> tuple[str, client.V1ConfigMap]:
    core = get_core_api()
    logger.info("Resolving JIT policy ConfigMap", extra={"details": {"namespace": JIT_POLICIES_NAMESPACE, "name": JIT_POLICIES_CONFIGMAP}})
    try:
        config_map = await core.read_namespaced_config_map(
            name=JIT_POLICIES_CONFIGMAP,
            namespace=JIT_POLICIES_NAMESPACE,
        )
        logger.info("Resolved JIT policy ConfigMap in preferred namespace", extra={"details": {"namespace": JIT_POLICIES_NAMESPACE, "name": JIT_POLICIES_CONFIGMAP}})
        return JIT_POLICIES_NAMESPACE, config_map
    except client.exceptions.ApiException as exc:
        if exc.status != 404:
            logger.exception("Failed resolving JIT policy ConfigMap in preferred namespace", extra={"details": {"namespace": JIT_POLICIES_NAMESPACE, "name": JIT_POLICIES_CONFIGMAP, "status": exc.status}})
            raise

    config_maps = await core.list_config_map_for_all_namespaces(field_selector=f"metadata.name={JIT_POLICIES_CONFIGMAP}")
    items = config_maps.items or []
    if not items:
        raise ZeroTrustException(
            error_code="JIT_POLICY_CONFIGMAP_NOT_FOUND",
            message="ConfigMap-ul de politici JIT nu a putut fi găsit.",
            technical_details=f"Expected {JIT_POLICIES_NAMESPACE}/{JIT_POLICIES_CONFIGMAP}",
            component="JIT_POLICY_EDITOR",
            action_required="Instalează chartul jit-access sau configurează JIT_POLICIES_NAMESPACE corect.",
        )
    config_map = items[0]
    logger.info("Resolved JIT policy ConfigMap by cluster-wide fallback", extra={"details": {"namespace": str(config_map.metadata.namespace), "name": JIT_POLICIES_CONFIGMAP}})
    return str(config_map.metadata.namespace), config_map


def _parse_policies(data: dict[str, str] | None) -> dict[str, Any]:
    payload = data or {}
    try:
        blocked_users = json.loads(payload.get("blockedUsers.json", "[]"))
    except json.JSONDecodeError:
        blocked_users = []

    try:
        anti_abuse = json.loads(payload.get("antiAbuse.json", "{}"))
    except json.JSONDecodeError:
        anti_abuse = {}

    return {
        "blockedUsers": sorted(str(item).strip() for item in blocked_users if str(item).strip()),
        "antiAbuse": {
            "maxActiveSessions": int(anti_abuse.get("maxActiveSessions", 1) or 1),
            "cooldownMinutes": int(anti_abuse.get("cooldownMinutes", 15) or 15),
            "maxRequestsPerDay": int(anti_abuse.get("maxRequestsPerDay", 5) or 5),
            "maxDurationMinutes": int(anti_abuse.get("maxDurationMinutes", 120) or 120),
        },
    }


async def get_jit_policies() -> dict[str, Any]:
    namespace, config_map = await _resolve_policy_configmap()
    policies = _parse_policies(config_map.data)
    logger.info("Loaded JIT policies", extra={"details": {"namespace": namespace, "name": config_map.metadata.name, "blockedUsers": len(policies.get("blockedUsers", []))}})
    return {
        "namespace": namespace,
        "name": config_map.metadata.name,
        **policies,
    }


async def update_jit_policies(payload: dict[str, Any]) -> dict[str, Any]:
    namespace, config_map = await _resolve_policy_configmap()
    blocked_users = sorted({str(item).strip() for item in (payload.get("blockedUsers", []) or []) if str(item).strip()})
    anti_abuse = payload.get("antiAbuse", {}) or {}

    updated_data = dict(config_map.data or {})
    updated_data["blockedUsers.json"] = json.dumps(blocked_users, indent=2)
    updated_data["antiAbuse.json"] = json.dumps(
        {
            "maxActiveSessions": int(anti_abuse.get("maxActiveSessions", 1) or 1),
            "cooldownMinutes": int(anti_abuse.get("cooldownMinutes", 15) or 15),
            "maxRequestsPerDay": int(anti_abuse.get("maxRequestsPerDay", 5) or 5),
            "maxDurationMinutes": int(anti_abuse.get("maxDurationMinutes", 120) or 120),
        },
        indent=2,
    )

    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=config_map.metadata.name), data=updated_data)
    logger.info("Updating JIT policies ConfigMap", extra={"details": {"namespace": namespace, "name": config_map.metadata.name, "blockedUsers": len(blocked_users), "antiAbuse": anti_abuse}})
    await get_core_api().patch_namespaced_config_map(name=config_map.metadata.name, namespace=namespace, body=body)
    logger.info("Updated JIT policies ConfigMap successfully", extra={"details": {"namespace": namespace, "name": config_map.metadata.name}})
    return await get_jit_policies()


async def get_jit_analytics() -> dict[str, Any]:
    logger.info("Computing JIT analytics")
    raw_items = await scanner.list_custom_resources(plural=JIT_PLURAL)
    items = [serialize_jit_request(item) for item in raw_items]
    policies = await get_jit_policies()

    status_counter = Counter()
    denied_counter = Counter()
    identities = Counter()

    for item in items:
        summary = item.get("summary", {}) or {}
        developer_id = str(summary.get("developerId", "Unknown") or "Unknown")
        state = str(summary.get("state", "PENDING") or "PENDING")
        status_counter[state] += 1
        identities[developer_id] += 1
        if state.startswith("DENIED") or state.startswith("BLOCKED"):
            denied_counter[state] += 1

    active_sessions = sum(1 for item in items if str((item.get("summary", {}) or {}).get("state", "")).upper() in {"ACTIVE", "APPROVED"})
    session_rows = [
        {
            "identity": (item.get("summary", {}) or {}).get("developerId"),
            "namespace": (item.get("summary", {}) or {}).get("targetNamespace"),
            "role": (item.get("summary", {}) or {}).get("requestedRole"),
            "state": (item.get("summary", {}) or {}).get("state"),
            "message": (item.get("summary", {}) or {}).get("message"),
        }
        for item in items
    ]

    payload = {
        "distribution": dict(status_counter),
        "deniedByType": dict(denied_counter),
        "activeSessions": active_sessions,
        "blockedUsers": policies.get("blockedUsers", []),
        "antiAbuse": policies.get("antiAbuse", {}),
        "topIdentities": [
            {"identity": identity, "requests": count}
            for identity, count in identities.most_common(10)
        ],
        "sessions": session_rows,
    }
    logger.info("Computed JIT analytics successfully", extra={"details": {"requests": len(items), "activeSessions": active_sessions, "deniedTypes": dict(denied_counter)}})
    return payload