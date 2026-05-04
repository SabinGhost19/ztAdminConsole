from __future__ import annotations

import logging
from typing import Any

from app.services.k8s_scanner import JIT_PLURAL, scanner
from app.services.serializers import serialize_jit_request

logger = logging.getLogger("zero_trust_k8s_jit_service")


async def get_jit_request(namespace: str, name: str) -> dict[str, Any]:
    """Fetch a single JITAccessRequest CRD and return a serialized view."""
    logger.info("Fetching single JIT request", extra={"details": {"namespace": namespace, "name": name}})
    payload = await scanner.get_custom_resource(plural=JIT_PLURAL, name=name, namespace=namespace)
    return serialize_jit_request(payload)


async def list_jit_requests(namespace: str = "") -> list[dict[str, Any]]:
    """List JITAccessRequest CRDs (delegates to existing scanner)."""
    items = await scanner.list_custom_resources(plural=JIT_PLURAL, namespace=namespace or None)
    return [serialize_jit_request(i) for i in items]


async def delete_jit_request(namespace: str, name: str) -> None:
    """Delete a JITAccessRequest CRD by name/namespace."""
    logger.info("Deleting JIT request", extra={"details": {"namespace": namespace, "name": name}})
    await scanner.delete_custom_resource(plural=JIT_PLURAL, name=name, namespace=namespace)
