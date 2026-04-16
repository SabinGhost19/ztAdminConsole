from __future__ import annotations

import logging
import time

from app.core.k8s import get_core_api, get_custom_api

GROUP = "devsecops.licenta.ro"
VERSION = "v1"
JIT_PLURAL = "jitaccessrequests"
ZTA_PLURAL = "zerotrustapplications"
ZTS_PLURAL = "zerotrustsecrets"
SCA_PLURAL = "supplychainattestations"

logger = logging.getLogger("zero_trust_k8s_scanner")


def _operation_target(plural: str, namespace: str | None, cluster_scoped: bool, name: str | None = None) -> dict[str, str | bool | None]:
    return {
        "plural": plural,
        "namespace": namespace,
        "clusterScoped": cluster_scoped,
        "name": name,
    }


class K8sScannerService:
    async def list_custom_resources(
        self,
        *,
        plural: str,
        namespace: str | None = None,
        cluster_scoped: bool = False,
    ) -> list[dict]:
        started = time.perf_counter()
        target = _operation_target(plural, namespace, cluster_scoped)
        logger.info("Listing custom resources", extra={"details": target})
        api = get_custom_api()
        try:
            if cluster_scoped or not namespace:
                response = await api.list_cluster_custom_object(
                    group=GROUP,
                    version=VERSION,
                    plural=plural,
                )
            else:
                response = await api.list_namespaced_custom_object(
                    group=GROUP,
                    version=VERSION,
                    namespace=namespace,
                    plural=plural,
                )
            items = response.get("items", []) or []
            logger.info(
                "Listed custom resources successfully",
                extra={"details": {**target, "count": len(items), "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
            )
            return items
        except Exception:
            logger.exception("Failed listing custom resources", extra={"details": target})
            raise

    async def get_custom_resource(
        self,
        *,
        plural: str,
        name: str,
        namespace: str | None = None,
        cluster_scoped: bool = False,
    ) -> dict:
        started = time.perf_counter()
        target = _operation_target(plural, namespace, cluster_scoped, name)
        logger.info("Fetching custom resource", extra={"details": target})
        api = get_custom_api()
        try:
            if cluster_scoped or not namespace:
                payload = await api.get_cluster_custom_object(
                    group=GROUP,
                    version=VERSION,
                    plural=plural,
                    name=name,
                )
            else:
                payload = await api.get_namespaced_custom_object(
                    group=GROUP,
                    version=VERSION,
                    namespace=namespace,
                    plural=plural,
                    name=name,
                )
            logger.info(
                "Fetched custom resource successfully",
                extra={"details": {**target, "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
            )
            return payload
        except Exception:
            logger.exception("Failed fetching custom resource", extra={"details": target})
            raise

    async def create_custom_resource(
        self,
        *,
        plural: str,
        body: dict,
        namespace: str | None = None,
        cluster_scoped: bool = False,
    ) -> dict:
        started = time.perf_counter()
        metadata = body.get("metadata", {}) or {}
        target = _operation_target(plural, namespace, cluster_scoped, metadata.get("name"))
        logger.info("Creating custom resource", extra={"details": {**target, "kind": body.get("kind")}})
        api = get_custom_api()
        try:
            if cluster_scoped or not namespace:
                payload = await api.create_cluster_custom_object(
                    group=GROUP,
                    version=VERSION,
                    plural=plural,
                    body=body,
                )
            else:
                payload = await api.create_namespaced_custom_object(
                    group=GROUP,
                    version=VERSION,
                    namespace=namespace,
                    plural=plural,
                    body=body,
                )
            logger.info(
                "Created custom resource successfully",
                extra={"details": {**target, "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
            )
            return payload
        except Exception:
            logger.exception("Failed creating custom resource", extra={"details": {**target, "kind": body.get("kind")}})
            raise

    async def delete_custom_resource(
        self,
        *,
        plural: str,
        name: str,
        namespace: str | None = None,
        cluster_scoped: bool = False,
    ) -> None:
        started = time.perf_counter()
        target = _operation_target(plural, namespace, cluster_scoped, name)
        logger.info("Deleting custom resource", extra={"details": target})
        api = get_custom_api()
        try:
            if cluster_scoped or not namespace:
                await api.delete_cluster_custom_object(
                    group=GROUP,
                    version=VERSION,
                    plural=plural,
                    name=name,
                )
                logger.info(
                    "Deleted custom resource successfully",
                    extra={"details": {**target, "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
                )
                return
            await api.delete_namespaced_custom_object(
                group=GROUP,
                version=VERSION,
                namespace=namespace,
                plural=plural,
                name=name,
            )
            logger.info(
                "Deleted custom resource successfully",
                extra={"details": {**target, "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
            )
        except Exception:
            logger.exception("Failed deleting custom resource", extra={"details": target})
            raise

    async def list_pods(self) -> list[dict]:
        started = time.perf_counter()
        logger.info("Listing pods across all namespaces")
        api = get_core_api()
        try:
            response = await api.list_pod_for_all_namespaces()
            items = response.to_dict().get("items", []) or []
            logger.info(
                "Listed pods across all namespaces successfully",
                extra={"details": {"count": len(items), "durationMs": round((time.perf_counter() - started) * 1000, 2)}},
            )
            return items
        except Exception:
            logger.exception("Failed listing pods across all namespaces")
            raise


scanner = K8sScannerService()