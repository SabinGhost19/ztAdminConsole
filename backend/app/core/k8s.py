import os
import logging
from kubernetes_asyncio import client, config

logger = logging.getLogger("zero_trust_k8s")
_api_client: client.ApiClient | None = None

async def init_k8s():
    """Inițializează conexiunea la Kubernetes API Server."""
    global _api_client
    try:
        # Detectează automat dacă rulează on-cluster sau local
        if 'KUBERNETES_SERVICE_HOST' in os.environ:
            config.load_incluster_config()
            logger.info("Folosind In-Cluster Config (ServiceAccount)")
        else:
            await config.load_kube_config()
            logger.info("Folosind Kube Config local")
        if _api_client is None:
            _api_client = client.ApiClient()
            logger.info("Client Kubernetes async partajat inițializat")
    except Exception as e:
        logger.error(f"Eroare la inițializarea clientului Kubernetes: {e}")
        raise


async def close_k8s():
    """Închide clientul Kubernetes async partajat."""
    global _api_client
    if _api_client is None:
        return
    await _api_client.close()
    _api_client = None
    logger.info("Client Kubernetes async închis")


def _get_api_client() -> client.ApiClient:
    if _api_client is None:
        raise RuntimeError("Kubernetes async client is not initialized")
    return _api_client


def get_custom_api():
    """Returnează o instanță async a CustomObjectsApi."""
    return client.CustomObjectsApi(_get_api_client())


def get_core_api():
    """Returnează o instanță async a CoreV1Api."""
    return client.CoreV1Api(_get_api_client())
