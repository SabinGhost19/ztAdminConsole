import os
import logging
from kubernetes_asyncio import client, config

logger = logging.getLogger("zero_trust_k8s")

async def init_k8s():
    """Inițializează conexiunea la Kubernetes API Server."""
    try:
        # Detectează automat dacă rulează on-cluster sau local
        if 'KUBERNETES_SERVICE_HOST' in os.environ:
            config.load_incluster_config()
            logger.info("Folosind In-Cluster Config (ServiceAccount)")
        else:
            await config.load_kube_config()
            logger.info("Folosind Kube Config local")
    except Exception as e:
        logger.error(f"Eroare la inițializarea clientului Kubernetes: {e}")
        raise

def get_custom_api():
    """Returnează o instanță async a CustomObjectsApi."""
    return client.CustomObjectsApi()
