"""Build a self-contained kubeconfig for a JIT session.

The developer must NOT run `kubectl --token=...` over their existing admin kubeconfig:
that kubeconfig carries a client certificate, and the kube-apiserver authenticates the
X509 client cert BEFORE the bearer token (union authenticator, first success wins), so the
token is silently ignored and every command runs as the cert identity (e.g. cluster-admin).

This module produces a kubeconfig whose user block contains ONLY the JIT token (no client
cert), so the token is the sole credential and the request authenticates as the temporary
ServiceAccount — scoped to the granted namespace.
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

import yaml

logger = logging.getLogger("zero_trust_jit_kubeconfig")

_INCLUSTER_CA_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"


def external_apiserver() -> str:
    """Externally reachable API server URL (e.g. https://178.105.152.139:6443).

    Required: the in-cluster URL (kubernetes.default.svc) is not reachable from a laptop,
    so it must be configured explicitly.
    """
    return os.getenv("JIT_EXTERNAL_APISERVER", "").strip()


def _cluster_ca_data() -> str | None:
    """base64-encoded CA bundle for the API server, or None to fall back to insecure."""
    env_ca = os.getenv("JIT_CLUSTER_CA_DATA", "").strip()
    if env_ca:
        return env_ca
    try:
        with open(_INCLUSTER_CA_FILE, "rb") as handle:
            return base64.b64encode(handle.read()).decode("ascii")
    except OSError:
        logger.warning(
            "No JIT_CLUSTER_CA_DATA and in-cluster CA unreadable; "
            "JIT kubeconfig will use insecure-skip-tls-verify"
        )
        return None


def build_jit_kubeconfig(summary: dict[str, Any]) -> str:
    """Render a kubeconfig YAML (server + CA + token + namespace, NO client cert).

    Raises ValueError when the token or the external API server URL is missing.
    """
    token = (summary or {}).get("temporaryToken")
    namespace = (summary or {}).get("targetNamespace") or "default"
    server = external_apiserver()

    if not token:
        raise ValueError("JIT session has no temporary token yet")
    if not server:
        raise ValueError("JIT_EXTERNAL_APISERVER is not configured on the backend")

    cluster: dict[str, Any] = {"server": server}
    ca_data = _cluster_ca_data()
    if ca_data:
        cluster["certificate-authority-data"] = ca_data
    else:
        cluster["insecure-skip-tls-verify"] = True

    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": "jit",
        "clusters": [{"name": "jit", "cluster": cluster}],
        "contexts": [
            {"name": "jit", "context": {"cluster": "jit", "user": "jit", "namespace": namespace}}
        ],
        "users": [{"name": "jit", "user": {"token": token}}],
    }
    return yaml.safe_dump(config, default_flow_style=False, sort_keys=False)
