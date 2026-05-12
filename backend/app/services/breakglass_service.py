"""Break-glass / eBPF honeypot orchestration service.

Three responsibilities, kept inside a single module so the route handler
in `breakglass_routes.py` stays thin:

1. Issue Ed25519-signed JWTs scoped to a single node + TTL. Agents
   verify them offline using the public key mounted from a shared
   Secret. Replay protection is handled on the agent side via `jti`.

2. Track in-memory the issued sessions so the dashboard can list /
   revoke them without a database. State survives a backend restart only
   if a sticky session is configured at the ingress; this is acceptable
   for the licenta scope. Sessions outlive their JWT TTL only as audit
   metadata (status flips to EXPIRED).

3. Aggregate per-node heartbeats and ring-buffer audit events received
   from the DaemonSet agents.

All time is stored UTC. The agent's clock is trusted insofar as it is
inside the cluster; the JWT `nbf`/`exp` are enforced by the verifier
library on the agent side too.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import jwt as pyjwt

logger = logging.getLogger("zero_trust_backend.breakglass")

ISSUER = "zero-trust-jit"
AUD_PREFIX = "node:"
DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 1800

AUDIT_RING_CAPACITY = 2000
SESSION_RING_CAPACITY = 500


# ---------------------------------------------------------------------------
# In-memory data model
# ---------------------------------------------------------------------------
@dataclass
class Session:
    jti: str
    node: str
    requester: str
    approver: str
    reason: str
    issued_at: datetime
    expires_at: datetime
    ttl_seconds: int
    state: str = "ISSUED"  # ISSUED | EXPIRED | REVOKED
    token: str = ""        # the encoded JWT, only kept for one-time fetch
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None

    def to_dict(self, include_token: bool = False) -> Dict[str, Any]:
        out = {
            "jti": self.jti,
            "node": self.node,
            "requester": self.requester,
            "approver": self.approver,
            "reason": self.reason,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "state": self.refreshed_state(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
        }
        if include_token:
            out["token"] = self.token
        return out

    def refreshed_state(self) -> str:
        if self.state == "REVOKED":
            return "REVOKED"
        if datetime.now(timezone.utc) >= self.expires_at:
            return "EXPIRED"
        return self.state


@dataclass
class NodeHeartbeat:
    node: str
    received_at: datetime
    payload: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Service singleton
# ---------------------------------------------------------------------------
class BreakGlassService:
    """Thread-safe singleton wired from main.py at startup."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key_pem: Optional[str] = None
        self._sessions: Dict[str, Session] = {}
        self._heartbeats: Dict[str, NodeHeartbeat] = {}
        self._audit: Deque[Dict[str, Any]] = deque(maxlen=AUDIT_RING_CAPACITY)

    # ---- key management --------------------------------------------------
    def configure_keys(self, private_key_path: Optional[str] = None) -> None:
        """Load the Ed25519 private key from disk, generate a new keypair
        if the path is missing. The generated public key PEM is exposed
        via ``public_key_pem()`` so a development workflow can copy it
        into the agents' ConfigMap manually.
        """
        with self._lock:
            if private_key_path and os.path.isfile(private_key_path):
                with open(private_key_path, "rb") as fh:
                    pem = fh.read()
                self._private_key = serialization.load_pem_private_key(pem, password=None)
                logger.info("Loaded Ed25519 private key from %s", private_key_path)
            else:
                logger.warning(
                    "Generating ephemeral Ed25519 keypair: agents will need a "
                    "matching public key. Set BREAKGLASS_JWT_PRIVATE_KEY_PATH "
                    "to point at a Secret-mounted PEM in production."
                )
                self._private_key = Ed25519PrivateKey.generate()

            pub: Ed25519PublicKey = self._private_key.public_key()
            self._public_key_pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

    def public_key_pem(self) -> str:
        with self._lock:
            return self._public_key_pem or ""

    # ---- token issuance -------------------------------------------------
    def issue_token(
        self,
        node: str,
        requester: str,
        approver: str,
        reason: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> Session:
        if not node:
            raise ValueError("node is required")
        if not requester:
            raise ValueError("requester is required")
        ttl = max(60, min(int(ttl_seconds or DEFAULT_TTL_SECONDS), MAX_TTL_SECONDS))

        with self._lock:
            if self._private_key is None:
                raise RuntimeError("BreakGlassService is not configured (no private key)")
            now = datetime.now(timezone.utc)
            jti = str(uuid.uuid4())
            exp = now + timedelta(seconds=ttl)
            claims = {
                "iss": ISSUER,
                "aud": f"{AUD_PREFIX}{node}",
                "sub": requester,
                "jti": jti,
                "iat": int(now.timestamp()),
                "nbf": int(now.timestamp()),
                "exp": int(exp.timestamp()),
                "ebpf-honeypot": {
                    "ttl_seconds": ttl,
                    "max_pid_ttl_seconds": ttl,
                    "approver": approver or requester,
                    "reason": reason or "",
                },
            }
            token = pyjwt.encode(claims, self._private_key, algorithm="EdDSA")
            session = Session(
                jti=jti,
                node=node,
                requester=requester,
                approver=approver or requester,
                reason=reason or "",
                issued_at=now,
                expires_at=exp,
                ttl_seconds=ttl,
                token=token,
            )
            self._sessions[jti] = session
            self._gc_sessions_locked()
            return session

    def revoke_session(self, jti: str, revoker: str) -> Optional[Session]:
        with self._lock:
            sess = self._sessions.get(jti)
            if not sess:
                return None
            if sess.state == "REVOKED":
                return sess
            sess.state = "REVOKED"
            sess.revoked_at = datetime.now(timezone.utc)
            sess.revoked_by = revoker
            return sess

    def list_sessions(self, include_token: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            self._gc_sessions_locked()
            return [s.to_dict(include_token=include_token) for s in self._sessions.values()]

    def get_session(self, jti: str, include_token: bool = False) -> Optional[Dict[str, Any]]:
        with self._lock:
            sess = self._sessions.get(jti)
            return sess.to_dict(include_token=include_token) if sess else None

    def _gc_sessions_locked(self) -> None:
        # Bounded retention: keep at most SESSION_RING_CAPACITY most recent.
        if len(self._sessions) <= SESSION_RING_CAPACITY:
            return
        to_drop = sorted(self._sessions.values(), key=lambda s: s.issued_at)[: -SESSION_RING_CAPACITY]
        for s in to_drop:
            self._sessions.pop(s.jti, None)

    # ---- agent ingress --------------------------------------------------
    def ingest_heartbeat(self, payload: Dict[str, Any]) -> None:
        node = (payload or {}).get("node") or "unknown"
        with self._lock:
            self._heartbeats[node] = NodeHeartbeat(
                node=node,
                received_at=datetime.now(timezone.utc),
                payload=payload or {},
            )

    def list_heartbeats(self) -> List[Dict[str, Any]]:
        with self._lock:
            now = datetime.now(timezone.utc)
            out: List[Dict[str, Any]] = []
            for hb in self._heartbeats.values():
                age = (now - hb.received_at).total_seconds()
                healthy = age < 30  # 3x the default 10s heartbeat
                payload = dict(hb.payload)
                payload["received_at"] = hb.received_at.isoformat()
                payload["age_seconds"] = round(age, 1)
                payload["healthy"] = healthy
                out.append(payload)
            return sorted(out, key=lambda p: p.get("node", ""))

    def ingest_audit(self, event: Dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return
        ev = dict(event)
        ev.setdefault("received_at", datetime.now(timezone.utc).isoformat())
        with self._lock:
            self._audit.append(ev)

    def list_audit(self, limit: int = 200, node: Optional[str] = None,
                   action: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._audit)
        items.reverse()  # newest first
        if node:
            items = [x for x in items if x.get("node") == node]
        if action:
            items = [x for x in items if x.get("action") == action]
        if limit > 0:
            items = items[:limit]
        return items

    # ---- analytics ------------------------------------------------------
    def analytics(self) -> Dict[str, Any]:
        with self._lock:
            sessions = list(self._sessions.values())
            audit = list(self._audit)
            heartbeats = list(self._heartbeats.values())
        denied = sum(1 for ev in audit if ev.get("action") == "denied")
        allowed = sum(1 for ev in audit if ev.get("action") == "allowed")
        active = sum(1 for s in sessions if s.refreshed_state() == "ISSUED")
        revoked = sum(1 for s in sessions if s.state == "REVOKED")
        expired = sum(1 for s in sessions if s.refreshed_state() == "EXPIRED")
        per_node_denied: Dict[str, int] = {}
        for ev in audit:
            if ev.get("action") == "denied":
                n = ev.get("node") or "unknown"
                per_node_denied[n] = per_node_denied.get(n, 0) + 1
        return {
            "sessions": {
                "active": active,
                "revoked": revoked,
                "expired": expired,
                "total": len(sessions),
            },
            "audit": {
                "denied": denied,
                "allowed": allowed,
                "total": len(audit),
                "denied_per_node": per_node_denied,
            },
            "agents": {
                "total": len(heartbeats),
                "healthy": sum(1 for hb in heartbeats
                               if (datetime.now(timezone.utc) - hb.received_at).total_seconds() < 30),
            },
        }

    # ---- policy management ----------------------------------------------
    async def list_policies(self) -> List[Dict[str, Any]]:
        """List NodeProtectionPolicy CRD resources cluster-scoped.

        group: devsecops.licenta.ro, version: v1alpha1, plural: nodeprotectionpolicies

        Uses the already-initialised async kubernetes_asyncio client from
        app.core.k8s so we don't accidentally mix the sync `kubernetes`
        package (which doesn't return coroutines) into the async stack.
        """
        try:
            # Imported lazily to avoid a hard dependency at module import
            # time — keeps breakglass_service importable for unit tests
            # that don't have the k8s client initialised.
            from app.core.k8s import get_custom_api
            crd_api = get_custom_api()
            result = await crd_api.list_cluster_custom_object(
                group="devsecops.licenta.ro",
                version="v1alpha1",
                plural="nodeprotectionpolicies",
            )
            return result.get("items", []) or []
        except Exception as e:
            logger.warning("Failed to list NodeProtectionPolicy CRDs: %s", e)
            return []


# ---------------------------------------------------------------------------
# Module-level singleton + helpers used by routes / main.py
# ---------------------------------------------------------------------------
_service: Optional[BreakGlassService] = None
_service_lock = threading.Lock()


def get_service() -> BreakGlassService:
    global _service
    with _service_lock:
        if _service is None:
            _service = BreakGlassService()
            _service.configure_keys(os.environ.get("BREAKGLASS_JWT_PRIVATE_KEY_PATH"))
        return _service


def configure_from_env() -> BreakGlassService:
    """Idempotent. Called from main.py startup."""
    return get_service()


__all__ = [
    "BreakGlassService",
    "Session",
    "configure_from_env",
    "get_service",
    "DEFAULT_TTL_SECONDS",
    "MAX_TTL_SECONDS",
]
