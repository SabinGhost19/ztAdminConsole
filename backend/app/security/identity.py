"""JWT identity resolver for the dashboard backend.

Trust contract:

* The frontend is a public Keycloak SPA client (`zero-trust-dashboard`).
* On every API call the SPA attaches `Authorization: Bearer <access_token>`.
* This module verifies the JWT against Keycloak's JWKS endpoint and turns
  it into an `Identity` object that route handlers can depend on.

Trust pivot is the Keycloak issuer URL, not OAuth2 Proxy or any reverse
proxy. This makes the dashboard authentication self-contained — the rest
of the JIT platform (oauth2-proxy + zta-operator + protected apps) is
completely orthogonal.

Operational concerns:

* JWKS keys are fetched lazily and cached for `JWKS_CACHE_SECONDS`.
* Audience claim is pinned by `KEYCLOAK_AUDIENCE`; `account` is not
  acceptable. Mis-issued tokens are rejected with HTTP 401.
* `BYPASS_AUTH=true` short-circuits validation and produces a fake
  identity with all groups; use only for `kubectl port-forward` against
  a development cluster.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional

import httpx
import jwt as pyjwt
from fastapi import Depends, HTTPException, Request, status

from app.security.permissions import ALL_GROUPS, groups_granting, permissions_for

logger = logging.getLogger("zero_trust_backend.identity")


# ---------------------------------------------------------------------------
# Runtime config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    audience: str
    jwks_url: str
    bypass: bool
    bypass_email: str
    groups_claim: str
    additional_groups_claims: tuple = ()
    public_url: str = ""
    realm: str = ""
    client_id: str = ""

    @classmethod
    def from_env(cls) -> "AuthConfig":
        # NOTE: env vars are prefixed with DASHBOARD_ to avoid collision
        # with KEYCLOAK_URL / KEYCLOAK_REALM / KEYCLOAK_CLIENT_ID which
        # the legacy `keycloak_service` uses for the M2M admin client.
        issuer = os.environ.get("DASHBOARD_KEYCLOAK_ISSUER", "").rstrip("/")
        audience = os.environ.get("DASHBOARD_KEYCLOAK_AUDIENCE", "zero-trust-dashboard")
        jwks_url = os.environ.get("DASHBOARD_KEYCLOAK_JWKS_URL")
        if not jwks_url and issuer:
            jwks_url = f"{issuer}/protocol/openid-connect/certs"
        bypass = os.environ.get("BYPASS_AUTH", "false").lower() in {"1", "true", "yes"}
        bypass_email = os.environ.get(
            "BYPASS_AUTH_EMAIL", "dev@devsecops.licenta.ro"
        )
        groups_claim = os.environ.get("DASHBOARD_KEYCLOAK_GROUPS_CLAIM", "groups")
        additional = tuple(
            x.strip()
            for x in os.environ.get(
                "DASHBOARD_KEYCLOAK_GROUPS_FALLBACK_CLAIMS", "realm_access.roles"
            ).split(",")
            if x.strip()
        )
        public_url = os.environ.get(
            "DASHBOARD_KEYCLOAK_PUBLIC_URL",
            issuer.rsplit("/realms/", 1)[0] if "/realms/" in issuer else "",
        )
        realm = ""
        client_id = os.environ.get(
            "DASHBOARD_KEYCLOAK_CLIENT_ID", "zero-trust-dashboard",
        )
        if "/realms/" in issuer:
            realm = issuer.split("/realms/", 1)[1].split("/", 1)[0]
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url or "",
            bypass=bypass,
            bypass_email=bypass_email,
            groups_claim=groups_claim,
            additional_groups_claims=additional,
            public_url=public_url,
            realm=realm,
            client_id=client_id,
        )


# ---------------------------------------------------------------------------
# JWKS cache
# ---------------------------------------------------------------------------
JWKS_CACHE_SECONDS = 300


class _JWKSCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fetched_at: float = 0.0
        self._jwks: Dict[str, Any] = {}

    def get(self, jwks_url: str) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            if self._jwks and (now - self._fetched_at) < JWKS_CACHE_SECONDS:
                return self._jwks
        jwks = self._fetch(jwks_url)
        with self._lock:
            self._jwks = jwks
            self._fetched_at = time.time()
        return jwks

    def invalidate(self) -> None:
        with self._lock:
            self._jwks = {}
            self._fetched_at = 0.0

    def _fetch(self, jwks_url: str) -> Dict[str, Any]:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(jwks_url)
            resp.raise_for_status()
            return resp.json()


_jwks_cache = _JWKSCache()


def _resolve_signing_key(jwks_url: str, kid: str):
    jwks = _jwks_cache.get(jwks_url)
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return pyjwt.algorithms.RSAAlgorithm.from_jwk(key)
    # Maybe Keycloak rotated; refresh once and retry.
    _jwks_cache.invalidate()
    jwks = _jwks_cache.get(jwks_url)
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return pyjwt.algorithms.RSAAlgorithm.from_jwk(key)
    raise HTTPException(status_code=401, detail=f"Signing key {kid!r} not found in JWKS")


# ---------------------------------------------------------------------------
# Identity dataclass
# ---------------------------------------------------------------------------
@dataclass
class Identity:
    subject: str
    email: str
    preferred_username: str
    name: str
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    permissions: FrozenSet[str] = field(default_factory=frozenset)
    raw: Dict[str, Any] = field(default_factory=dict)
    is_bypass: bool = False

    def has_group(self, *groups: str) -> bool:
        return any(g in self.groups for g in groups)

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "subject": self.subject,
            "preferred_username": self.preferred_username,
            "name": self.name,
            "groups": self.groups,
            "permissions": sorted(self.permissions),
            "is_bypass": self.is_bypass,
        }


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------
def _strip_group_prefix(g: str) -> str:
    """Keycloak prepends a forward-slash to group names. Drop it."""
    return g.lstrip("/")


def _extract_groups(payload: Dict[str, Any], cfg: AuthConfig) -> List[str]:
    raw: List[str] = []

    # Primary claim (default `groups`)
    primary = payload.get(cfg.groups_claim)
    if isinstance(primary, list):
        raw.extend(str(x) for x in primary)
    elif isinstance(primary, str):
        raw.append(primary)

    # Fallback claims, dot-paths supported (e.g. realm_access.roles)
    for path in cfg.additional_groups_claims:
        node: Any = payload
        for part in path.split("."):
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if isinstance(node, list):
            raw.extend(str(x) for x in node)
        elif isinstance(node, str):
            raw.append(node)

    seen: set[str] = set()
    out: List[str] = []
    for g in raw:
        cleaned = _strip_group_prefix(g)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out


def verify_jwt(token: str, cfg: AuthConfig) -> Identity:
    if not cfg.jwks_url:
        raise HTTPException(
            status_code=500,
            detail="Authentication not configured: KEYCLOAK_JWKS_URL is missing",
        )

    try:
        unverified = pyjwt.get_unverified_header(token)
    except pyjwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid JWT header: {exc}") from exc

    kid = unverified.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="JWT header missing kid")

    key = _resolve_signing_key(cfg.jwks_url, kid)

    try:
        payload = pyjwt.decode(
            token,
            key=key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=cfg.audience,
            issuer=cfg.issuer,
            options={"require": ["exp", "iat"]},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except pyjwt.InvalidAudienceError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Token audience mismatch (expected {cfg.audience!r})",
        ) from exc
    except pyjwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"JWT validation failed: {exc}") from exc

    groups = _extract_groups(payload, cfg)
    return Identity(
        subject=payload.get("sub", ""),
        email=payload.get("email", ""),
        preferred_username=payload.get("preferred_username", ""),
        name=payload.get("name", payload.get("preferred_username", payload.get("email", ""))),
        groups=groups,
        roles=list(payload.get("realm_access", {}).get("roles", []))
        if isinstance(payload.get("realm_access"), dict)
        else [],
        permissions=permissions_for(groups),
        raw=payload,
        is_bypass=False,
    )


def _bypass_identity(cfg: AuthConfig) -> Identity:
    return Identity(
        subject="bypass",
        email=cfg.bypass_email,
        preferred_username=cfg.bypass_email.split("@")[0],
        name="Local Dev (BYPASS_AUTH)",
        groups=list(ALL_GROUPS),
        roles=[],
        permissions=permissions_for(ALL_GROUPS),
        raw={"bypass": True},
        is_bypass=True,
    )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------
def get_auth_config() -> AuthConfig:
    cfg = getattr(get_auth_config, "_cached", None)
    if cfg is None:
        cfg = AuthConfig.from_env()
        get_auth_config._cached = cfg  # type: ignore[attr-defined]
    return cfg


def reload_auth_config() -> AuthConfig:
    cfg = AuthConfig.from_env()
    get_auth_config._cached = cfg  # type: ignore[attr-defined]
    _jwks_cache.invalidate()
    return cfg


def _extract_token(request: Request) -> str:
    auth = request.headers.get("Authorization") or request.headers.get("authorization")
    if not auth:
        return ""
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return ""


def get_identity(request: Request) -> Identity:
    """Resolve the caller identity. Used internally by the optional and
    required dependencies below. Raises 401 if no valid identity is
    available.
    """
    cfg = get_auth_config()

    # Cache the resolution per-request so multiple Depends() in the same
    # handler don't re-verify the JWT.
    cached = getattr(request.state, "identity", None)
    if cached is not None:
        return cached

    if cfg.bypass:
        ident = _bypass_identity(cfg)
        request.state.identity = ident
        logger.debug("BYPASS_AUTH active -> using fake identity %s", ident.email)
        return ident

    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization: Bearer header",
        )

    ident = verify_jwt(token, cfg)
    request.state.identity = ident
    return ident


def optional_identity(request: Request) -> Optional[Identity]:
    """Resolve identity but do not raise. Routes that should respond
    differently when authenticated vs anonymous can use this."""
    identity, _error = optional_identity_with_error(request)
    return identity


def optional_identity_with_error(request: Request) -> tuple[Optional[Identity], Optional[str]]:
    """Resolve identity without raising and expose the concrete reason.

    Useful for middleware-level diagnostics where we need to distinguish
    missing Authorization header from JWT validation mismatches.
    """
    try:
        return get_identity(request), None
    except HTTPException as exc:
        detail = exc.detail
        if isinstance(detail, str):
            reason = detail
        else:
            reason = str(detail)
        request.state.auth_error_reason = reason
        return None, reason


# Convenience exposed as a Depends() target for handlers that just need
# the caller email/name without enforcing a permission.
def current_user(identity: Identity = Depends(get_identity)) -> Identity:
    return identity


def require_groups(*groups: str):
    allowed = frozenset(groups)
    if not allowed:
        raise ValueError("require_groups: must specify at least one group")

    def dependency(identity: Identity = Depends(get_identity)) -> Identity:
        if identity.is_bypass:
            return identity
        if not allowed.intersection(identity.groups):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "forbidden",
                    "message": "You are not allowed to perform this action.",
                    "user_groups": identity.groups,
                    "required_groups": sorted(allowed),
                },
            )
        return identity

    return dependency


def require_permission(*permissions: str):
    needed = frozenset(permissions)
    if not needed:
        raise ValueError("require_permission: at least one permission required")

    def dependency(identity: Identity = Depends(get_identity)) -> Identity:
        if identity.is_bypass:
            return identity
        if not needed.issubset(identity.permissions):
            missing = sorted(needed - identity.permissions)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "forbidden",
                    "message": "Missing required permissions.",
                    "user_groups": identity.groups,
                    "user_permissions": sorted(identity.permissions),
                    "required_permissions": sorted(needed),
                    "missing_permissions": missing,
                    "groups_granting_missing": {
                        p: groups_granting(p) for p in missing
                    },
                },
            )
        return identity

    return dependency


def require_any_permission(*permissions: str):
    """Allow access when the identity holds at least one of the listed permissions."""
    accepted = frozenset(permissions)
    if not accepted:
        raise ValueError("require_any_permission: at least one permission required")

    def dependency(identity: Identity = Depends(get_identity)) -> Identity:
        if identity.is_bypass:
            return identity
        if accepted.isdisjoint(identity.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "forbidden",
                    "message": "Missing required permissions.",
                    "user_groups": identity.groups,
                    "user_permissions": sorted(identity.permissions),
                    "required_any_of": sorted(accepted),
                    "groups_granting_missing": {
                        p: groups_granting(p) for p in sorted(accepted)
                    },
                },
            )
        return identity

    return dependency


__all__ = [
    "AuthConfig",
    "Identity",
    "current_user",
    "get_auth_config",
    "get_identity",
    "optional_identity",
    "reload_auth_config",
    "require_any_permission",
    "require_groups",
    "require_permission",
    "verify_jwt",
]
