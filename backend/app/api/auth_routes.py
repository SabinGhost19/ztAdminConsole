"""HTTP routes that expose authentication metadata to the SPA.

* GET /api/v1/auth/config        - public; SPA bootstraps Keycloak from this
* GET /api/v1/auth/me            - authenticated; returns the resolved identity
* GET /api/v1/auth/permissions   - public; returns the full permission matrix
                                   so the frontend can build a role explainer
                                   without bundling it at build time.

Note: /auth/me requires a valid Bearer token. Anonymous calls return 401.
The SPA still calls it after login to populate the Pinia auth store.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Request

from app.security.identity import (
    AuthConfig,
    Identity,
    current_user,
    get_auth_config,
)
from app.security.permissions import (
    ALL_GROUPS,
    ALL_PERMISSIONS,
    GROUP_TO_PERMISSIONS,
)

router = APIRouter()


@router.get("/config", summary="Public Keycloak config for the SPA")
async def auth_config(cfg: AuthConfig = Depends(get_auth_config)) -> Dict[str, Any]:
    """Returned BEFORE the SPA logs in. Therefore PUBLIC: no secrets."""
    return {
        "status": "success",
        "authentication": {
            "url": cfg.public_url,
            "realm": cfg.realm,
            "client_id": cfg.client_id,
            "issuer": cfg.issuer,
            "audience": cfg.audience,
            "bypass": cfg.bypass,
        },
    }


@router.get("/me", summary="Resolved identity")
async def auth_me(identity: Identity = Depends(current_user)) -> Dict[str, Any]:
    return {"status": "success", "identity": identity.to_public_dict()}


@router.get("/permissions", summary="Full permission matrix")
async def auth_permissions() -> Dict[str, Any]:
    return {
        "status": "success",
        "groups": ALL_GROUPS,
        "permissions": sorted(ALL_PERMISSIONS),
        "matrix": {g: sorted(perms) for g, perms in GROUP_TO_PERMISSIONS.items()},
    }


@router.post("/refresh-jwks", summary="Force refresh of cached JWKS keys")
async def refresh_jwks(_request: Request,
                       identity: Identity = Depends(current_user)) -> Dict[str, Any]:
    """Convenience for operators after a Keycloak realm key rotation. The
    backend caches JWKS for 5 minutes, this short-circuits the wait."""
    from app.security.identity import _jwks_cache  # noqa: WPS433  (private import is intentional)
    _jwks_cache.invalidate()
    return {"status": "success", "message": "JWKS cache invalidated"}
