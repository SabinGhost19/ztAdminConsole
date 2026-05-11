from fastapi import APIRouter, Depends

from app.security.identity import Identity, require_permission
from app.security import permissions as perm
from app.services.overview_service import get_cluster_overview

router = APIRouter()


@router.get("/")
async def get_overview(
    _identity: Identity = Depends(require_permission(perm.P_OVERVIEW_READ)),
) -> dict:
    return await get_cluster_overview()