from fastapi import APIRouter
from app.services.overview_service import get_cluster_overview

router = APIRouter()


@router.get("/")
async def get_overview() -> dict:
    return await get_cluster_overview()