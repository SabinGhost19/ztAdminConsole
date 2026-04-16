from fastapi import APIRouter
from app.services.drift_service import get_drift_status

router = APIRouter()

@router.get("/")
async def list_drifts():
    return await get_drift_status()