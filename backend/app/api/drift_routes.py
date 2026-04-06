from fastapi import APIRouter
from app.services.drift_service import get_drift_status

router = APIRouter()

@router.get("/")
async def list_drifts():
    # Returneaza lista aplicatiilor ZTA care se afla in stare de drift.
    return await get_drift_status()