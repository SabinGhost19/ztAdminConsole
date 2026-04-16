from __future__ import annotations

from fastapi import APIRouter, Query

from app.core.logging import get_recent_logs

router = APIRouter()


@router.get("/logs")
async def get_backend_logs(limit: int = Query(default=100, ge=1, le=500)) -> dict:
    return {
        "items": get_recent_logs(limit=limit),
        "count": limit,
    }