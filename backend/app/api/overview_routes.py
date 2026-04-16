from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.services.event_stream_service import overview_event_generator
from app.services.overview_service import get_cluster_overview

router = APIRouter()


@router.get("/")
async def get_overview() -> dict:
    return await get_cluster_overview()


@router.get("/stream")
async def stream_overview() -> StreamingResponse:
    return StreamingResponse(overview_event_generator(), media_type="text/event-stream")