from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import AsyncIterator

from app.services.jit_admin_service import get_jit_analytics
from app.services.overview_service import get_cluster_overview


async def overview_event_generator() -> AsyncIterator[str]:
    while True:
        overview = await get_cluster_overview()
        jit_analytics = await get_jit_analytics()
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overview": overview,
            "jitAnalytics": jit_analytics,
        }
        yield f"event: pulse\ndata: {json.dumps(payload)}\n\n"
        await asyncio.sleep(5)