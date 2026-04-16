from __future__ import annotations

import json
import logging
import os
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any


class InMemoryLogHandler(logging.Handler):
    def __init__(self, capacity: int = 500):
        super().__init__()
        self.capacity = capacity
        self.records: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = {
                "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            trace_id = getattr(record, "trace_id", None)
            if trace_id:
                payload["trace_id"] = trace_id
            path = getattr(record, "path", None)
            if path:
                payload["path"] = path
            method = getattr(record, "method", None)
            if method:
                payload["method"] = method
            status_code = getattr(record, "status_code", None)
            if status_code is not None:
                payload["status_code"] = status_code
            details = getattr(record, "details", None)
            if details is not None:
                payload["details"] = details
            if record.exc_info:
                payload["exception"] = self.formatException(record.exc_info)
            with self._lock:
                self.records.appendleft(payload)
        except Exception:
            self.handleError(record)

    def snapshot(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.records)[:limit]


_memory_handler: InMemoryLogHandler | None = None


def configure_logging() -> InMemoryLogHandler:
    global _memory_handler
    if _memory_handler is not None:
        return _memory_handler

    level_name = os.getenv("DASHBOARD_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)

    memory_handler = InMemoryLogHandler(capacity=int(os.getenv("DASHBOARD_LOG_BUFFER_SIZE", "500")))
    memory_handler.setLevel(logging.DEBUG)
    memory_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()
    root_logger.addHandler(stream_handler)
    root_logger.addHandler(memory_handler)

    for noisy_logger in ("kubernetes_asyncio", "urllib3"):
      logging.getLogger(noisy_logger).setLevel(max(level, logging.WARNING))

    _memory_handler = memory_handler
    logging.getLogger("zero_trust_bootstrap").info(
        "Backend logging configured",
        extra={"details": json.dumps({"level": level_name})},
    )
    return memory_handler


def get_recent_logs(limit: int = 100) -> list[dict[str, Any]]:
    if _memory_handler is None:
        configure_logging()
    assert _memory_handler is not None
    return _memory_handler.snapshot(limit=limit)