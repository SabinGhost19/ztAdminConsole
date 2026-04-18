from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

# Shared in-memory SQLite DB; data lives as long as this backend process is alive.
_DB_URI = "file:ztadmin_state?mode=memory&cache=shared"
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_STATE_COLUMNS = {
    "cache_key",
    "namespace",
    "resource_name",
    "state_type",
    "state_version",
    "status",
    "fingerprint",
    "payload_json",
    "metadata_json",
    "updated_at",
    "accessed_at",
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(data: Any) -> str:
    # Stable JSON output keeps fingerprinting deterministic across writes.
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _fingerprint_payload(payload: dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS state_cache (
          cache_key TEXT PRIMARY KEY,
          namespace TEXT,
          resource_name TEXT,
          state_type TEXT NOT NULL,
          state_version INTEGER NOT NULL,
          status TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          metadata_json TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          accessed_at TEXT NOT NULL
        )
        """
    )
    columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(state_cache)").fetchall()
        if len(row) >= 2
    }
    if not _STATE_COLUMNS.issubset(columns):
        # In-memory DB should never keep legacy rows across process lifecycle.
        conn.execute("DROP TABLE IF EXISTS state_cache")
        conn.execute(
            """
            CREATE TABLE state_cache (
              cache_key TEXT PRIMARY KEY,
              namespace TEXT,
              resource_name TEXT,
              state_type TEXT NOT NULL,
              state_version INTEGER NOT NULL,
              status TEXT NOT NULL,
              fingerprint TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              metadata_json TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              accessed_at TEXT NOT NULL
            )
            """
        )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_state_cache_lookup
        ON state_cache(state_type, namespace, resource_name)
        """
    )


def init_state_db() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            return
        _conn = sqlite3.connect(_DB_URI, uri=True, check_same_thread=False)
        _ensure_schema(_conn)
        _conn.commit()


def close_state_db() -> None:
    global _conn
    with _lock:
        if _conn is None:
            return
        _conn.close()
        _conn = None


def read_state(cache_key: str) -> dict[str, Any] | None:
    record = read_state_record(cache_key)
    if not record:
        return None
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else None


def read_state_record(cache_key: str) -> dict[str, Any] | None:
    with _lock:
        if _conn is None:
            return None
        row = _conn.execute(
            """
            SELECT
              cache_key,
              namespace,
              resource_name,
              state_type,
              state_version,
              status,
              fingerprint,
              payload_json,
              metadata_json,
              updated_at,
              accessed_at
            FROM state_cache
            WHERE cache_key = ?
            """,
            (cache_key,),
        ).fetchone()
        if not row:
            return None
        now = _utc_now_iso()
        _conn.execute(
            "UPDATE state_cache SET accessed_at = ? WHERE cache_key = ?",
            (now, cache_key),
        )
        _conn.commit()
        return {
            "cacheKey": str(row[0]),
            "namespace": row[1],
            "resourceName": row[2],
            "stateType": str(row[3]),
            "stateVersion": int(row[4]),
            "status": str(row[5]),
            "fingerprint": str(row[6]),
            "payload": json.loads(str(row[7])),
            "metadata": json.loads(str(row[8])),
            "updatedAt": str(row[9]),
            "accessedAt": now,
        }


def write_state(
    cache_key: str,
    payload: dict[str, Any],
    *,
    state_type: str = "generic",
    namespace: str | None = None,
    resource_name: str | None = None,
    status: str = "ready",
    metadata: dict[str, Any] | None = None,
    state_version: int = 1,
) -> None:
    with _lock:
        if _conn is None:
            return
        now = _utc_now_iso()
        payload_json = _canonical_json(payload)
        metadata_payload = metadata or {}
        metadata_json = _canonical_json(metadata_payload)
        _conn.execute(
            """
            INSERT INTO state_cache (
              cache_key,
              namespace,
              resource_name,
              state_type,
              state_version,
              status,
              fingerprint,
              payload_json,
              metadata_json,
              updated_at,
              accessed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
              namespace = excluded.namespace,
              resource_name = excluded.resource_name,
              state_type = excluded.state_type,
              state_version = excluded.state_version,
              status = excluded.status,
              fingerprint = excluded.fingerprint,
              payload_json = excluded.payload_json,
              metadata_json = excluded.metadata_json,
              updated_at = excluded.updated_at,
              accessed_at = excluded.accessed_at
            """,
            (
                cache_key,
                namespace,
                resource_name,
                state_type,
                max(1, int(state_version)),
                status,
                _fingerprint_payload(payload),
                payload_json,
                metadata_json,
                now,
                now,
            ),
        )
        _conn.commit()


def delete_state(cache_key: str) -> None:
    with _lock:
        if _conn is None:
            return
        _conn.execute("DELETE FROM state_cache WHERE cache_key = ?", (cache_key,))
        _conn.commit()
