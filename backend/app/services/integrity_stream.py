"""SSE stream that surfaces ZeroTrustApplication integrity changes
plus the kopf events emitted by the operator, in real time.

The browser EventSource API cannot set custom headers, so the
caller passes the bearer token as `?access_token=`; identity.py
already extracts it from the query string.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator

from kubernetes_asyncio.client.exceptions import ApiException

from app.core.k8s import get_core_api
from app.services.integrity_service import get_application_integrity
from app.services.k8s_scanner import GROUP, VERSION, ZTA_PLURAL, scanner

logger = logging.getLogger("zero_trust_integrity_stream")


def _sse_error(code: str, message: str, *, recoverable: bool = True,
               details: dict[str, Any] | None = None) -> str:
    """Build a structured SSE error frame the frontend can pattern-match
    on `code` rather than doing string analysis on `message`."""
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "recoverable": bool(recoverable),
    }
    if details:
        payload["details"] = details
    return f"event: integrity.error\ndata: {json.dumps(payload, default=str)}\n\n"

_POLL_INTERVAL_SECONDS = 2
_KEEPALIVE_EVERY_N_TICKS = 15  # ~30s heartbeat


def _fingerprint(payload: dict[str, Any]) -> str:
    """Cheap fingerprint to detect changes without diffing the full doc.

    Concatenates the fields that drive UI re-renders: phase, trust,
    security state, verifications, active violations, GUAC status,
    sanction count, runtime forensics flags. JSON-encoded with
    sort_keys for deterministic comparison.
    """
    app = payload.get("application", {}) or {}
    status = app.get("status", {}) or {}
    summary = app.get("summary", {}) or {}
    runtime = payload.get("runtimeForensics", {}) or {}
    sanctions = payload.get("sanctionHistory", []) or []
    fp = {
        "phase": summary.get("phase"),
        "trust": summary.get("trustLevel"),
        "security": summary.get("securityState"),
        "lastError": summary.get("lastError"),
        "violations": summary.get("activeViolations", []),
        "verifications": status.get("verifications", {}),
        "provenance": status.get("provenance", {}),
        "guac": {
            "status": status.get("guacIngestionStatus"),
            "completedAt": status.get("guacIngestionCompletedAt"),
        },
        "runtime": {
            "falco": runtime.get("localRulePresent"),
            "talon": runtime.get("talonRulePresent"),
        },
        "sanctionCount": len(sanctions),
        "specHash": status.get("specReconcileHash"),
    }
    return json.dumps(fp, sort_keys=True, default=str)


async def _list_application_events(namespace: str, name: str, since_uid: str = "") -> list[dict[str, Any]]:
    """Return kopf events whose involvedObject is this ZTA.

    Caller filters by uid (kept opaque here).
    """
    core = get_core_api()
    field_selector = (
        f"involvedObject.name={name},"
        f"involvedObject.kind=ZeroTrustApplication,"
        f"involvedObject.apiVersion={GROUP}/{VERSION}"
    )
    try:
        result = await core.list_namespaced_event(
            namespace=namespace, field_selector=field_selector, limit=200,
        )
    except ApiException as exc:
        logger.warning("event list failed for %s/%s: %s", namespace, name, exc)
        return []

    items: list[dict[str, Any]] = []
    for event in result.items or []:
        meta = getattr(event, "metadata", None)
        involved = getattr(event, "involved_object", None)
        source = getattr(event, "source", None)
        items.append({
            "uid": getattr(meta, "uid", "") or "",
            "name": getattr(meta, "name", "") or "",
            "namespace": getattr(meta, "namespace", "") or namespace,
            "resourceVersion": getattr(meta, "resource_version", "") or "",
            "involvedKind": getattr(involved, "kind", "") if involved else "",
            "involvedName": getattr(involved, "name", "") if involved else "",
            "reason": getattr(event, "reason", "") or "",
            "message": getattr(event, "message", "") or "",
            "type": getattr(event, "type", "") or "Normal",
            "count": int(getattr(event, "count", 0) or 0),
            "firstTimestamp": str(getattr(event, "first_timestamp", "") or ""),
            "lastTimestamp": str(getattr(event, "last_timestamp", "") or ""),
            "eventTime": str(getattr(event, "event_time", "") or ""),
            "sourceComponent": getattr(source, "component", "") if source else "",
        })
    # Sort by lastTimestamp ascending so the timeline can append.
    items.sort(key=lambda e: e.get("lastTimestamp") or e.get("firstTimestamp") or "")
    return items


async def stream_integrity(namespace: str, name: str) -> AsyncIterator[str]:
    """SSE generator yielding `integrity.snapshot` and `event.kopf` records.

    Strategy: lightweight polling (2s) of the integrity payload + Events
    list. Re-emits only when the fingerprint changes. Sends keepalive
    every ~30s so intermediate proxies don't close the connection.

    Errors are classified into stable codes so the frontend can react
    without parsing free-text:
      - `zta-not-found`        : the CRD vanished or never existed → fatal for this stream
      - `k8s-api-error`        : Kubernetes API rejected a call (status >= 400)
      - `k8s-server-error`     : 5xx upstream — recoverable, keep streaming
      - `k8s-unreachable`      : network/OS failure when calling API server
      - `payload-encode-error` : JSON-encoding the payload failed
      - `tick-unexpected`      : catch-all for unanticipated exceptions
    """
    from kubernetes_asyncio.client.exceptions import ApiException

    last_fp: str | None = None
    last_event_resource_version = ""
    keepalive_ticks = 0
    consecutive_errors = 0
    try:
        while True:
            try:
                payload = await get_application_integrity(namespace, name)
                if not payload:
                    yield _sse_error(
                        "zta-not-found",
                        f"ZeroTrustApplication {namespace}/{name} not found.",
                        recoverable=False,
                    )
                    return

                fp = _fingerprint(payload)
                if fp != last_fp:
                    last_fp = fp
                    try:
                        encoded = json.dumps(payload, default=str)
                    except (TypeError, ValueError) as enc_exc:
                        yield _sse_error(
                            "payload-encode-error",
                            "Could not JSON-encode the integrity payload.",
                            recoverable=True,
                            details={"error": str(enc_exc)},
                        )
                    else:
                        yield f"event: integrity.snapshot\ndata: {encoded}\n\n"
                        keepalive_ticks = 0

                events = await _list_application_events(namespace, name)
                new_events: list[dict[str, Any]] = []
                for evt in events:
                    rv = evt.get("resourceVersion") or ""
                    if rv and (not last_event_resource_version or rv > last_event_resource_version):
                        new_events.append(evt)
                if new_events:
                    last_event_resource_version = max(
                        e.get("resourceVersion") or "" for e in new_events
                    )
                    yield f"event: event.kopf\ndata: {json.dumps(new_events, default=str)}\n\n"
                    keepalive_ticks = 0
                else:
                    keepalive_ticks += 1
                    if keepalive_ticks >= _KEEPALIVE_EVERY_N_TICKS:
                        yield ": keepalive\n\n"
                        keepalive_ticks = 0
                # Successful tick — reset the consecutive error counter.
                consecutive_errors = 0
            except asyncio.CancelledError:
                raise
            except ApiException as api_exc:
                consecutive_errors += 1
                status = int(getattr(api_exc, "status", 0) or 0)
                code = "k8s-server-error" if 500 <= status < 600 else "k8s-api-error"
                logger.warning("integrity stream API error %s: %s", status, api_exc.reason)
                yield _sse_error(
                    code,
                    f"Kubernetes API error {status}: {api_exc.reason or ''}".strip(),
                    recoverable=True,
                    details={"status": status, "reason": api_exc.reason or ""},
                )
                if consecutive_errors >= 5:
                    yield _sse_error(
                        "stream-giving-up",
                        "Too many consecutive K8s API failures; closing the stream.",
                        recoverable=False,
                    )
                    return
            except (ConnectionError, OSError) as net_exc:
                consecutive_errors += 1
                logger.warning("integrity stream upstream unreachable: %s", net_exc)
                yield _sse_error(
                    "k8s-unreachable",
                    f"Upstream unreachable: {type(net_exc).__name__}: {net_exc}",
                    recoverable=True,
                )
                if consecutive_errors >= 5:
                    yield _sse_error(
                        "stream-giving-up",
                        "Too many consecutive upstream failures; closing the stream.",
                        recoverable=False,
                    )
                    return
            except Exception as exc:  # noqa: BLE001 — catch-all so the loop doesn't die
                consecutive_errors += 1
                logger.warning("integrity stream tick failed: %s", exc)
                yield _sse_error(
                    "tick-unexpected",
                    f"{type(exc).__name__}: {exc}",
                    recoverable=True,
                    details={"exceptionType": type(exc).__name__},
                )
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        logger.info("integrity stream cancelled for %s/%s", namespace, name)
        return


async def list_application_events(namespace: str, name: str) -> list[dict[str, Any]]:
    """One-shot listing used by GET /events for initial backfill."""
    return await _list_application_events(namespace, name)
