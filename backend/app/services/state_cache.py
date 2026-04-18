from __future__ import annotations

from typing import Any

from app.core.state_db import read_state, read_state_record, write_state

_INTEGRITY_STATE_TYPE = "integrity.application"
_INTEGRITY_STATE_VERSION = 2


def _integrity_key(namespace: str, name: str) -> str:
    return f"integrity:{namespace}:{name}"


def _integrity_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    application = payload.get("application", {}) if isinstance(payload, dict) else {}
    summary = application.get("summary", {}) if isinstance(application, dict) else {}
    metadata = application.get("metadata", {}) if isinstance(application, dict) else {}
    reconcile_flow = payload.get("reconcileFlow", {}) if isinstance(payload, dict) else {}

    return {
        "resourceUid": metadata.get("uid"),
        "phase": summary.get("phase"),
        "trustLevel": summary.get("trustLevel"),
        "securityState": summary.get("securityState"),
        "lastVerified": summary.get("lastVerified"),
        "hasErrors": bool(summary.get("hasErrors", False)),
        "hasViolations": bool(summary.get("hasViolations", False)),
        "activeStage": reconcile_flow.get("activeStage"),
        "reconcilePhase": reconcile_flow.get("phase"),
        "policyBound": bool(payload.get("policy")),
        "secretBindingCount": len(payload.get("secretBindings", []) or []),
    }


def _integrity_status(payload: dict[str, Any]) -> str:
    summary = ((payload.get("application", {}) or {}).get("summary", {}) or {})
    phase = str(summary.get("phase", "") or "").strip().lower()
    if phase in {"running"}:
        return "running"
    if phase in {"degraded", "failed_supplychain", "failed"}:
        return "degraded"
    if phase in {"validating", "provisioning", "pending"}:
        return "in-progress"
    return "ready"


def get_integrity_snapshot(namespace: str, name: str) -> dict[str, Any] | None:
    return read_state(_integrity_key(namespace, name))


def get_integrity_snapshot_record(namespace: str, name: str) -> dict[str, Any] | None:
    return read_state_record(_integrity_key(namespace, name))


def set_integrity_snapshot(namespace: str, name: str, payload: dict[str, Any]) -> None:
    write_state(
        _integrity_key(namespace, name),
        payload,
        state_type=_INTEGRITY_STATE_TYPE,
        namespace=namespace,
        resource_name=name,
        status=_integrity_status(payload),
        metadata=_integrity_metadata(payload),
        state_version=_INTEGRITY_STATE_VERSION,
    )
