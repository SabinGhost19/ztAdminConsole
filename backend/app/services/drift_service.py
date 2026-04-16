import logging
import json

from app.services.k8s_scanner import ZTA_PLURAL, scanner
from app.services.serializers import serialize_zta_resource

logger = logging.getLogger("zero_trust_drift_service")

async def get_drift_status() -> list:
    try:
        logger.info("Computing drift status for ZTA applications")
        items = await scanner.list_custom_resources(plural=ZTA_PLURAL)
        drifting_apps = []

        for item in items:
            serialized = serialize_zta_resource(item)
            status = serialized.get("status", {}) or {}
            active_violations = (status.get("activeViolations", []) or [])
            security_state = str(status.get("securityState", "Compliant") or "Compliant")
            if active_violations or security_state not in {"Compliant", "PendingProvenance"} or status.get("lastError"):
                original_yaml = json.dumps(serialized.get("spec", {}), indent=2, sort_keys=True)
                current_state = {
                    "securityState": security_state,
                    "trustLevel": status.get("trustLevel"),
                    "lastError": status.get("lastError"),
                    "activeViolations": active_violations,
                    "provenance": status.get("provenance", {}),
                }
                drifted_yaml = json.dumps(current_state, indent=2, sort_keys=True)
                drifting_apps.append({
                    "name": serialized["metadata"]["name"],
                    "namespace": serialized["metadata"]["namespace"],
                    "state": security_state,
                    "violations": active_violations,
                    "original": original_yaml,
                    "modified": drifted_yaml,
                    "lastError": status.get("lastError"),
                })
        logger.info("Computed drift status successfully", extra={"details": {"applicationsScanned": len(items), "driftedApplications": len(drifting_apps)}})
        return drifting_apps
    except Exception as e:
        logger.exception(f"Eroare extragere drift ZTA: {e}")
        raise e
