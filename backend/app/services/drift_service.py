from kubernetes_asyncio import client
import logging
import json
from app.middleware.errors import ZeroTrustException

logger = logging.getLogger("zero_trust_drift_service")

# ZTA Operator patches Drift to ZeroTrustApplications
CRD_GROUP = "devsecops.licenta.ro"
CRD_VERSION = "v1alpha1"
CRD_PLURAL = "zerotrustapplications"

async def get_drift_status() -> list:
    """
    Extrage toate ZeroTrustApplications din cluster
    și le filtrează pe cele care au drift / încălcări (activeViolations populat)
    """
    api = client.CustomObjectsApi()
    
    try:
        res = await api.list_cluster_custom_object(
            group=CRD_GROUP, version=CRD_VERSION, plural=CRD_PLURAL
        )
        
        items = res.get("items", [])
        drifting_apps = []
        
        for item in items:
            status = item.get("status", {})
            active_violations = status.get("activeViolations", [])
            security_state = status.get("securityState", "Compliant")
            
            # Formatează un Payload pentru frontend
            if active_violations or security_state != "Compliant":
                # Mock Original GitOps source vs Current Drift
                # In real life, Source of truth is item['spec'] and current state is drifted
                original_yaml = json.dumps(item.get("spec", {}), indent=2)
                
                # Punem statusul ca modified YAML pentru a vedea vizual drift-ul in editor
                drifted_yaml = original_yaml + "\n# --- DRIFT DETECTAT ---\n" + "\n".join([f"# VIOLATION: {v}" for v in active_violations])
                
                drifting_apps.append({
                    "name": item["metadata"]["name"],
                    "namespace": item["metadata"]["namespace"],
                    "state": security_state,
                    "violations": active_violations,
                    "original": original_yaml,
                    "modified": drifted_yaml
                })
                
        return drifting_apps
    except Exception as e:
        logger.error(f"Eroare extragere drift ZTA: {e}")
        raise e
