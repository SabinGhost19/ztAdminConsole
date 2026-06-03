"""Security-scan aggregation service.

Surfaces the OSS "Snyk-style" security-scan attestation (gitleaks secrets +
checkov IaC + Semgrep SAST) that the zta-operator verifies at admission and
writes to status.verifications.securityScan / status.attestations.securityScan*.

No new data source: it reads the same ZTA custom resources the rest of the
dashboard already reads (via the shared k8s scanner + serializer), so it stays
consistent with the pull-based, operator-as-source-of-truth model.
"""
import logging

from app.services.zta_service import list_zta_applications

logger = logging.getLogger("zero_trust_security_scan_service")

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "": 0}


def _worst(*severities: str) -> str:
    worst = "NONE"
    for sev in severities:
        if _SEV_RANK.get(str(sev or "NONE").upper(), 0) > _SEV_RANK.get(worst, 0):
            worst = str(sev).upper()
    return worst


async def list_security_scans(namespace: str = "") -> dict:
    """Return per-application security-scan results plus a cluster rollup."""
    apps = await list_zta_applications(namespace=namespace)

    items = []
    totals = {"secrets": 0, "iac": 0, "sast": 0, "findings": 0}
    apps_with_secrets = 0
    enforced = 0

    for app in apps:
        meta = app.get("metadata", {}) or {}
        summary = app.get("summary", {}) or {}
        scan = summary.get("securityScan", {}) or {}
        scan_summary = scan.get("summary", {}) or {}

        secrets_total = int(scan.get("secretsTotal", 0) or 0)
        sast_total = int((scan_summary.get("sast", {}) or {}).get("total", 0) or 0)
        iac_total = int((scan_summary.get("iac", {}) or {}).get("total", 0) or 0)

        if scan.get("enforced"):
            enforced += 1
        if secrets_total > 0:
            apps_with_secrets += 1
        totals["secrets"] += secrets_total
        totals["sast"] += sast_total
        totals["iac"] += iac_total
        totals["findings"] += int(scan.get("findingsCount", 0) or 0)

        items.append({
            "namespace": meta.get("namespace"),
            "name": meta.get("name"),
            "image": summary.get("image"),
            "phase": summary.get("phase"),
            "securityState": summary.get("securityState"),
            "verified": bool(scan.get("verified", False)),
            "enforced": bool(scan.get("enforced", False)),
            "gating": scan.get("gating", ""),
            "reason": scan.get("reason", ""),
            "commit": scan.get("commit", ""),
            "completedAt": scan.get("completedAt"),
            "worstSeverity": _worst(scan.get("iacHighest"), scan.get("sastHighest"),
                                    "CRITICAL" if secrets_total > 0 else "NONE"),
            "counts": {
                "secrets": secrets_total,
                "sast": sast_total,
                "iac": iac_total,
                "findings": int(scan.get("findingsCount", 0) or 0),
            },
            "summary": scan_summary,
            "findings": scan.get("findings", []) or [],
        })

    return {
        "rollup": {
            "applications": len(items),
            "enforced": enforced,
            "appsWithSecrets": apps_with_secrets,
            "totals": totals,
        },
        "items": items,
    }
