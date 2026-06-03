from fastapi import APIRouter

from app.services.security_scan_service import list_security_scans

router = APIRouter()


@router.get("/")
async def get_all_security_scans(namespace: str = ""):
    """Per-application OSS security-scan results (gitleaks/checkov/semgrep)
    plus a cluster-wide rollup, read from ZTA status."""
    return await list_security_scans(namespace=namespace)
