from fastapi import APIRouter, HTTPException

from app.services.integrity_service import get_application_integrity, list_integrity_applications, revalidate_application_integrity

router = APIRouter()


@router.get("/applications")
async def get_integrity_applications() -> list[dict]:
    return await list_integrity_applications()


@router.get("/applications/{namespace}/{name}")
async def get_integrity_application(namespace: str, name: str) -> dict:
    payload = await get_application_integrity(namespace, name)
    if not payload:
        raise HTTPException(status_code=404, detail="ZeroTrustApplication not found")
    return payload


@router.post("/applications/{namespace}/{name}/revalidate")
async def revalidate_integrity_application(namespace: str, name: str) -> dict:
    return await revalidate_application_integrity(namespace, name)