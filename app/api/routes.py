from fastapi import APIRouter, Query
from app.services.scanner import scan_url_service

router = APIRouter()

@router.post("/scan-url")
def scan_url(url: str = Query(..., description="The URL to scan for threats")):
    return scan_url_service(url)
