"""
SFYNX Scan API endpoints.

POST /api/v1/scans          — Create a new scan
GET  /api/v1/scans          — List all scans
GET  /api/v1/scans/{id}     — Get scan details
GET  /api/v1/scans/{id}/findings — Get findings for a scan
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.finding import Finding
from app.schemas.scan import ScanRequest, ScanResponse, ScanResult, ScanSummary
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

# Service singleton — replaced by dependency injection in later phases
_service: ScanService | None = None


def _get_service() -> ScanService:
    global _service  # noqa: PLW0603
    if _service is None:
        _service = ScanService()
    return _service


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(request: ScanRequest) -> ScanResponse:
    """
    Submit a new security scan.

    The request MUST include:
    - target: URL to scan
    - authorization: must be true
    - scope: list of allowed host:port entries

    If authorization fails, the scan will be BLOCKED.
    """
    service = _get_service()
    return await service.create_scan(request)


@router.get("", response_model=list[ScanSummary])
async def list_scans() -> list[ScanSummary]:
    """List all scans with their current status."""
    service = _get_service()
    return service.list_scans()


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str) -> ScanResult:
    """Get detailed scan results including task statuses and findings."""
    service = _get_service()
    result = service.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return result


@router.get("/{scan_id}/findings", response_model=list[Finding])
async def get_findings(scan_id: str) -> list[Finding]:
    """Get all findings for a specific scan."""
    service = _get_service()
    findings = service.get_findings(scan_id)
    if findings is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return findings


# Compatibility router for root /scan endpoints (e.g. POST /scan)
compat_router = APIRouter(tags=["scans"])
compat_router.add_api_route(
    "/scan", create_scan, methods=["POST"], response_model=ScanResponse, status_code=201
)
compat_router.add_api_route(
    "/scan", list_scans, methods=["GET"], response_model=list[ScanSummary]
)
compat_router.add_api_route(
    "/scan/{scan_id}", get_scan, methods=["GET"], response_model=ScanResult
)
compat_router.add_api_route(
    "/scan/{scan_id}/findings",
    get_findings,
    methods=["GET"],
    response_model=list[Finding],
)

