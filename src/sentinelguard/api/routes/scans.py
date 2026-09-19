from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, Request, UploadFile
from starlette.concurrency import run_in_threadpool

from sentinelguard.api.deps import get_scan_service
from sentinelguard.api.schemas import ErrorResponse, ScanList
from sentinelguard.domain.models import Finding, ScanDetail, Severity
from sentinelguard.errors import InvalidUploadError
from sentinelguard.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

Service = Annotated[ScanService, Depends(get_scan_service)]


@router.post(
    "",
    response_model=ScanDetail,
    status_code=201,
    summary="Scan Terraform / CloudFormation files",
    description=(
        "Upload one or more `.tf`, `.json`, `.yaml`, `.yml` or `.template` files as multipart "
        "field `files`. Files are analysed as data in memory; nothing is executed or stored on disk."
    ),
    responses={
        400: {"model": ErrorResponse, "description": "No files, too many files, or invalid file"},
        413: {"model": ErrorResponse, "description": "File or request too large"},
        415: {"model": ErrorResponse, "description": "Unsupported file type"},
        422: {"model": ErrorResponse, "description": "File could not be parsed / validation error"},
    },
)
async def create_scan(
    request: Request,
    service: Service,
    files: Annotated[list[UploadFile], File(description="IaC files to audit")],
) -> ScanDetail:
    settings = request.app.state.settings
    if len(files) > settings.max_files_per_scan:
        raise InvalidUploadError(f"Too many files: at most {settings.max_files_per_scan} per scan.")
    uploads: list[tuple[str | None, bytes]] = []
    for upload in files:
        # Read one byte past the limit so oversize is detected without buffering unbounded data.
        data = await upload.read(settings.max_upload_bytes + 1)
        uploads.append((upload.filename, data))
    return await run_in_threadpool(service.run_scan, uploads)


@router.get("", response_model=ScanList, summary="List scans (newest first)")
def list_scans(
    service: Service,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanList:
    items, total = service.list_scans(limit, offset)
    return ScanList(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{scan_id}",
    response_model=ScanDetail,
    summary="Get a scan with its findings and score breakdown",
    responses={404: {"model": ErrorResponse}},
)
def get_scan(scan_id: str, service: Service) -> ScanDetail:
    return service.get_scan(scan_id)


@router.get(
    "/{scan_id}/findings",
    response_model=list[Finding],
    summary="List a scan's findings (most severe first)",
    responses={404: {"model": ErrorResponse}},
)
def list_findings(
    scan_id: str,
    service: Service,
    severity: Annotated[Severity | None, Query(description="Filter by severity")] = None,
) -> list[Finding]:
    return service.list_findings(scan_id, severity)
