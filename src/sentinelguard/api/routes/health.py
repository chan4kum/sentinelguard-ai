from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sentinelguard.api.schemas import HealthResponse, ReadyResponse
from sentinelguard.config import APP_NAME, APP_VERSION

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health() -> HealthResponse:
    return HealthResponse(service=APP_NAME, version=APP_VERSION)


@router.get(
    "/ready",
    response_model=ReadyResponse,
    responses={503: {"model": ReadyResponse, "description": "Database unreachable"}},
    summary="Readiness probe (checks the database)",
)
def ready(request: Request):
    if request.app.state.repository.ping():
        return ReadyResponse(status="ready", database="ok")
    return JSONResponse(
        status_code=503, content=ReadyResponse(status="unavailable", database="error").model_dump()
    )
