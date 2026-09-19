"""API-only schemas (envelopes). Domain models are reused directly as response bodies."""

from __future__ import annotations

from pydantic import BaseModel

from sentinelguard.domain.models import Scan


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str
    version: str


class ReadyResponse(BaseModel):
    status: str
    database: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[str] | None = None
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody


class ScanList(BaseModel):
    items: list[Scan]
    total: int
    limit: int
    offset: int
