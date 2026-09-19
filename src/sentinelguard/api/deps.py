"""Dependency wiring: routes get services, never repositories or engines."""

from __future__ import annotations

from fastapi import Request

from sentinelguard.services.dashboard_service import DashboardService
from sentinelguard.services.scan_service import ScanService


def get_scan_service(request: Request) -> ScanService:
    settings = request.app.state.settings
    return ScanService(
        request.app.state.repository, settings.max_upload_bytes, settings.max_files_per_scan
    )


def get_dashboard_service(request: Request) -> DashboardService:
    return DashboardService(request.app.state.repository)
