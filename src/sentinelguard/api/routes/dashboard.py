from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from sentinelguard.api.deps import get_dashboard_service
from sentinelguard.domain.models import DashboardSummary
from sentinelguard.services.dashboard_service import DashboardService

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary, summary="Aggregates for the dashboard")
def summary(
    service: Annotated[DashboardService, Depends(get_dashboard_service)],
) -> DashboardSummary:
    return service.summary()
