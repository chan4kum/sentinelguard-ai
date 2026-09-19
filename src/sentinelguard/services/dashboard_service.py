"""Aggregates for the dashboard."""

from __future__ import annotations

from sentinelguard.domain.models import DashboardSummary
from sentinelguard.persistence.repository import ScanRepository
from sentinelguard.scoring.engine import level_for_score

RECENT_SCANS = 5


class DashboardService:
    def __init__(self, repository: ScanRepository) -> None:
        self._repository = repository

    def summary(self) -> DashboardSummary:
        aggregates = self._repository.aggregates()
        recent, _ = self._repository.list_scans(limit=RECENT_SCANS, offset=0)

        if aggregates.average_score is None:
            overall = 0
            explanation = "No scans yet. Upload Terraform or CloudFormation to get a risk score."
        else:
            overall = int(aggregates.average_score + 0.5)
            explanation = (
                f"Overall score is the average of {aggregates.scan_count} scan score(s), rounded. "
                "Each scan score is the sum of its findings' risk weights (Critical 30, High 20, "
                "Medium 10), capped at 100."
            )
        return DashboardSummary(
            scan_count=aggregates.scan_count,
            finding_count=aggregates.finding_count,
            overall_risk_score=overall,
            overall_risk_level=level_for_score(overall),
            latest_scan_score=aggregates.latest_score,
            highest_scan_score=aggregates.highest_score,
            findings_by_severity=aggregates.findings_by_severity,
            findings_by_provider=aggregates.findings_by_provider,
            findings_by_rule=aggregates.findings_by_rule,
            recent_scans=recent,
            score_explanation=explanation,
        )
