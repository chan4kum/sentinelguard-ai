"""Builders for domain objects used across tests."""

from __future__ import annotations

from datetime import UTC, datetime

from sentinelguard.domain.models import (
    Finding,
    Provider,
    RiskLevel,
    Scan,
    ScoreBreakdown,
    Severity,
    SourceFormat,
)


def make_breakdown(score: int = 30, level: RiskLevel = RiskLevel.HIGH) -> ScoreBreakdown:
    return ScoreBreakdown(
        method="test",
        raw_total=score,
        score=score,
        cap=100,
        cap_applied=False,
        score_band=RiskLevel.MEDIUM,
        risk_level=level,
        escalated=True,
        by_severity=[],
        contributions=[],
        bands={"0": "secure"},
    )


def make_finding(
    scan_id: str,
    finding_id: str = "f1",
    rule_id: str = "AWS-S3-001",
    severity: Severity = Severity.CRITICAL,
    provider: Provider = Provider.AWS,
    resource_name: str = "aws_s3_bucket.logs",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        scan_id=scan_id,
        rule_id=rule_id,
        provider=provider,
        resource_type="aws_s3_bucket",
        resource_name=resource_name,
        source_file="main.tf",
        severity=severity,
        title="Public bucket",
        description="d",
        evidence=["acl = public-read"],
        remediation="fix it",
        risk_weight=30,
    )


def make_scan(
    scan_id: str = "s1",
    score: int = 30,
    created_at: datetime | None = None,
    findings: int = 1,
) -> Scan:
    return Scan(
        scan_id=scan_id,
        created_at=created_at or datetime(2026, 1, 1, tzinfo=UTC),
        files=["main.tf"],
        formats=[SourceFormat.TERRAFORM],
        resources_total=2,
        resources_analyzed=1,
        finding_count=findings,
        severity_counts={"critical": findings, "high": 0, "medium": 0, "low": 0},
        risk_score=score,
        risk_level=RiskLevel.HIGH,
        score_breakdown=make_breakdown(score),
    )
