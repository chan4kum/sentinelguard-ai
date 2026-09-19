"""Repository abstraction + SQLAlchemy implementation.

Business logic depends only on :class:`ScanRepository`. To use another store, implement the
same six methods; nothing above this layer changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC

from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from sentinelguard.domain.models import (
    SEVERITY_ORDER,
    Finding,
    RuleCount,
    Scan,
    ScoreBreakdown,
    Severity,
    severity_rank,
)
from sentinelguard.persistence.orm import FindingRow, ScanRow


class Aggregates(BaseModel):
    scan_count: int
    finding_count: int
    average_score: float | None
    highest_score: int
    latest_score: int | None
    findings_by_severity: dict[str, int]
    findings_by_provider: dict[str, int]
    findings_by_rule: list[RuleCount]


class ScanRepository(ABC):
    @abstractmethod
    def save_scan(self, scan: Scan, findings: list[Finding]) -> None: ...

    @abstractmethod
    def get_scan(self, scan_id: str) -> Scan | None: ...

    @abstractmethod
    def list_scans(self, limit: int, offset: int) -> tuple[list[Scan], int]: ...

    @abstractmethod
    def list_findings(self, scan_id: str, severity: Severity | None = None) -> list[Finding]: ...

    @abstractmethod
    def aggregates(self) -> Aggregates: ...

    @abstractmethod
    def ping(self) -> bool: ...


def _scan_from_row(row: ScanRow) -> Scan:
    return Scan(
        scan_id=row.scan_id,
        created_at=row.created_at.replace(tzinfo=UTC),
        files=row.files,
        formats=row.formats,
        resources_total=row.resources_total,
        resources_analyzed=row.resources_analyzed,
        finding_count=row.finding_count,
        severity_counts={
            "critical": row.critical_count,
            "high": row.high_count,
            "medium": row.medium_count,
            "low": row.low_count,
        },
        risk_score=row.risk_score,
        risk_level=row.risk_level,
        score_breakdown=ScoreBreakdown.model_validate(row.score_breakdown),
    )


def _finding_from_row(row: FindingRow) -> Finding:
    return Finding(
        finding_id=row.finding_id,
        scan_id=row.scan_id,
        rule_id=row.rule_id,
        provider=row.provider,
        resource_type=row.resource_type,
        resource_name=row.resource_name,
        source_file=row.source_file,
        severity=row.severity,
        title=row.title,
        description=row.description,
        evidence=row.evidence,
        remediation=row.remediation,
        risk_weight=row.risk_weight,
    )


class SqlAlchemyScanRepository(ScanRepository):
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def save_scan(self, scan: Scan, findings: list[Finding]) -> None:
        counts = scan.severity_counts
        row = ScanRow(
            scan_id=scan.scan_id,
            created_at=scan.created_at.astimezone(UTC).replace(tzinfo=None),
            files=list(scan.files),
            formats=[f.value for f in scan.formats],
            resources_total=scan.resources_total,
            resources_analyzed=scan.resources_analyzed,
            finding_count=scan.finding_count,
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            risk_score=scan.risk_score,
            risk_level=scan.risk_level.value,
            score_breakdown=scan.score_breakdown.model_dump(mode="json"),
            findings=[
                FindingRow(
                    finding_id=f.finding_id,
                    scan_id=f.scan_id,
                    rule_id=f.rule_id,
                    provider=f.provider.value,
                    resource_type=f.resource_type,
                    resource_name=f.resource_name,
                    source_file=f.source_file,
                    severity=f.severity.value,
                    title=f.title,
                    description=f.description,
                    evidence=list(f.evidence),
                    remediation=f.remediation,
                    risk_weight=f.risk_weight,
                )
                for f in findings
            ],
        )
        with self._session_factory.begin() as session:
            session.add(row)

    def get_scan(self, scan_id: str) -> Scan | None:
        with self._session_factory() as session:
            row = session.get(ScanRow, scan_id)
            return _scan_from_row(row) if row else None

    def list_scans(self, limit: int, offset: int) -> tuple[list[Scan], int]:
        with self._session_factory() as session:
            total = session.scalar(select(func.count()).select_from(ScanRow)) or 0
            rows = session.scalars(
                select(ScanRow)
                .order_by(ScanRow.created_at.desc(), ScanRow.scan_id)
                .limit(limit)
                .offset(offset)
            ).all()
            return [_scan_from_row(r) for r in rows], total

    def list_findings(self, scan_id: str, severity: Severity | None = None) -> list[Finding]:
        with self._session_factory() as session:
            stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)
            if severity is not None:
                stmt = stmt.where(FindingRow.severity == severity.value)
            findings = [_finding_from_row(r) for r in session.scalars(stmt).all()]
        findings.sort(key=lambda f: (severity_rank(f.severity), f.rule_id, f.resource_name))
        return findings

    def aggregates(self) -> Aggregates:
        with self._session_factory() as session:
            scan_count = session.scalar(select(func.count()).select_from(ScanRow)) or 0
            finding_count = session.scalar(select(func.count()).select_from(FindingRow)) or 0
            average = session.scalar(select(func.avg(ScanRow.risk_score)))
            highest = session.scalar(select(func.max(ScanRow.risk_score))) or 0
            latest = session.scalar(
                select(ScanRow.risk_score).order_by(ScanRow.created_at.desc()).limit(1)
            )
            by_severity = dict.fromkeys((s.value for s in SEVERITY_ORDER), 0)
            for severity, count in session.execute(
                select(FindingRow.severity, func.count()).group_by(FindingRow.severity)
            ):
                by_severity[severity] = count
            by_provider = {
                provider: count
                for provider, count in session.execute(
                    select(FindingRow.provider, func.count())
                    .group_by(FindingRow.provider)
                    .order_by(FindingRow.provider)
                )
            }
            by_rule = [
                RuleCount(rule_id=rule_id, title=title, count=count)
                for rule_id, title, count in session.execute(
                    select(FindingRow.rule_id, func.min(FindingRow.title), func.count())
                    .group_by(FindingRow.rule_id)
                    .order_by(func.count().desc(), FindingRow.rule_id)
                )
            ]
        return Aggregates(
            scan_count=scan_count,
            finding_count=finding_count,
            average_score=float(average) if average is not None else None,
            highest_score=highest,
            latest_score=latest,
            findings_by_severity=by_severity,
            findings_by_provider=by_provider,
            findings_by_rule=by_rule,
        )

    def ping(self) -> bool:
        try:
            with self._session_factory() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
