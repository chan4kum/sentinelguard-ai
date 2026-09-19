"""Scan use-cases. Orchestration only: every step is delegated to a focused layer."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sentinelguard.domain.models import Finding, Scan, ScanDetail, Severity
from sentinelguard.errors import InvalidUploadError, NotFoundError
from sentinelguard.parsing import parse_files
from sentinelguard.parsing.ingest import validate_upload
from sentinelguard.persistence.repository import ScanRepository
from sentinelguard.rules.registry import evaluate_resources
from sentinelguard.scoring.engine import calculate_risk

logger = logging.getLogger("sentinelguard.scan")


class ScanService:
    def __init__(self, repository: ScanRepository, max_upload_bytes: int, max_files: int) -> None:
        self._repository = repository
        self._max_upload_bytes = max_upload_bytes
        self._max_files = max_files

    def run_scan(self, uploads: list[tuple[str | None, bytes]]) -> ScanDetail:
        """parse -> rules -> score -> persist. ``uploads`` is [(client filename, raw bytes)]."""
        if not uploads:
            raise InvalidUploadError(
                "No files were uploaded. Send at least one .tf/.json/.yaml file."
            )
        if len(uploads) > self._max_files:
            raise InvalidUploadError(f"Too many files: at most {self._max_files} per scan.")

        files = [validate_upload(name, data, self._max_upload_bytes) for name, data in uploads]
        parsed = parse_files(files)

        scan_id = str(uuid.uuid4())
        findings = evaluate_resources(parsed.resources, scan_id)
        breakdown = calculate_risk(findings)
        counts = {s.severity.value: s.count for s in breakdown.by_severity}

        scan = Scan(
            scan_id=scan_id,
            created_at=datetime.now(UTC),
            files=[f.name for f in files],
            formats=parsed.formats,
            resources_total=parsed.resources_total,
            resources_analyzed=len(parsed.resources),
            finding_count=len(findings),
            severity_counts=counts,
            risk_score=breakdown.score,
            risk_level=breakdown.risk_level,
            score_breakdown=breakdown,
        )
        self._repository.save_scan(scan, findings)
        logger.info(
            "scan completed",
            extra={
                "event": "scan_completed",
                "scan_id": scan_id,
                "files": len(files),
                "findings": len(findings),
                "risk_score": breakdown.score,
            },
        )
        return ScanDetail(**scan.model_dump(), findings=findings)

    def get_scan(self, scan_id: str) -> ScanDetail:
        scan = self._require_scan(scan_id)
        findings = self._repository.list_findings(scan_id)
        return ScanDetail(**scan.model_dump(), findings=findings)

    def list_scans(self, limit: int, offset: int) -> tuple[list[Scan], int]:
        return self._repository.list_scans(limit, offset)

    def list_findings(self, scan_id: str, severity: Severity | None = None) -> list[Finding]:
        self._require_scan(scan_id)
        return self._repository.list_findings(scan_id, severity)

    def _require_scan(self, scan_id: str) -> Scan:
        scan = self._repository.get_scan(scan_id)
        if scan is None:
            raise NotFoundError("Scan not found.")
        return scan
