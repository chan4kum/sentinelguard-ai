"""Integration Test Agent: parser → rules → scoring → persistence → retrieval, with no mocks."""

from __future__ import annotations

import pytest

from sentinelguard.domain.models import Severity
from sentinelguard.errors import IaCParseError, InvalidUploadError, NotFoundError
from sentinelguard.persistence.database import init_db, make_engine, make_session_factory
from sentinelguard.persistence.repository import SqlAlchemyScanRepository
from sentinelguard.services.dashboard_service import DashboardService
from sentinelguard.services.scan_service import ScanService

pytestmark = pytest.mark.integration


@pytest.fixture
def repo(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'int.db'}")
    init_db(engine)
    return SqlAlchemyScanRepository(make_session_factory(engine))


@pytest.fixture
def service(repo):
    return ScanService(repo, max_upload_bytes=1_000_000, max_files=5)


def upload_of(samples, relative):
    path = samples / relative
    return [(path.name, path.read_bytes())]


MATRIX = [
    # sample, findings, score, level
    ("terraform/vulnerable.tf", 10, 100, "critical"),
    ("terraform/safe.tf", 0, 0, "secure"),
    ("cloudformation/vulnerable.json", 8, 100, "critical"),
    ("cloudformation/vulnerable.yaml", 3, 70, "critical"),
    ("cloudformation/safe.json", 0, 0, "secure"),
    ("cloudformation/safe.yaml", 0, 0, "secure"),
    ("azure/vulnerable.tf", 4, 100, "critical"),
    ("azure/safe.tf", 0, 0, "secure"),
]


@pytest.mark.parametrize(("relative", "findings", "score", "level"), MATRIX)
def test_pipeline_end_to_end_and_persistence(service, samples, relative, findings, score, level):
    result = service.run_scan(upload_of(samples, relative))
    assert (result.finding_count, result.risk_score, result.risk_level.value) == (
        findings,
        score,
        level,
    )
    reloaded = service.get_scan(result.scan_id)
    assert reloaded == result  # what was persisted is exactly what was returned

    # internal consistency between findings, counts and the score explanation
    assert len(result.findings) == result.finding_count
    assert sum(result.severity_counts.values()) == result.finding_count
    assert result.score_breakdown.raw_total == sum(f.risk_weight for f in result.findings)
    assert result.risk_score == min(100, result.score_breakdown.raw_total)
    assert {f.scan_id for f in result.findings} == ({result.scan_id} if findings else set())


def test_severity_filter_and_dashboard_over_multiple_scans(service, repo, samples):
    service.run_scan(upload_of(samples, "terraform/vulnerable.tf"))
    second = service.run_scan(upload_of(samples, "cloudformation/vulnerable.json"))
    service.run_scan(upload_of(samples, "terraform/safe.tf"))

    crit = service.list_findings(second.scan_id, severity=Severity.CRITICAL)
    assert {f.rule_id for f in crit} == {"AWS-S3-001", "AWS-EC2-001", "AWS-EC2-002"}

    summary = DashboardService(repo).summary()
    assert summary.scan_count == 3 and summary.finding_count == 18
    assert summary.overall_risk_score == 67 and summary.overall_risk_level.value == "high"
    assert sum(summary.findings_by_severity.values()) == 18
    assert sum(r.count for r in summary.findings_by_rule) == 18


def test_failed_scan_persists_nothing(service, repo):
    with pytest.raises(IaCParseError):
        service.run_scan([("bad.tf", b"resource {{{")])
    assert repo.list_scans(10, 0)[1] == 0


def test_service_rejects_bad_requests(service):
    with pytest.raises(InvalidUploadError):
        service.run_scan([])
    with pytest.raises(InvalidUploadError):
        service.run_scan([(f"f{i}.tf", b"# x") for i in range(6)])
    with pytest.raises(NotFoundError):
        service.get_scan("nope")
    with pytest.raises(NotFoundError):
        service.list_findings("nope")


def test_scan_ids_and_finding_ids_are_unique(service, samples):
    a = service.run_scan(upload_of(samples, "terraform/vulnerable.tf"))
    b = service.run_scan(upload_of(samples, "terraform/vulnerable.tf"))
    assert a.scan_id != b.scan_id
    assert len({f.finding_id for f in a.findings + b.findings}) == 20
    # identical input → identical findings apart from identifiers (determinism)
    key = lambda f: (f.rule_id, f.resource_name, tuple(f.evidence))  # noqa: E731
    assert [key(f) for f in a.findings] == [key(f) for f in b.findings]
    assert a.risk_score == b.risk_score


def test_repository_is_swappable_behind_the_interface(samples):
    """The service depends only on the ScanRepository interface: an in-memory fake works."""
    from sentinelguard.persistence.repository import Aggregates, ScanRepository

    class MemoryRepo(ScanRepository):
        def __init__(self):
            self.scans, self.findings = {}, {}

        def save_scan(self, scan, findings):
            self.scans[scan.scan_id] = scan
            self.findings[scan.scan_id] = findings

        def get_scan(self, scan_id):
            return self.scans.get(scan_id)

        def list_scans(self, limit, offset):
            items = list(self.scans.values())
            return items[offset : offset + limit], len(items)

        def list_findings(self, scan_id, severity=None):
            return [f for f in self.findings.get(scan_id, []) if severity in (None, f.severity)]

        def aggregates(self):
            return Aggregates(
                scan_count=len(self.scans), finding_count=0, average_score=None, highest_score=0,
                latest_score=None, findings_by_severity={}, findings_by_provider={},
                findings_by_rule=[],
            )  # fmt: skip

        def ping(self):
            return True

    memory = MemoryRepo()
    service = ScanService(memory, 1_000_000, 5)
    result = service.run_scan(upload_of(samples, "terraform/vulnerable.tf"))
    assert service.get_scan(result.scan_id).risk_score == 100
    assert len(memory.findings[result.scan_id]) == 10
