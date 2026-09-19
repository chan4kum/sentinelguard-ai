from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinelguard.domain.models import Provider, Severity
from sentinelguard.persistence.database import init_db, make_engine, make_session_factory
from sentinelguard.persistence.repository import SqlAlchemyScanRepository
from tests.factories import make_finding, make_scan


@pytest.fixture
def repo(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'r.db'}")
    init_db(engine)
    return SqlAlchemyScanRepository(make_session_factory(engine))


def test_ping(repo):
    assert repo.ping() is True


def test_save_and_get_roundtrip(repo):
    scan = make_scan("s1")
    repo.save_scan(scan, [make_finding("s1")])
    loaded = repo.get_scan("s1")
    assert loaded == scan
    assert loaded.created_at.tzinfo is not None


def test_get_missing_scan_is_none(repo):
    assert repo.get_scan("nope") is None


def test_findings_roundtrip_filter_and_order(repo):
    repo.save_scan(
        make_scan("s1", findings=3),
        [
            make_finding("s1", "a", "AWS-ENC-001", Severity.MEDIUM),
            make_finding("s1", "b", "AWS-S3-001", Severity.CRITICAL),
            make_finding("s1", "c", "AWS-S3-002", Severity.HIGH),
        ],
    )
    all_findings = repo.list_findings("s1")
    assert [f.severity for f in all_findings] == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    only_high = repo.list_findings("s1", Severity.HIGH)
    assert [f.finding_id for f in only_high] == ["c"]
    assert only_high[0].evidence == ["acl = public-read"]
    assert repo.list_findings("other") == []


def test_list_scans_newest_first_with_paging(repo):
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(5):
        repo.save_scan(make_scan(f"s{i}", created_at=base + timedelta(minutes=i)), [])
    items, total = repo.list_scans(limit=2, offset=0)
    assert total == 5
    assert [s.scan_id for s in items] == ["s4", "s3"]
    items, _ = repo.list_scans(limit=2, offset=4)
    assert [s.scan_id for s in items] == ["s0"]


def test_aggregates_empty(repo):
    agg = repo.aggregates()
    assert agg.scan_count == 0 and agg.finding_count == 0
    assert agg.average_score is None and agg.latest_score is None
    assert agg.findings_by_severity == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert agg.findings_by_rule == []


def test_aggregates_counts(repo):
    base = datetime(2026, 1, 1, tzinfo=UTC)
    repo.save_scan(
        make_scan("s1", 30, base, 2),
        [
            make_finding("s1", "1", "AWS-S3-001", Severity.CRITICAL),
            make_finding("s1", "2", "AWS-S3-001", Severity.CRITICAL, resource_name="b2"),
        ],
    )
    repo.save_scan(
        make_scan("s2", 10, base + timedelta(hours=1), 1),
        [make_finding("s2", "3", "AZ-NSG-001", Severity.CRITICAL, Provider.AZURE)],
    )
    agg = repo.aggregates()
    assert agg.scan_count == 2 and agg.finding_count == 3
    assert agg.average_score == 20.0
    assert agg.highest_score == 30
    assert agg.latest_score == 10
    assert agg.findings_by_severity["critical"] == 3
    assert agg.findings_by_provider == {"aws": 2, "azure": 1}
    assert [(r.rule_id, r.count) for r in agg.findings_by_rule] == [
        ("AWS-S3-001", 2),
        ("AZ-NSG-001", 1),
    ]


def test_ping_false_when_engine_disposed_and_db_removed(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'p.db'}")
    init_db(engine)
    repo = SqlAlchemyScanRepository(make_session_factory(engine))

    class Broken:
        def __call__(self):
            raise RuntimeError("db down")

    repo._session_factory = Broken()
    assert repo.ping() is False
