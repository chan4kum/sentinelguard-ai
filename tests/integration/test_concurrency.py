"""Concurrent scans must be exactly as correct as sequential ones.

Regression for a real defect: ``python-hcl2`` serializes through a mutable
``SerializationContext`` created once as a *default argument*, so parsing Terraform from several
threads at once corrupted results (findings silently missing). The scan path now serialises access
to the HCL parser; these tests force aggressive thread switching so the race, if reintroduced,
fails deterministically instead of once in a while on a slow CI runner.
"""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sentinelguard.parsing import parse_files
from sentinelguard.parsing.ingest import validate_upload
from sentinelguard.rules.registry import evaluate_resources

pytestmark = pytest.mark.integration

SAMPLES = Path(__file__).resolve().parents[2] / "samples"

# (sample, expected finding count)
CASES = [
    ("terraform/vulnerable.tf", 10),
    ("azure/vulnerable.tf", 4),
    ("terraform/safe.tf", 0),
]


@pytest.fixture
def aggressive_thread_switching():
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        yield
    finally:
        sys.setswitchinterval(previous)


def scan_count(relative: str) -> int:
    path = SAMPLES / relative
    upload = validate_upload(path.name, path.read_bytes(), 1_000_000)
    return len(evaluate_resources(parse_files([upload]).resources, "scan"))


@pytest.mark.parametrize(("relative", "expected"), CASES)
def test_concurrent_terraform_scans_return_the_same_findings_as_sequential(
    aggressive_thread_switching, relative, expected
):
    assert scan_count(relative) == expected  # sequential baseline
    for _ in range(10):
        with ThreadPoolExecutor(max_workers=8) as pool:
            counts = list(pool.map(lambda _: scan_count(relative), range(16)))
        assert counts == [expected] * 16


def test_concurrent_mixed_formats_are_all_correct(aggressive_thread_switching):
    work = [c for c in CASES for _ in range(6)] + [
        ("cloudformation/vulnerable.json", 8),
        ("cloudformation/vulnerable.yaml", 3),
    ] * 6
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda case: (case, scan_count(case[0])), work))
    assert all(count == case[1] for case, count in results)
