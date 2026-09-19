from __future__ import annotations

import pytest

from sentinelguard.domain.models import RiskLevel, Severity
from sentinelguard.scoring.engine import SCORE_CAP, calculate_risk, level_for_score
from tests.factories import make_finding

WEIGHTS = {Severity.CRITICAL: 30, Severity.HIGH: 20, Severity.MEDIUM: 10, Severity.LOW: 4}


def findings_of(*severities: Severity):
    return [
        make_finding("s", f"f{i}", f"R-{i}", sev, resource_name=f"res{i}").model_copy(
            update={"risk_weight": WEIGHTS[sev]}
        )
        for i, sev in enumerate(severities)
    ]


def test_no_findings_is_zero_and_secure():
    b = calculate_risk([])
    assert (b.score, b.raw_total, b.risk_level, b.score_band) == (
        0,
        0,
        RiskLevel.SECURE,
        RiskLevel.SECURE,
    )
    assert not b.cap_applied and not b.escalated and b.contributions == []
    assert [s.count for s in b.by_severity] == [0, 0, 0, 0]


@pytest.mark.parametrize(
    ("score", "level"),
    [(0, "secure"), (1, "low"), (19, "low"), (20, "medium"), (39, "medium"), (40, "high"),
     (69, "high"), (70, "critical"), (99, "critical"), (100, "critical")],
)  # fmt: skip
def test_level_band_boundaries(score, level):
    assert level_for_score(score).value == level


@pytest.mark.parametrize(
    ("severities", "score", "level", "escalated"),
    [
        ([Severity.LOW], 4, RiskLevel.LOW, False),
        ([Severity.MEDIUM], 10, RiskLevel.LOW, False),
        ([Severity.HIGH], 20, RiskLevel.MEDIUM, False),
        ([Severity.HIGH, Severity.MEDIUM], 30, RiskLevel.MEDIUM, False),
        ([Severity.CRITICAL], 30, RiskLevel.HIGH, True),  # escalation: 30 alone is a "medium" band
        ([Severity.CRITICAL, Severity.MEDIUM], 40, RiskLevel.HIGH, False),  # band already high
        ([Severity.CRITICAL] * 2, 60, RiskLevel.HIGH, False),
        ([Severity.CRITICAL] * 2 + [Severity.MEDIUM], 70, RiskLevel.CRITICAL, False),
    ],
)  # fmt: skip
def test_score_level_and_escalation(severities, score, level, escalated):
    b = calculate_risk(findings_of(*severities))
    assert (b.score, b.risk_level, b.escalated) == (score, level, escalated)


def test_score_is_capped_and_says_so():
    b = calculate_risk(findings_of(*[Severity.CRITICAL] * 5))
    assert b.raw_total == 150 and b.score == SCORE_CAP == 100
    assert b.cap_applied and b.risk_level == RiskLevel.CRITICAL


def test_exactly_at_cap_is_not_reported_as_capped():
    b = calculate_risk(findings_of(*[Severity.CRITICAL] * 3, Severity.MEDIUM))
    assert b.raw_total == 100 and not b.cap_applied


def test_breakdown_explains_every_point():
    findings = findings_of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.MEDIUM)
    b = calculate_risk(findings)
    assert sum(c.points for c in b.contributions) == b.raw_total == 70
    assert [(c.rule_id, c.points) for c in b.contributions] == [
        (f.rule_id, f.risk_weight) for f in findings
    ]
    subtotal = {s.severity: (s.count, s.points) for s in b.by_severity}
    assert subtotal == {
        Severity.CRITICAL: (1, 30), Severity.HIGH: (1, 20),
        Severity.MEDIUM: (2, 20), Severity.LOW: (0, 0),
    }  # fmt: skip
    assert "capped at 100" in b.method and b.bands["70-100"] == "critical"


def test_scoring_is_deterministic_and_order_independent():
    findings = findings_of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    a = calculate_risk(findings)
    b = calculate_risk(list(reversed(findings)))
    assert (a.score, a.risk_level, a.raw_total) == (b.score, b.risk_level, b.raw_total)
    assert calculate_risk(findings) == calculate_risk(findings)


def test_score_is_always_an_integer_within_bounds():
    for n in range(0, 8):
        b = calculate_risk(findings_of(*[Severity.HIGH] * n))
        assert isinstance(b.score, int) and 0 <= b.score <= 100
