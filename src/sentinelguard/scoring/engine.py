"""Deterministic, explainable risk scoring. No LLM, no randomness, integers only.

    score = min(100, sum(finding.risk_weight))

Each rule owns its weight (Critical 30, High 20, Medium 10). The level comes from fixed score
bands; any CRITICAL finding lifts the level to at least HIGH so a single public bucket can
never read as "medium".
"""

from __future__ import annotations

from sentinelguard.domain.models import (
    SEVERITY_ORDER,
    Finding,
    RiskLevel,
    ScoreBreakdown,
    ScoreContribution,
    Severity,
    SeveritySubtotal,
)

SCORE_CAP = 100

# (minimum score, level), highest first.
LEVEL_BANDS: tuple[tuple[int, RiskLevel], ...] = (
    (70, RiskLevel.CRITICAL),
    (40, RiskLevel.HIGH),
    (20, RiskLevel.MEDIUM),
    (1, RiskLevel.LOW),
    (0, RiskLevel.SECURE),
)
BAND_LABELS = {
    "0": "secure",
    "1-19": "low",
    "20-39": "medium",
    "40-69": "high",
    "70-100": "critical",
}
_LEVEL_RANK = {
    RiskLevel.SECURE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

METHOD = (
    "Score = sum of the risk weight of every finding (Critical 30, High 20, Medium 10 per rule), "
    f"capped at {SCORE_CAP}. The level comes from the score band (0 secure, 1-19 low, 20-39 medium, "
    "40-69 high, 70-100 critical); any CRITICAL finding raises the level to at least high."
)


def level_for_score(score: int) -> RiskLevel:
    for minimum, level in LEVEL_BANDS:
        if score >= minimum:
            return level
    return RiskLevel.SECURE


def calculate_risk(findings: list[Finding]) -> ScoreBreakdown:
    raw_total = sum(f.risk_weight for f in findings)
    score = min(SCORE_CAP, raw_total)
    band = level_for_score(score)

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    level = band
    escalated = False
    if has_critical and _LEVEL_RANK[band] < _LEVEL_RANK[RiskLevel.HIGH]:
        level, escalated = RiskLevel.HIGH, True

    by_severity = [
        SeveritySubtotal(
            severity=severity,
            count=sum(1 for f in findings if f.severity == severity),
            points=sum(f.risk_weight for f in findings if f.severity == severity),
        )
        for severity in SEVERITY_ORDER
    ]
    contributions = [
        ScoreContribution(
            rule_id=f.rule_id,
            resource_name=f.resource_name,
            severity=f.severity,
            points=f.risk_weight,
        )
        for f in findings
    ]
    return ScoreBreakdown(
        method=METHOD,
        raw_total=raw_total,
        score=score,
        cap=SCORE_CAP,
        cap_applied=raw_total > SCORE_CAP,
        score_band=band,
        risk_level=level,
        escalated=escalated,
        by_severity=by_severity,
        contributions=contributions,
        bands=dict(BAND_LABELS),
    )
