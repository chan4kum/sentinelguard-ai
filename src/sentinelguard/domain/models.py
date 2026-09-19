"""Domain models shared by every layer. Pure data: no I/O, no framework coupling."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)


def severity_rank(severity: Severity) -> int:
    """0 = most severe. Used for deterministic ordering."""
    return SEVERITY_ORDER.index(severity)


class Provider(StrEnum):
    AWS = "aws"
    AZURE = "azure"


class SourceFormat(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"


class RiskLevel(StrEnum):
    SECURE = "secure"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Kind:
    """Canonical (format-independent) resource kinds the rules engine understands."""

    S3_BUCKET = "s3_bucket"
    SECURITY_GROUP = "security_group"
    RDS_INSTANCE = "rds_instance"
    EBS_VOLUME = "ebs_volume"
    AZURE_STORAGE = "azure_storage"
    AZURE_NSG = "azure_nsg"
    # Auxiliary kinds: merged into an s3_bucket by the linker, never evaluated by rules.
    S3_ACL = "s3_acl"
    S3_PUBLIC_ACCESS_BLOCK = "s3_public_access_block"
    S3_BUCKET_POLICY = "s3_bucket_policy"
    S3_ENCRYPTION = "s3_encryption"


class NormalizedResource(BaseModel):
    """A cloud resource in a format-independent shape.

    Unknown or unresolvable values are stored as ``None`` so rules never flag on a guess.
    """

    model_config = ConfigDict(frozen=False)

    provider: Provider
    kind: str
    source_type: str = Field(description='Original type, e.g. "aws_s3_bucket" or "AWS::S3::Bucket"')
    name: str = Field(description='Terraform "type.name" or CloudFormation logical ID')
    source_format: SourceFormat
    source_file: str
    properties: dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    """Metadata describing one guardrail (also the public rule-catalogue schema)."""

    rule_id: str
    title: str
    provider: Provider
    resource_kinds: list[str]
    description: str
    detection: str = Field(description="Plain-English detection condition")
    severity: Severity
    risk_weight: int = Field(ge=0, le=100)
    remediation: str


class Finding(BaseModel):
    finding_id: str
    scan_id: str
    rule_id: str
    provider: Provider
    resource_type: str
    resource_name: str
    source_file: str
    severity: Severity
    title: str
    description: str
    evidence: list[str]
    remediation: str
    risk_weight: int


class ScoreContribution(BaseModel):
    rule_id: str
    resource_name: str
    severity: Severity
    points: int


class SeveritySubtotal(BaseModel):
    severity: Severity
    count: int
    points: int


class ScoreBreakdown(BaseModel):
    """Everything needed to explain WHY a score was assigned."""

    method: str
    raw_total: int
    score: int
    cap: int
    cap_applied: bool
    score_band: RiskLevel = Field(description="Level implied by the score alone")
    risk_level: RiskLevel = Field(description="Final level after escalation")
    escalated: bool = Field(description="True if a CRITICAL finding raised the level")
    by_severity: list[SeveritySubtotal]
    contributions: list[ScoreContribution]
    bands: dict[str, str]


class Scan(BaseModel):
    scan_id: str
    created_at: datetime
    files: list[str]
    formats: list[SourceFormat]
    resources_total: int
    resources_analyzed: int
    finding_count: int
    severity_counts: dict[str, int]
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    score_breakdown: ScoreBreakdown


class ScanDetail(Scan):
    findings: list[Finding]


class RuleCount(BaseModel):
    rule_id: str
    title: str
    count: int


class DashboardSummary(BaseModel):
    scan_count: int
    finding_count: int
    overall_risk_score: int = Field(ge=0, le=100)
    overall_risk_level: RiskLevel
    latest_scan_score: int | None
    highest_scan_score: int
    findings_by_severity: dict[str, int]
    findings_by_provider: dict[str, int]
    findings_by_rule: list[RuleCount]
    recent_scans: list[Scan]
    score_explanation: str
