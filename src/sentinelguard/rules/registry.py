"""The approved security baseline: one registry, deterministic evaluation."""

from __future__ import annotations

import uuid

from sentinelguard.domain.models import Finding, NormalizedResource, Rule, severity_rank
from sentinelguard.rules.aws import (
    OpenIngressRule,
    PublicS3Rule,
    RdpOpenRule,
    RdsPublicRule,
    S3EncryptionRule,
    S3PublicAccessBlockRule,
    SshOpenRule,
    UnencryptedStorageRule,
)
from sentinelguard.rules.azure import AzureNsgAdminPortRule, AzureStoragePublicRule
from sentinelguard.rules.base import GuardrailRule

BASELINE: tuple[GuardrailRule, ...] = (
    PublicS3Rule(),
    S3PublicAccessBlockRule(),
    S3EncryptionRule(),
    SshOpenRule(),
    RdpOpenRule(),
    OpenIngressRule(),
    RdsPublicRule(),
    UnencryptedStorageRule(),
    AzureStoragePublicRule(),
    AzureNsgAdminPortRule(),
)


def rule_catalogue() -> list[Rule]:
    return [rule.meta for rule in BASELINE]


def evaluate_resources(
    resources: list[NormalizedResource],
    scan_id: str,
    rules: tuple[GuardrailRule, ...] = BASELINE,
) -> list[Finding]:
    """Run every applicable rule against every resource; one finding per (rule, resource)."""
    findings: list[Finding] = []
    for resource in resources:
        for rule in rules:
            meta = rule.meta
            if resource.provider != meta.provider or resource.kind not in meta.resource_kinds:
                continue
            evidence = rule.evaluate(resource)
            if not evidence:
                continue
            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    scan_id=scan_id,
                    rule_id=meta.rule_id,
                    provider=meta.provider,
                    resource_type=resource.source_type,
                    resource_name=resource.name,
                    source_file=resource.source_file,
                    severity=meta.severity,
                    title=meta.title,
                    description=meta.description,
                    evidence=evidence,
                    remediation=meta.remediation,
                    risk_weight=meta.risk_weight,
                )
            )
    findings.sort(key=lambda f: (severity_rank(f.severity), f.rule_id, f.resource_name))
    return findings
