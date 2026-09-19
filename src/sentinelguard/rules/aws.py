"""AWS guardrails (Terraform and CloudFormation, via the normalized model)."""

from __future__ import annotations

from typing import Any

from sentinelguard.domain.models import Kind, NormalizedResource, Provider, Rule, Severity
from sentinelguard.parsing.values import is_world_cidr
from sentinelguard.rules.base import GuardrailRule

PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}


def _world_ingress(resource: NormalizedResource) -> list[tuple[dict[str, Any], list[str]]]:
    """Ingress rules open to the internet, with the offending CIDRs."""
    found = []
    for rule in resource.properties.get("ingress", []):
        world = [c for c in rule.get("cidrs", []) if is_world_cidr(c)]
        if world:
            found.append((rule, world))
    return found


def _all_ports_open(rule: dict[str, Any]) -> bool:
    return rule.get("protocol") == "-1" or (
        rule.get("from_port") == 0 and rule.get("to_port") == 65535
    )


def _covers_tcp_port(rule: dict[str, Any], port: int) -> bool:
    low, high = rule.get("from_port"), rule.get("to_port")
    return (
        rule.get("protocol") == "tcp"
        and low is not None
        and high is not None
        and low <= port <= high
    )


class PublicS3Rule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-S3-001",
        title="S3 bucket is publicly accessible",
        provider=Provider.AWS,
        resource_kinds=[Kind.S3_BUCKET],
        description="A bucket that grants access to everyone can leak or expose data to the internet.",
        detection=(
            "Bucket ACL is public-read, public-read-write or authenticated-read, or an unconditional "
            'bucket-policy statement Allows Principal "*".'
        ),
        severity=Severity.CRITICAL,
        risk_weight=30,
        remediation=(
            'Set the ACL to "private", remove policy statements with Principal "*", and enable all '
            "four S3 Block Public Access settings. Grant access to specific IAM principals or use "
            "CloudFront with Origin Access Control for public content."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        evidence = []
        for acl in resource.properties.get("acls", []):
            if acl["value"] in PUBLIC_ACLS:
                via = f" (set by {acl['via']})" if acl.get("via") else ""
                evidence.append(f'ACL is "{acl["value"]}"{via}')
        policy = resource.properties.get("public_policy_evidence")
        if policy:
            evidence.append(policy)
        return evidence


class S3PublicAccessBlockRule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-S3-002",
        title="S3 Block Public Access is missing or disabled",
        provider=Provider.AWS,
        resource_kinds=[Kind.S3_BUCKET],
        description="Block Public Access is the safety net that prevents accidental public exposure.",
        detection=(
            "No public-access-block is configured for the bucket, or any of block_public_acls, "
            "block_public_policy, ignore_public_acls, restrict_public_buckets is false."
        ),
        severity=Severity.HIGH,
        risk_weight=20,
        remediation=(
            "Add aws_s3_bucket_public_access_block (Terraform) or PublicAccessBlockConfiguration "
            "(CloudFormation) with all four settings true. If it is enforced at account level, "
            "document that decision."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        block = resource.properties.get("public_access_block")
        if block is None:
            return ["No public access block is configured for this bucket"]
        disabled = [name for name, value in block.items() if value is False]
        if disabled:
            return [f"Public access block setting(s) disabled: {', '.join(sorted(disabled))}"]
        return []


class S3EncryptionRule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-S3-003",
        title="S3 bucket has no explicit default encryption",
        provider=Provider.AWS,
        resource_kinds=[Kind.S3_BUCKET],
        description=(
            "Explicit server-side encryption (ideally SSE-KMS) enforces key control and auditability."
        ),
        detection=(
            "No aws_s3_bucket_server_side_encryption_configuration / server_side_encryption_configuration "
            "(Terraform) or BucketEncryption (CloudFormation) is associated with the bucket."
        ),
        severity=Severity.MEDIUM,
        risk_weight=10,
        remediation=(
            "Add aws_s3_bucket_server_side_encryption_configuration (Terraform) or BucketEncryption "
            "(CloudFormation) using aws:kms or AES256."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        if resource.properties.get("encryption_configured"):
            return []
        return ["No server-side encryption configuration found for this bucket"]


class _OpenAdminPortRule(GuardrailRule):
    port: int
    label: str

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        evidence = []
        for rule, world in _world_ingress(resource):
            if not _all_ports_open(rule) and _covers_tcp_port(rule, self.port):
                span = f"{rule['from_port']}" + (
                    f"-{rule['to_port']}" if rule["from_port"] != rule["to_port"] else ""
                )
                evidence.append(
                    f"Ingress tcp/{span} (covers {self.label} port {self.port}) is open to "
                    f"{', '.join(world)}"
                )
        return evidence


class SshOpenRule(_OpenAdminPortRule):
    port = 22
    label = "SSH"
    meta = Rule(
        rule_id="AWS-EC2-001",
        title="SSH (port 22) is open to the internet",
        provider=Provider.AWS,
        resource_kinds=[Kind.SECURITY_GROUP],
        description="Internet-wide SSH exposes instances to brute force and exploitation.",
        detection="A TCP ingress rule covering port 22 has source 0.0.0.0/0 or ::/0.",
        severity=Severity.CRITICAL,
        risk_weight=30,
        remediation=(
            "Restrict the source to a corporate CIDR/VPN, or remove SSH and use AWS Systems Manager "
            'Session Manager. Example: cidr_blocks = ["10.0.0.0/8"].'
        ),
    )


class RdpOpenRule(_OpenAdminPortRule):
    port = 3389
    label = "RDP"
    meta = Rule(
        rule_id="AWS-EC2-002",
        title="RDP (port 3389) is open to the internet",
        provider=Provider.AWS,
        resource_kinds=[Kind.SECURITY_GROUP],
        description="Internet-wide RDP is a leading ransomware entry point.",
        detection="A TCP ingress rule covering port 3389 has source 0.0.0.0/0 or ::/0.",
        severity=Severity.CRITICAL,
        risk_weight=30,
        remediation=(
            "Restrict the source to a trusted CIDR/VPN or use Systems Manager Fleet Manager / a "
            "bastion. Never expose 3389 publicly."
        ),
    )


class OpenIngressRule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-EC2-003",
        title="Security group allows all traffic from the internet",
        provider=Provider.AWS,
        resource_kinds=[Kind.SECURITY_GROUP],
        description="Allowing every protocol and port from anywhere defeats network segmentation.",
        detection="An ingress rule with protocol -1 (all) or ports 0-65535 has source 0.0.0.0/0 or ::/0.",
        severity=Severity.HIGH,
        risk_weight=20,
        remediation=(
            "Replace the rule with the specific ports the workload needs (e.g. 443) and limit sources "
            "to known CIDRs or referenced security groups."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        return [
            f"Ingress allowing all protocols/ports is open to {', '.join(world)}"
            for rule, world in _world_ingress(resource)
            if _all_ports_open(rule)
        ]


class RdsPublicRule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-RDS-001",
        title="Database instance is publicly accessible",
        provider=Provider.AWS,
        resource_kinds=[Kind.RDS_INSTANCE],
        description="A publicly addressable database can be reached and attacked from the internet.",
        detection="publicly_accessible (Terraform) / PubliclyAccessible (CloudFormation) is true.",
        severity=Severity.HIGH,
        risk_weight=20,
        remediation=(
            "Set publicly_accessible = false, place the instance in private subnets, and reach it "
            "through the application tier, VPN, or a bastion."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        if resource.properties.get("publicly_accessible") is True:
            return ["publicly_accessible = true"]
        return []


class UnencryptedStorageRule(GuardrailRule):
    meta = Rule(
        rule_id="AWS-ENC-001",
        title="Storage is not encrypted at rest",
        provider=Provider.AWS,
        resource_kinds=[Kind.RDS_INSTANCE, Kind.EBS_VOLUME],
        description="Unencrypted volumes and databases expose data if snapshots or media are leaked.",
        detection=(
            "RDS storage_encrypted / StorageEncrypted, or EBS encrypted / Encrypted, is false or "
            "omitted (omitted means unencrypted). Unknown values are not flagged."
        ),
        severity=Severity.MEDIUM,
        risk_weight=10,
        remediation=(
            "Set storage_encrypted = true (RDS) or encrypted = true (EBS), preferably with a customer "
            "managed KMS key. Existing resources must be recreated from an encrypted snapshot."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        key = "storage_encrypted" if resource.kind == Kind.RDS_INSTANCE else "encrypted"
        if resource.properties.get(key) is False:
            return [f"{key} is false or not set: data at rest is not encrypted"]
        return []
