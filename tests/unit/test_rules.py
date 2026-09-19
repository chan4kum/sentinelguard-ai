"""Guardrail tests. They run the REAL parser + rules engine: nothing about detection is mocked."""

from __future__ import annotations

from collections import Counter

import pytest

from sentinelguard.domain.models import Provider, Severity
from sentinelguard.parsing import parse_files
from sentinelguard.parsing.ingest import validate_upload
from sentinelguard.rules.registry import BASELINE, evaluate_resources, rule_catalogue


def scan_text(filename: str, text: str):
    parsed = parse_files([validate_upload(filename, text.encode(), 1_000_000)])
    return evaluate_resources(parsed.resources, "test-scan")


def ids(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)


def scan_sample(path):
    parsed = parse_files([validate_upload(path.name, path.read_bytes(), 1_000_000)])
    return evaluate_resources(parsed.resources, "test-scan")


def tf_sg(*ingress: str) -> str:
    blocks = "\n".join(f"  ingress {{\n{b}\n  }}" for b in ingress)
    return f'resource "aws_security_group" "sg" {{\n  name = "sg"\n{blocks}\n}}\n'


def ing(port_from, port_to, cidrs, protocol="tcp", key="cidr_blocks") -> str:
    listed = ", ".join(f'"{c}"' for c in cidrs)
    return (
        f'    from_port = {port_from}\n    to_port = {port_to}\n    protocol = "{protocol}"\n'
        f"    {key} = [{listed}]"
    )


# ------------------------------------------------------------------ baseline catalogue


def test_baseline_has_ten_unique_fully_specified_rules():
    catalogue = rule_catalogue()
    assert len(catalogue) == 10
    assert len({r.rule_id for r in catalogue}) == 10
    for rule in catalogue:
        assert rule.title and rule.description and rule.detection and rule.remediation
        assert rule.resource_kinds and rule.risk_weight > 0
    assert {r.provider for r in catalogue} == {Provider.AWS, Provider.AZURE}


def test_severity_weights_are_consistent():
    weight_by_severity = {}
    for rule in rule_catalogue():
        weight_by_severity.setdefault(rule.severity, set()).add(rule.risk_weight)
    assert weight_by_severity == {
        Severity.CRITICAL: {30},
        Severity.HIGH: {20},
        Severity.MEDIUM: {10},
    }


# --------------------------------------------------------------- sample fixture contracts


def test_vulnerable_terraform_sample_exact_findings(samples):
    findings = scan_sample(samples / "terraform" / "vulnerable.tf")
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {
            ("AWS-S3-001", "aws_s3_bucket.public_assets"): 1,
            ("AWS-S3-002", "aws_s3_bucket.public_assets"): 1,
            ("AWS-S3-003", "aws_s3_bucket.public_assets"): 1,
            ("AWS-S3-001", "aws_s3_bucket.policy_open"): 1,
            ("AWS-EC2-001", "aws_security_group.bastion"): 1,
            ("AWS-EC2-002", "aws_security_group.bastion"): 1,
            ("AWS-EC2-003", "aws_security_group.wide_open"): 1,
            ("AWS-RDS-001", "aws_db_instance.orders"): 1,
            ("AWS-ENC-001", "aws_db_instance.orders"): 1,
            ("AWS-ENC-001", "aws_ebs_volume.scratch"): 1,
        }
    )


def test_vulnerable_cloudformation_json_exact_findings(samples):
    findings = scan_sample(samples / "cloudformation" / "vulnerable.json")
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {
            ("AWS-S3-001", "PublicBucket"): 1,
            ("AWS-S3-002", "PublicBucket"): 1,
            ("AWS-S3-003", "PublicBucket"): 1,
            ("AWS-EC2-001", "OpenSecurityGroup"): 1,
            ("AWS-EC2-002", "OpenSecurityGroup"): 1,
            ("AWS-RDS-001", "Database"): 1,
            ("AWS-ENC-001", "Database"): 1,
            ("AWS-ENC-001", "DataVolume"): 1,
        }
    )


def test_vulnerable_cloudformation_yaml_exact_findings(samples):
    findings = scan_sample(samples / "cloudformation" / "vulnerable.yaml")
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {
            ("AWS-S3-001", "LogsBucket"): 1,
            ("AWS-EC2-001", "SshFromAnywhere"): 1,
            ("AWS-ENC-001", "ScratchVolume"): 1,
        }
    )


def test_vulnerable_azure_sample_exact_findings(samples):
    findings = scan_sample(samples / "azure" / "vulnerable.tf")
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {
            ("AZ-STOR-001", "azurerm_storage_account.public"): 1,
            ("AZ-STOR-001", "azurerm_storage_container.open"): 1,
            ("AZ-NSG-001", "azurerm_network_security_group.web"): 1,
            ("AZ-NSG-001", "azurerm_network_security_rule.rdp"): 1,
        }
    )


@pytest.mark.parametrize(
    "relative",
    ["terraform/safe.tf", "cloudformation/safe.json", "cloudformation/safe.yaml", "azure/safe.tf"],
)
def test_safe_samples_have_zero_findings(samples, relative):
    assert scan_sample(samples / relative) == []


def test_findings_are_complete_and_deterministic(samples):
    path = samples / "terraform" / "vulnerable.tf"
    first, second = scan_sample(path), scan_sample(path)
    key = lambda f: (f.rule_id, f.resource_name, f.severity, tuple(f.evidence))  # noqa: E731
    assert [key(f) for f in first] == [key(f) for f in second]
    for f in first:
        assert f.scan_id == "test-scan" and f.finding_id
        assert f.title and f.description and f.remediation and f.evidence and f.risk_weight > 0
        assert f.source_file == "vulnerable.tf"
    severities = [f.severity for f in first]
    assert severities == sorted(
        severities, key=lambda s: ["critical", "high", "medium", "low"].index(s.value)
    )


# -------------------------------------------------------------------- AWS-S3-001 public


@pytest.mark.parametrize("acl", ["public-read", "public-read-write", "authenticated-read"])
def test_s3_public_acls_flagged(acl):
    f = scan_text("a.tf", f'resource "aws_s3_bucket" "b" {{\n  acl = "{acl}"\n}}\n')
    assert "AWS-S3-001" in ids(f)


def test_s3_private_acl_not_flagged():
    f = scan_text("a.tf", 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n')
    assert "AWS-S3-001" not in ids(f)


def test_s3_public_acl_via_separate_resource_names_the_source():
    text = (
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
        'resource "aws_s3_bucket_acl" "a" {\n  bucket = aws_s3_bucket.b.id\n  acl = "public-read"\n}\n'
    )
    finding = next(f for f in scan_text("a.tf", text) if f.rule_id == "AWS-S3-001")
    assert "aws_s3_bucket_acl.a" in finding.evidence[0]


def test_s3_public_policy_flagged_and_conditional_policy_not():
    base = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\nresource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.b.id\n  policy = %s\n}\n'
    public = (
        base
        % '"{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":\\"*\\",\\"Action\\":\\"s3:GetObject\\"}]}"'
    )
    conditional = (
        base
        % '"{\\"Statement\\":[{\\"Effect\\":\\"Allow\\",\\"Principal\\":\\"*\\",\\"Condition\\":{\\"IpAddress\\":{}}}]}"'
    )
    assert "AWS-S3-001" in ids(scan_text("a.tf", public))
    assert "AWS-S3-001" not in ids(scan_text("a.tf", conditional))


def test_s3_cloudformation_public_read_flagged():
    text = '{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}}}}'
    assert "AWS-S3-001" in ids(scan_text("t.json", text))


# --------------------------------------------------------------- AWS-S3-002 / AWS-S3-003


PAB = 'resource "aws_s3_bucket_public_access_block" "p" {{\n  bucket = aws_s3_bucket.b.id\n{flags}\n}}\n'
BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'


def test_s3_missing_public_access_block_flagged():
    assert "AWS-S3-002" in ids(scan_text("a.tf", BUCKET))


def test_s3_partial_public_access_block_flagged_with_names():
    flags = "  block_public_acls = true\n  block_public_policy = false\n  ignore_public_acls = true\n  restrict_public_buckets = true"
    findings = scan_text("a.tf", BUCKET + PAB.format(flags=flags))
    finding = next(f for f in findings if f.rule_id == "AWS-S3-002")
    assert "block_public_policy" in finding.evidence[0]


def test_s3_omitted_terraform_flags_default_to_false():
    findings = scan_text("a.tf", BUCKET + PAB.format(flags="  block_public_acls = true"))
    assert "AWS-S3-002" in ids(findings)


def test_s3_full_public_access_block_passes():
    flags = "\n".join(
        f"  {k} = true"
        for k in (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        )
    )
    assert "AWS-S3-002" not in ids(scan_text("a.tf", BUCKET + PAB.format(flags=flags)))


def test_s3_encryption_required():
    assert "AWS-S3-003" in ids(scan_text("a.tf", BUCKET))
    encrypted = (
        BUCKET
        + 'resource "aws_s3_bucket_server_side_encryption_configuration" "e" {\n  bucket = aws_s3_bucket.b.id\n}\n'
    )
    assert "AWS-S3-003" not in ids(scan_text("a.tf", encrypted))


def test_s3_cloudformation_pab_and_encryption():
    text = """
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration: []
"""
    assert ids(scan_text("t.yaml", text)) == []


# ---------------------------------------------------------- AWS-EC2-001 / 002 / 003


def test_ssh_open_ipv4_and_ipv6_flagged_with_evidence():
    f = scan_text(
        "a.tf", tf_sg(ing(22, 22, ["0.0.0.0/0"]), ing(22, 22, ["::/0"], key="ipv6_cidr_blocks"))
    )
    assert ids(f) == ["AWS-EC2-001"]  # ONE finding per (rule, resource)
    assert (
        len(f[0].evidence) == 2 and "0.0.0.0/0" in f[0].evidence[0] and "::/0" in f[0].evidence[1]
    )


def test_ssh_restricted_cidr_not_flagged():
    assert ids(scan_text("a.tf", tf_sg(ing(22, 22, ["10.0.0.0/8"])))) == []
    assert ids(scan_text("a.tf", tf_sg(ing(22, 22, ["203.0.113.0/24", "10.0.0.0/8"])))) == []


def test_ssh_within_port_range_flagged_and_outside_range_not():
    assert ids(scan_text("a.tf", tf_sg(ing(0, 1024, ["0.0.0.0/0"])))) == ["AWS-EC2-001"]
    assert ids(scan_text("a.tf", tf_sg(ing(23, 1024, ["0.0.0.0/0"])))) == []


def test_ssh_udp_and_https_not_flagged():
    assert ids(scan_text("a.tf", tf_sg(ing(22, 22, ["0.0.0.0/0"], protocol="udp")))) == []
    assert ids(scan_text("a.tf", tf_sg(ing(443, 443, ["0.0.0.0/0"])))) == []


def test_rdp_open_flagged_and_restricted_not():
    assert ids(scan_text("a.tf", tf_sg(ing(3389, 3389, ["0.0.0.0/0"])))) == ["AWS-EC2-002"]
    assert ids(scan_text("a.tf", tf_sg(ing(3389, 3389, ["192.168.0.0/16"])))) == []


def test_range_covering_ssh_and_rdp_yields_both_rules():
    assert ids(scan_text("a.tf", tf_sg(ing(0, 4000, ["0.0.0.0/0"])))) == [
        "AWS-EC2-001",
        "AWS-EC2-002",
    ]


@pytest.mark.parametrize(
    "rule",
    [ing(0, 0, ["0.0.0.0/0"], protocol="-1"), ing(0, 65535, ["0.0.0.0/0"], protocol="tcp"),
     ing(0, 0, ["::/0"], protocol="-1", key="ipv6_cidr_blocks")],
)  # fmt: skip
def test_all_traffic_open_flagged_once_without_double_counting(rule):
    assert ids(scan_text("a.tf", tf_sg(rule))) == ["AWS-EC2-003"]


def test_all_traffic_from_private_range_not_flagged():
    assert ids(scan_text("a.tf", tf_sg(ing(0, 0, ["10.0.0.0/8"], protocol="-1")))) == []


def test_cloudformation_security_group_rules():
    text = """
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
        - {IpProtocol: tcp, FromPort: 3389, ToPort: 3389, CidrIpv6: "::/0"}
        - {IpProtocol: -1, CidrIp: 0.0.0.0/0}
  Safe:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 10.1.0.0/16}
"""
    findings = scan_text("t.yaml", text)
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {("AWS-EC2-001", "SG"): 1, ("AWS-EC2-002", "SG"): 1, ("AWS-EC2-003", "SG"): 1}
    )


def test_unresolved_port_or_cidr_is_never_flagged():
    text = 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = var.p\n    to_port = var.p\n    protocol = "tcp"\n    cidr_blocks = [var.c]\n  }\n}\n'
    assert ids(scan_text("a.tf", text)) == []


# --------------------------------------------------------- AWS-RDS-001 / AWS-ENC-001


def rds(**attrs) -> str:
    body = "\n".join(f"  {k} = {v}" for k, v in attrs.items())
    return f'resource "aws_db_instance" "d" {{\n{body}\n}}\n'


def test_rds_public_flagged_private_not():
    assert "AWS-RDS-001" in ids(
        scan_text("a.tf", rds(publicly_accessible="true", storage_encrypted="true"))
    )
    assert ids(scan_text("a.tf", rds(publicly_accessible="false", storage_encrypted="true"))) == []
    assert ids(scan_text("a.tf", rds(storage_encrypted="true"))) == []


def test_rds_encryption_absent_or_false_flagged():
    assert ids(scan_text("a.tf", rds(engine='"mysql"'))) == ["AWS-ENC-001"]
    assert ids(scan_text("a.tf", rds(storage_encrypted="false"))) == ["AWS-ENC-001"]


def test_ebs_encryption():
    assert ids(scan_text("a.tf", 'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')) == [
        "AWS-ENC-001"
    ]
    assert ids(scan_text("a.tf", 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n')) == [
        "AWS-ENC-001"
    ]
    assert ids(scan_text("a.tf", 'resource "aws_ebs_volume" "v" {\n  encrypted = true\n}\n')) == []
    assert (
        ids(scan_text("a.tf", 'resource "aws_ebs_volume" "v" {\n  snapshot_id = "snap-1"\n}\n'))
        == []
    )


def test_cloudformation_rds_and_ebs():
    text = """
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties: {PubliclyAccessible: true}
  Cluster:
    Type: AWS::RDS::DBCluster
    Properties: {StorageEncrypted: true}
  Vol:
    Type: AWS::EC2::Volume
    Properties: {Encrypted: !Ref Enc}
"""
    findings = scan_text("t.yaml", text)
    assert Counter((f.rule_id, f.resource_name) for f in findings) == Counter(
        {("AWS-RDS-001", "Db"): 1, ("AWS-ENC-001", "Db"): 1}
    )


# ------------------------------------------------------------------------------ Azure


def nsg(
    name="ssh",
    access="Allow",
    direction="Inbound",
    protocol="Tcp",
    port='"22"',
    source='"*"',
    key="source_address_prefix",
    pkey="destination_port_range",
) -> str:
    return (
        'resource "azurerm_network_security_group" "n" {\n  security_rule {\n'
        f'    name = "{name}"\n    direction = "{direction}"\n    access = "{access}"\n    protocol = "{protocol}"\n'
        f"    {pkey} = {port}\n    {key} = {source}\n  }}\n}}\n"
    )


@pytest.mark.parametrize("source", ['"*"', '"Internet"', '"0.0.0.0/0"', '"any"'])
def test_azure_nsg_ssh_from_internet_flagged(source):
    assert ids(scan_text("a.tf", nsg(source=source))) == ["AZ-NSG-001"]


def test_azure_nsg_rdp_and_star_port_flagged_once_listing_both():
    findings = scan_text("a.tf", nsg(port='"*"'))
    assert ids(findings) == ["AZ-NSG-001"]
    assert "SSH (22)" in findings[0].evidence[0] and "RDP (3389)" in findings[0].evidence[0]
    assert ids(scan_text("a.tf", nsg(port='"3389"'))) == ["AZ-NSG-001"]
    assert ids(
        scan_text("a.tf", nsg(port='["443", "3380-3390"]', pkey="destination_port_ranges"))
    ) == ["AZ-NSG-001"]


@pytest.mark.parametrize(
    "kwargs",
    [dict(source='"10.0.0.0/8"'), dict(access="Deny"), dict(direction="Outbound"), dict(protocol="Udp"),
     dict(port='"443"'), dict(port='"${var.port}"'), dict(source='"VirtualNetwork"')],
)  # fmt: skip
def test_azure_nsg_safe_variants_not_flagged(kwargs):
    assert ids(scan_text("a.tf", nsg(**kwargs))) == []


def test_azure_nsg_source_prefix_list_flagged():
    text = nsg(source='["10.0.0.0/8", "*"]', key="source_address_prefixes")
    assert ids(scan_text("a.tf", text)) == ["AZ-NSG-001"]


def test_azure_storage_public_variants():
    def acct(**a):
        body = "\n".join(f"  {k} = {v}" for k, v in a.items())
        return f'resource "azurerm_storage_account" "s" {{\n{body}\n}}\n'

    assert ids(scan_text("a.tf", acct(allow_nested_items_to_be_public="true"))) == ["AZ-STOR-001"]
    assert ids(scan_text("a.tf", acct(allow_blob_public_access="true"))) == ["AZ-STOR-001"]
    assert ids(scan_text("a.tf", acct(allow_nested_items_to_be_public="false"))) == []
    assert ids(scan_text("a.tf", acct(name='"x"'))) == []  # default is not asserted -> not flagged
    for access, expected in (("blob", 1), ("container", 1), ("private", 0)):
        text = f'resource "azurerm_storage_container" "c" {{\n  container_access_type = "{access}"\n}}\n'
        assert len(scan_text("a.tf", text)) == expected


# ----------------------------------------------------------------- multi / zero / scope


def test_multiple_findings_in_one_scan_across_formats():
    tf = validate_upload("a.tf", tf_sg(ing(22, 22, ["0.0.0.0/0"])).encode(), 10_000)
    cfn = validate_upload(
        "b.json",
        b'{"Resources": {"V": {"Type": "AWS::EC2::Volume", "Properties": {"Encrypted": false}}}}',
        10_000,
    )
    findings = evaluate_resources(parse_files([tf, cfn]).resources, "s")
    assert sorted(ids(findings)) == ["AWS-EC2-001", "AWS-ENC-001"]
    assert {f.source_file for f in findings} == {"a.tf", "b.json"}


def test_empty_configuration_yields_no_findings():
    assert scan_text("a.tf", "# nothing here\n") == []
    assert scan_text("a.json", '{"Resources": {}}') == []


def test_rules_only_apply_to_their_provider_and_kind():
    from sentinelguard.rules.aws import SshOpenRule

    parsed = parse_files([validate_upload("a.tf", nsg().encode(), 10_000)])
    assert evaluate_resources(parsed.resources, "s", rules=(SshOpenRule(),)) == []


def test_every_baseline_rule_is_exercised_by_the_vulnerable_samples(samples):
    fired = set()
    for rel in ("terraform/vulnerable.tf", "azure/vulnerable.tf", "cloudformation/vulnerable.json"):
        fired |= {f.rule_id for f in scan_sample(samples / rel)}
    assert fired == {r.meta.rule_id for r in BASELINE}
