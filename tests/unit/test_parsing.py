from __future__ import annotations

import pytest

from sentinelguard.domain.models import Kind, SourceFormat
from sentinelguard.errors import (
    FileTooLargeError,
    IaCParseError,
    InvalidUploadError,
    UnsupportedFileTypeError,
)
from sentinelguard.parsing import parse_files
from sentinelguard.parsing.cloudformation import parse_cloudformation
from sentinelguard.parsing.ingest import IacFile, sanitize_filename, validate_upload
from sentinelguard.parsing.policy import public_policy_evidence
from sentinelguard.parsing.terraform import parse_terraform
from sentinelguard.parsing.values import (
    as_bool,
    as_int,
    as_str,
    normalize_protocol,
    port_ranges,
    ranges_cover,
    str_list,
)


def load(path) -> IacFile:
    return validate_upload(path.name, path.read_bytes(), 1_000_000)


def by_name(resources):
    return {r.name: r for r in resources}


# ----------------------------------------------------------------------------- values


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), ("true", True), ("FALSE", False), ("yes", None),
     ("${var.x}", None), (1, None), (None, None), ({"Ref": "P"}, None)],
)  # fmt: skip
def test_as_bool(value, expected):
    assert as_bool(value) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(22, 22), ("22", 22), (" 3389 ", 3389), (True, None), ("x", None), ("${var.p}", None),
     (None, None)],
)  # fmt: skip
def test_as_int(value, expected):
    assert as_int(value) == expected


def test_as_str_and_str_list_drop_unresolved():
    assert as_str("0.0.0.0/0") == "0.0.0.0/0"
    assert as_str("${var.cidr}") is None
    assert as_str({"Ref": "X"}) is None
    assert str_list(["a", "${var.b}", 3, "c"]) == ["a", "c"]
    assert str_list("only") == ["only"]
    assert str_list(None) == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [("TCP", "tcp"), ("-1", "-1"), ("all", "-1"), ("*", "-1"), ("6", "tcp"), (6, "tcp"),
     (17, "udp"), (None, None), ({"Ref": "x"}, None)],
)  # fmt: skip
def test_normalize_protocol(value, expected):
    assert normalize_protocol(value) == expected


def test_port_ranges():
    assert port_ranges("22") == [(22, 22)]
    assert port_ranges("*") == [(0, 65535)]
    assert port_ranges("20-30") == [(20, 30)]
    assert port_ranges(["22", "3389"]) == [(22, 22), (3389, 3389)]
    assert port_ranges(22) == [(22, 22)]
    assert port_ranges("${var.p}") is None
    assert port_ranges(["22", "bogus"]) is None
    assert ranges_cover([(20, 30)], 22) and not ranges_cover([(23, 30)], 22)


# ---------------------------------------------------------------------------- ingest


def test_sanitize_filename_strips_paths_and_control_chars():
    assert sanitize_filename("../../etc/passwd.tf") == "passwd.tf"
    assert sanitize_filename("C:\\Users\\me\\main.tf") == "main.tf"
    assert sanitize_filename("we\x00ird\n.tf") == "weird.tf"
    assert len(sanitize_filename("a" * 500 + ".tf")) == 128


@pytest.mark.parametrize("bad", [None, "", "   ", "/", "..", "///"])
def test_sanitize_filename_rejects_empty(bad):
    with pytest.raises(InvalidUploadError):
        sanitize_filename(bad)


@pytest.mark.parametrize(
    ("name", "fmt"),
    [("main.tf", SourceFormat.TERRAFORM), ("t.json", SourceFormat.CLOUDFORMATION),
     ("t.YAML", SourceFormat.CLOUDFORMATION), ("t.yml", SourceFormat.CLOUDFORMATION),
     ("stack.template", SourceFormat.CLOUDFORMATION)],
)  # fmt: skip
def test_validate_upload_detects_format(name, fmt):
    assert validate_upload(name, b"x", 100).format == fmt


@pytest.mark.parametrize(
    "name", ["evil.exe", "script.sh", "main.tf.exe", "noext", "a.py", "x.tfstate"]
)
def test_validate_upload_rejects_unsupported_extension(name):
    with pytest.raises(UnsupportedFileTypeError):
        validate_upload(name, b"x", 100)


def test_validate_upload_limits_and_content_checks():
    with pytest.raises(FileTooLargeError):
        validate_upload("a.tf", b"x" * 11, 10)
    with pytest.raises(InvalidUploadError, match="empty"):
        validate_upload("a.tf", b"  \n ", 10)
    with pytest.raises(InvalidUploadError, match="binary"):
        validate_upload("a.tf", b"ab\x00cd", 100)
    with pytest.raises(InvalidUploadError, match="UTF-8"):
        validate_upload("a.tf", b"\xff\xfe\xfa", 100)


def test_validate_upload_strips_bom_and_uses_basename():
    f = validate_upload("../x/main.tf", b"\xef\xbb\xbfresource", 100)
    assert f.name == "main.tf" and f.text == "resource"


# ----------------------------------------------------------------------------- policy


def test_policy_dict_public_and_private():
    public = {"Statement": [{"Sid": "P", "Effect": "Allow", "Principal": "*", "Action": "s3:Get*"}]}
    assert 'allows Principal "*"' in public_policy_evidence(public)
    assert public_policy_evidence({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}}})
    assert public_policy_evidence({"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]}}]})
    assert public_policy_evidence({"Statement": [{"Effect": "Deny", "Principal": "*"}]}) is None
    assert (
        public_policy_evidence(
            {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::1:root"}}]}
        )
        is None
    )
    with_condition = {
        "Statement": [{"Effect": "Allow", "Principal": "*", "Condition": {"IpAddress": {}}}]
    }
    assert public_policy_evidence(with_condition) is None
    assert public_policy_evidence({"Statement": "garbage"}) is None
    assert public_policy_evidence(None) is None
    assert public_policy_evidence(42) is None


def test_policy_from_json_heredoc_and_jsonencode_text():
    raw = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:*"}]}'
    assert public_policy_evidence(raw)
    assert public_policy_evidence(f"<<EOF\n{raw}\nEOF")
    encoded = '${jsonencode({Statement = [{Effect = "Allow", Principal = "*", Action = "s3:*"}]})}'
    assert public_policy_evidence(encoded)
    private = '${jsonencode({Statement = [{Effect = "Allow", Principal = {AWS = "arn:aws:iam::1:root"}}]})}'
    assert public_policy_evidence(private) is None


def test_policy_text_heuristic_for_unparseable_hcl():
    text = '${jsonencode({Statement = [{Effect = "Allow", Principal = "*", Resource = aws_s3_bucket.b.arn}]})}'
    assert "heuristic" in public_policy_evidence(text)
    with_deny = text.replace('"Allow"', '"Allow"}, {Effect = "Deny"')
    assert public_policy_evidence(with_deny) is None


# -------------------------------------------------------------------------- terraform


def test_terraform_vulnerable_sample_normalizes(samples):
    result = parse_files([load(samples / "terraform" / "vulnerable.tf")])
    assert result.formats == [SourceFormat.TERRAFORM]
    assert result.resources_total == 9  # 2 buckets + PAB + SSE + policy + 2 SGs + DB + EBS
    res = by_name(result.resources)

    bucket = res["aws_s3_bucket.public_assets"].properties
    assert bucket["acls"] == [{"value": "public-read", "via": None}]
    assert bucket["public_access_block"] is None and bucket["encryption_configured"] is False

    linked = res["aws_s3_bucket.policy_open"].properties
    assert linked["public_policy_evidence"]  # from aws_s3_bucket_policy
    assert linked["public_access_block"] == {
        "block_public_acls": True, "block_public_policy": True,
        "ignore_public_acls": True, "restrict_public_buckets": True,
    }  # fmt: skip
    assert linked["encryption_configured"] is True

    sg = res["aws_security_group.bastion"].properties["ingress"]
    assert sg[0]["cidrs"] == ["0.0.0.0/0"]  # var.admin_cidr resolved from its default
    assert sg[1]["cidrs"] == ["::/0"] and sg[1]["from_port"] == 3389
    assert res["aws_security_group.wide_open"].properties["ingress"][0]["protocol"] == "-1"

    db = res["aws_db_instance.orders"].properties
    assert db == {"publicly_accessible": True, "storage_encrypted": False}
    assert res["aws_ebs_volume.scratch"].properties["encrypted"] is False


def test_terraform_safe_sample_normalizes(samples):
    result = parse_files([load(samples / "terraform" / "safe.tf")])
    res = by_name(result.resources)
    bucket = res["aws_s3_bucket.data"].properties
    assert bucket["encryption_configured"] is True
    assert all(bucket["public_access_block"].values())
    assert bucket["acls"] == [{"value": "private", "via": "aws_s3_bucket_acl.data"}]
    assert res["aws_security_group.web"].properties["ingress"][1]["cidrs"] == ["10.0.0.0/16"]


def test_terraform_azure_sample_normalizes(samples):
    result = parse_files([load(samples / "azure" / "vulnerable.tf")])
    res = by_name(result.resources)
    assert res["azurerm_storage_account.public"].properties["public_access_evidence"]
    assert res["azurerm_storage_container.open"].properties["public_access_evidence"]
    nsg = res["azurerm_network_security_group.web"].properties["rules"]
    assert nsg[0]["ports"] == "22" and nsg[0]["sources"] == ["*"] and nsg[0]["access"] == "allow"
    rdp = res["azurerm_network_security_rule.rdp"].properties["rules"][0]
    assert rdp["ports"] == ["3389", "8080"] and rdp["sources"] == ["Internet"]


def test_terraform_unknown_resources_are_counted_but_ignored():
    parsed = parse_terraform('resource "aws_instance" "x" {\n  ami = "a"\n}\n', "a.tf")
    assert parsed.resources_total == 1 and parsed.resources == []


def test_terraform_unresolved_values_are_unknown_not_flagged():
    text = (
        'resource "aws_security_group" "s" {\n'
        '  ingress {\n    from_port = var.port\n    to_port = var.port\n    protocol = "tcp"\n'
        "    cidr_blocks = [var.cidr]\n  }\n}\n"
    )
    rule = parse_terraform(text, "a.tf").resources[0].properties["ingress"][0]
    assert rule["cidrs"] == [] and rule["from_port"] is None


def test_terraform_standalone_sg_rules_and_egress_ignored():
    text = """
resource "aws_security_group_rule" "in" {
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_security_group_rule" "out" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_vpc_security_group_ingress_rule" "v" {
  ip_protocol = "tcp"
  from_port = 3389
  to_port = 3389
  cidr_ipv4 = "0.0.0.0/0"
}
"""
    resources = parse_terraform(text, "a.tf").resources
    assert [r.name for r in resources] == [
        "aws_security_group_rule.in",
        "aws_vpc_security_group_ingress_rule.v",
    ]
    assert resources[1].properties["ingress"][0]["cidrs"] == ["0.0.0.0/0"]


def test_terraform_replica_db_encryption_is_unknown():
    text = 'resource "aws_db_instance" "r" {\n  replicate_source_db = "src"\n}\n'
    assert parse_terraform(text, "a.tf").resources[0].properties["storage_encrypted"] is None


@pytest.mark.parametrize(
    "bad",
    ['resource "aws_s3_bucket" "b" {', "this is not hcl {{{", 'resource "a" "b" { x = }', "}"],
)
def test_terraform_malformed_raises_safe_error(bad):
    with pytest.raises(IaCParseError) as exc:
        parse_terraform(bad, "broken.tf")
    assert "broken.tf" in exc.value.message
    assert "Traceback" not in exc.value.message and "lark" not in exc.value.message.lower()


# ------------------------------------------------------------------- cloudformation


def test_cloudformation_json_vulnerable_sample(samples):
    result = parse_files([load(samples / "cloudformation" / "vulnerable.json")])
    assert result.resources_total == 4 and result.formats == [SourceFormat.CLOUDFORMATION]
    res = by_name(result.resources)
    bucket = res["PublicBucket"].properties
    assert bucket["acls"] == [{"value": "public-read", "via": None}]
    assert bucket["public_access_block"] is None and bucket["encryption_configured"] is False
    sg = res["OpenSecurityGroup"].properties["ingress"]
    assert sg[1]["from_port"] == 3389  # "3389" string coerced
    assert res["Database"].properties == {"publicly_accessible": True, "storage_encrypted": False}
    assert res["DataVolume"].properties["encrypted"] is False


def test_cloudformation_yaml_with_intrinsics_and_linking(samples):
    result = parse_files([load(samples / "cloudformation" / "vulnerable.yaml")])
    res = by_name(result.resources)
    assert res["LogsBucket"].properties["public_policy_evidence"]  # BucketPolicy linked via !Ref
    assert res["LogsBucket"].properties["encryption_configured"] is True
    assert res["SshFromAnywhere"].properties["ingress"][0]["cidrs"] == ["0.0.0.0/0"]
    assert res["ScratchVolume"].properties["encrypted"] is False


def test_cloudformation_safe_samples(samples):
    for name in ("safe.json", "safe.yaml"):
        parsed = parse_files([load(samples / "cloudformation" / name)])
        assert parsed.resources, name


def test_cloudformation_unresolved_values_are_unknown():
    text = """
Resources:
  V:
    Type: AWS::EC2::Volume
    Properties:
      Encrypted: !Ref EncryptParam
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: !Ref Port
          ToPort: !Ref Port
          CidrIp: !Ref Cidr
"""
    res = by_name(parse_cloudformation(text, "t.yaml").resources)
    assert res["V"].properties["encrypted"] is None
    assert res["SG"].properties["ingress"][0]["cidrs"] == []


def test_cloudformation_acl_normalisation_and_pab_defaults():
    text = """
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
"""
    props = parse_cloudformation(text, "t.yaml").resources[0].properties
    assert props["acls"][0]["value"] == "public-read-write"
    assert props["public_access_block"] == {
        "block_public_acls": True, "block_public_policy": False,
        "ignore_public_acls": False, "restrict_public_buckets": False,
    }  # fmt: skip


@pytest.mark.parametrize(
    "bad",
    [
        '{"Resources": ',
        "{not json}",
        "Resources: [unclosed",
        "a: b: c: d",
        "\t- broken\n\tyaml: [",
        "!!python/object/apply:os.system ['echo hi']",
    ],
)
def test_cloudformation_malformed_or_unsafe_raises_parse_error(bad):
    with pytest.raises(IaCParseError):
        parse_cloudformation(bad, "bad.yaml")


@pytest.mark.parametrize("doc", ["[]", '"just a string"', "{}", '{"Resources": []}', "Foo: bar"])
def test_cloudformation_non_template_rejected(doc):
    with pytest.raises(IaCParseError, match="not a CloudFormation template"):
        parse_cloudformation(doc, "x.json")


def test_kinds_are_canonical(samples):
    kinds = {r.kind for r in parse_files([load(samples / "terraform" / "vulnerable.tf")]).resources}
    assert {Kind.S3_BUCKET, Kind.SECURITY_GROUP, Kind.RDS_INSTANCE, Kind.EBS_VOLUME} <= kinds


def test_cross_file_linking(samples):
    bucket = IacFile(
        "a.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "n"\n}\n', SourceFormat.TERRAFORM
    )
    pab = IacFile(
        "b.tf",
        'resource "aws_s3_bucket_public_access_block" "p" {\n  bucket = aws_s3_bucket.b.id\n'
        "  block_public_acls = true\n}\n",
        SourceFormat.TERRAFORM,
    )
    res = by_name(parse_files([bucket, pab]).resources)
    assert res["aws_s3_bucket.b"].properties["public_access_block"]["block_public_acls"] is True
    assert res["aws_s3_bucket.b"].properties["public_access_block"]["block_public_policy"] is False


def test_link_by_literal_bucket_name():
    text = (
        'resource "aws_s3_bucket" "b" {\n  bucket = "literal"\n}\n'
        'resource "aws_s3_bucket_server_side_encryption_configuration" "e" {\n  bucket = "literal"\n}\n'
    )
    res = by_name(parse_terraform(text, "a.tf").resources)
    from sentinelguard.parsing.linking import link_resources

    link_resources(list(res.values()))
    assert res["aws_s3_bucket.b"].properties["encryption_configured"] is True
