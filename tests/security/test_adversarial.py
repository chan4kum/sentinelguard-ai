"""Security Adversarial Agent: hostile inputs must be rejected or neutralised, never executed."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from sentinelguard.errors import IaCParseError
from sentinelguard.parsing.cloudformation import parse_cloudformation
from sentinelguard.parsing.terraform import parse_terraform

pytestmark = pytest.mark.security

SRC = Path(__file__).resolve().parents[2] / "src" / "sentinelguard"


def upload(client, name: str, data: bytes):
    return client.post("/api/v1/scans", files=[("files", (name, data, "text/plain"))])


# ------------------------------------------------------------- path traversal / filenames


@pytest.mark.parametrize(
    "name",
    [
        "../../../etc/passwd.tf",
        "..\\..\\windows\\system32\\evil.tf",
        "/etc/shadow.tf",
        "....//....//x.tf",
        "a/b/c/../../../../root.tf",
    ],
)
def test_path_traversal_filenames_are_reduced_to_a_label_and_write_nothing(
    client, tmp_path, name, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.rglob("*"))
    r = upload(client, name, b'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    assert r.status_code == 201
    stored = r.json()["files"][0]
    assert "/" not in stored and "\\" not in stored and ".." not in stored.replace(".tf", "")
    # the app must never create files from uploads
    created = {p for p in tmp_path.rglob("*") if p not in before and p.suffix != ".db"}
    created = {p for p in created if "-wal" not in p.name and "-shm" not in p.name}
    assert not any("passwd" in p.name or "shadow" in p.name or "evil" in p.name for p in created)


@pytest.mark.parametrize(
    "name", ["evil.exe", "x.sh", "x.py", "a.tf.exe", "x.tfstate", "noext", ".tf.bak"]
)
def test_dangerous_or_unsupported_extensions_rejected(client, name):
    assert upload(client, name, b"echo pwned").status_code == 415


def test_filename_with_control_characters_and_null_is_neutralised(client):
    r = upload(client, "we\x00ird\r\nname.tf", b'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    # httpx/starlette may reject before us; if accepted the label must be clean
    if r.status_code == 201:
        assert "\x00" not in r.json()["files"][0] and "\n" not in r.json()["files"][0]
    else:
        assert r.status_code in {400, 415, 422}


@pytest.mark.parametrize("length", [300, 1000])
def test_long_filename_is_truncated_but_keeps_its_extension(client, length):
    r = upload(client, "a" * length + ".tf", b'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    assert r.status_code == 201
    label = r.json()["files"][0]
    assert len(label) <= 128 and label.endswith(".tf")


def test_absurdly_long_filename_is_rejected_by_the_multipart_parser(client):
    r = upload(client, "a" * 5000 + ".tf", b'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    assert r.status_code == 400 and "error" in r.json()


# ------------------------------------------------------------------- code execution / YAML


@pytest.mark.parametrize(
    "payload",
    [
        "!!python/object/apply:os.system ['touch /tmp/sg_pwned_yaml']",
        "!!python/object/new:subprocess.Popen [['touch', '/tmp/sg_pwned_yaml']]",
        "Resources: !!python/object/apply:os.system ['touch /tmp/sg_pwned_yaml']",
        "Resources: !!python/name:os.system",
        "a: !!python/module:os",
    ],
)
def test_yaml_python_tags_are_rejected_and_never_executed(client, payload):
    marker = Path("/tmp/sg_pwned_yaml")  # noqa: S108
    marker.unlink(missing_ok=True)
    r = upload(client, "evil.yaml", payload.encode())
    assert r.status_code == 422
    assert not marker.exists()


def test_yaml_billion_laughs_is_bounded(client):
    levels = ["a: &a [x, x, x, x, x, x, x, x, x]"]
    for prev, cur in zip("abcdefgh", "bcdefghi", strict=False):
        levels.append(f"{cur}: &{cur} [{', '.join([f'*{prev}'] * 9)}]")
    doc = "Resources: {}\n" + "\n".join(levels) + "\n"
    started = time.perf_counter()
    r = upload(client, "bomb.yaml", doc.encode())
    assert time.perf_counter() - started < 5
    assert r.status_code in {
        201,
        422,
    }  # parses (aliases are shared refs) or is rejected; never hangs


def test_yaml_deep_nesting_does_not_crash_server(client):
    doc = "Resources: " + "[" * 5000 + "]" * 5000
    r = upload(client, "deep.yaml", doc.encode())
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "parse_error"


def test_json_deep_nesting_does_not_crash_server(client):
    doc = '{"Resources": ' + "[" * 100000 + "]" * 100000 + "}"
    r = upload(client, "deep.json", doc.encode())
    assert r.status_code in {413, 422}


def test_terraform_local_exec_and_shell_content_is_treated_as_data(client, tmp_path):
    marker = Path("/tmp/sg_pwned_tf")  # noqa: S108
    marker.unlink(missing_ok=True)
    tf = (
        b'resource "null_resource" "x" {\n  provisioner "local-exec" {\n'
        b'    command = "touch /tmp/sg_pwned_tf"\n  }\n}\n'
        b'data "external" "e" {\n  program = ["sh", "-c", "touch /tmp/sg_pwned_tf"]\n}\n'
        b'module "m" {\n  source = "git::https://example.invalid/evil.git"\n}\n'
        b'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n'
    )
    r = upload(client, "evil.tf", tf)
    assert r.status_code == 201
    assert [f["rule_id"] for f in r.json()["findings"]] == ["AWS-ENC-001"]
    assert not marker.exists()


def test_terraform_interpolation_functions_are_not_evaluated():
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "${file("/etc/passwd")}"\n'
        '  acl    = "${lookup(var.x, "y")}"\n'
        "}\n"
    )
    props = parse_terraform(text, "a.tf").resources[0].properties
    assert props["bucket_name"] is None  # unresolved expression, never evaluated
    assert props["acls"] == []


def test_source_tree_has_no_dynamic_execution_or_shell_calls():
    """Static guard: the app must never gain eval/exec/subprocess/os.system usage."""
    banned = (
        "eval(",
        "exec(",
        "subprocess",
        "os.system",
        "os.popen",
        "pickle",
        "yaml.load(",
        "shell=True",
    )
    offenders = []
    for path in SRC.rglob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for token in banned:
                if token in line:
                    offenders.append(f"{path.relative_to(SRC)}:{lineno}: {token}")
    assert offenders == []


def test_yaml_loader_is_a_safeloader_subclass():
    import yaml

    from sentinelguard.parsing.cloudformation import _CfnLoader

    assert issubclass(_CfnLoader, yaml.SafeLoader)
    assert not issubclass(_CfnLoader, yaml.UnsafeLoader) and not issubclass(
        _CfnLoader, yaml.FullLoader
    )


# ---------------------------------------------------------------------- size / abuse


def test_oversized_upload_rejected_without_processing(client):
    r = upload(client, "big.tf", b"#" * (64 * 1024 + 1))
    assert r.status_code == 413


def test_many_small_resources_still_scan_quickly(client):
    blocks = "".join(f'resource "aws_ebs_volume" "v{i}" {{\n  size = 1\n}}\n' for i in range(600))
    started = time.perf_counter()
    r = upload(client, "many.tf", blocks[: 64 * 1024].rsplit("}\n", 1)[0].encode() + b"}\n")
    assert r.status_code == 201
    assert time.perf_counter() - started < 10


def test_malformed_terraform_variants_never_raise_unhandled():
    samples = [
        "resource",
        'resource "a"',
        'resource "a" "b" {',
        "}}}}",
        "\x01\x02",
        'variable "x" { default = }',
        'resource "aws_s3_bucket" "b" { acl = "public-read" ',
        "a = ${",
        "<<EOF\nnever closed",
        "/* unterminated comment",
        'resource "aws_security_group" "s" { ingress = 5 }',
        'resource "aws_security_group" "s" { ingress { cidr_blocks = 7 from_port = "x" } }',
    ]
    for text in samples:
        try:
            parse_terraform(text, "f.tf")
        except IaCParseError:
            pass  # the only acceptable failure mode


def test_malformed_cloudformation_shapes_never_raise_unhandled():
    docs = [
        '{"Resources": {"A": 5}}',
        '{"Resources": {"A": {"Type": ["x"]}}}',
        '{"Resources": {"A": {"Type": "AWS::S3::Bucket", "Properties": "str"}}}',
        '{"Resources": {"A": {"Type": "AWS::S3::Bucket", "Properties": {"PublicAccessBlockConfiguration": 5}}}}',
        '{"Resources": {"A": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": {"a": 1}}}}}',
        '{"Resources": {"A": {"Type": "AWS::EC2::SecurityGroup", "Properties": {"SecurityGroupIngress": [1, "x", null]}}}}',
        '{"Resources": {"A": {"Type": "AWS::S3::BucketPolicy", "Properties": {"PolicyDocument": "not-a-dict", "Bucket": [1]}}}}',
        '{"Resources": {"1": {"Type": "AWS::EC2::Volume", "Properties": {"Encrypted": {"Fn::If": ["c", true, false]}}}}}',
    ]
    for doc in docs:
        parse_cloudformation(doc, "t.json")  # must not raise at all


# ------------------------------------------------------------ injection / output safety


def test_sql_injection_strings_in_ids_and_filters_are_inert(client):
    for scan_id in ["' OR '1'='1", "1; DROP TABLE scans;--", "%", "\\"]:
        r = client.get("/api/v1/scans/" + scan_id.replace("/", "%2F"))
        assert r.status_code in {404, 405}
    r = client.get("/api/v1/scans/x/findings", params={"severity": "critical' OR 1=1--"})
    assert r.status_code == 422
    assert client.get("/api/v1/scans").json()["total"] == 0  # table intact


def test_sql_injection_via_resource_names_is_stored_as_text(client):
    tf = b'resource "aws_ebs_volume" "x\'); DROP TABLE findings;--" {\n  size = 1\n}\n'
    r = upload(client, "inj.tf", tf)
    assert r.status_code in {201, 422}
    assert client.get("/api/v1/dashboard/summary").status_code == 200
    if r.status_code == 201:
        scan_id = r.json()["scan_id"]
        assert client.get(f"/api/v1/scans/{scan_id}/findings").status_code == 200


def test_hostile_resource_names_round_trip_as_plain_json(client):
    name = "<script>alert(1)</script>"
    tf = f'resource "aws_ebs_volume" "{name}" {{\n  size = 1\n}}\n'.encode()
    r = upload(client, "xss.tf", tf)
    if r.status_code == 201:
        assert r.headers["content-type"].startswith("application/json")
        assert r.json()["findings"][0]["resource_name"].endswith(name)


def test_error_messages_do_not_leak_paths_or_internals(client):
    responses = [
        upload(client, "a.tf", b"resource {{{"),
        upload(client, "a.json", b"{bad"),
        upload(client, "a.yaml", b"a: [unclosed"),
        upload(client, "a.exe", b"x"),
        client.get("/api/v1/scans/none"),
        client.get("/nope"),
    ]
    for r in responses:
        text = r.text
        for leak in (
            "Traceback",
            "site-packages",
            "/Users/",
            "lark",
            "yaml.",
            "sqlalchemy",
            'File "',
        ):
            assert leak not in text, (leak, text)


def test_security_headers_do_not_expose_server_internals(client):
    r = client.get("/health")
    assert "x-powered-by" not in {k.lower() for k in r.headers}


def test_uploads_are_never_persisted_to_the_database(client, settings):
    secret = b'resource "aws_ebs_volume" "v" {\n  size = 1\n  # AKIAIOSFODNN7EXAMPLE secret-token-123\n}\n'
    assert upload(client, "s.tf", secret).status_code == 201
    db_bytes = b""
    for path in Path(settings.database_url.removeprefix("sqlite:///")).parent.glob("test.db*"):
        db_bytes += path.read_bytes()
    assert b"AKIAIOSFODNN7EXAMPLE" not in db_bytes and b"secret-token-123" not in db_bytes


def test_no_hardcoded_secrets_in_repository():
    root = SRC.parents[1]
    patterns = ("AKIA", "-----BEGIN", "aws_secret_access_key", "password=", "api_key=")
    skip = {
        ".venv",
        ".git",
        "tests",
        "samples",
        "__pycache__",
        ".ruff_cache",
        ".pytest_cache",
        "docs",
    }
    hits = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in skip for part in path.relative_to(root).parts):
            continue
        if (
            path.suffix in {".py", ".yml", ".yaml", ".toml", ".md", ".example", ""}
            and path.stat().st_size < 2_000_000
        ):
            try:
                text = path.read_text()
            except UnicodeDecodeError:
                continue
            hits += [
                f"{path.name}: {p}" for p in patterns if p in text and path.name != "prompts.md"
            ]
    assert hits == []


def test_env_example_contains_no_secrets():
    text = (SRC.parents[1] / ".env.example").read_text()
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            key = line.split("=", 1)[0]
            assert not any(w in key.upper() for w in ("SECRET", "PASSWORD", "TOKEN", "KEY"))


def test_docker_image_runs_as_non_root():
    dockerfile = (SRC.parents[1] / "Dockerfile").read_text()
    assert "USER sentinel" in dockerfile and "useradd" in dockerfile


def test_no_cloud_sdk_dependencies_or_credentials_needed():
    pyproject = (SRC.parents[1] / "pyproject.toml").read_text().lower()
    for sdk in ("boto3", "botocore", "azure-", "google-cloud"):
        assert sdk not in pyproject
    for path in SRC.rglob("*.py"):
        text = path.read_text()
        assert "import boto3" not in text and "import azure" not in text
    assert "AWS_ACCESS_KEY_ID" not in os.environ.get("SENTINELGUARD_PLACEHOLDER", "")


def test_subprocess_is_not_available_to_parsers(monkeypatch):
    """Even if a parser were tricked, spawning a process must not be part of its flow."""

    def boom(*_a, **_k):
        raise AssertionError("subprocess must never be used by the scanner")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    tf = 'resource "aws_ebs_volume" "v" {\n  provisioner "local-exec" { command = "id" }\n}\n'
    assert parse_terraform(tf, "a.tf").resources_total == 1
