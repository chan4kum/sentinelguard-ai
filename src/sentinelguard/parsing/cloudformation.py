"""CloudFormation (JSON or YAML) → normalized resources.

YAML is loaded with a ``SafeLoader`` subclass that only understands CloudFormation short-form
intrinsics (``!Ref``, ``!Sub`` …) and turns them into plain dicts. Arbitrary Python object tags
are rejected by SafeLoader, so a hostile template cannot execute code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import yaml

from sentinelguard.domain.models import Kind, NormalizedResource, Provider, SourceFormat
from sentinelguard.errors import IaCParseError
from sentinelguard.parsing.policy import public_policy_evidence
from sentinelguard.parsing.terraform import ParsedFile
from sentinelguard.parsing.values import as_bool, as_int, as_str, normalize_protocol, str_list

_PAB_KEYS = {
    "BlockPublicAcls": "block_public_acls",
    "BlockPublicPolicy": "block_public_policy",
    "IgnorePublicAcls": "ignore_public_acls",
    "RestrictPublicBuckets": "restrict_public_buckets",
}
_KNOWN_ACLS = {
    "PublicRead": "public-read",
    "PublicReadWrite": "public-read-write",
    "AuthenticatedRead": "authenticated-read",
}


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader + CloudFormation short-form tags."""


def _intrinsic(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> dict[str, Any]:
    name = suffix if suffix in {"Ref", "Condition"} else f"Fn::{suffix}"
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)  # type: ignore[arg-type]
    return {name: value}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def _load(text: str, filename: str) -> Any:
    try:
        if text.lstrip().startswith("{"):
            return json.loads(text)
        loader = _CfnLoader(text)  # SafeLoader subclass: python/object tags are rejected
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()
    except RecursionError:
        raise IaCParseError(f"'{filename}' is nested too deeply to parse.") from None
    except json.JSONDecodeError as exc:
        raise IaCParseError(
            f"'{filename}' is not valid JSON (line {exc.lineno}, column {exc.colno})."
        ) from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        raise IaCParseError(f"'{filename}' is not valid or safe YAML{where}.") from None
    except Exception:
        raise IaCParseError(f"'{filename}' could not be parsed.") from None


def _ref(value: Any) -> str | None:
    """Logical ID targeted by ``Ref`` / ``Fn::GetAtt``; None otherwise."""
    if isinstance(value, dict):
        if isinstance(value.get("Ref"), str):
            return value["Ref"]
        getatt = value.get("Fn::GetAtt")
        if isinstance(getatt, list) and getatt and isinstance(getatt[0], str):
            return getatt[0]
        if isinstance(getatt, str):
            return getatt.split(".", 1)[0]
    return None


def _props(body: Any) -> dict[str, Any]:
    props = body.get("Properties") if isinstance(body, dict) else None
    return props if isinstance(props, dict) else {}


def _resource(kind, provider, source_type, name, filename, props) -> NormalizedResource:
    return NormalizedResource(
        provider=provider,
        kind=kind,
        source_type=source_type,
        name=name,
        source_format=SourceFormat.CLOUDFORMATION,
        source_file=filename,
        properties=props,
    )


def _normalize_acl(value: Any) -> str | None:
    text = as_str(value)
    if not text:
        return None
    return _KNOWN_ACLS.get(text) or re.sub(r"(?<!^)(?=[A-Z])", "-", text).lower()


def _s3_bucket(stype, name, p, filename):
    acl = _normalize_acl(p.get("AccessControl"))
    pab = None
    config = p.get("PublicAccessBlockConfiguration")
    if isinstance(config, dict):
        pab = {
            snake: (False if cfn not in config else as_bool(config[cfn]))
            for cfn, snake in _PAB_KEYS.items()
        }
    return _resource(
        Kind.S3_BUCKET, Provider.AWS, stype, name, filename,
        {
            "bucket_name": as_str(p.get("BucketName")),
            "acls": [{"value": acl, "via": None}] if acl else [],
            "public_policy_evidence": None,
            "public_access_block": pab,
            "encryption_configured": bool(p.get("BucketEncryption")),
        },
    )  # fmt: skip


def _s3_bucket_policy(stype, name, p, filename):
    bucket = p.get("Bucket")
    return _resource(
        Kind.S3_BUCKET_POLICY, Provider.AWS, stype, name, filename,
        {
            "bucket_ref": _ref(bucket),
            "bucket_literal": as_str(bucket),
            "public_policy_evidence": public_policy_evidence(p.get("PolicyDocument")),
        },
    )  # fmt: skip


def _ingress(rule: dict[str, Any]) -> dict[str, Any]:
    cidrs = str_list(rule.get("CidrIp")) + str_list(rule.get("CidrIpv6"))
    return {
        "from_port": as_int(rule.get("FromPort")),
        "to_port": as_int(rule.get("ToPort")),
        "protocol": normalize_protocol(rule.get("IpProtocol")),
        "cidrs": cidrs,
    }


def _security_group(stype, name, p, filename):
    items = p.get("SecurityGroupIngress")
    rules = [_ingress(r) for r in (items if isinstance(items, list) else []) if isinstance(r, dict)]
    return _resource(Kind.SECURITY_GROUP, Provider.AWS, stype, name, filename, {"ingress": rules})


def _security_group_ingress(stype, name, p, filename):
    return _resource(
        Kind.SECURITY_GROUP, Provider.AWS, stype, name, filename, {"ingress": [_ingress(p)]}
    )


def _encrypted(p: dict[str, Any], key: str, inherits: tuple[str, ...]) -> bool | None:
    if any(k in p for k in inherits):
        return None
    if key not in p:
        return False
    return as_bool(p[key])


def _rds_instance(stype, name, p, filename):
    public = as_bool(p["PubliclyAccessible"]) if "PubliclyAccessible" in p else None
    encrypted = _encrypted(
        p,
        "StorageEncrypted",
        ("SourceDBInstanceIdentifier", "DBSnapshotIdentifier", "DBClusterIdentifier",
         "SnapshotIdentifier", "SourceDBClusterIdentifier"),
    )  # fmt: skip
    return _resource(
        Kind.RDS_INSTANCE, Provider.AWS, stype, name, filename,
        {"publicly_accessible": public, "storage_encrypted": encrypted},
    )  # fmt: skip


def _ebs_volume(stype, name, p, filename):
    return _resource(
        Kind.EBS_VOLUME, Provider.AWS, stype, name, filename,
        {"encrypted": _encrypted(p, "Encrypted", ("SnapshotId",))},
    )  # fmt: skip


_Handler = Callable[[str, str, dict[str, Any], str], NormalizedResource | None]
_HANDLERS: dict[str, _Handler] = {
    "AWS::S3::Bucket": _s3_bucket,
    "AWS::S3::BucketPolicy": _s3_bucket_policy,
    "AWS::EC2::SecurityGroup": _security_group,
    "AWS::EC2::SecurityGroupIngress": _security_group_ingress,
    "AWS::RDS::DBInstance": _rds_instance,
    "AWS::RDS::DBCluster": _rds_instance,
    "AWS::EC2::Volume": _ebs_volume,
}


def parse_cloudformation(text: str, filename: str) -> ParsedFile:
    data = _load(text, filename)
    if not isinstance(data, dict) or not isinstance(data.get("Resources"), dict):
        raise IaCParseError(
            f"'{filename}' is not a CloudFormation template (no 'Resources' section)."
        )
    resources: list[NormalizedResource] = []
    total = 0
    for logical_id, body in data["Resources"].items():
        total += 1
        stype = body.get("Type") if isinstance(body, dict) else None
        handler = _HANDLERS.get(stype) if isinstance(stype, str) else None
        if handler is None:
            continue
        normalized = handler(stype, str(logical_id), _props(body), filename)
        if normalized is not None:
            resources.append(normalized)
    return ParsedFile(resources=resources, resources_total=total)
