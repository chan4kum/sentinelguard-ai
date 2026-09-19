"""Terraform (HCL) → normalized resources.

HCL is parsed with ``python-hcl2`` purely as data. Terraform itself is never invoked, and no
provider, module, or ``local-exec`` is ever evaluated.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import hcl2
from hcl2 import SerializationOptions

from sentinelguard.domain.models import Kind, NormalizedResource, Provider, SourceFormat
from sentinelguard.errors import IaCParseError
from sentinelguard.parsing.policy import public_policy_evidence
from sentinelguard.parsing.values import (
    as_bool,
    as_int,
    as_str,
    normalize_protocol,
    str_list,
)

_OPTIONS = SerializationOptions(
    with_comments=False, explicit_blocks=False, strip_string_quotes=True
)
_VAR_REF = re.compile(r"^\$\{\s*var\.([A-Za-z0-9_-]+)\s*\}$")
_BUCKET_REF = re.compile(r"(?:^|\$\{|[\s(,])(aws_s3_bucket\.[A-Za-z0-9_-]+)")
_MAX_DEPTH = 40
_PAB_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


@dataclass(frozen=True)
class ParsedFile:
    resources: list[NormalizedResource]
    resources_total: int


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _resolve(value: Any, variables: dict[str, Any], depth: int = 0) -> Any:
    """Substitute exact ``${var.x}`` references that have a literal default."""
    if depth > _MAX_DEPTH:
        return value
    if isinstance(value, str):
        match = _VAR_REF.match(value)
        if match and match.group(1) in variables:
            return variables[match.group(1)]
        return value
    if isinstance(value, list):
        return [_resolve(v, variables, depth + 1) for v in value]
    if isinstance(value, dict):
        return {k: _resolve(v, variables, depth + 1) for k, v in value.items()}
    return value


def _collect_variables(data: dict[str, Any]) -> dict[str, Any]:
    variables: dict[str, Any] = {}
    for block in _as_list(data.get("variable")):
        if not isinstance(block, dict):
            continue
        for name, body in block.items():
            if isinstance(body, dict) and "default" in body:
                variables[name] = body["default"]
    return variables


def _bucket_target(value: Any) -> tuple[str | None, str | None]:
    """(resource key, literal bucket name) for a ``bucket`` attribute."""
    if isinstance(value, str):
        match = _BUCKET_REF.search(value)
        if match:
            return match.group(1), None
    return None, as_str(value)


def _resource(
    kind: str, provider: Provider, rtype: str, rname: str, filename: str, props: dict[str, Any]
) -> NormalizedResource:
    return NormalizedResource(
        provider=provider,
        kind=kind,
        source_type=rtype,
        name=f"{rtype}.{rname}",
        source_format=SourceFormat.TERRAFORM,
        source_file=filename,
        properties=props,
    )


# ---------------------------------------------------------------------------- AWS: S3


def _s3_bucket(rtype, rname, body, filename):
    policy = body.get("policy")
    acl = as_str(body.get("acl"))
    return _resource(
        Kind.S3_BUCKET, Provider.AWS, rtype, rname, filename,
        {
            "bucket_name": as_str(body.get("bucket")),
            "acls": [{"value": acl, "via": None}] if acl else [],
            "public_policy_evidence": public_policy_evidence(policy) if policy else None,
            "public_access_block": None,
            "encryption_configured": bool(_as_list(body.get("server_side_encryption_configuration"))),
        },
    )  # fmt: skip


def _s3_acl(rtype, rname, body, filename):
    ref, literal = _bucket_target(body.get("bucket"))
    return _resource(
        Kind.S3_ACL, Provider.AWS, rtype, rname, filename,
        {"bucket_ref": ref, "bucket_literal": literal, "acl": as_str(body.get("acl"))},
    )  # fmt: skip


def _s3_pab(rtype, rname, body, filename):
    ref, literal = _bucket_target(body.get("bucket"))
    # Terraform defaults every flag to false when omitted; unresolved values stay unknown (None).
    flags = {f: (False if f not in body else as_bool(body[f])) for f in _PAB_FLAGS}
    return _resource(
        Kind.S3_PUBLIC_ACCESS_BLOCK, Provider.AWS, rtype, rname, filename,
        {"bucket_ref": ref, "bucket_literal": literal, "flags": flags},
    )  # fmt: skip


def _s3_policy(rtype, rname, body, filename):
    ref, literal = _bucket_target(body.get("bucket"))
    policy = body.get("policy")
    return _resource(
        Kind.S3_BUCKET_POLICY, Provider.AWS, rtype, rname, filename,
        {
            "bucket_ref": ref,
            "bucket_literal": literal,
            "public_policy_evidence": public_policy_evidence(policy) if policy else None,
        },
    )  # fmt: skip


def _s3_encryption(rtype, rname, body, filename):
    ref, literal = _bucket_target(body.get("bucket"))
    return _resource(
        Kind.S3_ENCRYPTION, Provider.AWS, rtype, rname, filename,
        {"bucket_ref": ref, "bucket_literal": literal},
    )  # fmt: skip


# ---------------------------------------------------------------------------- AWS: network


def _ingress(from_port: Any, to_port: Any, protocol: Any, cidrs: list[str]) -> dict[str, Any]:
    return {
        "from_port": as_int(from_port),
        "to_port": as_int(to_port),
        "protocol": normalize_protocol(protocol),
        "cidrs": cidrs,
    }


def _security_group(rtype, rname, body, filename):
    rules = []
    for block in _as_list(body.get("ingress")):
        if not isinstance(block, dict):
            continue
        cidrs = str_list(block.get("cidr_blocks")) + str_list(block.get("ipv6_cidr_blocks"))
        rules.append(
            _ingress(block.get("from_port"), block.get("to_port"), block.get("protocol"), cidrs)
        )
    return _resource(Kind.SECURITY_GROUP, Provider.AWS, rtype, rname, filename, {"ingress": rules})


def _security_group_rule(rtype, rname, body, filename):
    if as_str(body.get("type")) != "ingress":
        return None
    cidrs = str_list(body.get("cidr_blocks")) + str_list(body.get("ipv6_cidr_blocks"))
    rule = _ingress(body.get("from_port"), body.get("to_port"), body.get("protocol"), cidrs)
    return _resource(Kind.SECURITY_GROUP, Provider.AWS, rtype, rname, filename, {"ingress": [rule]})


def _vpc_ingress_rule(rtype, rname, body, filename):
    cidrs = str_list(body.get("cidr_ipv4")) + str_list(body.get("cidr_ipv6"))
    rule = _ingress(body.get("from_port"), body.get("to_port"), body.get("ip_protocol"), cidrs)
    return _resource(Kind.SECURITY_GROUP, Provider.AWS, rtype, rname, filename, {"ingress": [rule]})


# ---------------------------------------------------------------------------- AWS: storage


def _encrypted_flag(body: dict[str, Any], key: str, inherits: tuple[str, ...]) -> bool | None:
    """Encryption flag with Terraform's default (false); unknown if it may be inherited."""
    if any(k in body for k in inherits):
        return None
    if key not in body:
        return False
    return as_bool(body[key])


def _rds(rtype, rname, body, filename):
    public = as_bool(body["publicly_accessible"]) if "publicly_accessible" in body else None
    encrypted = _encrypted_flag(
        body,
        "storage_encrypted",
        ("replicate_source_db", "snapshot_identifier", "replication_source_identifier",
         "global_cluster_identifier"),
    )  # fmt: skip
    return _resource(
        Kind.RDS_INSTANCE, Provider.AWS, rtype, rname, filename,
        {"publicly_accessible": public, "storage_encrypted": encrypted},
    )  # fmt: skip


def _ebs(rtype, rname, body, filename):
    return _resource(
        Kind.EBS_VOLUME, Provider.AWS, rtype, rname, filename,
        {"encrypted": _encrypted_flag(body, "encrypted", ("snapshot_id",))},
    )  # fmt: skip


# ---------------------------------------------------------------------------- Azure

_PUBLIC_CONTAINER_ACCESS = {"blob", "container"}


def _azure_storage_account(rtype, rname, body, filename):
    evidence = None
    for key in ("allow_nested_items_to_be_public", "allow_blob_public_access"):
        if key in body and as_bool(body[key]) is True:
            evidence = f"{key} = true"
            break
    return _resource(
        Kind.AZURE_STORAGE, Provider.AZURE, rtype, rname, filename,
        {"public_access_evidence": evidence},
    )  # fmt: skip


def _azure_storage_container(rtype, rname, body, filename):
    access = (as_str(body.get("container_access_type")) or "").lower()
    evidence = f'container_access_type = "{access}"' if access in _PUBLIC_CONTAINER_ACCESS else None
    return _resource(
        Kind.AZURE_STORAGE, Provider.AZURE, rtype, rname, filename,
        {"public_access_evidence": evidence},
    )  # fmt: skip


def _nsg_rule(block: dict[str, Any]) -> dict[str, Any]:
    ports = block.get("destination_port_ranges")
    if ports is None:
        ports = block.get("destination_port_range")
    sources = str_list(block.get("source_address_prefixes")) + str_list(
        block.get("source_address_prefix")
    )
    return {
        "name": as_str(block.get("name")) or "(unnamed)",
        "direction": (as_str(block.get("direction")) or "").lower() or None,
        "access": (as_str(block.get("access")) or "").lower() or None,
        "protocol": normalize_protocol(block.get("protocol")),
        "sources": sources,
        "ports": ports,
    }


def _azure_nsg(rtype, rname, body, filename):
    rules = [_nsg_rule(b) for b in _as_list(body.get("security_rule")) if isinstance(b, dict)]
    return _resource(Kind.AZURE_NSG, Provider.AZURE, rtype, rname, filename, {"rules": rules})


def _azure_nsg_rule(rtype, rname, body, filename):
    return _resource(
        Kind.AZURE_NSG, Provider.AZURE, rtype, rname, filename, {"rules": [_nsg_rule(body)]}
    )


_Handler = Callable[[str, str, dict[str, Any], str], NormalizedResource | None]
_HANDLERS: dict[str, _Handler] = {
    "aws_s3_bucket": _s3_bucket,
    "aws_s3_bucket_acl": _s3_acl,
    "aws_s3_bucket_public_access_block": _s3_pab,
    "aws_s3_bucket_policy": _s3_policy,
    "aws_s3_bucket_server_side_encryption_configuration": _s3_encryption,
    "aws_security_group": _security_group,
    "aws_security_group_rule": _security_group_rule,
    "aws_vpc_security_group_ingress_rule": _vpc_ingress_rule,
    "aws_db_instance": _rds,
    "aws_rds_cluster": _rds,
    "aws_ebs_volume": _ebs,
    "azurerm_storage_account": _azure_storage_account,
    "azurerm_storage_container": _azure_storage_container,
    "azurerm_network_security_group": _azure_nsg,
    "azurerm_network_security_rule": _azure_nsg_rule,
}


def parse_terraform(text: str, filename: str) -> ParsedFile:
    try:
        data = hcl2.loads(text, serialization_options=_OPTIONS)
    except RecursionError:
        raise IaCParseError(f"'{filename}' is nested too deeply to parse.") from None
    except Exception as exc:  # lark raises many exception types; never leak internals
        line = getattr(exc, "line", None)
        column = getattr(exc, "column", None)
        where = f" near line {line}, column {column}" if line and column else ""
        raise IaCParseError(f"'{filename}' is not valid Terraform (HCL){where}.") from None
    if not isinstance(data, dict):
        raise IaCParseError(f"'{filename}' did not contain Terraform configuration.")

    variables = _collect_variables(data)
    resources: list[NormalizedResource] = []
    total = 0
    for block in _as_list(data.get("resource")):
        if not isinstance(block, dict):
            continue
        for rtype, named in block.items():
            if not isinstance(named, dict):
                continue
            for rname, body in named.items():
                total += 1
                handler = _HANDLERS.get(rtype)
                if handler is None:
                    continue
                resolved = _resolve(body if isinstance(body, dict) else {}, variables)
                normalized = handler(rtype, rname, resolved, filename)
                if normalized is not None:
                    resources.append(normalized)
    return ParsedFile(resources=resources, resources_total=total)
