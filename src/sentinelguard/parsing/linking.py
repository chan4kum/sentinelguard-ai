"""Cross-resource joins: fold auxiliary S3 resources into the bucket they configure.

Terraform splits one bucket across several resources (ACL, policy, public-access-block,
encryption). Rules are per-resource, so the linker merges those facts onto the bucket first.
"""

from __future__ import annotations

from sentinelguard.domain.models import Kind, NormalizedResource

_AUXILIARY = {Kind.S3_ACL, Kind.S3_PUBLIC_ACCESS_BLOCK, Kind.S3_BUCKET_POLICY, Kind.S3_ENCRYPTION}


def link_resources(resources: list[NormalizedResource]) -> None:
    """Mutates bucket properties in place."""
    by_key = {(r.source_format, r.name): r for r in resources if r.kind == Kind.S3_BUCKET}
    by_name = {
        (r.source_format, r.properties["bucket_name"]): r
        for r in resources
        if r.kind == Kind.S3_BUCKET and r.properties.get("bucket_name")
    }
    for aux in resources:
        if aux.kind not in _AUXILIARY:
            continue
        props = aux.properties
        target = by_key.get((aux.source_format, props.get("bucket_ref"))) or by_name.get(
            (aux.source_format, props.get("bucket_literal"))
        )
        if target is None:
            continue
        bucket = target.properties
        if aux.kind == Kind.S3_ACL and props.get("acl"):
            bucket["acls"].append({"value": props["acl"], "via": aux.name})
        elif aux.kind == Kind.S3_PUBLIC_ACCESS_BLOCK:
            bucket["public_access_block"] = dict(props["flags"])
        elif aux.kind == Kind.S3_BUCKET_POLICY and not bucket.get("public_policy_evidence"):
            bucket["public_policy_evidence"] = props.get("public_policy_evidence")
        elif aux.kind == Kind.S3_ENCRYPTION:
            bucket["encryption_configured"] = True
