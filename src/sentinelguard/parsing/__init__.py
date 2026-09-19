"""IaC ingestion and normalization: validated uploads in, normalized resources out."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelguard.domain.models import NormalizedResource, SourceFormat
from sentinelguard.parsing.cloudformation import parse_cloudformation
from sentinelguard.parsing.ingest import IacFile
from sentinelguard.parsing.linking import link_resources
from sentinelguard.parsing.terraform import parse_terraform


@dataclass(frozen=True)
class ParseResult:
    resources: list[NormalizedResource]
    resources_total: int
    formats: list[SourceFormat]


def parse_files(files: list[IacFile]) -> ParseResult:
    """Parse every file, then link cross-file resources (e.g. bucket + its public-access-block)."""
    resources: list[NormalizedResource] = []
    total = 0
    formats: list[SourceFormat] = []
    for file in files:
        if file.format == SourceFormat.TERRAFORM:
            parsed = parse_terraform(file.text, file.name)
        else:
            parsed = parse_cloudformation(file.text, file.name)
        resources.extend(parsed.resources)
        total += parsed.resources_total
        if file.format not in formats:
            formats.append(file.format)
    link_resources(resources)
    return ParseResult(resources=resources, resources_total=total, formats=formats)
