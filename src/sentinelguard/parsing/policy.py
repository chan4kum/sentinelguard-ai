"""Static analysis of S3 bucket-policy documents (parsed JSON, JSON text, or Terraform text)."""

from __future__ import annotations

import json
import re
from typing import Any

_HEREDOC_RE = re.compile(r"^<<-?\s*[A-Za-z_][\w]*\s*\n(?P<body>.*)\n\s*[A-Za-z_][\w]*\s*$", re.S)
_JSONENCODE_RE = re.compile(r"^\$\{\s*jsonencode\((?P<body>.*)\)\s*\}$", re.S)
_HCL_KEY_RE = re.compile(r'(?<![\w"])"?([A-Za-z_][\w:.-]*)"?\s*=(?!=)')
_FALLBACK_PUBLIC_RE = re.compile(r'Principal"?\s*[:=]\s*(?:"\*"|\{\s*"?AWS"?\s*[:=]\s*"\*"\s*\})')


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


def _statements(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [s for s in statements if isinstance(s, dict)]


def _evidence_from_document(document: Any) -> str | None:
    for index, statement in enumerate(_statements(document)):
        if statement.get("Effect") != "Allow" or "Condition" in statement:
            continue  # a Condition may restrict the principal; do not guess
        if _principal_is_public(statement.get("Principal")):
            label = statement.get("Sid") or f"#{index}"
            return f'Bucket policy statement "{label}" allows Principal "*" (anonymous access)'
    return None


def _document_from_text(text: str) -> Any | None:
    stripped = text.strip()
    heredoc = _HEREDOC_RE.match(stripped)
    if heredoc:
        stripped = heredoc.group("body").strip()
    encoded = _JSONENCODE_RE.match(stripped)
    if encoded:
        stripped = _HCL_KEY_RE.sub(lambda m: f'"{m.group(1)}":', encoded.group("body"))
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def public_policy_evidence(policy: Any) -> str | None:
    """Evidence string if the policy grants anonymous access, else None."""
    if isinstance(policy, dict):
        return _evidence_from_document(policy)
    if not isinstance(policy, str):
        return None
    document = _document_from_text(policy)
    if document is not None:
        return _evidence_from_document(document)
    # Unparseable (e.g. contains Terraform references): conservative text heuristic.
    if (
        '"Allow"' in policy
        and '"Deny"' not in policy
        and "Condition" not in policy
        and _FALLBACK_PUBLIC_RE.search(policy)
    ):
        return 'Bucket policy allows Principal "*" (anonymous access) [text heuristic]'
    return None
