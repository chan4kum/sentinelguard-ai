"""Small, pure helpers for coercing loosely-typed IaC values.

Convention: anything that cannot be determined statically (variables, intrinsic functions,
unexpected types) becomes ``None`` so rules never flag on a guess.
"""

from __future__ import annotations

from typing import Any

WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
_PROTOCOL_ALIASES = {"6": "tcp", "17": "udp", "1": "icmp", "all": "-1", "*": "-1"}


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def as_str(value: Any) -> str | None:
    """A plain literal string, or None when it is unresolved / not a string."""
    if isinstance(value, str) and "${" not in value:
        return value.strip()
    return None


def str_list(value: Any) -> list[str]:
    """Literal strings from a scalar-or-list value; unresolved entries are dropped."""
    items = value if isinstance(value, list) else [value]
    return [s for s in (as_str(i) for i in items) if s]


def is_world_cidr(cidr: str) -> bool:
    return cidr.strip() in WORLD_CIDRS


def normalize_protocol(value: Any) -> str | None:
    text = (
        as_str(value)
        if isinstance(value, str)
        else (str(value) if isinstance(value, int) else None)
    )
    if text is None:
        return None
    text = text.strip().lower()
    return _PROTOCOL_ALIASES.get(text, text)


def port_ranges(spec: Any) -> list[tuple[int, int]] | None:
    """Parse Azure-style port specs ("22", "*", "20-30", or a list of those).

    Returns None if any element is not statically understood.
    """
    items = spec if isinstance(spec, list) else [spec]
    ranges: list[tuple[int, int]] = []
    for item in items:
        text = as_str(item) if not isinstance(item, int) else str(item)
        if not text:
            return None
        if text == "*":
            ranges.append((0, 65535))
        elif text.isdigit():
            ranges.append((int(text), int(text)))
        elif "-" in text and all(p.strip().isdigit() for p in text.split("-", 1)):
            low, high = (int(p) for p in text.split("-", 1))
            ranges.append((low, high))
        else:
            return None
    return ranges


def ranges_cover(ranges: list[tuple[int, int]], port: int) -> bool:
    return any(low <= port <= high for low, high in ranges)
