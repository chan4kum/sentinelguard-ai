"""Rule interface. A rule is metadata + a pure function over one normalized resource."""

from __future__ import annotations

from abc import ABC, abstractmethod

from sentinelguard.domain.models import NormalizedResource, Rule


class GuardrailRule(ABC):
    """Deterministic, side-effect-free check.

    ``evaluate`` returns human-readable evidence lines — an empty list means the resource is
    compliant (or the property could not be determined statically, which is never flagged).
    """

    meta: Rule

    @abstractmethod
    def evaluate(self, resource: NormalizedResource) -> list[str]: ...
