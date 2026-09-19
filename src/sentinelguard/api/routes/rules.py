from __future__ import annotations

from fastapi import APIRouter

from sentinelguard.domain.models import Rule
from sentinelguard.rules.registry import rule_catalogue

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("", response_model=list[Rule], summary="The security baseline (all guardrails)")
def list_rules() -> list[Rule]:
    return rule_catalogue()
