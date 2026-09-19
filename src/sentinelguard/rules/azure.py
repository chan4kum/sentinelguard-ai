"""Azure guardrails (azurerm Terraform resources)."""

from __future__ import annotations

from sentinelguard.domain.models import Kind, NormalizedResource, Provider, Rule, Severity
from sentinelguard.parsing.values import port_ranges, ranges_cover
from sentinelguard.rules.base import GuardrailRule

_INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}
_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


class AzureStoragePublicRule(GuardrailRule):
    meta = Rule(
        rule_id="AZ-STOR-001",
        title="Azure storage allows anonymous public access",
        provider=Provider.AZURE,
        resource_kinds=[Kind.AZURE_STORAGE],
        description="Anonymous blob/container access lets anyone read stored data without credentials.",
        detection=(
            "azurerm_storage_account sets allow_nested_items_to_be_public (or allow_blob_public_access) "
            'to true, or azurerm_storage_container has container_access_type "blob" or "container".'
        ),
        severity=Severity.HIGH,
        risk_weight=20,
        remediation=(
            "Set allow_nested_items_to_be_public = false on the account and container_access_type = "
            '"private" on containers. Use SAS tokens or Azure AD authorisation for sharing.'
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        evidence = resource.properties.get("public_access_evidence")
        return [f"{evidence}: anonymous public access is enabled"] if evidence else []


class AzureNsgAdminPortRule(GuardrailRule):
    meta = Rule(
        rule_id="AZ-NSG-001",
        title="NSG exposes SSH/RDP to the internet",
        provider=Provider.AZURE,
        resource_kinds=[Kind.AZURE_NSG],
        description="Internet-wide SSH (22) or RDP (3389) exposes virtual machines to attack.",
        detection=(
            "An Inbound Allow rule for TCP (or any protocol) with source *, Internet or 0.0.0.0/0 "
            "covers port 22 or 3389."
        ),
        severity=Severity.CRITICAL,
        risk_weight=30,
        remediation=(
            "Restrict source_address_prefix to a trusted CIDR/service tag, or use Azure Bastion / "
            "Just-In-Time VM access instead of opening 22/3389."
        ),
    )

    def evaluate(self, resource: NormalizedResource) -> list[str]:
        evidence = []
        for rule in resource.properties.get("rules", []):
            if rule.get("direction") != "inbound" or rule.get("access") != "allow":
                continue
            if rule.get("protocol") not in {"tcp", "-1"}:
                continue
            public = [s for s in rule.get("sources", []) if s.lower() in _INTERNET_SOURCES]
            ranges = port_ranges(rule.get("ports")) if rule.get("ports") is not None else None
            if not public or ranges is None:
                continue
            exposed = [
                f"{label} ({port})"
                for port, label in _ADMIN_PORTS.items()
                if ranges_cover(ranges, port)
            ]
            if exposed:
                evidence.append(
                    f'Rule "{rule["name"]}" allows Inbound from {", ".join(public)} to '
                    f"{', '.join(exposed)}"
                )
        return evidence
