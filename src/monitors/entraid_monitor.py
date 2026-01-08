from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase


class EntraIdMonitor(MonitorBase):
    name = "entraid_monitor"
    event_category = "EntraId"
    event_provider = "MicrosoftGraph"
    severity = "high"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        tenant_id = self.config.get("tenant_id")

        policies = self._graph_paged("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies")
        for policy in policies:
            items.append(
                {
                    "id": f"conditionalAccessPolicy:{policy.get('id')}",
                    "name": policy.get("displayName"),
                    "type": "conditionalAccessPolicy",
                    "scope": "tenant",
                    "subscriptionId": None,
                    "tenantId": tenant_id,
                    "data": {
                        "state": policy.get("state"),
                        "conditions": policy.get("conditions"),
                        "grantControls": policy.get("grantControls"),
                        "sessionControls": policy.get("sessionControls"),
                    },
                }
            )

        locations = self._graph_paged("https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations")
        for location in locations:
            items.append(
                {
                    "id": f"namedLocation:{location.get('id')}",
                    "name": location.get("displayName"),
                    "type": "namedLocation",
                    "scope": "tenant",
                    "subscriptionId": None,
                    "tenantId": tenant_id,
                    "data": {
                        "isTrusted": location.get("isTrusted"),
                        "ipRanges": location.get("ipRanges"),
                        "countriesAndRegions": location.get("countriesAndRegions"),
                        "includeUnknownCountriesAndRegions": location.get(
                            "includeUnknownCountriesAndRegions"
                        ),
                    },
                }
            )

        auth_policy = self._graph_get("https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy")
        items.append(
            {
                "id": "authenticationMethodsPolicy",
                "name": auth_policy.get("id", "authenticationMethodsPolicy"),
                "type": "authenticationMethodsPolicy",
                "scope": "tenant",
                "subscriptionId": None,
                "tenantId": tenant_id,
                "data": {
                    "policyVersion": auth_policy.get("policyVersion"),
                    "authenticationMethodsPolicy": auth_policy.get("authenticationMethodConfigurations"),
                    "policyState": auth_policy.get("state"),
                },
            }
        )

        return items
