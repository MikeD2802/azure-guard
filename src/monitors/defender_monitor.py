from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase


class DefenderMonitor(MonitorBase):
    name = "defender_monitor"
    event_category = "DefenderForCloud"
    event_provider = "Azure.Security"
    severity = "high"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        tenant_id = self.config.get("tenant_id")
        for subscription_id in self.config.get("subscriptions", []):
            pricings_url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings"
            )
            pricing_data = self._arm_get(pricings_url, params={"api-version": "2023-01-01"})
            for pricing in pricing_data.get("value", []):
                props = pricing.get("properties", {})
                items.append(
                    {
                        "id": pricing.get("id"),
                        "name": pricing.get("name"),
                        "type": pricing.get("type"),
                        "scope": f"/subscriptions/{subscription_id}",
                        "subscriptionId": subscription_id,
                        "tenantId": tenant_id,
                        "data": {
                            "pricingTier": props.get("pricingTier"),
                            "subPlan": props.get("subPlan"),
                            "freeTrialRemainingTime": props.get("freeTrialRemainingTime"),
                            "extensions": props.get("extensions"),
                        },
                    }
                )

            auto_url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.Security/autoProvisioningSettings"
            )
            auto_data = self._arm_get(auto_url, params={"api-version": "2017-08-01-preview"})
            for setting in auto_data.get("value", []):
                props = setting.get("properties", {})
                items.append(
                    {
                        "id": setting.get("id"),
                        "name": setting.get("name"),
                        "type": setting.get("type"),
                        "scope": f"/subscriptions/{subscription_id}",
                        "subscriptionId": subscription_id,
                        "tenantId": tenant_id,
                        "data": {
                            "autoProvision": props.get("autoProvision"),
                        },
                    }
                )
        return items
