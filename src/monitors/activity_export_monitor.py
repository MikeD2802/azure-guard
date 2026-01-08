from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase


class ActivityExportMonitor(MonitorBase):
    name = "activity_export_monitor"
    event_category = "AzureDiagnosticSettings"
    event_provider = "Azure.ResourceManager"
    severity = "high"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        tenant_id = self.config.get("tenant_id")
        for subscription_id in self.config.get("subscriptions", []):
            url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/diagnosticSettings"
            )
            data = self._arm_get(url, params={"api-version": "2021-05-01-preview"})
            for setting in data.get("value", []):
                props = setting.get("properties", {})
                logs = [
                    {
                        "category": log.get("category"),
                        "enabled": log.get("enabled"),
                        "retention": log.get("retentionPolicy", {}).get("days"),
                    }
                    for log in props.get("logs", [])
                ]
                metrics = [
                    {
                        "category": metric.get("category"),
                        "enabled": metric.get("enabled"),
                        "retention": metric.get("retentionPolicy", {}).get("days"),
                    }
                    for metric in props.get("metrics", [])
                ]
                items.append(
                    {
                        "id": setting.get("id"),
                        "name": setting.get("name"),
                        "type": setting.get("type"),
                        "scope": f"/subscriptions/{subscription_id}",
                        "subscriptionId": subscription_id,
                        "tenantId": tenant_id,
                        "data": {
                            "workspaceId": props.get("workspaceId"),
                            "eventHubAuthorizationRuleId": props.get("eventHubAuthorizationRuleId"),
                            "storageAccountId": props.get("storageAccountId"),
                            "logs": logs,
                            "metrics": metrics,
                        },
                    }
                )
        return items
