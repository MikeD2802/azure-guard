from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase


class SentinelMonitor(MonitorBase):
    name = "sentinel_monitor"
    event_category = "MicrosoftSentinel"
    event_provider = "Azure.ResourceManager"
    severity = "high"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        tenant_id = self.config.get("tenant_id")
        workspaces = self.config.get("sentinel_workspaces", [])
        if not workspaces:
            workspaces = self._discover_workspaces()
        for workspace_id in workspaces:
            base = f"https://management.azure.com{workspace_id}/providers/Microsoft.SecurityInsights"
            for resource, label in [
                ("alertRules", "alertRule"),
                ("automationRules", "automationRule"),
                ("dataConnectors", "dataConnector"),
            ]:
                url = f"{base}/{resource}"
                data = self._arm_get(url, params={"api-version": "2023-02-01-preview"})
                for entry in data.get("value", []):
                    props = entry.get("properties", {})
                    items.append(
                        {
                            "id": entry.get("id"),
                            "name": entry.get("name"),
                            "type": entry.get("type"),
                            "scope": workspace_id,
                            "subscriptionId": self._subscription_from_id(workspace_id),
                            "tenantId": tenant_id,
                            "data": {
                                "kind": entry.get("kind"),
                                "label": label,
                                "displayName": props.get("displayName"),
                                "enabled": props.get("enabled"),
                                "severity": props.get("severity"),
                                "query": props.get("query"),
                                "triggerOperator": props.get("triggerOperator"),
                                "triggerThreshold": props.get("triggerThreshold"),
                                "queryFrequency": props.get("queryFrequency"),
                                "queryPeriod": props.get("queryPeriod"),
                                "tactics": props.get("tactics"),
                                "techniques": props.get("techniques"),
                            },
                        }
                    )
        return items

    def _discover_workspaces(self) -> list[str]:
        discovered: list[str] = []
        for subscription_id in self.config.get("subscriptions", []):
            url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces"
            )
            data = self._arm_get(url, params={"api-version": "2022-10-01"})
            for workspace in data.get("value", []):
                if workspace.get("id"):
                    discovered.append(workspace["id"])
        if self.verbose:
            self.logger.info(f"Discovered {len(discovered)} workspaces")
        return discovered

    @staticmethod
    def _subscription_from_id(resource_id: str) -> str | None:
        parts = resource_id.split("/")
        if "subscriptions" in parts:
            idx = parts.index("subscriptions") + 1
            if idx < len(parts):
                return parts[idx]
        return None
