from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase


class RBACMonitor(MonitorBase):
    name = "rbac_monitor"
    event_category = "AzureRBAC"
    event_provider = "Azure.Authorization"
    severity = "high"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        tenant_id = self.config.get("tenant_id")
        scopes = list(self.config.get("rbac_scopes", []))
        scopes.extend(self.config.get("sentinel_workspaces", []))
        for subscription_id in self.config.get("subscriptions", []):
            scopes.append(f"/subscriptions/{subscription_id}")

        for scope in sorted(set(scopes)):
            if not scope:
                continue
            role_assignments_url = (
                f"https://management.azure.com{scope}"
                "/providers/Microsoft.Authorization/roleAssignments"
            )
            data = self._arm_get(role_assignments_url, params={"api-version": "2022-04-01"})
            for assignment in data.get("value", []):
                props = assignment.get("properties", {})
                items.append(
                    {
                        "id": assignment.get("id"),
                        "name": assignment.get("name"),
                        "type": assignment.get("type"),
                        "scope": scope,
                        "subscriptionId": self._subscription_from_scope(scope),
                        "tenantId": tenant_id,
                        "data": {
                            "principalId": props.get("principalId"),
                            "principalType": props.get("principalType"),
                            "roleDefinitionId": props.get("roleDefinitionId"),
                            "scope": props.get("scope"),
                        },
                    }
                )

        for subscription_id in self.config.get("subscriptions", []):
            role_def_url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions"
            )
            data = self._arm_get(role_def_url, params={"api-version": "2022-04-01"})
            for definition in data.get("value", []):
                props = definition.get("properties", {})
                if props.get("roleType") != "CustomRole":
                    continue
                items.append(
                    {
                        "id": definition.get("id"),
                        "name": definition.get("name"),
                        "type": definition.get("type"),
                        "scope": f"/subscriptions/{subscription_id}",
                        "subscriptionId": subscription_id,
                        "tenantId": tenant_id,
                        "data": {
                            "roleName": props.get("roleName"),
                            "description": props.get("description"),
                            "permissions": props.get("permissions"),
                            "assignableScopes": props.get("assignableScopes"),
                        },
                    }
                )

        return items

    @staticmethod
    def _subscription_from_scope(scope: str) -> str | None:
        parts = scope.split("/")
        if "subscriptions" in parts:
            idx = parts.index("subscriptions") + 1
            if idx < len(parts):
                return parts[idx]
        return None
