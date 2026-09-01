from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path

ROLE_API_VERSION = "2022-04-01"

# Built-in roles whose assignment grants the ability to disable monitoring or
# grant further access. Keyed by the trailing GUID of roleDefinitionId.
PRIVILEGED_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Resource Policy Contributor",
    "fb1c8493-542b-48eb-b624-b4c8fea62acd": "Security Admin",
}

# Actions that let a principal turn off or rewrite the telemetry this tool reads.
SUPPRESSION_ACTIONS = (
    "microsoft.insights/diagnosticsettings/delete",
    "microsoft.insights/diagnosticsettings/write",
    "microsoft.securityinsights/alertrules/delete",
    "microsoft.securityinsights/alertrules/write",
    "microsoft.security/pricings/write",
    "*",
)


class RBACMonitor(MonitorBase):
    name = "rbac_monitor"
    event_category = "AzureRBAC"
    event_provider = "Azure.Authorization"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for scope in self._scopes():
            items.extend(
                self.collect_scope(scope, "role assignments", self._collect_assignments, scope)
            )

        for subscription_id in self.config.get("subscriptions", []):
            scope = f"/subscriptions/{subscription_id}#roleDefinitions"
            items.extend(
                self.collect_scope(
                    scope, "custom role definitions", self._collect_definitions, subscription_id
                )
            )
        return items

    def _scopes(self) -> list[str]:
        scopes = list(self.config.get("rbac_scopes", []))
        scopes.extend(self.config.get("sentinel_workspaces", []))
        scopes.extend(f"/subscriptions/{sub}" for sub in self.config.get("subscriptions", []))
        return sorted({scope for scope in scopes if scope})

    def _collect_assignments(self, scope: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        url = (
            f"https://management.azure.com{scope}"
            "/providers/Microsoft.Authorization/roleAssignments"
        )
        collected = []
        # atScope() keeps each assignment reported at the scope that defines it;
        # without it, ancestor assignments are echoed at every child scope.
        assignments = self._arm_paged(
            url, params={"api-version": ROLE_API_VERSION, "$filter": "atScope()"}
        )
        for assignment in assignments:
            props = assignment.get("properties", {}) or {}
            collected.append(
                {
                    "id": assignment.get("id"),
                    "name": assignment.get("name"),
                    "type": assignment.get("type"),
                    "scope": scope,
                    "subscriptionId": self._subscription_from_scope(scope),
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "roleAssignment",
                        "principalId": props.get("principalId"),
                        "principalType": props.get("principalType"),
                        "roleDefinitionId": props.get("roleDefinitionId"),
                        "scope": props.get("scope"),
                    },
                }
            )
        return collected

    def _collect_definitions(self, subscription_id: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        url = (
            "https://management.azure.com"
            f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions"
        )
        collected = []
        for definition in self._arm_paged(url, params={"api-version": ROLE_API_VERSION}):
            props = definition.get("properties", {}) or {}
            if props.get("roleType") != "CustomRole":
                continue
            collected.append(
                {
                    "id": definition.get("id"),
                    "name": definition.get("name"),
                    "type": definition.get("type"),
                    "scope": f"/subscriptions/{subscription_id}#roleDefinitions",
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "roleDefinition",
                        "roleName": props.get("roleName"),
                        "description": props.get("description"),
                        "permissions": props.get("permissions"),
                        "assignableScopes": props.get("assignableScopes"),
                    },
                }
            )
        return collected

    # ------------------------------------------------------------------
    def classify(self, change: dict[str, Any]) -> Verdict:
        verdict = super().classify(change)
        old = get_path(change.get("old") or {}, "data") or {}
        new = get_path(change.get("new") or {}, "data") or {}
        kind = (new or old).get("kind")
        change_type = change["changeType"]

        if kind == "roleAssignment":
            data = new or old
            role = _role_name(data.get("roleDefinitionId"))
            if change_type == "Created":
                if role:
                    verdict.note(
                        "high",
                        f"privileged role '{role}' assigned to {data.get('principalType') or 'principal'}",
                        suppression=False,
                    )
                else:
                    verdict.note("medium", "role assignment created", suppression=False)
            elif change_type == "Deleted":
                verdict.note("medium", "role assignment removed")
            return verdict

        if kind == "roleDefinition":
            if change_type == "Deleted":
                return verdict.note("medium", "custom role definition deleted")
            gained = _suppression_actions(new) - _suppression_actions(old)
            if gained:
                verdict.note(
                    "high",
                    f"custom role gained telemetry-affecting actions: {', '.join(sorted(gained))}",
                )
            elif change_type == "Updated" and old.get("permissions") != new.get("permissions"):
                verdict.note("high", "custom role permissions changed")
            if old.get("assignableScopes") != new.get("assignableScopes"):
                verdict.note("medium", "custom role assignable scopes changed")

        return verdict

    @staticmethod
    def _subscription_from_scope(scope: str) -> str | None:
        parts = scope.split("/")
        if "subscriptions" in parts:
            idx = parts.index("subscriptions") + 1
            if idx < len(parts):
                return parts[idx].split("#")[0]
        return None


def _role_name(role_definition_id: Any) -> str | None:
    if not isinstance(role_definition_id, str):
        return None
    return PRIVILEGED_ROLES.get(role_definition_id.rsplit("/", 1)[-1].lower())


def _suppression_actions(data: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for permission in data.get("permissions") or []:
        if not isinstance(permission, dict):
            continue
        for action in permission.get("actions") or []:
            lowered = str(action).lower()
            if lowered in SUPPRESSION_ACTIONS:
                found.add(lowered)
    return found
