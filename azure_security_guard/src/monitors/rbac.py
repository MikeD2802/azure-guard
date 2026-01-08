from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from azure_security_guard.src.arm_client import ArmClient
from azure_security_guard.src.activity_log import ActivityLogEvent


@dataclass
class RbacMonitor:
    name: str = "rbac"

    def matches(self, event: ActivityLogEvent) -> bool:
        return "microsoft.authorization/roleassignments" in event.operation_name.lower()

    def fetch_after_state(self, event: ActivityLogEvent, arm: ArmClient) -> Optional[Dict[str, Any]]:
        resource_id = event.resource_id
        if not resource_id:
            return None
        url = f"https://management.azure.com{resource_id}"
        payload = arm.try_get(url, "2022-04-01")
        if not payload:
            return None
        props = payload.get("properties", {})
        state: Dict[str, Any] = {
            "id": payload.get("id"),
            "name": payload.get("name"),
            "type": payload.get("type"),
            "properties": {
                "principalId": props.get("principalId"),
                "roleDefinitionId": props.get("roleDefinitionId"),
                "scope": props.get("scope"),
            },
        }
        if props.get("roleDefinitionId"):
            role_def = arm.try_get(
                f"https://management.azure.com{props['roleDefinitionId']}",
                "2022-04-01",
            )
            if role_def:
                state["roleDefinition"] = {
                    "id": role_def.get("id"),
                    "name": role_def.get("name"),
                    "properties": {
                        "roleName": role_def.get("properties", {}).get("roleName"),
                        "type": role_def.get("properties", {}).get("type"),
                        "description": role_def.get("properties", {}).get("description"),
                    },
                }
        return state
