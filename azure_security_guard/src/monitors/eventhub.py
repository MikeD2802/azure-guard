from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from azure_security_guard.src.arm_client import ArmClient
from azure_security_guard.src.activity_log import ActivityLogEvent


@dataclass
class EventHubMonitor:
    name: str = "eventhub"

    def matches(self, event: ActivityLogEvent) -> bool:
        return "microsoft.eventhub" in event.operation_name.lower()

    def fetch_after_state(self, event: ActivityLogEvent, arm: ArmClient) -> Optional[Dict[str, Any]]:
        resource_id = event.resource_id
        if not resource_id:
            return None
        url = f"https://management.azure.com{resource_id}"
        payload = arm.try_get(url, "2024-01-01")
        if not payload:
            return None
        state: Dict[str, Any] = {
            "id": payload.get("id"),
            "name": payload.get("name"),
            "type": payload.get("type"),
            "location": payload.get("location"),
            "properties": payload.get("properties"),
        }
        if "/authorizationrules/" in resource_id.lower():
            state["rights"] = payload.get("properties", {}).get("rights")
        if "/namespaces/" in resource_id.lower() and "/eventhubs/" not in resource_id.lower():
            rules_url = f"https://management.azure.com{resource_id}/authorizationRules"
            rules_payload = arm.try_get(rules_url, "2024-01-01")
            if rules_payload:
                state["authorizationRules"] = [
                    {
                        "id": item.get("id"),
                        "name": item.get("name"),
                        "rights": item.get("properties", {}).get("rights"),
                    }
                    for item in rules_payload.get("value", [])
                ]
        if "/namespaces/" in resource_id.lower() and "/eventhubs/" not in resource_id.lower():
            network_rules_url = f"https://management.azure.com{resource_id}/networkRuleSets"
            network_payload = arm.try_get(network_rules_url, "2024-01-01")
            if network_payload:
                state["networkRuleSets"] = network_payload.get("properties")
        return state
