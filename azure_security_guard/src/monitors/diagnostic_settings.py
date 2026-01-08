from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from azure_security_guard.src.arm_client import ArmClient
from azure_security_guard.src.activity_log import ActivityLogEvent


@dataclass
class DiagnosticSettingsMonitor:
    name: str = "diagnostic_settings"

    def matches(self, event: ActivityLogEvent) -> bool:
        return "microsoft.insights/diagnosticsettings" in event.operation_name.lower()

    def fetch_after_state(self, event: ActivityLogEvent, arm: ArmClient) -> Optional[Dict[str, Any]]:
        resource_id = event.resource_id
        if not resource_id:
            return None
        url = f"https://management.azure.com{resource_id}/providers/Microsoft.Insights/diagnosticSettings"
        payload = arm.try_get(url, "2021-05-01-preview")
        if not payload:
            return None
        settings = []
        for item in payload.get("value", []):
            props = item.get("properties", {})
            settings.append(
                {
                    "name": item.get("name"),
                    "workspaceId": props.get("workspaceId"),
                    "storageAccountId": props.get("storageAccountId"),
                    "eventHubAuthorizationRuleId": props.get("eventHubAuthorizationRuleId"),
                    "serviceBusRuleId": props.get("serviceBusRuleId"),
                    "logs": props.get("logs"),
                    "metrics": props.get("metrics"),
                }
            )
        return {"diagnosticSettings": settings}
