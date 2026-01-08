from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from azure_security_guard.src.arm_client import ArmClient
from azure_security_guard.src.activity_log import ActivityLogEvent


@dataclass
class SentinelRulesMonitor:
    name: str = "sentinel_rules"

    def matches(self, event: ActivityLogEvent) -> bool:
        return "microsoft.securityinsights" in event.operation_name.lower()

    def fetch_after_state(self, event: ActivityLogEvent, arm: ArmClient) -> Optional[Dict[str, Any]]:
        return None
