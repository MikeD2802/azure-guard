from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, transition, turned_off

ACTIVITY_LOG_ALERT_API_VERSION = "2020-10-01"
ACTION_GROUP_API_VERSION = "2023-01-01"

RECEIVER_KEYS = (
    "emailReceivers",
    "smsReceivers",
    "webhookReceivers",
    "azureAppPushReceivers",
    "eventHubReceivers",
    "logicAppReceivers",
    "automationRunbookReceivers",
    "azureFunctionReceivers",
)


class AlertingMonitor(MonitorBase):
    """Activity log alert rules and the action groups they notify.

    Disabling an action group silences every alert routed through it without
    changing a single alert rule, so both halves of the path are monitored.
    """

    name = "alerting_monitor"
    event_category = "AzureMonitorAlerting"
    event_provider = "Azure.Insights"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for subscription_id in self.config.get("subscriptions", []):
            scope = f"/subscriptions/{subscription_id}"
            items.extend(
                self.collect_scope(
                    scope,
                    "activity log alerts and action groups",
                    self._collect_subscription,
                    subscription_id,
                )
            )
        return items

    def _collect_subscription(self, subscription_id: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        scope = f"/subscriptions/{subscription_id}"
        base = f"https://management.azure.com{scope}/providers/Microsoft.Insights"
        collected: list[dict[str, Any]] = []

        for alert in self._arm_paged(
            f"{base}/activityLogAlerts", params={"api-version": ACTIVITY_LOG_ALERT_API_VERSION}
        ):
            props = alert.get("properties", {}) or {}
            collected.append(
                {
                    "id": alert.get("id"),
                    "name": alert.get("name"),
                    "type": alert.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "activityLogAlert",
                        "enabled": props.get("enabled"),
                        "scopes": props.get("scopes"),
                        "condition": props.get("condition"),
                        "actions": props.get("actions"),
                    },
                }
            )

        for group in self._arm_paged(
            f"{base}/actionGroups", params={"api-version": ACTION_GROUP_API_VERSION}
        ):
            props = group.get("properties", {}) or {}
            collected.append(
                {
                    "id": group.get("id"),
                    "name": group.get("name"),
                    "type": group.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "actionGroup",
                        "enabled": props.get("enabled"),
                        "groupShortName": props.get("groupShortName"),
                        **{key: props.get(key) for key in RECEIVER_KEYS},
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

        if change_type == "Deleted":
            label = "activity log alert" if kind == "activityLogAlert" else "action group"
            return verdict.note("critical", f"{label} deleted, its notifications stop")

        if change_type == "Created":
            return verdict

        if turned_off(*transition(old, new, "enabled")):
            label = "activity log alert" if kind == "activityLogAlert" else "action group"
            verdict.note("critical", f"{label} disabled")

        if kind == "activityLogAlert":
            if old.get("condition") != new.get("condition"):
                verdict.note("high", "alert condition changed, coverage may have narrowed")
            if old.get("actions") != new.get("actions"):
                verdict.note("high", "alert actions changed")
            if old.get("scopes") != new.get("scopes"):
                verdict.note("medium", "alert scopes changed")

        if kind == "actionGroup":
            emptied = [
                key
                for key in RECEIVER_KEYS
                if (old.get(key) or []) and not (new.get(key) or [])
            ]
            if emptied:
                verdict.note("critical", f"all recipients removed from: {', '.join(emptied)}")
            elif any(old.get(key) != new.get(key) for key in RECEIVER_KEYS):
                verdict.note("high", "action group recipients changed")

        return verdict
