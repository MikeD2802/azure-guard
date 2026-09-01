from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, transition, turned_off

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3}

SENTINEL_API_VERSION = "2023-02-01-preview"
WORKSPACE_API_VERSION = "2022-10-01"
SOLUTIONS_API_VERSION = "2015-11-01-preview"


class SentinelMonitor(MonitorBase):
    name = "sentinel_monitor"
    event_category = "MicrosoftSentinel"
    event_provider = "Azure.ResourceManager"

    RESOURCES = [
        ("alertRules", "alertRule"),
        ("automationRules", "automationRule"),
        ("dataConnectors", "dataConnector"),
    ]

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        workspaces = self.config.get("sentinel_workspaces", [])
        if not workspaces:
            workspaces = self._discover_workspaces()
        for workspace_id in workspaces:
            items.extend(
                self.collect_scope(
                    workspace_id,
                    "Sentinel collection",
                    self._collect_workspace,
                    workspace_id,
                )
            )
        return items

    def _collect_workspace(self, workspace_id: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        base = f"https://management.azure.com{workspace_id}/providers/Microsoft.SecurityInsights"
        collected: list[dict[str, Any]] = []
        for resource, label in self.RESOURCES:
            entries = self._arm_paged(
                f"{base}/{resource}", params={"api-version": SENTINEL_API_VERSION}
            )
            for entry in entries:
                props = entry.get("properties", {}) or {}
                collected.append(
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
                            "suppressionEnabled": props.get("suppressionEnabled"),
                            "suppressionDuration": props.get("suppressionDuration"),
                            "tactics": props.get("tactics"),
                            "techniques": props.get("techniques"),
                            # Automation rules can silently auto-close incidents,
                            # so their actions and trigger are part of the state.
                            "actions": props.get("actions"),
                            "triggeringLogic": props.get("triggeringLogic"),
                            "order": props.get("order"),
                            # A connector that stops ingesting a data type blinds
                            # every rule built on that table.
                            "dataTypes": props.get("dataTypes"),
                        },
                    }
                )
        return collected

    def _discover_workspaces(self) -> list[str]:
        """Find workspaces actually onboarded to Sentinel.

        Listing every Log Analytics workspace meant querying SecurityInsights on
        workspaces that do not have it installed, which errors. The
        SecurityInsights solution is what marks a workspace as onboarded.
        """
        discovered: list[str] = []
        for subscription_id in self.config.get("subscriptions", []):
            solutions_url = (
                "https://management.azure.com"
                f"/subscriptions/{subscription_id}/providers/Microsoft.OperationsManagement/solutions"
            )
            solutions = self.collect_scope(
                f"/subscriptions/{subscription_id}",
                "Sentinel workspace discovery",
                self._arm_paged,
                solutions_url,
                params={"api-version": SOLUTIONS_API_VERSION},
            )
            for solution in solutions:
                if not str(solution.get("name", "")).startswith("SecurityInsights("):
                    continue
                workspace = (solution.get("properties", {}) or {}).get("workspaceResourceId")
                if workspace:
                    discovered.append(workspace)
        if self.verbose:
            self.logger.info(f"Discovered {len(discovered)} Sentinel-onboarded workspace(s)")
        return discovered

    # ------------------------------------------------------------------
    def classify(self, change: dict[str, Any]) -> Verdict:
        verdict = super().classify(change)
        old = get_path(change.get("old") or {}, "data") or {}
        new = get_path(change.get("new") or {}, "data") or {}
        label = (new or old).get("label")
        change_type = change["changeType"]

        if change_type == "Deleted":
            if label in {"alertRule", "dataConnector"}:
                verdict.note("critical", f"{label} removed, ending its detection coverage")
            return verdict

        if change_type == "Created":
            if label == "automationRule" and self._closes_incidents(new):
                verdict.note("critical", "new automation rule auto-closes incidents")
            return verdict

        old_enabled, new_enabled = transition(old, new, "enabled")
        if turned_off(old_enabled, new_enabled):
            verdict.note("critical", f"{label} disabled")

        if label == "alertRule":
            old_sev, new_sev = transition(old, new, "severity")
            if self._severity_lowered(old_sev, new_sev):
                verdict.note("high", f"alert rule severity lowered {old_sev} -> {new_sev}")
            if not self._equal(old, new, "query"):
                verdict.note("high", "detection query modified")
            old_threshold, new_threshold = transition(old, new, "triggerThreshold")
            if _is_number(old_threshold) and _is_number(new_threshold) and new_threshold > old_threshold:
                verdict.note(
                    "high", f"trigger threshold raised {old_threshold} -> {new_threshold}"
                )
            if not self._equal(old, new, "queryFrequency") or not self._equal(old, new, "queryPeriod"):
                verdict.note("medium", "query schedule changed")
            if turned_off(*transition(new, old, "suppressionEnabled")):
                verdict.note("high", "alert suppression enabled on rule")

        if label == "dataConnector" and not self._equal(old, new, "dataTypes"):
            verdict.note("high", "connector data types changed, ingestion may have stopped")

        if label == "automationRule":
            if self._closes_incidents(new) and not self._closes_incidents(old):
                verdict.note("critical", "automation rule now auto-closes incidents")
            elif not self._equal(old, new, "actions"):
                verdict.note("high", "automation rule actions changed")

        return verdict

    @staticmethod
    def _equal(old: dict, new: dict, key: str) -> bool:
        return old.get(key) == new.get(key)

    @staticmethod
    def _severity_lowered(old_sev: Any, new_sev: Any) -> bool:
        old_rank = SEVERITY_RANK.get(str(old_sev).lower())
        new_rank = SEVERITY_RANK.get(str(new_sev).lower())
        return old_rank is not None and new_rank is not None and new_rank < old_rank

    @staticmethod
    def _closes_incidents(data: dict[str, Any]) -> bool:
        for action in data.get("actions") or []:
            if not isinstance(action, dict):
                continue
            config = action.get("actionConfiguration") or {}
            if str(config.get("status", "")).lower() == "closed":
                return True
        return False

    @staticmethod
    def _subscription_from_id(resource_id: str) -> str | None:
        parts = resource_id.split("/")
        if "subscriptions" in parts:
            idx = parts.index("subscriptions") + 1
            if idx < len(parts):
                return parts[idx]
        return None


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)
