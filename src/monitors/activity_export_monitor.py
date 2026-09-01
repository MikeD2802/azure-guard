from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, removed, transition, turned_off

DIAGNOSTIC_API_VERSION = "2021-05-01-preview"
AAD_DIAGNOSTIC_API_VERSION = "2017-04-01-preview"

DESTINATIONS = ("workspaceId", "storageAccountId", "eventHubAuthorizationRuleId", "marketplacePartnerId")


class ActivityExportMonitor(MonitorBase):
    """Diagnostic settings that ship logs off the resource that produced them.

    Covers subscription activity logs, Entra ID tenant logs (sign-in and audit),
    and any additional resource explicitly listed in ``diagnostic_scopes``.
    """

    name = "activity_export_monitor"
    event_category = "AzureDiagnosticSettings"
    event_provider = "Azure.ResourceManager"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        for subscription_id in self.config.get("subscriptions", []):
            scope = f"/subscriptions/{subscription_id}"
            items.extend(
                self.collect_scope(
                    scope,
                    "activity log diagnostic settings",
                    self._collect_scope_settings,
                    scope,
                    subscription_id,
                    DIAGNOSTIC_API_VERSION,
                )
            )

        for scope in self.config.get("diagnostic_scopes", []):
            if not scope:
                continue
            items.extend(
                self.collect_scope(
                    scope,
                    "resource diagnostic settings",
                    self._collect_scope_settings,
                    scope,
                    self._subscription_from_scope(scope),
                    DIAGNOSTIC_API_VERSION,
                )
            )

        if self.config.get("monitor_entra_diagnostics", True):
            aad_scope = "/providers/microsoft.aadiam"
            items.extend(
                self.collect_scope(
                    aad_scope,
                    "Entra ID tenant diagnostic settings",
                    self._collect_scope_settings,
                    aad_scope,
                    None,
                    AAD_DIAGNOSTIC_API_VERSION,
                )
            )

        return items

    def _collect_scope_settings(
        self, scope: str, subscription_id: str | None, api_version: str
    ) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        url = f"https://management.azure.com{scope}/providers/Microsoft.Insights/diagnosticSettings"
        collected: list[dict[str, Any]] = []
        for setting in self._arm_paged(url, params={"api-version": api_version}):
            props = setting.get("properties", {}) or {}
            collected.append(
                {
                    "id": setting.get("id"),
                    "name": setting.get("name"),
                    "type": setting.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "workspaceId": props.get("workspaceId"),
                        "eventHubAuthorizationRuleId": props.get("eventHubAuthorizationRuleId"),
                        "eventHubName": props.get("eventHubName"),
                        "storageAccountId": props.get("storageAccountId"),
                        "marketplacePartnerId": props.get("marketplacePartnerId"),
                        "logs": _categories(props.get("logs")),
                        "metrics": _categories(props.get("metrics")),
                    },
                }
            )
        return collected

    # ------------------------------------------------------------------
    def classify(self, change: dict[str, Any]) -> Verdict:
        verdict = super().classify(change)
        old = get_path(change.get("old") or {}, "data") or {}
        new = get_path(change.get("new") or {}, "data") or {}
        change_type = change["changeType"]

        if change_type == "Deleted":
            return verdict.note(
                "critical", "diagnostic setting deleted, log export to this destination stopped"
            )

        if change_type == "Created":
            return verdict

        for destination in DESTINATIONS:
            old_value, new_value = transition(old, new, destination)
            if removed(old_value, new_value):
                verdict.note("critical", f"log destination {destination} removed")

        disabled = _disabled_categories(old.get("logs"), new.get("logs"))
        if disabled:
            verdict.note("critical", f"log categories disabled: {', '.join(disabled)}")

        reduced = _reduced_retention(old.get("logs"), new.get("logs"))
        if reduced:
            verdict.note("high", f"log retention reduced: {', '.join(reduced)}")

        if _disabled_categories(old.get("metrics"), new.get("metrics")):
            verdict.note("medium", "metric categories disabled")

        return verdict

    @staticmethod
    def _subscription_from_scope(scope: str) -> str | None:
        parts = scope.split("/")
        if "subscriptions" in parts:
            idx = parts.index("subscriptions") + 1
            if idx < len(parts):
                return parts[idx]
        return None


def _categories(entries: Any) -> list[dict[str, Any]]:
    result = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        result.append(
            {
                "category": entry.get("category"),
                "categoryGroup": entry.get("categoryGroup"),
                "enabled": entry.get("enabled"),
                "retention": (entry.get("retentionPolicy", {}) or {}).get("days"),
            }
        )
    return result


def _by_category(entries: Any) -> dict[str, dict[str, Any]]:
    indexed = {}
    for entry in entries or []:
        if isinstance(entry, dict):
            key = entry.get("category") or entry.get("categoryGroup")
            if key:
                indexed[key] = entry
    return indexed


def _disabled_categories(old_entries: Any, new_entries: Any) -> list[str]:
    old_map = _by_category(old_entries)
    new_map = _by_category(new_entries)
    disabled = []
    for category, old_entry in old_map.items():
        new_entry = new_map.get(category)
        if new_entry is None:
            disabled.append(category)
        elif turned_off(old_entry.get("enabled"), new_entry.get("enabled")):
            disabled.append(category)
    return sorted(disabled)


def _reduced_retention(old_entries: Any, new_entries: Any) -> list[str]:
    old_map = _by_category(old_entries)
    new_map = _by_category(new_entries)
    reduced = []
    for category, old_entry in old_map.items():
        new_entry = new_map.get(category)
        if new_entry is None:
            continue
        old_days, new_days = old_entry.get("retention"), new_entry.get("retention")
        if isinstance(old_days, int) and isinstance(new_days, int) and 0 < new_days < old_days:
            reduced.append(f"{category} ({old_days}d -> {new_days}d)")
    return sorted(reduced)
