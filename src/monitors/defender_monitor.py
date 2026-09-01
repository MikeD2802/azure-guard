from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, transition, turned_off

PRICINGS_API_VERSION = "2023-01-01"
AUTO_PROVISIONING_API_VERSION = "2017-08-01-preview"
SECURITY_CONTACTS_API_VERSION = "2020-01-01-preview"


class DefenderMonitor(MonitorBase):
    name = "defender_monitor"
    event_category = "DefenderForCloud"
    event_provider = "Azure.Security"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for subscription_id in self.config.get("subscriptions", []):
            scope = f"/subscriptions/{subscription_id}"
            items.extend(
                self.collect_scope(
                    scope,
                    "Defender for Cloud settings",
                    self._collect_subscription,
                    subscription_id,
                )
            )
        return items

    def _collect_subscription(self, subscription_id: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        scope = f"/subscriptions/{subscription_id}"
        base = f"https://management.azure.com{scope}/providers/Microsoft.Security"
        collected: list[dict[str, Any]] = []

        def add(entry: dict[str, Any], kind: str, data: dict[str, Any]) -> None:
            collected.append(
                {
                    "id": entry.get("id"),
                    "name": entry.get("name"),
                    "type": entry.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {"kind": kind, **data},
                }
            )

        for pricing in self._arm_paged(
            f"{base}/pricings", params={"api-version": PRICINGS_API_VERSION}
        ):
            props = pricing.get("properties", {}) or {}
            add(
                pricing,
                "pricing",
                {
                    "pricingTier": props.get("pricingTier"),
                    "subPlan": props.get("subPlan"),
                    "extensions": props.get("extensions"),
                },
            )

        for setting in self._arm_paged(
            f"{base}/autoProvisioningSettings",
            params={"api-version": AUTO_PROVISIONING_API_VERSION},
        ):
            props = setting.get("properties", {}) or {}
            add(setting, "autoProvisioning", {"autoProvision": props.get("autoProvision")})

        for contact in self._arm_paged(
            f"{base}/securityContacts", params={"api-version": SECURITY_CONTACTS_API_VERSION}
        ):
            props = contact.get("properties", {}) or {}
            add(
                contact,
                "securityContact",
                {
                    "emails": props.get("emails"),
                    "phone": props.get("phone"),
                    "alertNotifications": props.get("alertNotifications"),
                    "notificationsByRole": props.get("notificationsByRole"),
                },
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
            if kind == "securityContact":
                verdict.note("critical", "security contact deleted, alert notifications stop")
            elif kind == "pricing":
                verdict.note("high", "Defender plan configuration removed")
            return verdict

        if change_type == "Created":
            return verdict

        if kind == "pricing":
            old_tier, new_tier = transition(old, new, "pricingTier")
            if str(old_tier).lower() == "standard" and str(new_tier).lower() == "free":
                verdict.note(
                    "critical", f"Defender plan downgraded to Free for {new.get('kind') or 'plan'}"
                )
            elif old_tier != new_tier:
                verdict.note("high", f"Defender pricing tier changed {old_tier} -> {new_tier}")
            if old.get("extensions") != new.get("extensions"):
                verdict.note("high", "Defender plan extensions changed")

        if kind == "autoProvisioning" and turned_off(*transition(old, new, "autoProvision")):
            verdict.note("high", "Defender agent auto-provisioning disabled")

        if kind == "securityContact":
            old_alerts = get_path(old, "alertNotifications.state", get_path(old, "alertNotifications"))
            new_alerts = get_path(new, "alertNotifications.state", get_path(new, "alertNotifications"))
            if turned_off(old_alerts, new_alerts):
                verdict.note("critical", "Defender alert notifications disabled")
            if old.get("emails") != new.get("emails"):
                verdict.note("high", "security contact email recipients changed")

        return verdict
