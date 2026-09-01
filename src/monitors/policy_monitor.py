from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, transition

ASSIGNMENT_API_VERSION = "2022-06-01"
EXEMPTION_API_VERSION = "2022-07-01-preview"

ENFORCING_EFFECTS = {"deny", "denyaction", "deployifnotexists", "modify", "append"}


class PolicyMonitor(MonitorBase):
    """Azure Policy assignments and exemptions.

    Policy is a common way to enforce that diagnostic settings and security
    agents exist. Setting an assignment to DoNotEnforce, or exempting a scope,
    disables that enforcement without touching any individual resource.
    """

    name = "policy_monitor"
    event_category = "AzurePolicy"
    event_provider = "Azure.Authorization"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for subscription_id in self.config.get("subscriptions", []):
            scope = f"/subscriptions/{subscription_id}"
            items.extend(
                self.collect_scope(
                    scope,
                    "policy assignments and exemptions",
                    self._collect_subscription,
                    subscription_id,
                )
            )
        return items

    def _collect_subscription(self, subscription_id: str) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        scope = f"/subscriptions/{subscription_id}"
        base = f"https://management.azure.com{scope}/providers/Microsoft.Authorization"
        collected: list[dict[str, Any]] = []

        for assignment in self._arm_paged(
            f"{base}/policyAssignments", params={"api-version": ASSIGNMENT_API_VERSION}
        ):
            props = assignment.get("properties", {}) or {}
            collected.append(
                {
                    "id": assignment.get("id"),
                    "name": assignment.get("name"),
                    "type": assignment.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "policyAssignment",
                        "displayName": props.get("displayName"),
                        "policyDefinitionId": props.get("policyDefinitionId"),
                        "enforcementMode": props.get("enforcementMode"),
                        "notScopes": props.get("notScopes"),
                        "parameters": props.get("parameters"),
                        "overrides": props.get("overrides"),
                    },
                }
            )

        for exemption in self._arm_paged(
            f"{base}/policyExemptions", params={"api-version": EXEMPTION_API_VERSION}
        ):
            props = exemption.get("properties", {}) or {}
            collected.append(
                {
                    "id": exemption.get("id"),
                    "name": exemption.get("name"),
                    "type": exemption.get("type"),
                    "scope": scope,
                    "subscriptionId": subscription_id,
                    "tenantId": tenant_id,
                    "data": {
                        "kind": "policyExemption",
                        "displayName": props.get("displayName"),
                        "policyAssignmentId": props.get("policyAssignmentId"),
                        "exemptionCategory": props.get("exemptionCategory"),
                        "expiresOn": props.get("expiresOn"),
                        "policyDefinitionReferenceIds": props.get("policyDefinitionReferenceIds"),
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

        if kind == "policyExemption":
            if change_type == "Created":
                verdict.note("high", "policy exemption created, enforcement bypassed for a scope")
            elif change_type == "Updated":
                verdict.note("medium", "policy exemption modified")
            return verdict

        if change_type == "Deleted":
            return verdict.note("critical", "policy assignment deleted, its enforcement is gone")

        if change_type == "Created":
            return verdict

        old_mode, new_mode = transition(old, new, "enforcementMode")
        if str(new_mode).lower() == "donotenforce" and str(old_mode).lower() != "donotenforce":
            verdict.note("critical", "policy assignment switched to DoNotEnforce")

        old_not_scopes = set(old.get("notScopes") or [])
        new_not_scopes = set(new.get("notScopes") or [])
        added = new_not_scopes - old_not_scopes
        if added:
            verdict.note("high", f"scopes excluded from policy: {', '.join(sorted(added))}")

        if old.get("overrides") != new.get("overrides"):
            verdict.note("high", "policy overrides changed, effect may be weakened")
        if old.get("parameters") != new.get("parameters"):
            verdict.note("medium", "policy assignment parameters changed")

        return verdict
