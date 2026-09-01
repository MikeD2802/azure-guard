from __future__ import annotations

from typing import Any

from src.monitors.base import MonitorBase
from src.severity import Verdict, get_path, transition

STRONG_CONTROLS = {"mfa", "compliantdevice", "domainjoineddevice", "passwordchange"}


class EntraIdMonitor(MonitorBase):
    name = "entraid_monitor"
    event_category = "EntraId"
    event_provider = "MicrosoftGraph"

    def collect(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        items.extend(
            self.collect_scope(
                "tenant:conditionalAccess", "Conditional Access policies", self._collect_policies
            )
        )
        items.extend(
            self.collect_scope("tenant:namedLocations", "named locations", self._collect_locations)
        )
        items.extend(
            self.collect_scope(
                "tenant:authenticationMethods",
                "authentication methods policy",
                self._collect_auth_policy,
            )
        )
        return items

    def _collect_policies(self) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        collected = []
        for policy in self._graph_paged(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        ):
            collected.append(
                {
                    "id": f"conditionalAccessPolicy:{policy.get('id')}",
                    "name": policy.get("displayName"),
                    "type": "conditionalAccessPolicy",
                    "scope": "tenant:conditionalAccess",
                    "subscriptionId": None,
                    "tenantId": tenant_id,
                    "data": {
                        "displayName": policy.get("displayName"),
                        "state": policy.get("state"),
                        "conditions": policy.get("conditions"),
                        "grantControls": policy.get("grantControls"),
                        "sessionControls": policy.get("sessionControls"),
                    },
                }
            )
        return collected

    def _collect_locations(self) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        collected = []
        for location in self._graph_paged(
            "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        ):
            collected.append(
                {
                    "id": f"namedLocation:{location.get('id')}",
                    "name": location.get("displayName"),
                    "type": "namedLocation",
                    "scope": "tenant:namedLocations",
                    "subscriptionId": None,
                    "tenantId": tenant_id,
                    "data": {
                        "isTrusted": location.get("isTrusted"),
                        "ipRanges": location.get("ipRanges"),
                        "countriesAndRegions": location.get("countriesAndRegions"),
                        "includeUnknownCountriesAndRegions": location.get(
                            "includeUnknownCountriesAndRegions"
                        ),
                    },
                }
            )
        return collected

    def _collect_auth_policy(self) -> list[dict[str, Any]]:
        tenant_id = self.config.get("tenant_id")
        auth_policy = self._graph_get(
            "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        )
        return [
            {
                "id": "authenticationMethodsPolicy",
                "name": auth_policy.get("id", "authenticationMethodsPolicy"),
                "type": "authenticationMethodsPolicy",
                "scope": "tenant:authenticationMethods",
                "subscriptionId": None,
                "tenantId": tenant_id,
                "data": {
                    "policyVersion": auth_policy.get("policyVersion"),
                    "authenticationMethodsPolicy": auth_policy.get(
                        "authenticationMethodConfigurations"
                    ),
                    "policyState": auth_policy.get("state"),
                },
            }
        ]

    # ------------------------------------------------------------------
    def classify(self, change: dict[str, Any]) -> Verdict:
        verdict = super().classify(change)
        old = get_path(change.get("old") or {}, "data") or {}
        new = get_path(change.get("new") or {}, "data") or {}
        item_type = (change.get("new") or change.get("old") or {}).get("type")
        change_type = change["changeType"]

        if change_type == "Deleted":
            if item_type == "conditionalAccessPolicy":
                verdict.note("critical", "Conditional Access policy deleted")
            return verdict

        if change_type == "Created":
            if item_type == "namedLocation" and new.get("isTrusted") is True:
                verdict.note("high", "new trusted named location created")
            return verdict

        if item_type == "conditionalAccessPolicy":
            old_state, new_state = transition(old, new, "state")
            if _policy_weakened(old_state, new_state):
                verdict.note("critical", f"Conditional Access policy state {old_state} -> {new_state}")
            if _controls_weakened(old, new):
                verdict.note("critical", "Conditional Access grant controls weakened")
            elif old.get("grantControls") != new.get("grantControls"):
                verdict.note("high", "Conditional Access grant controls changed")
            if old.get("conditions") != new.get("conditions"):
                verdict.note("high", "Conditional Access conditions changed, scope may have narrowed")
            if old.get("sessionControls") != new.get("sessionControls"):
                verdict.note("medium", "Conditional Access session controls changed")

        if item_type == "namedLocation":
            if old.get("isTrusted") is not True and new.get("isTrusted") is True:
                verdict.note("high", "named location marked trusted, bypassing location conditions")
            if old.get("ipRanges") != new.get("ipRanges"):
                severity = "high" if new.get("isTrusted") else "medium"
                verdict.note(severity, "named location IP ranges changed")

        if item_type == "authenticationMethodsPolicy":
            verdict.note("high", "tenant authentication methods policy changed")

        return verdict


def _policy_weakened(old_state: Any, new_state: Any) -> bool:
    enforced = "enabled"
    return str(old_state).lower() == enforced and str(new_state).lower() != enforced


def _controls_weakened(old: dict[str, Any], new: dict[str, Any]) -> bool:
    """True when a strong grant control (MFA, compliant device) was dropped."""
    old_controls = _controls(old)
    new_controls = _controls(new)
    return bool((old_controls & STRONG_CONTROLS) - new_controls)


def _controls(data: dict[str, Any]) -> set[str]:
    grant = data.get("grantControls") or {}
    if not isinstance(grant, dict):
        return set()
    controls = grant.get("builtInControls") or []
    return {str(control).lower() for control in controls if control}
