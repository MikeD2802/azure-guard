from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from typing import Any

import requests

from src.diff import normalize_item
from src.scopes import ARM_SCOPE, GRAPH_SCOPE
from src.severity import Verdict

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
MAX_BACKOFF_SECONDS = 60


class MonitorBase:
    name = "base"
    event_category = "DetectionSuppression"
    event_provider = "Azure"
    event_source = "azure-security-guard"

    def __init__(self, config: dict, credential, logger, verbose: bool = False) -> None:
        self.config = config
        self.credential = credential
        self.logger = logger
        self.verbose = verbose
        # Scopes whose objects were read in full this cycle, and those that
        # failed. Only covered scopes may be diffed -- see collect_scope.
        self.covered_scopes: set[str] = set()
        self.failed_scopes: set[str] = set()

    def collect(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    def classify(self, change: dict[str, Any]) -> Verdict:
        """Map a change onto a severity and a suppression flag.

        Subclasses call ``super().classify(change)`` for this baseline and then
        escalate on the transitions that actually weaken detection. Without an
        override every change of a class scores the same, which is what made
        renaming a rule indistinguishable from disabling one.
        """
        change_type = change["changeType"]
        if change_type == "Deleted":
            return Verdict().note("high", "monitored object was deleted")
        if change_type == "Created":
            return Verdict().note("low", "new object appeared", suppression=False)
        fields = ", ".join(change.get("changedFields", [])) or "unknown fields"
        return Verdict().note("medium", f"fields changed: {fields}", suppression=False)

    def build_event(self, change: dict[str, Any]) -> dict[str, Any]:
        new_item = change.get("new")
        old_item = change.get("old")
        item = new_item or old_item or {}
        raw_old = None
        raw_new = None
        if change["changeType"] == "Updated":
            raw_old = normalize_item(old_item["data"]) if old_item else None
            raw_new = normalize_item(new_item["data"]) if new_item else None
        elif change["changeType"] == "Deleted":
            raw_old = normalize_item(old_item["data"]) if old_item else None
        elif change["changeType"] == "Created":
            raw_new = normalize_item(new_item["data"]) if new_item else None

        verdict = self.classify(change)

        return {
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "eventSource": self.event_source,
            "eventCategory": self.event_category,
            "eventProvider": self.event_provider,
            "eventName": f"{self.name}:{change['changeType']}",
            "monitor": self.name,
            "tenantId": item.get("tenantId"),
            "subscriptionId": item.get("subscriptionId"),
            "scope": item.get("scope"),
            "resourceType": item.get("type"),
            "resourceId": item.get("id"),
            "resourceName": item.get("name"),
            "changeType": change["changeType"],
            "severity": verdict.severity,
            "suppressionIndicator": verdict.suppression,
            "severityReasons": verdict.reasons,
            "changedFields": change.get("changedFields", []),
            "baselineHash": change.get("baselineHash"),
            "currentHash": change.get("currentHash"),
            "raw": {
                "old": raw_old,
                "new": raw_new,
            },
        }

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    @staticmethod
    def _retry_delay(response: requests.Response, attempt: int) -> float:
        """Honour Retry-After when the service sends it, else back off."""
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(float(header), MAX_BACKOFF_SECONDS)
            except ValueError:
                pass
        return min(2**attempt + random.uniform(0, 1), MAX_BACKOFF_SECONDS)

    def _request(
        self,
        method: str,
        url: str,
        scope: str = ARM_SCOPE,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        max_retries: int = 5,
    ) -> dict[str, Any]:
        token = self.credential.get_token(scope).token
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if headers:
            request_headers.update(headers)

        attempts = max(1, max_retries)
        response: requests.Response | None = None
        for attempt in range(attempts):
            response = requests.request(
                method,
                url,
                headers=request_headers,
                params=params,
                json=json_body,
                timeout=30,
            )
            if response.status_code < 400:
                return response.json() if response.content else {}
            if response.status_code in RETRYABLE_STATUS and attempt < attempts - 1:
                delay = self._retry_delay(response, attempt)
                if self.verbose:
                    self.logger.info(
                        f"Retrying {url} in {delay:.1f}s after HTTP {response.status_code}"
                    )
                time.sleep(delay)
                continue
            break

        assert response is not None
        response.raise_for_status()
        return {}

    def _arm_get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.verbose:
            self.logger.info(f"ARM GET {url}")
        return self._request("GET", url, scope=ARM_SCOPE, params=params)

    def _arm_paged(self, url: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Follow ARM ``nextLink`` pagination.

        Reading only the first page made every object beyond it look deleted on
        the next cycle, so large scopes produced a stream of false alerts.
        """
        items: list[dict[str, Any]] = []
        data = self._arm_get(url, params=params)
        items.extend(data.get("value", []))
        next_url = data.get("nextLink") or data.get("@odata.nextLink")
        seen: set[str] = set()
        while next_url and next_url not in seen:
            seen.add(next_url)
            # nextLink already carries api-version and continuation state.
            data = self._arm_get(next_url)
            items.extend(data.get("value", []))
            next_url = data.get("nextLink") or data.get("@odata.nextLink")
        return items

    def _graph_get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.verbose:
            self.logger.info(f"Graph GET {url}")
        return self._request("GET", url, scope=GRAPH_SCOPE, params=params)

    def _graph_paged(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url = url
        seen: set[str] = set()
        while next_url and next_url not in seen:
            seen.add(next_url)
            data = self._graph_get(next_url)
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
        return items

    def collect_scope(self, scope: str, description: str, func, *args, **kwargs) -> list:
        """Collect one scope, isolating its failure from the rest of the cycle.

        A scope is marked covered only when it was read end to end. Anything
        that failed is recorded instead, so the caller can carry the previous
        baseline forward for it rather than diffing against a short read and
        reporting every missing object as deleted.
        """
        try:
            items = func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001
            self.failed_scopes.add(scope)
            self.logger.warning(f"{self.name}: {description} failed for {scope}: {exc}")
            return []
        self.covered_scopes.add(scope)
        return items or []
