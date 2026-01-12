from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import requests

from src.credentials import ARM_SCOPE, GRAPH_SCOPE
from src.diff import normalize_item


class MonitorBase:
    name = "base"
    event_category = "DetectionSuppression"
    event_provider = "Azure"
    event_source = "azure-security-guard"
    severity = "medium"

    def __init__(self, config: dict, credential, logger, verbose: bool = False) -> None:
        self.config = config
        self.credential = credential
        self.logger = logger
        self.verbose = verbose

    def collect(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def build_event(self, change: dict[str, Any]) -> dict[str, Any]:
        new_item = change.get("new")
        old_item = change.get("old")
        item = new_item or old_item
        raw_old = None
        raw_new = None
        if change["changeType"] == "Updated":
            raw_old = normalize_item(old_item["data"]) if old_item else None
            raw_new = normalize_item(new_item["data"]) if new_item else None
        elif change["changeType"] == "Deleted":
            raw_old = normalize_item(old_item["data"]) if old_item else None
        elif change["changeType"] == "Created":
            raw_new = normalize_item(new_item["data"]) if new_item else None

        return {
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "eventSource": self.event_source,
            "eventCategory": self.event_category,
            "eventProvider": self.event_provider,
            "eventName": f"{self.name}:{change['changeType']}",
            "tenantId": item.get("tenantId"),
            "subscriptionId": item.get("subscriptionId"),
            "scope": item.get("scope"),
            "resourceType": item.get("type"),
            "resourceId": item.get("id"),
            "resourceName": item.get("name"),
            "changeType": change["changeType"],
            "severity": self.severity,
            "changedFields": change.get("changedFields", []),
            "baselineHash": change.get("baselineHash"),
            "currentHash": change.get("currentHash"),
            "raw": {
                "old": raw_old,
                "new": raw_new,
            },
        }

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

        for attempt in range(max_retries):
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
            if response.status_code in {429, 500, 502, 503, 504}:
                backoff = 2**attempt
                if self.verbose:
                    self.logger.info(f"Retrying {url} after {backoff}s due to {response.status_code}")
                time.sleep(backoff)
                continue
            response.raise_for_status()
        response.raise_for_status()

    def _arm_get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.verbose:
            self.logger.info(f"ARM GET {url}")
        return self._request("GET", url, scope=ARM_SCOPE, params=params)

    def _graph_get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.verbose:
            self.logger.info(f"Graph GET {url}")
        return self._request("GET", url, scope=GRAPH_SCOPE, params=params)

    def _graph_paged(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url = url
        while next_url:
            data = self._graph_get(next_url)
            items.extend(data.get("value", []))
            next_url = data.get("@odata.nextLink")
        return items
