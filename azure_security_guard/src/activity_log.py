from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

import requests


@dataclass
class ActivityLogEvent:
    raw: Dict[str, Any]

    @property
    def event_timestamp(self) -> str:
        return self.raw.get("eventTimestamp") or self.raw.get("event_timestamp") or ""

    @property
    def submission_timestamp(self) -> str:
        return self.raw.get("submissionTimestamp") or self.raw.get("submission_timestamp") or ""

    @property
    def operation_name(self) -> str:
        op = self.raw.get("operationName") or {}
        if isinstance(op, dict):
            return op.get("value") or op.get("localizedValue") or ""
        return self.raw.get("operationNameValue") or str(op)

    @property
    def status(self) -> str:
        status = self.raw.get("status") or {}
        if isinstance(status, dict):
            return status.get("value") or status.get("localizedValue") or ""
        return str(status)

    @property
    def caller(self) -> str:
        return self.raw.get("caller") or ""

    @property
    def correlation_id(self) -> str:
        return self.raw.get("correlationId") or ""

    @property
    def resource_id(self) -> str:
        return self.raw.get("resourceId") or ""

    @property
    def resource_group(self) -> str:
        return self.raw.get("resourceGroupName") or ""

    @property
    def category(self) -> str:
        category = self.raw.get("category") or {}
        if isinstance(category, dict):
            return category.get("value") or category.get("localizedValue") or ""
        return str(category)


@dataclass
class ActivityLogClient:
    credential: Any
    session: requests.Session

    def list_events(
        self,
        subscription_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> List[ActivityLogEvent]:
        token = self.credential.get_token("https://management.azure.com/.default").token
        url = (
            "https://management.azure.com/subscriptions/"
            f"{subscription_id}/providers/microsoft.insights/eventtypes/management/values"
        )
        filter_value = (
            f"eventTimestamp ge '{start_time.isoformat().replace('+00:00', 'Z')}' "
            f"and eventTimestamp le '{end_time.isoformat().replace('+00:00', 'Z')}'"
        )
        params = {"api-version": "2015-04-01", "$filter": filter_value}
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        payload = response.json()
        items = payload.get("value", [])
        return [ActivityLogEvent(item) for item in items]
