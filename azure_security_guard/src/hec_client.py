from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

import requests


@dataclass
class HecClient:
    url: str
    token: str

    def send(self, event: Dict[str, Any]) -> None:
        headers = {"Authorization": f"Splunk {self.token}"}
        response = requests.post(self.url, headers=headers, json=event, timeout=30)
        response.raise_for_status()


def build_hec_envelope(event: Dict[str, Any], hostname: str, epoch_seconds: int) -> Dict[str, Any]:
    return {
        "sourcetype": "azure_security_guard",
        "source": "azure-security-guard",
        "host": hostname,
        "time": epoch_seconds,
        "event": json.loads(json.dumps(event)),
    }
