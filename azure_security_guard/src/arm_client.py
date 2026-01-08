from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class ArmClient:
    credential: Any
    session: requests.Session

    def get(self, url: str, api_version: str) -> Dict[str, Any]:
        token = self.credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}
        response = self.session.get(url, headers=headers, params={"api-version": api_version}, timeout=30)
        response.raise_for_status()
        return response.json()

    def try_get(self, url: str, api_version: str) -> Optional[Dict[str, Any]]:
        try:
            return self.get(url, api_version)
        except requests.HTTPError:
            return None
