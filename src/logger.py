import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


class AuditLogger:
    def __init__(self, log_file: str, fluency: dict, verbose: bool = False) -> None:
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.fluency = fluency or {}
        self.verbose = verbose
        logging.basicConfig(level=logging.INFO)

    def log_event(self, event: dict[str, Any]) -> None:
        event.setdefault("eventTime", datetime.now(timezone.utc).isoformat())
        self.log_path.open("a", encoding="utf-8").write(json.dumps(event) + "\n")
        if self.fluency.get("enabled"):
            self._post_fluency(event)

    def info(self, message: str) -> None:
        if self.verbose:
            logging.info(message)

    def error(self, message: str) -> None:
        logging.error(message)

    def _post_fluency(self, event: dict[str, Any]) -> None:
        url = self.fluency.get("url")
        api_key = self.fluency.get("api_key")
        if not url or not api_key:
            self.error("Fluency enabled but url/api_key not configured")
            return
        verify_tls = self.fluency.get("verify_tls", True)
        timeout = self.fluency.get("timeout_seconds", 10)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            requests.post(url, json=event, headers=headers, timeout=timeout, verify=verify_tls)
        except requests.RequestException as exc:
            self.error(f"Failed to post to Fluency: {exc}")
