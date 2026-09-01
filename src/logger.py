from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

DEFAULT_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5


class AuditLogger:
    """Writes JSON-line audit events and optionally forwards them to Fluency.

    Forwarding is best effort per request, but a failed POST is spooled to disk
    and retried on the next cycle so a brief network outage does not mean the
    alert never reaches the SIEM.
    """

    def __init__(
        self,
        log_file: str,
        fluency: dict,
        verbose: bool = False,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> None:
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.spool_path = self.log_path.with_suffix(self.log_path.suffix + ".spool")
        self.fluency = fluency or {}
        self.verbose = verbose

        logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
        self._log = logging.getLogger("azure-security-guard")

        # Named per destination, and its handlers are replaced rather than
        # reused: a module-wide logger would leave a second AuditLogger in the
        # same process silently writing to the first one's file.
        self._audit = logging.getLogger(f"azure-security-guard.audit.{self.log_path.resolve()}")
        self._audit.propagate = False
        self._audit.setLevel(logging.INFO)
        for existing in list(self._audit.handlers):
            self._audit.removeHandler(existing)
            existing.close()
        handler = logging.handlers.RotatingFileHandler(
            self.log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._audit.addHandler(handler)

    def log_event(self, event: dict[str, Any]) -> None:
        event.setdefault("eventTime", datetime.now(timezone.utc).isoformat())
        self._audit.info(json.dumps(event, ensure_ascii=False))
        if self.fluency.get("enabled"):
            if not self._post_fluency(event):
                self._spool(event)

    def info(self, message: str) -> None:
        if self.verbose:
            self._log.info(message)

    def warning(self, message: str) -> None:
        self._log.warning(message)

    def error(self, message: str) -> None:
        self._log.error(message)

    def _spool(self, event: dict[str, Any]) -> None:
        try:
            with self.spool_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as exc:
            self.error(f"Failed to spool undelivered event: {exc}")

    def flush_spool(self) -> None:
        """Retry previously undeliverable events, oldest first."""
        if not self.fluency.get("enabled") or not self.spool_path.exists():
            return
        try:
            lines = self.spool_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.error(f"Failed to read spool: {exc}")
            return

        remaining: list[str] = []
        for index, line in enumerate(lines):
            if not line.strip():
                continue
            if remaining:
                remaining.append(line)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not self._post_fluency(event):
                remaining.extend(lines[index:])
                break

        try:
            if remaining:
                self.spool_path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                self.spool_path.unlink(missing_ok=True)
            delivered = len(lines) - len(remaining)
            if delivered and self.verbose:
                self.info(f"Flushed {delivered} spooled event(s) to Fluency")
        except OSError as exc:
            self.error(f"Failed to rewrite spool: {exc}")

    def _post_fluency(self, event: dict[str, Any]) -> bool:
        url = self.fluency.get("url")
        api_key = self.fluency.get("api_key")
        if not url or not api_key:
            self.error("Fluency enabled but url/api_key not configured")
            return False
        verify_tls = self.fluency.get("verify_tls", True)
        timeout = self.fluency.get("timeout_seconds", 10)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                url, json=event, headers=headers, timeout=timeout, verify=verify_tls
            )
        except requests.RequestException as exc:
            self.error(f"Failed to post to Fluency: {exc}")
            return False
        if response.status_code >= 400:
            self.error(f"Fluency rejected event with HTTP {response.status_code}")
            return False
        return True
