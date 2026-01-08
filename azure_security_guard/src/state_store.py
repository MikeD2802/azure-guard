from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class LocalStateStore:
    base_dir: Path

    def __post_init__(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        (self.base_dir / "snapshots").mkdir(parents=True, exist_ok=True)
        (self.base_dir / "checkpoints").mkdir(parents=True, exist_ok=True)

    def _snapshot_path(self, resource_id: str) -> Path:
        digest = hashlib.sha256(resource_id.encode("utf-8")).hexdigest()
        return self.base_dir / "snapshots" / f"{digest}.json"

    def get_snapshot(self, resource_id: str) -> Optional[Dict[str, Any]]:
        path = self._snapshot_path(resource_id)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def save_snapshot(self, resource_id: str, state: Dict[str, Any]) -> None:
        path = self._snapshot_path(resource_id)
        path.write_text(json.dumps(state, indent=2, sort_keys=True))

    def get_checkpoint(self, subscription_id: str) -> Optional[str]:
        path = self.base_dir / "checkpoints" / f"{subscription_id}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        return data.get("last_successful_poll_utc")

    def save_checkpoint(self, subscription_id: str, timestamp_utc: datetime) -> None:
        path = self.base_dir / "checkpoints" / f"{subscription_id}.json"
        payload = {"last_successful_poll_utc": timestamp_utc.isoformat().replace("+00:00", "Z")}
        path.write_text(json.dumps(payload, indent=2, sort_keys=True))


@dataclass
class BlobStateStore:
    connection_string: str

    def get_snapshot(self, resource_id: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("BlobStateStore is not implemented yet.")

    def save_snapshot(self, resource_id: str, state: Dict[str, Any]) -> None:
        raise NotImplementedError("BlobStateStore is not implemented yet.")

    def get_checkpoint(self, subscription_id: str) -> Optional[str]:
        raise NotImplementedError("BlobStateStore is not implemented yet.")

    def save_checkpoint(self, subscription_id: str, timestamp_utc: datetime) -> None:
        raise NotImplementedError("BlobStateStore is not implemented yet.")
