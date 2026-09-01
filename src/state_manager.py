from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.diff import stable_hash

MANIFEST_NAME = "_manifest.json"


class SnapshotStatus:
    """Why ``load_snapshot`` returned nothing."""

    FIRST_RUN = "FirstRun"
    MISSING = "Missing"
    CORRUPT = "Corrupt"
    TAMPERED = "Tampered"
    OK = "Ok"


class StateManager:
    """Baseline storage for each monitor.

    The state directory is itself a suppression target: deleting it would
    silently re-baseline every monitor and make an attacker's change the new
    normal. A manifest records which monitors have ever been baselined, plus a
    hash of each snapshot, so a removed or edited baseline is reported rather
    than accepted.
    """

    def __init__(self, state_dir: str) -> None:
        self.state_path = Path(state_dir)
        self.state_path.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.state_path / MANIFEST_NAME
        self.manifest = self._load_manifest()

    def _path_for(self, monitor_name: str) -> Path:
        return self.state_path / f"{monitor_name}.json"

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {}
        try:
            data = json.loads(self.manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _atomic_write(path: Path, payload: str) -> None:
        """Write via a temp file in the same directory, then rename.

        ``Path.write_text`` truncates first, so a crash or SIGTERM midway
        through left a half-written baseline that failed to parse on every
        subsequent run.
        """
        handle, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    def load_snapshot(self, monitor_name: str) -> tuple[list[dict[str, Any]] | None, str]:
        """Return ``(snapshot, status)``.

        ``snapshot`` is None whenever the baseline could not be trusted; the
        status distinguishes a genuine first run from a baseline that was
        deleted, corrupted, or modified outside this tool.
        """
        path = self._path_for(monitor_name)
        known = monitor_name in self.manifest

        if not path.exists():
            return None, SnapshotStatus.MISSING if known else SnapshotStatus.FIRST_RUN

        try:
            raw = path.read_text()
            snapshot = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            return None, SnapshotStatus.CORRUPT

        if not isinstance(snapshot, list):
            return None, SnapshotStatus.CORRUPT

        expected = self.manifest.get(monitor_name, {}).get("snapshotHash")
        if expected and stable_hash(snapshot) != expected:
            return None, SnapshotStatus.TAMPERED

        return snapshot, SnapshotStatus.OK

    def save_snapshot(self, monitor_name: str, snapshot: list[dict[str, Any]]) -> None:
        path = self._path_for(monitor_name)
        stable = sorted(snapshot, key=lambda item: item.get("id") or "")
        self._atomic_write(path, json.dumps(stable, sort_keys=True, indent=2))

        entry = self.manifest.get(monitor_name, {})
        entry.update(
            {
                "snapshotHash": stable_hash(stable),
                "itemCount": len(stable),
                "lastSaved": datetime.now(timezone.utc).isoformat(),
            }
        )
        entry.setdefault("firstBaselined", entry["lastSaved"])
        self.manifest[monitor_name] = entry
        self._atomic_write(self.manifest_path, json.dumps(self.manifest, sort_keys=True, indent=2))

    def previously_baselined(self, monitor_name: str) -> bool:
        return monitor_name in self.manifest
