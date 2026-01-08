import json
from pathlib import Path
from typing import Any


class StateManager:
    def __init__(self, state_dir: str) -> None:
        self.state_path = Path(state_dir)
        self.state_path.mkdir(parents=True, exist_ok=True)

    def _path_for(self, monitor_name: str) -> Path:
        return self.state_path / f"{monitor_name}.json"

    def load_snapshot(self, monitor_name: str) -> list[dict[str, Any]] | None:
        path = self._path_for(monitor_name)
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def save_snapshot(self, monitor_name: str, snapshot: list[dict[str, Any]]) -> None:
        path = self._path_for(monitor_name)
        stable = sorted(snapshot, key=lambda item: item.get("id", ""))
        path.write_text(json.dumps(stable, sort_keys=True, indent=2))
