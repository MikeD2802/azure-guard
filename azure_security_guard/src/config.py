from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclasses.dataclass
class OutputConfig:
    fluency_hec_url: Optional[str] = None
    fluency_hec_token: Optional[str] = None
    eventhub_connection_string: Optional[str] = None
    eventhub_name: Optional[str] = None


@dataclasses.dataclass
class MonitorConfig:
    enable_defender_pricings: bool = False
    enable_sentinel_rules: bool = False


@dataclasses.dataclass
class AppConfig:
    poll_interval_seconds: int = 300
    subscriptions: List[str] = dataclasses.field(default_factory=list)
    state_dir: Path = Path("state")
    output: OutputConfig = dataclasses.field(default_factory=OutputConfig)
    monitors: MonitorConfig = dataclasses.field(default_factory=MonitorConfig)

    @staticmethod
    def _env_bool(value: Optional[str]) -> bool:
        if value is None:
            return False
        return value.lower() in {"1", "true", "yes", "on"}

    @classmethod
    def from_env(cls) -> "AppConfig":
        subscriptions = os.getenv("AZURE_SUBSCRIPTIONS", "")
        subscription_list = [s.strip() for s in subscriptions.split(",") if s.strip()]
        return cls(
            poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "300")),
            subscriptions=subscription_list,
            state_dir=Path(os.getenv("STATE_DIR", "state")),
            output=OutputConfig(
                fluency_hec_url=os.getenv("FLUENCY_HEC_URL"),
                fluency_hec_token=os.getenv("FLUENCY_HEC_TOKEN"),
                eventhub_connection_string=os.getenv("EVENTHUB_CONNECTION_STRING"),
                eventhub_name=os.getenv("EVENTHUB_NAME"),
            ),
            monitors=MonitorConfig(
                enable_defender_pricings=cls._env_bool(os.getenv("ENABLE_DEFENDER_PRICINGS")),
                enable_sentinel_rules=cls._env_bool(os.getenv("ENABLE_SENTINEL_RULES")),
            ),
        )

    @classmethod
    def from_yaml(cls, path: Path) -> "AppConfig":
        data: Dict[str, Any] = {}
        if path.exists():
            data = yaml.safe_load(path.read_text()) or {}
        output = data.get("output", {})
        monitors = data.get("monitors", {})
        return cls(
            poll_interval_seconds=int(data.get("poll_interval_seconds", 300)),
            subscriptions=list(data.get("subscriptions", [])),
            state_dir=Path(data.get("state_dir", "state")),
            output=OutputConfig(
                fluency_hec_url=output.get("fluency_hec_url"),
                fluency_hec_token=output.get("fluency_hec_token"),
                eventhub_connection_string=output.get("eventhub_connection_string"),
                eventhub_name=output.get("eventhub_name"),
            ),
            monitors=MonitorConfig(
                enable_defender_pricings=bool(monitors.get("enable_defender_pricings", False)),
                enable_sentinel_rules=bool(monitors.get("enable_sentinel_rules", False)),
            ),
        )

    @classmethod
    def load(cls) -> "AppConfig":
        config_path = os.getenv("CONFIG_PATH")
        if config_path:
            return cls.from_yaml(Path(config_path))
        return cls.from_env()
