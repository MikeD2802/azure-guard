#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path

from src.credentials import get_credential
from src.diff import diff_snapshots
from src.logger import AuditLogger
from src.state_manager import StateManager
from src.monitors.activity_export_monitor import ActivityExportMonitor
from src.monitors.sentinel_monitor import SentinelMonitor
from src.monitors.defender_monitor import DefenderMonitor
from src.monitors.entraid_monitor import EntraIdMonitor
from src.monitors.rbac_monitor import RBACMonitor

import yaml


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if config_path.suffix in {".yaml", ".yml"}:
        return yaml.safe_load(config_path.read_text()) or {}
    return json.loads(config_path.read_text())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Azure Security Guard")
    parser.add_argument("--config", help="Path to YAML or JSON config")
    parser.add_argument("--tenant-id")
    parser.add_argument("--subscriptions")
    parser.add_argument("--sentinel-workspaces")
    parser.add_argument("--enabled-monitors")
    parser.add_argument("--interval-seconds", type=int)
    parser.add_argument("--state-dir")
    parser.add_argument("--log-file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--fluency-enabled", action="store_true")
    parser.add_argument("--fluency-url")
    parser.add_argument("--fluency-api-key")
    parser.add_argument("--fluency-verify-tls", type=str)
    parser.add_argument("--fluency-timeout-seconds", type=int)
    return parser.parse_args()


def merge_config(base: dict, overrides: dict) -> dict:
    config = base.copy()
    config.update({k: v for k, v in overrides.items() if v is not None})
    return config


def parse_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def build_config(args: argparse.Namespace, loaded: dict) -> dict:
    overrides = {
        "tenant_id": args.tenant_id,
        "subscriptions": parse_list(args.subscriptions),
        "sentinel_workspaces": parse_list(args.sentinel_workspaces),
        "enabled_monitors": parse_list(args.enabled_monitors),
        "interval_seconds": args.interval_seconds,
        "state_dir": args.state_dir,
        "log_file": args.log_file,
    }
    config = merge_config(loaded, overrides)

    fluency = loaded.get("fluency", {}).copy() if loaded else {}
    if args.fluency_enabled:
        fluency["enabled"] = True
    if args.fluency_url:
        fluency["url"] = args.fluency_url
    if args.fluency_api_key:
        fluency["api_key"] = args.fluency_api_key
    if args.fluency_verify_tls is not None:
        fluency["verify_tls"] = args.fluency_verify_tls.lower() == "true"
    if args.fluency_timeout_seconds is not None:
        fluency["timeout_seconds"] = args.fluency_timeout_seconds
    config["fluency"] = fluency

    config.setdefault("interval_seconds", 300)
    config.setdefault("state_dir", ".state")
    config.setdefault("log_file", "audit.log")
    config.setdefault("subscriptions", [])
    config.setdefault("sentinel_workspaces", [])
    config.setdefault("enabled_monitors", [])
    config.setdefault("tenant_id", None)
    config.setdefault("rbac_scopes", [])
    return config


def get_enabled_monitors(config: dict) -> dict:
    available = {
        "activity_export_monitor": ActivityExportMonitor,
        "sentinel_monitor": SentinelMonitor,
        "defender_monitor": DefenderMonitor,
        "entraid_monitor": EntraIdMonitor,
        "rbac_monitor": RBACMonitor,
    }
    enabled = config.get("enabled_monitors") or list(available.keys())
    return {name: available[name] for name in enabled if name in available}


def run_once(config: dict, credential, logger: AuditLogger, state: StateManager, verbose: bool) -> None:
    enabled = get_enabled_monitors(config)
    for name, monitor_cls in enabled.items():
        monitor = monitor_cls(config=config, credential=credential, logger=logger, verbose=verbose)
        try:
            current_items = monitor.collect()
            snapshot = state.load_snapshot(name)
            if snapshot is None:
                state.save_snapshot(name, current_items)
                if verbose:
                    logger.info(f"Baseline snapshot saved for {name}: {len(current_items)} items")
                continue

            changes = diff_snapshots(snapshot, current_items)
            for change in changes:
                event = monitor.build_event(change)
                logger.log_event(event)
            state.save_snapshot(name, current_items)
            if verbose:
                logger.info(f"{name}: {len(changes)} changes detected")
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Monitor {name} failed: {exc}")


def main() -> int:
    args = parse_args()
    try:
        loaded = load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to load config: {exc}", file=sys.stderr)
        return 1

    config = build_config(args, loaded)
    credential = get_credential()
    logger = AuditLogger(
        log_file=config["log_file"],
        fluency=config.get("fluency", {}),
        verbose=args.verbose,
    )
    state = StateManager(config["state_dir"])

    interval = config.get("interval_seconds", 300)
    while True:
        run_once(config, credential, logger, state, args.verbose)
        if args.once:
            break
        time.sleep(interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
