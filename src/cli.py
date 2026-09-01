from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.credentials import get_credential
from src.diff import diff_snapshots
from src.logger import AuditLogger
from src.monitors.activity_export_monitor import ActivityExportMonitor
from src.monitors.alerting_monitor import AlertingMonitor
from src.monitors.defender_monitor import DefenderMonitor
from src.monitors.entraid_monitor import EntraIdMonitor
from src.monitors.policy_monitor import PolicyMonitor
from src.monitors.rbac_monitor import RBACMonitor
from src.monitors.sentinel_monitor import SentinelMonitor
from src.state_manager import SnapshotStatus, StateManager

AVAILABLE_MONITORS = {
    "activity_export_monitor": ActivityExportMonitor,
    "sentinel_monitor": SentinelMonitor,
    "defender_monitor": DefenderMonitor,
    "entraid_monitor": EntraIdMonitor,
    "rbac_monitor": RBACMonitor,
    "policy_monitor": PolicyMonitor,
    "alerting_monitor": AlertingMonitor,
}

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

# Baselines that vanished or no longer match their recorded hash are reported
# rather than silently accepted, since the state directory is itself a target.
BASELINE_ALERTS = {
    SnapshotStatus.MISSING: (
        "critical",
        "baseline snapshot is missing for a monitor that was previously baselined",
    ),
    SnapshotStatus.TAMPERED: ("critical", "baseline snapshot does not match its recorded hash"),
    SnapshotStatus.CORRUPT: ("high", "baseline snapshot could not be parsed"),
}


class Shutdown:
    """Cooperative stop so a SIGTERM cannot land mid-snapshot-write."""

    def __init__(self) -> None:
        self.event = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._handle)
            except (ValueError, OSError):
                pass

    def _handle(self, signum, _frame) -> None:
        self.event.set()

    @property
    def requested(self) -> bool:
        return self.event.is_set()

    def wait(self, seconds: float) -> None:
        self.event.wait(seconds)


def expand_env(value: Any) -> Any:
    """Expand ``${VAR}`` references so secrets can live outside the config."""
    if isinstance(value, str):
        def replace(match: re.Match) -> str:
            name = match.group(1)
            resolved = os.environ.get(name)
            if resolved is None:
                raise KeyError(f"Config references ${{{name}}} but it is not set in the environment")
            return resolved

        return ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {key: expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [expand_env(item) for item in value]
    return value


def load_config(path: str | None) -> dict:
    if not path:
        return {}
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    if config_path.suffix in {".yaml", ".yml"}:
        loaded = yaml.safe_load(config_path.read_text()) or {}
    else:
        loaded = json.loads(config_path.read_text())
    if not isinstance(loaded, dict):
        raise ValueError("Config root must be a mapping")
    return expand_env(loaded)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
    parser.add_argument(
        "--list-monitors", action="store_true", help="Print available monitor names and exit"
    )
    parser.add_argument("--fluency-enabled", action="store_true")
    parser.add_argument("--fluency-url")
    parser.add_argument("--fluency-api-key")
    parser.add_argument("--fluency-verify-tls", type=str)
    parser.add_argument("--fluency-timeout-seconds", type=int)
    return parser.parse_args(argv)


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

    fluency = dict(loaded.get("fluency") or {})
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
    config.setdefault("diagnostic_scopes", [])
    config.setdefault("enabled_monitors", [])
    config.setdefault("tenant_id", None)
    config.setdefault("rbac_scopes", [])
    return config


def validate_config(config: dict) -> list[str]:
    """Return human-readable configuration errors.

    Unknown monitor names used to be dropped silently, so a typo meant that
    monitor simply never ran and nothing said so.
    """
    errors: list[str] = []
    unknown = [name for name in config.get("enabled_monitors") or [] if name not in AVAILABLE_MONITORS]
    if unknown:
        errors.append(
            f"Unknown monitor(s): {', '.join(sorted(unknown))}. "
            f"Available: {', '.join(sorted(AVAILABLE_MONITORS))}"
        )
    if not config.get("subscriptions") and not config.get("sentinel_workspaces"):
        enabled = config.get("enabled_monitors") or list(AVAILABLE_MONITORS)
        if any(name != "entraid_monitor" for name in enabled):
            errors.append("No subscriptions configured; Azure monitors would collect nothing")
    interval = config.get("interval_seconds")
    if not isinstance(interval, int) or interval <= 0:
        errors.append(f"interval_seconds must be a positive integer, got {interval!r}")
    fluency = config.get("fluency") or {}
    if fluency.get("enabled") and not (fluency.get("url") and fluency.get("api_key")):
        errors.append("Fluency forwarding is enabled but url and api_key are not both set")
    if fluency.get("enabled") and fluency.get("verify_tls") is False:
        errors.append("Fluency verify_tls is disabled; refusing to forward events over unverified TLS")
    return errors


def get_enabled_monitors(config: dict) -> dict:
    enabled = config.get("enabled_monitors") or list(AVAILABLE_MONITORS)
    return {name: AVAILABLE_MONITORS[name] for name in enabled if name in AVAILABLE_MONITORS}


def baseline_event(monitor_name: str, status: str, severity: str, reason: str) -> dict[str, Any]:
    return {
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "eventSource": "azure-security-guard",
        "eventCategory": "GuardIntegrity",
        "eventProvider": "azure-security-guard",
        "eventName": f"{monitor_name}:BaselineReset",
        "monitor": monitor_name,
        "changeType": "BaselineReset",
        "severity": severity,
        "suppressionIndicator": True,
        "severityReasons": [reason],
        "baselineStatus": status,
        "changedFields": [],
        "raw": {"old": None, "new": None},
    }


def partition_baseline(
    baseline: list[dict[str, Any]], covered: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split a baseline into the parts this cycle actually re-read, and the rest.

    Objects from a scope that failed to collect are carried forward untouched;
    diffing against a short read would report every one of them as deleted.
    """
    comparable = [item for item in baseline if item.get("scope") in covered]
    retained = [item for item in baseline if item.get("scope") not in covered]
    return comparable, retained


def run_once(config: dict, credential, logger: AuditLogger, state: StateManager, verbose: bool) -> None:
    logger.flush_spool()
    for name, monitor_cls in get_enabled_monitors(config).items():
        monitor = monitor_cls(config=config, credential=credential, logger=logger, verbose=verbose)
        try:
            current_items = monitor.collect()
        except Exception as exc:  # noqa: BLE001
            logger.error(f"Monitor {name} failed: {exc}")
            continue

        if monitor.failed_scopes and not monitor.covered_scopes:
            logger.error(f"Monitor {name}: every scope failed to collect; skipping this cycle")
            continue

        snapshot, status = state.load_snapshot(name)

        if status in BASELINE_ALERTS:
            severity, reason = BASELINE_ALERTS[status]
            logger.log_event(baseline_event(name, status, severity, reason))

        if snapshot is None:
            state.save_snapshot(name, current_items)
            logger.info(f"Baseline snapshot saved for {name}: {len(current_items)} items")
            continue

        comparable, retained = partition_baseline(snapshot, monitor.covered_scopes)
        if retained:
            logger.warning(
                f"Monitor {name}: carrying forward {len(retained)} baseline item(s) "
                f"from {len(monitor.failed_scopes)} uncollected scope(s)"
            )

        changes = diff_snapshots(comparable, current_items, warn=logger.warning)
        for change in changes:
            logger.log_event(monitor.build_event(change))

        state.save_snapshot(name, retained + current_items)
        logger.info(f"{name}: {len(changes)} change(s) detected")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.list_monitors:
        for name in sorted(AVAILABLE_MONITORS):
            print(name)
        return 0

    try:
        loaded = load_config(args.config)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to load config: {exc}", file=sys.stderr)
        return 2

    config = build_config(args, loaded)
    errors = validate_config(config)
    if errors:
        for error in errors:
            print(f"Config error: {error}", file=sys.stderr)
        return 2

    logger = AuditLogger(
        log_file=config["log_file"],
        fluency=config.get("fluency", {}),
        verbose=args.verbose,
    )

    try:
        credential = get_credential()
        state = StateManager(config["state_dir"])
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to initialise: {exc}", file=sys.stderr)
        return 2

    shutdown = Shutdown()
    interval = config["interval_seconds"]
    while not shutdown.requested:
        run_once(config, credential, logger, state, args.verbose)
        if args.once:
            break
        shutdown.wait(interval)

    if shutdown.requested and not args.once:
        logger.info("Shutting down on signal")
    return 0
