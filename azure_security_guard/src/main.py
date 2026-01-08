from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from azure.identity import DefaultAzureCredential

from azure_security_guard.src.activity_log import ActivityLogClient, ActivityLogEvent
from azure_security_guard.src.arm_client import ArmClient
from azure_security_guard.src.config import AppConfig
from azure_security_guard.src.diff import build_diff
from azure_security_guard.src.eventhub_client import EventHubClient
from azure_security_guard.src.hec_client import HecClient, build_hec_envelope
from azure_security_guard.src.monitors.defender_pricings import DefenderPricingsMonitor
from azure_security_guard.src.monitors.diagnostic_settings import DiagnosticSettingsMonitor
from azure_security_guard.src.monitors.eventhub import EventHubMonitor
from azure_security_guard.src.monitors.rbac import RbacMonitor
from azure_security_guard.src.monitors.sentinel_rules import SentinelRulesMonitor
from azure_security_guard.src.state_store import LocalStateStore


logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("azure-security-guard")


@dataclass
class MonitorResult:
    monitor_name: str
    after_state: Optional[Dict[str, Any]]
    fetch_error: Optional[str]


def parse_target(resource_id: str) -> Dict[str, str]:
    parts = resource_id.strip("/").split("/")
    provider = ""
    resource_type = ""
    resource_name = ""
    if "providers" in parts:
        idx = parts.index("providers")
        if idx + 1 < len(parts):
            provider = parts[idx + 1]
            remaining = parts[idx + 2 :]
            if len(remaining) >= 2:
                resource_type = "/".join(remaining[0::2])
                resource_name = "/".join(remaining[1::2])
    return {
        "provider": provider,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "resource_name": resource_name,
    }


def change_kind(operation_name: str) -> str:
    op = operation_name.lower()
    if "/delete" in op:
        return "DELETE"
    if "/write" in op:
        return "WRITE"
    if "/create" in op:
        return "CREATE"
    return "WRITE"


def build_activity_log_section(event: ActivityLogEvent) -> Dict[str, str]:
    return {
        "event_timestamp_utc": event.event_timestamp,
        "operation_name": event.operation_name,
        "status": event.status,
        "caller": event.caller,
        "correlation_id": event.correlation_id,
        "resource_id": event.resource_id,
        "resource_group": event.resource_group,
        "category": event.category,
    }


def build_change_event(
    tenant_id: str,
    subscription_id: str,
    activity_event: ActivityLogEvent,
    before_state: Optional[Dict[str, Any]],
    monitor_result: MonitorResult,
    checkpoint_from: datetime,
    checkpoint_to: datetime,
    run_id: str,
) -> Dict[str, Any]:
    after_state = monitor_result.after_state
    diff = []
    if before_state is not None or after_state is not None:
        diff = build_diff(before_state, after_state)
    return {
        "event_version": "1.0",
        "event_type": "AZURE_CONTROL_PLANE_CHANGE",
        "detected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tenant_id": tenant_id,
        "subscription_id": subscription_id,
        "activity_log": build_activity_log_section(activity_event),
        "target": parse_target(activity_event.resource_id),
        "change": {
            "change_kind": change_kind(activity_event.operation_name),
            "before_state": before_state,
            "after_state": after_state,
            "diff": diff,
        },
        "guard_meta": {
            "run_id": run_id,
            "monitor": monitor_result.monitor_name,
            "checkpoint_from_utc": checkpoint_from.isoformat().replace("+00:00", "Z"),
            "checkpoint_to_utc": checkpoint_to.isoformat().replace("+00:00", "Z"),
            "fetch_error": monitor_result.fetch_error,
        },
    }


def select_monitor(event: ActivityLogEvent, monitors: Iterable[Any]) -> Optional[Any]:
    for monitor in monitors:
        if monitor.matches(event):
            return monitor
    return None


def fetch_after_state(
    monitor: Any,
    event: ActivityLogEvent,
    arm: ArmClient,
) -> MonitorResult:
    try:
        after_state = monitor.fetch_after_state(event, arm)
        if after_state is None and change_kind(event.operation_name) != "DELETE":
            return MonitorResult(monitor.name, None, "after_state_unavailable")
        return MonitorResult(monitor.name, after_state, None)
    except requests.HTTPError as exc:
        return MonitorResult(monitor.name, None, f"http_error: {exc}")
    except requests.RequestException as exc:
        return MonitorResult(monitor.name, None, f"request_error: {exc}")


def emit_event(
    event: Dict[str, Any],
    hec_client: Optional[HecClient],
    eventhub_client: Optional[EventHubClient],
) -> None:
    if hec_client:
        envelope = build_hec_envelope(
            event,
            hostname=socket.gethostname(),
            epoch_seconds=int(time.time()),
        )
        hec_client.send(envelope)
    if eventhub_client:
        eventhub_client.send(event)
    LOGGER.info("Emitted change event: %s", json.dumps(event))


def monitor_subscription(
    subscription_id: str,
    tenant_id: str,
    config: AppConfig,
    state_store: LocalStateStore,
    activity_client: ActivityLogClient,
    arm: ArmClient,
    hec_client: Optional[HecClient],
    eventhub_client: Optional[EventHubClient],
    monitors: List[Any],
    run_id: str,
) -> None:
    now = datetime.now(timezone.utc)
    last_checkpoint = state_store.get_checkpoint(subscription_id)
    if last_checkpoint:
        start_time = datetime.fromisoformat(last_checkpoint.replace("Z", "+00:00"))
    else:
        start_time = now - timedelta(seconds=config.poll_interval_seconds)
    events = activity_client.list_events(subscription_id, start_time, now)
    for event in events:
        monitor = select_monitor(event, monitors)
        if not monitor:
            continue
        before_state = state_store.get_snapshot(event.resource_id)
        monitor_result = fetch_after_state(monitor, event, arm)
        change_event = build_change_event(
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            activity_event=event,
            before_state=before_state,
            monitor_result=monitor_result,
            checkpoint_from=start_time,
            checkpoint_to=now,
            run_id=run_id,
        )
        emit_event(change_event, hec_client, eventhub_client)
        if monitor_result.after_state is not None:
            state_store.save_snapshot(event.resource_id, monitor_result.after_state)
    state_store.save_checkpoint(subscription_id, now)


def build_monitors(config: AppConfig) -> List[Any]:
    monitors: List[Any] = [
        DiagnosticSettingsMonitor(),
        EventHubMonitor(),
        RbacMonitor(),
    ]
    if config.monitors.enable_defender_pricings:
        monitors.append(DefenderPricingsMonitor())
    if config.monitors.enable_sentinel_rules:
        monitors.append(SentinelRulesMonitor())
    return monitors


def run() -> None:
    config = AppConfig.load()
    if not config.subscriptions:
        raise SystemExit("No subscriptions configured. Set AZURE_SUBSCRIPTIONS or CONFIG_PATH.")
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    session = requests.Session()
    activity_client = ActivityLogClient(credential=credential, session=session)
    arm_client = ArmClient(credential=credential, session=session)
    state_store = LocalStateStore(config.state_dir)
    hec_client = None
    if config.output.fluency_hec_url and config.output.fluency_hec_token:
        hec_client = HecClient(config.output.fluency_hec_url, config.output.fluency_hec_token)
    eventhub_client = None
    if config.output.eventhub_connection_string and config.output.eventhub_name:
        eventhub_client = EventHubClient(
            config.output.eventhub_connection_string,
            config.output.eventhub_name,
        )
    monitors = build_monitors(config)
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    run_id = f"run-{int(time.time())}"
    while True:
        for subscription_id in config.subscriptions:
            monitor_subscription(
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                config=config,
                state_store=state_store,
                activity_client=activity_client,
                arm=arm_client,
                hec_client=hec_client,
                eventhub_client=eventhub_client,
                monitors=monitors,
                run_id=run_id,
            )
        time.sleep(config.poll_interval_seconds)


if __name__ == "__main__":
    run()
