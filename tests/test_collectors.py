"""Collectors turn provider payloads into comparable items."""
from unittest import mock

from conftest import FakeCredential, RecordingLogger

from src.monitors.activity_export_monitor import ActivityExportMonitor
from src.monitors.defender_monitor import DefenderMonitor
from src.monitors.sentinel_monitor import SentinelMonitor

CONFIG = {"tenant_id": "t", "subscriptions": ["sub-1"], "monitor_entra_diagnostics": False}


def build(cls, config=None):
    return cls(config=config or CONFIG, credential=FakeCredential(), logger=RecordingLogger())


def test_diagnostic_settings_are_flattened():
    payload = [
        {
            "id": "/subscriptions/sub-1/.../ds1",
            "name": "ds1",
            "type": "Microsoft.Insights/diagnosticSettings",
            "properties": {
                "storageAccountId": "/sa",
                "logs": [
                    {"category": "Administrative", "enabled": True, "retentionPolicy": {"days": 90}}
                ],
                "metrics": [],
            },
        }
    ]
    monitor = build(ActivityExportMonitor)
    with mock.patch.object(monitor, "_arm_paged", return_value=payload):
        items = monitor.collect()
    assert len(items) == 1
    assert items[0]["scope"] == "/subscriptions/sub-1"
    assert items[0]["subscriptionId"] == "sub-1"
    assert items[0]["data"]["logs"] == [
        {"category": "Administrative", "categoryGroup": None, "enabled": True, "retention": 90}
    ]


def test_entra_diagnostics_collected_when_enabled():
    monitor = build(ActivityExportMonitor, {**CONFIG, "monitor_entra_diagnostics": True})
    with mock.patch.object(monitor, "_arm_paged", return_value=[]):
        monitor.collect()
    assert "/providers/microsoft.aadiam" in monitor.covered_scopes


def test_one_failing_subscription_does_not_stop_the_others():
    monitor = build(DefenderMonitor, {**CONFIG, "subscriptions": ["good", "bad"]})

    def fake(url, params=None):
        if "/subscriptions/bad/" in url:
            raise RuntimeError("403")
        return [{"id": f"{url}/x", "name": "x", "properties": {"pricingTier": "Standard"}}]

    with mock.patch.object(monitor, "_arm_paged", side_effect=fake):
        items = monitor.collect()

    assert monitor.covered_scopes == {"/subscriptions/good"}
    assert monitor.failed_scopes == {"/subscriptions/bad"}
    assert items and all(i["subscriptionId"] == "good" for i in items)


def test_sentinel_discovery_selects_only_onboarded_workspaces():
    solutions = [
        {"name": "SecurityInsights(ws-a)", "properties": {"workspaceResourceId": "/ws/a"}},
        {"name": "Updates(ws-b)", "properties": {"workspaceResourceId": "/ws/b"}},
    ]
    monitor = build(SentinelMonitor)
    with mock.patch.object(monitor, "_arm_paged", return_value=solutions):
        assert monitor._discover_workspaces() == ["/ws/a"]


def test_sentinel_captures_automation_rule_actions():
    entries = [
        {
            "id": "/ws/a/automationRules/r1",
            "name": "r1",
            "type": "Microsoft.SecurityInsights/automationRules",
            "properties": {"actions": [{"actionConfiguration": {"status": "Closed"}}]},
        }
    ]
    monitor = build(SentinelMonitor, {**CONFIG, "sentinel_workspaces": ["/ws/a"]})
    with mock.patch.object(monitor, "_arm_paged", return_value=entries):
        items = monitor.collect()
    automation = [i for i in items if i["data"]["label"] == "automationRule"]
    assert automation[0]["data"]["actions"] == [{"actionConfiguration": {"status": "Closed"}}]


def test_subscription_is_parsed_from_a_workspace_resource_id():
    assert SentinelMonitor._subscription_from_id("/subscriptions/abc/resourceGroups/rg") == "abc"
    assert SentinelMonitor._subscription_from_id("/nothing/here") is None
