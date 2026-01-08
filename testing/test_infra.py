import os
from unittest import mock

import pytest

from src.diff import diff_snapshots
from src.monitors.sentinel_monitor import SentinelMonitor


class DummyLogger:
    def info(self, message: str) -> None:
        return None


class DummyCredential:
    def get_token(self, scope):
        class Token:
            token = "dummy"

        return Token()


@pytest.mark.skipif(os.getenv("AZURE_TEST_REAL") != "1", reason="real Azure tests disabled")
def test_optional_real_sentinel_rule_creation():
    credential = DummyCredential()
    logger = DummyLogger()
    config = {
        "tenant_id": os.getenv("AZURE_TENANT_ID"),
        "sentinel_workspaces": [os.getenv("AZURE_SENTINEL_WORKSPACE", "")],
    }
    monitor = SentinelMonitor(config=config, credential=credential, logger=logger, verbose=False)
    with mock.patch.object(monitor, "_arm_get", return_value={"value": []}):
        items = monitor.collect()
    assert items == []


def test_mocked_sentinel_diff_detects_change():
    old = [
        {
            "id": "rule-1",
            "name": "rule-1",
            "type": "alertRule",
            "scope": "workspace",
            "subscriptionId": "sub",
            "tenantId": "tenant",
            "data": {"enabled": True, "severity": "High"},
        }
    ]
    new = [
        {
            "id": "rule-1",
            "name": "rule-1",
            "type": "alertRule",
            "scope": "workspace",
            "subscriptionId": "sub",
            "tenantId": "tenant",
            "data": {"enabled": False, "severity": "High"},
        }
    ]
    changes = diff_snapshots(old, new)
    assert changes[0]["changeType"] == "Updated"
    assert "enabled" in changes[0]["changedFields"][0]
