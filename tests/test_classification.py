"""The core promise: a suppressive change must outrank a cosmetic one."""

import pytest
from conftest import FakeCredential, RecordingLogger, change_between, make_item

from src.diff import diff_snapshots
from src.monitors.activity_export_monitor import ActivityExportMonitor
from src.monitors.alerting_monitor import AlertingMonitor
from src.monitors.defender_monitor import DefenderMonitor
from src.monitors.entraid_monitor import EntraIdMonitor
from src.monitors.policy_monitor import PolicyMonitor
from src.monitors.rbac_monitor import RBACMonitor
from src.monitors.sentinel_monitor import SentinelMonitor
from src.severity import SEVERITY_ORDER


def build(monitor_cls, config=None):
    return monitor_cls(
        config=config or {}, credential=FakeCredential(), logger=RecordingLogger(), verbose=False
    )


def verdict_for(monitor_cls, old, new, **item_kwargs):
    monitor = build(monitor_cls)
    return monitor.classify(change_between(monitor, old, new, **item_kwargs))


def deletion_verdict(monitor_cls, data, **item_kwargs):
    monitor = build(monitor_cls)
    change = diff_snapshots([make_item("obj", **{**item_kwargs, **data})], [])[0]
    return monitor.classify(change)


def creation_verdict(monitor_cls, data, **item_kwargs):
    monitor = build(monitor_cls)
    change = diff_snapshots([], [make_item("obj", **{**item_kwargs, **data})])[0]
    return monitor.classify(change)


# ----------------------------------------------------------------- Sentinel
def test_disabling_an_alert_rule_is_critical_suppression():
    v = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "enabled": True},
        {"label": "alertRule", "enabled": False},
    )
    assert v.severity == "critical"
    assert v.suppression


def test_renaming_an_alert_rule_is_not_suppression():
    v = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "enabled": True, "displayName": "Old"},
        {"label": "alertRule", "enabled": True, "displayName": "New"},
    )
    assert v.severity == "medium"
    assert not v.suppression


def test_cosmetic_change_ranks_below_disabling():
    disabled = verdict_for(
        SentinelMonitor, {"label": "alertRule", "enabled": True}, {"label": "alertRule", "enabled": False}
    )
    renamed = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "enabled": True, "displayName": "a"},
        {"label": "alertRule", "enabled": True, "displayName": "b"},
    )
    assert SEVERITY_ORDER[disabled.severity] > SEVERITY_ORDER[renamed.severity]


def test_lowering_rule_severity_is_flagged():
    v = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "severity": "High"},
        {"label": "alertRule", "severity": "Low"},
    )
    assert v.severity == "high"
    assert v.suppression


def test_raising_trigger_threshold_is_flagged():
    v = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "triggerThreshold": 1},
        {"label": "alertRule", "triggerThreshold": 500},
    )
    assert v.severity == "high"


def test_lowering_trigger_threshold_is_not_suppression():
    v = verdict_for(
        SentinelMonitor,
        {"label": "alertRule", "triggerThreshold": 500},
        {"label": "alertRule", "triggerThreshold": 1},
    )
    assert not v.suppression


def test_automation_rule_that_auto_closes_incidents_is_critical():
    v = verdict_for(
        SentinelMonitor,
        {"label": "automationRule", "actions": []},
        {"label": "automationRule", "actions": [{"actionConfiguration": {"status": "Closed"}}]},
    )
    assert v.severity == "critical"


def test_new_auto_closing_automation_rule_is_critical():
    v = creation_verdict(
        SentinelMonitor,
        {"label": "automationRule", "actions": [{"actionConfiguration": {"status": "Closed"}}]},
    )
    assert v.severity == "critical"


def test_deleting_an_alert_rule_is_critical():
    assert deletion_verdict(SentinelMonitor, {"label": "alertRule"}).severity == "critical"


# --------------------------------------------------------- Activity export
def test_deleting_a_diagnostic_setting_is_critical():
    assert deletion_verdict(ActivityExportMonitor, {"logs": []}).severity == "critical"


def test_removing_a_log_destination_is_critical():
    v = verdict_for(
        ActivityExportMonitor,
        {"storageAccountId": "/subscriptions/x/sa", "logs": []},
        {"storageAccountId": None, "logs": []},
    )
    assert v.severity == "critical"


def test_disabling_a_log_category_is_critical():
    v = verdict_for(
        ActivityExportMonitor,
        {"logs": [{"category": "Administrative", "enabled": True, "retention": 90}]},
        {"logs": [{"category": "Administrative", "enabled": False, "retention": 90}]},
    )
    assert v.severity == "critical"
    assert "Administrative" in v.reasons[-1]


def test_reducing_retention_is_high_not_critical():
    v = verdict_for(
        ActivityExportMonitor,
        {"logs": [{"category": "Administrative", "enabled": True, "retention": 365}]},
        {"logs": [{"category": "Administrative", "enabled": True, "retention": 1}]},
    )
    assert v.severity == "high"


def test_increasing_retention_is_not_suppression():
    v = verdict_for(
        ActivityExportMonitor,
        {"logs": [{"category": "Administrative", "enabled": True, "retention": 30}]},
        {"logs": [{"category": "Administrative", "enabled": True, "retention": 365}]},
    )
    assert not v.suppression


# ----------------------------------------------------------------- Defender
def test_downgrading_defender_to_free_is_critical():
    v = verdict_for(
        DefenderMonitor,
        {"kind": "pricing", "pricingTier": "Standard"},
        {"kind": "pricing", "pricingTier": "Free"},
    )
    assert v.severity == "critical"
    assert v.suppression


def test_upgrading_defender_is_not_critical():
    v = verdict_for(
        DefenderMonitor,
        {"kind": "pricing", "pricingTier": "Free"},
        {"kind": "pricing", "pricingTier": "Standard"},
    )
    assert v.severity == "high"


def test_disabling_alert_notifications_is_critical():
    v = verdict_for(
        DefenderMonitor,
        {"kind": "securityContact", "alertNotifications": {"state": "On"}},
        {"kind": "securityContact", "alertNotifications": {"state": "Off"}},
    )
    assert v.severity == "critical"


def test_disabling_auto_provisioning_is_high():
    v = verdict_for(
        DefenderMonitor,
        {"kind": "autoProvisioning", "autoProvision": "On"},
        {"kind": "autoProvisioning", "autoProvision": "Off"},
    )
    assert v.severity == "high"


# ----------------------------------------------------------------- Entra ID
def test_disabling_a_conditional_access_policy_is_critical():
    v = verdict_for(
        EntraIdMonitor, {"state": "enabled"}, {"state": "disabled"}, type="conditionalAccessPolicy"
    )
    assert v.severity == "critical"


def test_report_only_mode_counts_as_weakening():
    v = verdict_for(
        EntraIdMonitor,
        {"state": "enabled"},
        {"state": "enabledForReportingButNotEnforced"},
        type="conditionalAccessPolicy",
    )
    assert v.severity == "critical"


def test_dropping_mfa_grant_control_is_critical():
    v = verdict_for(
        EntraIdMonitor,
        {"state": "enabled", "grantControls": {"builtInControls": ["mfa"]}},
        {"state": "enabled", "grantControls": {"builtInControls": []}},
        type="conditionalAccessPolicy",
    )
    assert v.severity == "critical"
    assert any("weakened" in r for r in v.reasons)


def test_adding_a_grant_control_is_not_weakening():
    v = verdict_for(
        EntraIdMonitor,
        {"state": "enabled", "grantControls": {"builtInControls": ["mfa"]}},
        {"state": "enabled", "grantControls": {"builtInControls": ["mfa", "compliantDevice"]}},
        type="conditionalAccessPolicy",
    )
    assert v.severity == "high"
    assert not any("weakened" in r for r in v.reasons)


def test_marking_a_location_trusted_is_high():
    v = verdict_for(
        EntraIdMonitor, {"isTrusted": False}, {"isTrusted": True}, type="namedLocation"
    )
    assert v.severity == "high"


# --------------------------------------------------------------------- RBAC
def test_assigning_owner_is_high():
    v = creation_verdict(
        RBACMonitor,
        {
            "kind": "roleAssignment",
            "principalType": "User",
            "roleDefinitionId": "/subscriptions/x/providers/Microsoft.Authorization/"
            "roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        },
    )
    assert v.severity == "high"
    assert "Owner" in v.reasons[-1]


def test_assigning_an_unremarkable_role_is_medium():
    v = creation_verdict(
        RBACMonitor,
        {"kind": "roleAssignment", "principalType": "User", "roleDefinitionId": "/x/roleDefinitions/reader"},
    )
    assert v.severity == "medium"


def test_custom_role_gaining_diagnostic_delete_is_high():
    v = verdict_for(
        RBACMonitor,
        {"kind": "roleDefinition", "permissions": [{"actions": ["Microsoft.Insights/read"]}]},
        {
            "kind": "roleDefinition",
            "permissions": [{"actions": ["Microsoft.Insights/diagnosticSettings/delete"]}],
        },
    )
    assert v.severity == "high"
    assert v.suppression


# ------------------------------------------------------------------- Policy
def test_policy_set_to_do_not_enforce_is_critical():
    v = verdict_for(
        PolicyMonitor,
        {"kind": "policyAssignment", "enforcementMode": "Default"},
        {"kind": "policyAssignment", "enforcementMode": "DoNotEnforce"},
    )
    assert v.severity == "critical"


def test_new_policy_exemption_is_high():
    v = creation_verdict(PolicyMonitor, {"kind": "policyExemption"})
    assert v.severity == "high"


def test_excluding_a_scope_from_policy_is_high():
    v = verdict_for(
        PolicyMonitor,
        {"kind": "policyAssignment", "notScopes": []},
        {"kind": "policyAssignment", "notScopes": ["/subscriptions/x/rg/prod"]},
    )
    assert v.severity == "high"


# ----------------------------------------------------------------- Alerting
def test_disabling_an_action_group_is_critical():
    v = verdict_for(
        AlertingMonitor, {"kind": "actionGroup", "enabled": True}, {"kind": "actionGroup", "enabled": False}
    )
    assert v.severity == "critical"


def test_emptying_action_group_recipients_is_critical():
    v = verdict_for(
        AlertingMonitor,
        {"kind": "actionGroup", "enabled": True, "emailReceivers": [{"name": "soc"}]},
        {"kind": "actionGroup", "enabled": True, "emailReceivers": []},
    )
    assert v.severity == "critical"
    assert "emailReceivers" in v.reasons[-1]


@pytest.mark.parametrize("monitor_cls", [
    ActivityExportMonitor, AlertingMonitor, DefenderMonitor,
    EntraIdMonitor, PolicyMonitor, RBACMonitor, SentinelMonitor,
])
def test_every_monitor_classifies_without_error_on_sparse_data(monitor_cls):
    """Classification must survive fields the API did not return."""
    assert verdict_for(monitor_cls, {"a": 1}, {"a": 2}).severity in SEVERITY_ORDER
    assert deletion_verdict(monitor_cls, {}).severity in SEVERITY_ORDER
    assert creation_verdict(monitor_cls, {}).severity in SEVERITY_ORDER
