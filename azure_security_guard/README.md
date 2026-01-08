# azure-security-guard

`azure-security-guard` polls Azure control-plane Activity Logs and emits fact-only JSON change events to Fluency (Splunk HEC-compatible) and optionally to Azure Event Hub. It stores local snapshots of resource state for before/after diffs.

## Features

- Uses Azure Activity Logs as the authoritative signal for control-plane changes.
- Fetches current resource state for diagnostic settings, Event Hub resources, and RBAC role assignments.
- Emits fact-only events with before/after snapshots and JSON-pointer-like diffs.
- Persists checkpoints per subscription to avoid reprocessing.

## Requirements

- Python 3.10+
- Azure credentials available for `DefaultAzureCredential`.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Configure with environment variables or a YAML file.

### Environment variables

- `AZURE_SUBSCRIPTIONS` (required): comma-separated subscription IDs.
- `POLL_INTERVAL_SECONDS` (optional, default `300`).
- `STATE_DIR` (optional, default `state`).
- `CONFIG_PATH` (optional): if set, load YAML config instead of env.
- `AZURE_TENANT_ID` (optional): included in emitted events.

**Fluency HEC output** (optional):
- `FLUENCY_HEC_URL`
- `FLUENCY_HEC_TOKEN`

**Event Hub output** (optional):
- `EVENTHUB_CONNECTION_STRING`
- `EVENTHUB_NAME`

**Optional monitors**:
- `ENABLE_DEFENDER_PRICINGS` (default `false`)
- `ENABLE_SENTINEL_RULES` (default `false`)

### YAML config example

```yaml
poll_interval_seconds: 300
subscriptions:
  - "00000000-0000-0000-0000-000000000000"
state_dir: state
output:
  fluency_hec_url: "https://example.com:8088/services/collector"
  fluency_hec_token: "your-token"
  eventhub_connection_string: "Endpoint=sb://..."
  eventhub_name: "guard-events"
monitors:
  enable_defender_pricings: false
  enable_sentinel_rules: false
```

Run:

```bash
python -m azure_security_guard.src.main
```

## Event payload

Events are emitted with a Splunk HEC-compatible envelope containing `ChangeEvent`:

```json
{
  "event_version": "1.0",
  "event_type": "AZURE_CONTROL_PLANE_CHANGE",
  "detected_at_utc": "...",
  "tenant_id": "...",
  "subscription_id": "...",
  "activity_log": {
    "event_timestamp_utc": "...",
    "operation_name": "...",
    "status": "...",
    "caller": "...",
    "correlation_id": "...",
    "resource_id": "...",
    "resource_group": "...",
    "category": "Administrative|Policy|Security|Alert"
  },
  "target": {
    "provider": "...",
    "resource_type": "...",
    "resource_id": "...",
    "resource_name": "..."
  },
  "change": {
    "change_kind": "WRITE|DELETE|CREATE",
    "before_state": { },
    "after_state": { },
    "diff": [
      {"path": "/properties/logs/0/enabled", "before": true, "after": false}
    ]
  },
  "guard_meta": {
    "run_id": "run-...",
    "monitor": "diagnostic_settings|eventhub|rbac|defender_pricings|sentinel_rules",
    "checkpoint_from_utc": "...",
    "checkpoint_to_utc": "...",
    "fetch_error": "..."
  }
}
```

## Permissions

At minimum, the identity should have:

- Reader on target subscriptions.
- Permission to read diagnostic settings.
- Permission to read Event Hub namespaces and authorization rules.
- Permission to read RBAC role assignments.
- (Optional) permission to read Defender pricing objects.
- (Optional) permission to read Sentinel alert/automation rules.

If a read fails, the guard emits the activity log facts and includes a `fetch_error` value.
