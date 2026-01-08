# Azure Security Guard

`azure-security-guard` detects detection-suppression and telemetry-weakening changes across Microsoft Azure and Entra ID. It captures a baseline snapshot on first run, polls on an interval, diffs current state against the stored snapshot, and emits normalized JSON-line audit events.

## Features

- Baseline snapshot on first run (no alerts)
- Periodic polling with stable diff normalization
- JSON-lines audit log with optional Fluency REST source forwarding
- Independent monitors for Azure, Sentinel, Defender, Entra ID, and RBAC

## Architecture

```
azure-security-guard.py
src/
  credentials.py
  diff.py
  logger.py
  state_manager.py
  monitors/
    base.py
    activity_export_monitor.py
    sentinel_monitor.py
    defender_monitor.py
    entraid_monitor.py
    rbac_monitor.py
```

## Setup

### Dependencies

Install dependencies (Python 3.11 recommended):

```
pip install -r requirements.txt
```

### Authentication

Uses `DefaultAzureCredential`, which supports Managed Identity or Service Principal via environment variables:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_SECRET`

For Entra ID (Graph) access, ensure the service principal has the appropriate Graph permissions.

### Required Azure permissions

Assign the service principal at subscription scope with:

- `Microsoft.Insights/diagnosticSettings/read`
- `Microsoft.Security/pricings/read`
- `Microsoft.Security/autoProvisioningSettings/read`
- `Microsoft.SecurityInsights/*/read`
- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleDefinitions/read`

For Entra ID (Graph), the service principal needs:

- `Policy.Read.All`
- `Policy.Read.ConditionalAccess`
- `Policy.Read.AuthenticationMethod`

## Configuration

Provide YAML or JSON configuration. CLI arguments override config values.

```yaml
tenant_id: "00000000-0000-0000-0000-000000000000"
subscriptions:
  - "11111111-1111-1111-1111-111111111111"
sentinel_workspaces:
  - "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
enabled_monitors:
  - activity_export_monitor
  - sentinel_monitor
  - defender_monitor
  - entraid_monitor
  - rbac_monitor
interval_seconds: 300
state_dir: ".state"
log_file: "audit.log"
rbac_scopes:
  - "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/eh"
  - "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"
fluency:
  enabled: false
  url: "https://example.fluencysecurity.com/api/events"
  api_key: "REDACTED"
  verify_tls: true
  timeout_seconds: 10
```

### CLI

```
python azure-security-guard.py --config config.yaml --verbose
```

Run once:

```
python azure-security-guard.py --config config.yaml --once
```

## Event format

Events are JSON lines with the following keys:

- `eventTime`, `eventSource`, `eventCategory`, `eventProvider`, `eventName`
- `tenantId`, `subscriptionId`, `scope`, `resourceType`, `resourceId`, `resourceName`
- `changeType`, `severity`, `changedFields`, `baselineHash`, `currentHash`
- `raw.old`, `raw.new` for updated items

## Testing

Run unit tests with:

```
pytest
```

`testing/test_infra.py` contains an optional Azure integration stub that can be enabled by setting `AZURE_TEST_REAL=1` and providing environment variables. By default, it uses mocked responses.
