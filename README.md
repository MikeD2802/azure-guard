# Azure Security Guard

`azure-security-guard` detects **detection-suppression** and telemetry-weakening changes across Microsoft Azure and Entra ID: the class of change an intruder with privileges makes to stop being seen. Disabling a Sentinel analytics rule, dropping Defender for Cloud to the Free tier, deleting the diagnostic setting that ships activity logs off-box, flipping a Conditional Access policy to report-only, or adding an automation rule that auto-closes incidents.

It captures a baseline on first run, polls on an interval, diffs current state against the stored baseline, classifies each change by how much detection it removes, and emits normalized JSON-line audit events.

## What it does differently

**Every change is scored, not just reported.** Renaming an alert rule and disabling one are both changes; only one is an attack signal. Each monitor maps concrete transitions onto a severity and a `suppressionIndicator` flag:

| Transition | Severity |
| --- | --- |
| Sentinel rule / data connector deleted or disabled | `critical` |
| Diagnostic setting deleted, or its log destination removed | `critical` |
| Log category disabled | `critical` |
| Defender plan `Standard` → `Free` | `critical` |
| Conditional Access policy disabled, or MFA grant control dropped | `critical` |
| Policy assignment set to `DoNotEnforce` | `critical` |
| Action group disabled, or all its recipients removed | `critical` |
| Automation rule that auto-closes incidents | `critical` |
| Alert rule severity lowered, trigger threshold raised, query rewritten | `high` |
| Log retention reduced | `high` |
| Named location marked trusted | `high` |
| Custom role gains diagnostic-settings write/delete | `high` |
| Display names, tactics, descriptions | `low` |

**The tool's own state is treated as a target.** Deleting `.state/` would otherwise silently re-baseline every monitor and make an intruder's change the new normal. A manifest records which monitors have been baselined and the hash of each snapshot, so a baseline that is missing, edited, or corrupt raises a `critical` `BaselineReset` event instead of being accepted as a first run.

**A partial read can never look like a deletion.** Collection is per scope. If one subscription or workspace fails, its previous baseline is carried forward untouched and only the scopes actually re-read are diffed.

## Architecture

```
azure-security-guard.py     thin entry point
src/
  cli.py                    argument parsing, config, the polling loop
  scopes.py                 OAuth scope constants (no SDK import)
  credentials.py            DefaultAzureCredential construction
  diff.py                   normalization, stable hashing, change detection
  severity.py               Verdict type and transition helpers
  logger.py                 rotating JSONL audit log + Fluency forwarding
  state_manager.py          atomic baselines, manifest, integrity checks
  monitors/
    base.py                 HTTP, pagination, retry, classification hook
    activity_export_monitor.py   diagnostic settings (subscription, Entra, resources)
    sentinel_monitor.py          alert rules, automation rules, data connectors
    defender_monitor.py          pricing tiers, auto-provisioning, security contacts
    entraid_monitor.py           Conditional Access, named locations, auth methods
    rbac_monitor.py              role assignments, custom role definitions
    policy_monitor.py            policy assignments and exemptions
    alerting_monitor.py          activity log alerts, action groups
```

## Setup

```
pip install -r requirements.txt
cp config.example.yaml config.yaml   # then edit
python azure-security-guard.py --config config.yaml --once --verbose
```

Python 3.10 or newer.

### Authentication

Uses `DefaultAzureCredential` — Managed Identity, or a service principal via `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`.

### Required permissions

At subscription scope (Reader covers most of this):

- `Microsoft.Insights/diagnosticSettings/read`
- `Microsoft.Insights/activityLogAlerts/read`
- `Microsoft.Insights/actionGroups/read`
- `Microsoft.Security/pricings/read`
- `Microsoft.Security/autoProvisioningSettings/read`
- `Microsoft.Security/securityContacts/read`
- `Microsoft.SecurityInsights/*/read`
- `Microsoft.OperationsManagement/solutions/read` (Sentinel workspace discovery)
- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleDefinitions/read`
- `Microsoft.Authorization/policyAssignments/read`
- `Microsoft.Authorization/policyExemptions/read`

Microsoft Graph application permissions:

- `Policy.Read.All`
- `Policy.Read.ConditionalAccess`
- `Policy.Read.AuthenticationMethod`

Entra ID tenant diagnostic settings additionally need reader access at tenant scope; set `monitor_entra_diagnostics: false` if that is not granted.

## Configuration

See `config.example.yaml` for the annotated reference. CLI flags override config values, and `${VAR}` references anywhere in the file are expanded from the environment, so API keys stay out of the file.

Configuration is validated at startup and the process exits `2` on error — an unknown monitor name is rejected rather than silently skipped.

### CLI

```
python azure-security-guard.py --config config.yaml            # poll forever
python azure-security-guard.py --config config.yaml --once     # single cycle
python azure-security-guard.py --list-monitors                 # valid monitor names
```

Exit codes: `0` clean shutdown (including `SIGTERM`/`SIGINT`), `2` configuration or startup error.

## Event format

JSON lines, one event per change:

- `eventTime`, `eventSource`, `eventCategory`, `eventProvider`, `eventName`, `monitor`
- `tenantId`, `subscriptionId`, `scope`, `resourceType`, `resourceId`, `resourceName`
- `changeType` — `Created`, `Updated`, `Deleted`, or `BaselineReset`
- `severity` — `info` | `low` | `medium` | `high` | `critical`
- `suppressionIndicator` — true when the change reduces detection or telemetry
- `severityReasons` — plain-language reasons the severity was assigned
- `changedFields`, `baselineHash`, `currentHash`
- `raw.old`, `raw.new`

Alerting on `suppressionIndicator == true` gives the high-signal stream; `severity` orders it.

The audit log rotates at 50 MB, keeping five files. When Fluency forwarding is enabled, an event that fails to POST is spooled to `<log_file>.spool` and retried at the start of the next cycle, so a brief outage does not lose it.

## Operational notes

- **Baselines drift forward.** After a change is reported, current state becomes the new baseline. Each change alerts once rather than on every cycle; act on events as they arrive.
- **Run it somewhere the monitored tenant cannot edit.** The state directory and audit log are themselves suppression targets. Integrity checks catch tampering, but only forwarding events off-box makes them durable.

## Testing

```
pip install -r requirements-dev.txt
pytest
ruff check .
```

94 tests cover diff normalization, baseline integrity, pagination and retry behaviour, per-scope failure isolation, and the severity classification table for every monitor. No Azure credentials are required — all provider responses are mocked.
