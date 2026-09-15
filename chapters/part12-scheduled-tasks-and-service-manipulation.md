---
title: "Scheduled Tasks & Service Manipulation"
part: 12
author: "author-agent"
reviewer: "technical-reviewer-agent"
status: "reviewed"
last_validated: "2026-09-16"
depends_on: []
---

# Part 12 — Scheduled Tasks & Service Manipulation

## Why this part exists

**[CONCEPT]** Scheduled tasks, Windows services, cron jobs, and systemd units all answer the same attacker question — "how do I run again on a schedule, or without a logged-on user, rather than only when someone logs on" — which is a different question from the one Registry Run keys, the startup folder, and shell profile files answer. DEH Part 11 §5.1 groups persistence mechanisms by which of those questions they satisfy; this part owns the "scheduled" and "service/daemon" categories specifically, on both Windows and Linux, and hands the "autostart on logon" category to this book's own Part 13 (Registry, Startup & Alternate Persistence).

This part covers five query patterns: new or modified Task Scheduler tasks and Service Control Manager service installs on Windows (`QC-12-01` through `QC-12-03`), and cron and systemd unit creation on Linux (`QC-12-04`, `QC-12-05`).

Stated once, the explicit boundaries against neighboring parts: Part 11 (Account Creation & Privilege Escalation) owns the account and token side of persistence — a scheduled task or service that runs as a newly created account needs Part 11's pattern for the account-creation half and this part's pattern for the task/service half, not a single merged pattern in either part. Part 13 owns Registry Run keys, the startup folder, and WMI event subscriptions. Part 16 (Lateral Movement via Admin Tools & Remote Services) owns the *use* of a remotely created service to execute code on a peer host, PsExec-style; this part covers the service-creation event itself as a persistence signal regardless of whether the creation originated locally or over the network, and a hunter chasing the remote-execution angle specifically should pair `QC-12-03` below with Part 16's own patterns rather than expecting this part to cover that combination.

Query-language syntax, operator semantics, and backend translation loss are DEH's job, not this book's — see DEH Parts 23–29 and DEH Appendix A5 for the fundamentals any query below assumes. Deciding whether a pattern below is worth graduating from an ad hoc hunt into a standing, versioned detection rule, and scoring that rule's coverage, quality, and accumulated debt once it exists, is DEH Parts 41–43's methodology, applied to this book's own catalog in Part 28 — this part states the hunt and its false-positive driver, not a maturity score.

## 1. Windows: Task Scheduler and Service Control Manager patterns

### QC-12-01 — New scheduled task created with a suspicious action

| Field | Value |
|---|---|
| **Pattern ID** | `QC-12-01` |
| **MITRE** | T1053.005 (Scheduled Task/Job: Scheduled Task) |
| **Behavior** | A new Task Scheduler task is registered whose action launches an executable, script, or LOLBin from a location a legitimate installer would not use. |
| **DEH cross-ref** | DEH Part 11 §5.2 (Windows: services, scheduled tasks, and Registry Run keys) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic KQL |

**[HUNTER]** A mature environment usually already has a standing detection on Event ID 4698 (A scheduled task was created), but it is typically tuned against a known-bad path list and misses a first-time LOLBin combination nobody has written a rule for yet. Run this hunt directly after any host shows another precursor (a suspicious download, a LOLBin invocation) rather than waiting for the standing rule's narrower list to catch up — a freshly registered task deserves the same lineage scrutiny as a freshly spawned process.

**[QUERY]** Targets the Windows Security event log, 4698, as ingested by any SIEM with a standard Sigma Security-log backend.

CONCEPTUAL SAMPLE — field names and thresholds illustrative; validate against your own schema and baseline before use.

```yaml
title: Scheduled task created with a suspicious action path
id: 8f1e2b6a-12ab-4c3d-9e77-000000000001
status: experimental
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4698
    suspicious_path:
        TaskContent|contains:
            - '\Users\Public\'
            - '\AppData\Local\Temp\'
            - '\ProgramData\'
    condition: selection and suspicious_path
level: high
```

Plausible expected result: a match returns one event per registration, with `TaskName` often a random or spoofed-legitimate string (`\Microsoft\Windows\UpdateOrchestrator\Report`) and a `TaskContent` XML blob whose `<Command>` element points into a user-writable directory. This event type is rare enough on most fleets that a 30-day window plausibly returns single digits to low tens of hits fleet-wide, not hundreds — treat that as an illustrative order of magnitude, not a validated count. Interpretation: a hit is consistent with a task staged from a location an attacker, not an installer, would use; it does not by itself distinguish a red-team engagement from a real intrusion.

**[QUERY]** Microsoft Defender for Endpoint advanced hunting via Microsoft Sentinel's Defender XDR connector, `DeviceEvents` table — disambiguated here from the Elastic KQL block shown later in this pattern.

CONCEPTUAL SAMPLE — field/value assumptions illustrative; validate `AdditionalFields` JSON shape against your own tenant.

```kql
DeviceEvents
| where ActionType == "ScheduledTaskCreated"
| extend TaskCommand = tostring(parse_json(AdditionalFields).TaskCommand)
| where TaskCommand has_any ("\\Users\\Public\\", "\\AppData\\Local\\Temp\\", "\\ProgramData\\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, TaskCommand
```

Plausible expected result: one row per task, with `InitiatingProcessAccountName` showing which account registered it — worth checking immediately against expected admin/automation accounts. Interpretation: consistent with a task registered from an interactively driven session rather than a packaged installer, if the initiating account isn't one you'd expect to be touching Task Scheduler.

**[QUERY]** Splunk, Windows Security event log ingestion (Splunk Add-on for Microsoft Windows), `EventCode=4698`.

CONCEPTUAL SAMPLE — regex against `Message` is illustrative; a normalized field extraction may already exist in your environment.

```spl
index=wineventlog EventCode=4698
| rex field=Message "Task Content:(?<task_xml>[\s\S]+)"
| where match(task_xml, "(?i)\\\\Users\\\\Public\\\\|\\\\AppData\\\\Local\\\\Temp\\\\|\\\\ProgramData\\\\")
| table _time, Computer, Task_Name, task_xml
```

Plausible expected result: a handful of rows per week on a well-managed fleet, each with a full task-content XML excerpt in `task_xml`. Interpretation: same as above — a path-based signal that narrows the field for a manual read, not a conclusive verdict.

**[QUERY]** QRadar AQL — note this is AQL, not standard SQL — against a Windows Security Event Log source mapped by the standard Microsoft DSM, filtering Event ID 4698.

CONCEPTUAL SAMPLE — field/table names illustrative; confirm your DSM's actual parsed field names before use.

```sql
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS "Time",
       username, UTF8(payload) AS "Raw Event"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
  AND EVENTID = '4698'
  AND (UTF8(payload) ILIKE '%\Users\Public\%' OR UTF8(payload) ILIKE '%\AppData\Local\Temp\%')
LAST 30 DAYS
```

Plausible expected result: a small raw-event list a hunter reads by hand rather than a pre-parsed field table, since AQL's visibility into the 4698 payload's nested XML depends on how thoroughly the DSM parses it. Interpretation: same signal as above, at a coarser parsing granularity.

**[QUERY]** Google SecOps (Chronicle) YARA-L against the UDM, targeting the `SCHEDULED_TASK_CREATION` event type produced by the standard Windows Event Log parser.

CONCEPTUAL SAMPLE — UDM field paths illustrative; confirm against your own parser's mapping.

```yaral
rule scheduled_task_suspicious_path {
  meta:
    author = "author-agent"
    description = "New scheduled task with an action path outside trusted directories"

  events:
    $task.metadata.event_type = "SCHEDULED_TASK_CREATION"
    $task.target.process.command_line = /(Users\\Public|AppData\\Local\\Temp|ProgramData)/ nocase

  condition:
    $task
}
```

Plausible expected result: one detection per matching task, carrying whatever asset/user context the UDM record has attached. Interpretation: identical signal, YARA-L surface.

**[QUERY]** Elastic Stack — a single-event boolean match, not a sequence, so Elastic KQL is the right surface here per DEH Appendix A5 §8's decision table — over a Windows event log ingested via Winlogbeat or Elastic Defend.

CONCEPTUAL SAMPLE — field names illustrative for a Winlogbeat-shaped index.

```kql
event.code : "4698" and winlog.event_data.TaskContent : (*Users\Public* or *AppData\Local\Temp* or *ProgramData*)
```

Plausible expected result: same shape as the KQL/SPL results above, filtered to Elastic's own field naming. Interpretation: unchanged.

**[FALSE POSITIVE]** Software packagers and RMM/patch-management tools legitimately register scheduled tasks whose action briefly stages a payload in `%TEMP%` before moving it to a permanent install directory — this is the dominant false-positive driver across every implementation above. Exclude by the account named in `SubjectUserName`/`InitiatingProcessAccountName` for your known RMM/patch-management service accounts rather than broadening the path exclusion list, since the path itself is exactly the attacker's own preferred staging ground too.

**[PIVOT]** Pull the process-creation event for the account named as the task's creator in the minutes before registration — a legitimate installer usually has an MSI or signed-installer parent, while an attacker's registration is more often a bare `schtasks.exe /create` invoked from a script host or an already-suspicious PowerShell session. Check whether the same `TaskName` or command reappears on other hosts in a short window, which would point to propagation rather than a single opportunistic foothold.

> **What Would Change My Mind**
> This pattern's "single digits to low tens of hits fleet-wide" claim assumes 4698 stays a genuinely rare event type on your fleet. If a production audit showed a deployment tool registering hundreds of tasks per day as its normal operating mode, the volume assumption behind treating any hit as worth a same-day look would break, and this pattern would need a tuning layer (an allowlist keyed on the registering tool) before it's cheap enough to run daily.

### QC-12-02 — Existing scheduled task's action modified to point at a new target

| Field | Value |
|---|---|
| **Pattern ID** | `QC-12-02` |
| **MITRE** | T1053.005 (Scheduled Task/Job: Scheduled Task) |
| **Behavior** | A previously legitimate scheduled task has its action (`Command`/`Arguments`) changed to point at a different, attacker-controlled target, rather than a brand-new task being created. |
| **DEH cross-ref** | DEH Part 11 §5.2; cf. DEH Appendix A5 §7.4 (investigative-search-before-standing-objects precedent), DEH Part 27 §2–§3 (QRadar multi-object deployment model) |
| **Languages covered** | KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (ES\|QL) — Sigma: `N/A`, see note below |

**[HUNTER]** A new-task rule like `QC-12-01` misses the quieter version of this behavior: an attacker who edits an already-trusted task's action inherits that task's clean history and an analyst's habit of skipping it during triage. Event ID 4702 (A scheduled task was updated) fires for the edit itself, but the event alone doesn't say whether the new action is meaningful or routine maintenance — that requires comparing it against the task's own prior value. Reach for this hunt whenever a task with an elevated run-as identity (SYSTEM, a service account) shows any 4702 activity at all, since the base rate of legitimate manual edits to a SYSTEM-run task is low enough that even one edit is worth a look.

**(Sigma — `N/A`, structurally poor fit, not impossible.)** Flagging "this task's action changed from its own prior value" needs either a stateful diff against a previously stored value or Sigma's narrow-backend-support `temporal_ordered`/`value_count` correlation type. Forcing it through Sigma here would produce a rule only a couple of backends can even execute, presented misleadingly as portable. See the KQL, SPL, and ES\|QL implementations below, each of which has a native previous-value or self-join construct.

**[QUERY]** Microsoft Sentinel, `SecurityEvent` table (Windows Security Events via the AMA connector), comparing each task's current 4702 action against its own immediately preceding value with `prev()` over a `serialize` keyed on `TaskName`.

CONCEPTUAL SAMPLE — XML parsing paths and field names illustrative; validate against your own `EventData` shape.

```kql
SecurityEvent
| where EventID in (4698, 4702)
| extend TaskName = tostring(parse_xml(EventData).UserData.EventXML.TaskName)
| extend TaskAction = tostring(parse_xml(EventData).UserData.EventXML.Actions)
| sort by TaskName asc, TimeGenerated asc
| serialize
| extend PrevAction = prev(TaskAction), PrevTask = prev(TaskName)
| where TaskName == PrevTask and TaskAction != PrevAction
| project TimeGenerated, TaskName, PrevAction, TaskAction, SubjectUserName
```

Plausible expected result: a short list — plausibly zero on most days, given how rarely a SYSTEM-run task's action legitimately changes — with paired `PrevAction`/`TaskAction` values a hunter can eyeball directly. Interpretation: a row here means the task's action genuinely changed between two consecutive observed events; it does not yet say whether the change is malicious.

**[QUERY]** Splunk, comparing each task's action to the value seen on the immediately preceding event for the same `Task_Name` with `streamstats`.

CONCEPTUAL SAMPLE — field names illustrative for a Windows TA-parsed 4698/4702 pair.

```spl
index=wineventlog (EventCode=4698 OR EventCode=4702)
| sort 0 Task_Name, _time
| streamstats current=f window=1 last(Command) as prev_command by Task_Name
| where isnotnull(prev_command) AND prev_command!=Command
| table _time, Task_Name, prev_command, Command, Subject_User_Name
```

Plausible expected result and interpretation: same shape as the KQL block above.

**[QUERY]** QRadar AQL — note this is AQL, not standard SQL — pulled here as the investigative search a hunter runs by hand; a standing previous-value diff needs a QRadar Reference Set storing each task's last-seen action plus a Building Block to compare against it (DEH Part 27 §2–§3's multi-object model), which is a build task, not a single query, per DEH Appendix A5 §7.4's own precedent for this exact situation.

CONCEPTUAL SAMPLE — field/table names illustrative.

```sql
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS "Time",
       username, UTF8(payload) AS "Raw Event"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
  AND EVENTID = '4702'
LAST 7 DAYS
ORDER BY starttime ASC
```

Plausible expected result: every task-update event in the window, unsorted by task and undiffed. Interpretation: this version tells a hunter *that* updates happened, not whether any one of them changed the action meaningfully — the diff step above is manual until the standing objects exist.

**[QUERY]** Google SecOps YARA-L, a two-event multi-variable rule matching a task's creation or an earlier update against a later update for the same task name within a lookback window.

CONCEPTUAL SAMPLE — UDM event-type and field-path names illustrative.

```yaral
rule scheduled_task_action_changed {
  meta:
    description = "A task's action differs between two consecutive UDM events for the same task name"

  events:
    $e1.metadata.event_type = "SCHEDULED_TASK_CREATION" or $e1.metadata.event_type = "SCHEDULED_TASK_UPDATE"
    $e2.metadata.event_type = "SCHEDULED_TASK_UPDATE"
    $e1.target.resource.name = $e2.target.resource.name
    $e1.target.process.command_line != $e2.target.process.command_line
    $e2.metadata.event_timestamp.seconds > $e1.metadata.event_timestamp.seconds

  match:
    $e1.target.resource.name over 30d

  condition:
    $e1 and $e2
}
```

Plausible expected result and interpretation: identical shape to the KQL/SPL versions — a paired before/after action for one task name.

**[QUERY]** Elastic ES\|QL — chosen over EQL because this pattern needs a wide-lookback aggregation across each task's own history rather than an ordered sequence, per §4.2's decision rule — over Winlogbeat-ingested 4698/4702 events.

CONCEPTUAL SAMPLE — field names illustrative; `VALUES()` behavior may vary by Elastic version.

```esql
FROM winlogbeat-*
| WHERE event.code IN ("4698", "4702")
| STATS actions = VALUES(winlog.event_data.Actions) BY winlog.event_data.TaskName
| WHERE MV_COUNT(actions) > 1
```

Plausible expected result: a small table of task names with more than one distinct action string on file within the query's lookback window. Interpretation: `MV_COUNT(actions) > 1` flags a task whose action value genuinely differs across its observed events, not merely a task that was touched more than once — a task updated twice with the same action each time correctly falls out of this filter. ES\|QL's `VALUES()` returns a distinct set, not an ordered pair, so this surface tells you a task changed but not which direction — pull the raw events for that `TaskName` to see the before/after order.

**[FALSE POSITIVE]** Patch-management and configuration-management tools routinely re-register the same scheduled task on every agent check-in, rewriting its action to point at whatever deployment-script version is current — this is structurally identical to an attacker edit and is the dominant false-positive source here. Filter on the task's run-as account or the editor's `SubjectUserName` matching your CM tool's service account, the same exclusion discipline DEH Part 11 §5.3's own False Positive Trap box recommends for cron/systemd tooling churn.

**[PIVOT]** Diff the new `Command`/`Arguments` value against known-LOLBin or known-malicious-path indicators, then check the account named in `SubjectUserName` against your expected list of accounts with rights to edit that specific task — an edit from an account that has never touched Task Scheduler before is a stronger signal than the edit alone.

> **Blind Spot**
> Every diff shown above only has something to diff against if the task's prior action was captured before the edit. A task last modified before your 4698/4702 retention window began, or on a host that only recently started forwarding these events, gives you a single observed action with no earlier value to compare — the first edit you can see might already be the compromised one, and every query above will silently return nothing rather than flag it.

### QC-12-03 — Windows service created via the Service Control Manager pointing outside a trusted binary path

| Field | Value |
|---|---|
| **Pattern ID** | `QC-12-03` |
| **MITRE** | T1543.003 (Create or Modify System Process: Windows Service) |
| **Behavior** | A new Windows service is installed through the Service Control Manager whose binary path, start type, or run-as account is inconsistent with a legitimate install. |
| **DEH cross-ref** | DEH Part 11 §5.2; cf. DEH Part 28 §1.1 (YARA-L unconfirmed schema-field precedent) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), Elastic KQL — YARA-L: `N/A`, see note below |

**[HUNTER]** Event ID 7045 (A service was installed in the system) is one of the lowest-volume, highest-signal events on a Windows fleet — DEH Part 11 §5.2 notes new legitimate service installs are relatively rare compared to routine process activity — which makes this a hunt worth running proactively on a schedule rather than only after another alert points here first. The corresponding Security-log equivalent, Event ID 4697, requires the "Audit Security System Extension" subcategory and carries additional identity context if you have it enabled. The two fields worth anchoring on together are the binary path (user-writable versus `Program Files`/`System32`) and the start type: a service registered demand-start (manual) rather than auto-start is a mild anomaly alone, but combined with an unusual path it looks like a service built for one-off, on-demand attacker execution rather than a real background service.

**[QUERY]** Windows System event log (Service Control Manager provider), Event ID 7045.

CONCEPTUAL SAMPLE — field names illustrative; validate against your own parsed event schema.

```yaml
title: Service installed with a binary path outside trusted directories
id: 8f1e2b6a-12ab-4c3d-9e77-000000000003
status: experimental
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    suspicious_path:
        ImagePath|contains:
            - '\Users\'
            - '\AppData\'
            - '\ProgramData\'
            - '\Temp\'
    trusted_path:
        ImagePath|contains:
            - '\Program Files\'
            - '\Windows\System32\'
    condition: selection and suspicious_path and not trusted_path
level: high
```

Plausible expected result: individually rare hits — a healthy fleet might see this settle to single-digit weekly volume once the false-positive driver below is tuned out. Interpretation: consistent with a service staged for on-demand execution from a non-standard location; not, by itself, proof of malicious intent.

**[QUERY]** Microsoft Defender for Endpoint advanced hunting, `DeviceEvents` table, `ActionType == "ServiceInstalled"` — Sentinel/Defender KQL, disambiguated here from the Elastic KQL block shown later in this pattern.

CONCEPTUAL SAMPLE — `AdditionalFields` shape illustrative; confirm against your own tenant schema.

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| extend ServiceImagePath = tostring(parse_json(AdditionalFields).ImagePath),
         ServiceStartType = tostring(parse_json(AdditionalFields).StartType)
| where ServiceImagePath has_any ("\\Users\\", "\\AppData\\", "\\ProgramData\\", "\\Temp\\")
| project Timestamp, DeviceName, ServiceImagePath, ServiceStartType, InitiatingProcessAccountName
```

Plausible expected result: one row per install with both the path and start type surfaced together, letting you apply the demand-start-plus-unusual-path heuristic directly in the query. Interpretation: same as above, with start type available for immediate triage.

**[QUERY]** Splunk, Windows System event log, `EventCode=7045`.

CONCEPTUAL SAMPLE — field names illustrative for the standard Windows TA field extraction.

```spl
index=wineventlog EventCode=7045
| where match(Service_File_Name, "(?i)\\\\Users\\\\|\\\\AppData\\\\|\\\\ProgramData\\\\|\\\\Temp\\\\")
| table _time, Computer, Service_Name, Service_File_Name, Service_Start_Type, Account_Name
```

Plausible expected result and interpretation: identical shape to the KQL block above.

**[QUERY]** QRadar AQL — note this is AQL, not standard SQL — against the Windows System Event Log source, filtering Event ID 7045.

CONCEPTUAL SAMPLE — field/table names illustrative.

```sql
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS "Time",
       username, UTF8(payload) AS "Raw Event"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Microsoft Windows Security Event Log'
  AND EVENTID = '7045'
  AND (UTF8(payload) ILIKE '%\Users\%' OR UTF8(payload) ILIKE '%\AppData\%' OR UTF8(payload) ILIKE '%\ProgramData\%' OR UTF8(payload) ILIKE '%\Temp\%')
LAST 30 DAYS
```

Plausible expected result: a raw-event list a hunter reads by hand, since start type may or may not be broken out as its own parsed field depending on your DSM. Interpretation: same signal, coarser parsing granularity.

**(YARA-L — `N/A`, missing schema field.)** This pattern's false-positive suppression depends on the service's start-type value (demand-start versus auto-start) to tell a one-off attacker-created service apart from a routinely reinstalled auto-start agent that happens to live in an unusual path. Google SecOps' UDM has no confirmed field equivalent for NT service start type, the same category of gap DEH Part 28 §1.1 documents for `GrantedAccess` — a path-only YARA-L match would misclassify legitimate auto-start agents in custom install directories about as often as it caught a genuine attacker service, so this pattern is marked `N/A` here rather than shipping that misleading version.

**[QUERY]** Elastic Stack — Elastic KQL, not the Sentinel/Defender KQL shown earlier in this pattern — a single-event boolean match, Windows System event log ingested via Winlogbeat.

CONCEPTUAL SAMPLE — field names illustrative for a Winlogbeat-shaped index.

```kql
event.code : "7045" and winlog.event_data.ImagePath : (*\Users\* or *\AppData\* or *\ProgramData\* or *\Temp\*) and not winlog.event_data.ImagePath : (*\Program Files\* or *\Windows\System32\*)
```

Plausible expected result and interpretation: identical shape to the Sigma/KQL/SPL blocks above.

**[FALSE POSITIVE]** Endpoint agents (EDR, backup, vulnerability-scan clients) and self-updating consumer software routinely install a Windows service from a per-user or `ProgramData` vendor directory rather than `Program Files` — this is the largest false-positive driver across every implementation above, more so than the equivalent scheduled-task pattern. Build an allowlist keyed on the `ServiceName`/`ImagePath` prefix for your known agent fleet rather than broadening the trusted-path list, since a broader list just gives an attacker a wider set of paths to imitate.

**[PIVOT]** Pull the process-creation event for `services.exe` spawning the new service's binary on first start — a legitimate service typically has a signed binary and a stable, versioned parent-child relationship across the fleet, while an attacker's service binary is more often unsigned or spawns a LOLBin. Cross-check the installing account against your change-management record for that host.

> **Detection Autopsy — "any service path outside Program Files or System32 is suspicious"**
>
> **The rule:** Fires on every Event ID 7045 whose `ImagePath` doesn't start with `C:\Program Files` or `C:\Windows\System32`.
>
> **Why it shipped:** legitimate, vendor-signed services install into one of those two locations by convention, so excluding them looked like a clean, low-effort way to cut alert volume to just the anomalous cases.
>
> **How it failed:** a large share of endpoint agents, backup clients, and self-updating consumer software install their service binary into `C:\ProgramData\<Vendor>\` or a per-user `AppData` directory by design, not by compromise — on a fleet running even three or four such tools, this rule pages on every routine agent reinstall or version bump.
>
> **The fix:** replace the two-path allowlist with a fleet-specific vendor-path allowlist plus the start-type/account combination described in **[FALSE POSITIVE]** above, and treat "not Program Files or System32" alone as too coarse a signal to page on by itself.

**[SOC MANAGEMENT]** Given how low-volume genuine 7045 events are on most fleets, this hunt is cheap to run daily rather than reserved for a periodic sweep, and it graduates to a standing detection easily once the vendor-path allowlist above stabilizes. Treat a hit on an unrecognized path as worth a same-day look, not a queued ticket — the low-noise property that makes DEH's own SOC Management View recommend near-zero-tolerance handling for Event ID 1102 applies here in a lighter form.

## 2. Linux: cron and systemd patterns

### QC-12-04 — New or modified cron entry outside a recognized change window

| Field | Value |
|---|---|
| **Pattern ID** | `QC-12-04` |
| **MITRE** | T1053.003 (Scheduled Task/Job: Cron) |
| **Behavior** | A crontab entry, `/etc/cron.d` drop-in, or `cron.hourly`/`cron.daily` script is created or modified outside a recognized change-management window. |
| **DEH cross-ref** | DEH Part 11 §5.3 (Linux: cron, systemd, and init) |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic KQL |

**[HUNTER]** Cron has no single authoritative "job created" event the way Windows Task Scheduler has Event ID 4698 — per DEH Part 11 §5.3, most environments reconstruct "a cron entry changed" from file-integrity monitoring on the crontab paths themselves or from auditd watch rules, not from one clean structured record. Reach for this hunt specifically when file-integrity monitoring is the only signal a host has, since that telemetry gap means a standing detection here is often thinner than its Windows-side equivalent, and a manual sweep of recent FIM hits against these specific paths catches drops a coarser "any file changed" rule misses.

**[QUERY]** Linux auditd, watching writes to the standard cron paths.

CONCEPTUAL SAMPLE — path list illustrative; extend to any distribution-specific cron directories in your environment.

```yaml
title: File integrity change on a cron persistence path
id: 8f1e2b6a-12ab-4c3d-9e77-000000000004
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name|contains:
            - '/etc/cron.d/'
            - '/etc/cron.hourly/'
            - '/etc/cron.daily/'
            - '/var/spool/cron/crontabs/'
        nametype:
            - 'CREATE'
            - 'NORMAL'
    condition: selection
level: medium
```

Plausible expected result: a modest daily count dominated by legitimate configuration-management runs (see **[FALSE POSITIVE]** below), with a genuine attacker-authored entry indistinguishable from the rest until a human reads the entry's command. Interpretation: a hit means a cron-relevant path changed; it says nothing yet about intent.

**[QUERY]** Microsoft Defender for Endpoint on Linux, advanced hunting via Sentinel's Defender XDR connector, `DeviceFileEvents` table — Sentinel/Defender KQL, disambiguated here from the Elastic KQL block shown later in this pattern.

CONCEPTUAL SAMPLE — path list illustrative.

```kql
DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/var/spool/cron/crontabs")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
```

Plausible expected result and interpretation: same shape as the Sigma block, with the added benefit of the initiating process's command line for a faster first read.

**[QUERY]** Splunk, Linux auditd ingestion.

CONCEPTUAL SAMPLE — field/sourcetype names illustrative for a standard auditd forwarding pipeline.

```spl
index=linux sourcetype=auditd type=PATH
| where match(name, "(?i)/etc/cron\.(d|hourly|daily)/|/var/spool/cron/crontabs/")
| table _time, host, name, nametype, uid
```

Plausible expected result and interpretation: same shape as above.

**[QUERY]** QRadar AQL — note this is AQL, not standard SQL — against a Linux OS log source parsed by the standard auditd DSM.

CONCEPTUAL SAMPLE — field/table names illustrative.

```sql
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS "Time",
       username, filename, UTF8(payload) AS "Raw Event"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Linux OS'
  AND (filename ILIKE '%cron.d%' OR filename ILIKE '%cron.hourly%' OR filename ILIKE '%cron.daily%' OR filename ILIKE '%crontabs%')
LAST 14 DAYS
```

Plausible expected result and interpretation: same shape, coarser parsing.

**[QUERY]** Google SecOps YARA-L, a UDM file event matching the cron directories.

CONCEPTUAL SAMPLE — UDM field paths illustrative.

```yaral
rule cron_persistence_path_change {
  meta:
    description = "File creation or modification under a standard cron persistence path"

  events:
    $e.metadata.event_type = "FILE_CREATION" or $e.metadata.event_type = "FILE_MODIFICATION"
    $e.target.file.full_path = /(\/etc\/cron\.(d|hourly|daily)\/|\/var\/spool\/cron\/crontabs\/)/ nocase

  condition:
    $e
}
```

Plausible expected result and interpretation: same shape as above.

**[QUERY]** Elastic Stack — Elastic KQL, not the Sentinel/Defender KQL shown earlier in this pattern — a single-event boolean match, Auditbeat or Elastic Defend on the Linux host.

CONCEPTUAL SAMPLE — field names illustrative.

```kql
event.category : "file" and event.action : ("creation" or "modification") and file.path : ("/etc/cron.d/*" or "/etc/cron.hourly/*" or "/etc/cron.daily/*" or "/var/spool/cron/crontabs/*")
```

Plausible expected result and interpretation: same shape as above.

**[FALSE POSITIVE]** Configuration-management tools running in pull mode (Ansible via a cron-triggered pull, Chef, Puppet, Salt) rewrite cron entries and drop-ins on every scheduled run as their normal operating mode — DEH Part 11 §5.3's own False Positive Trap box names this same driver for the broader Linux persistence surface. Exclude by the writing process's UID/service-account identity rather than by path, since the path is exactly what a real cron-based persistence attempt also has to touch.

**[PIVOT]** Read the new or modified entry's actual command line — a base64-decoded payload, a `curl | sh` pipeline, or a reference to a script outside `/opt` or a package-managed location is the next thing to check by hand, since none of the queries above parse cron's own syntax. Check `/var/log/cron` or the journal's `CRON` execution lines once the schedule fires, to confirm what the entry actually ran and whether the outcome matches a legitimate job.

> **Engineering Reality**
> Because cron itself produces no single "entry created" event, every query above depends on file-integrity monitoring or auditd coverage being enabled and retained on the specific paths shown — neither is on by default on most Linux distributions, and log rotation on a busy host can age out the original change event within days. If a query above returns nothing, confirm FIM/auditd is actually watching these paths and still has the relevant window in retention before trusting the empty result as "no change happened."

### QC-12-05 — New systemd unit or timer installed and enabled with an untrusted `ExecStart` target

| Field | Value |
|---|---|
| **Pattern ID** | `QC-12-05` |
| **MITRE** | T1543.002 (Create or Modify System Process: Systemd Service) |
| **Behavior** | A new systemd unit or timer is installed and enabled whose `ExecStart` target resolves outside a package-managed or known-deployment path. |
| **DEH cross-ref** | DEH Part 11 §5.3; cf. DEH DET-11-03 (the ExecStart-path-gated corrected rule) and its accompanying Blind Spot |
| **Languages covered** | Sigma, KQL (Sentinel/Defender), SPL, AQL (QRadar), YARA-L, Elastic (EQL) |

**[HUNTER]** DEH Part 11 §5.3 already dissects why alerting on every new unit *name* fails — ordinary deployment creates new units constantly — and its corrected rule, DET-11-03, gates on the `ExecStart` path's provenance instead. This pattern hunts that corrected shape directly: a unit file appearing under `/etc/systemd/system/` followed by the corresponding `systemctl start`/`daemon-reload` activity, where the `ExecStart` target has no package-manager record. The timer variant of this technique maps to a separate sub-technique, T1053.006 (Scheduled Task/Job: Systemd Timer); the queries below target the unit-install shape common to both services and timers. Run this hunt when a host shows another precursor signal, since a path-gated match still can't distinguish a legitimate one-off script from a malicious one on path alone — see DEH's own Blind Spot for this exact rule on the interpreter-target case.

**[QUERY]** Linux auditd, file creation under the systemd system unit directory — a single-event proxy for the unit-install half of DET-11-03's two-part gate; correlating the subsequent `systemctl start` requires chaining to a second rule or a SOAR playbook, not a single Sigma rule.

CONCEPTUAL SAMPLE — path/extension matching illustrative.

```yaml
title: New systemd unit file created outside expected deployment tooling
id: 8f1e2b6a-12ab-4c3d-9e77-000000000005
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name|contains: '/etc/systemd/system/'
        name|endswith:
            - '.service'
            - '.timer'
        nametype: 'CREATE'
    condition: selection
level: medium
```

Plausible expected result: frequent hits on an actively deployed fleet (see **[FALSE POSITIVE]** below), each naming the new unit file's path. Interpretation: a hit means a unit file was written; it is not yet gated on `ExecStart` provenance the way the corrected DET-11-03 logic requires — treat this as the file-creation half of a two-part check.

**[QUERY]** Microsoft Defender for Endpoint on Linux, joining a new unit-file write to the subsequent `systemctl` process launch within a short window.

CONCEPTUAL SAMPLE — join syntax and field alignment illustrative; validate the resulting column names against your own Sentinel workspace.

```kql
DeviceFileEvents
| where ActionType == "FileCreated" and FolderPath == "/etc/systemd/system" and FileName has_any (".service", ".timer")
| join kind=inner (
    DeviceProcessEvents
    | where FileName == "systemctl" and ProcessCommandLine has_any ("enable", "start", "daemon-reload")
) on DeviceId
| where Timestamp1 >= Timestamp and datetime_diff('minute', Timestamp1, Timestamp) <= 10
| project Timestamp, DeviceName, FileName, InitiatingProcessAccountName, ProcessCommandLine
```

Plausible expected result: a smaller, more precise set than the Sigma block above, since the join requires both halves of the pattern within ten minutes. Interpretation: consistent with a unit being written and immediately activated in one operator session — closer to DET-11-03's full two-part shape, though still not reading the `ExecStart=` line itself.

**[QUERY]** Splunk, correlating a new unit-file write with the subsequent `systemctl` invocation using `transaction`.

CONCEPTUAL SAMPLE — sourcetype and field names illustrative.

```spl
index=linux (sourcetype=auditd path="/etc/systemd/system/*" nametype=CREATE) OR (sourcetype=linux_secure process=systemctl)
| transaction host maxspan=10m startswith="nametype=CREATE" endswith="process=systemctl"
| where mvcount(name)>0 AND match(_raw, "enable|start|daemon-reload")
| table _time, host, name, process
```

Plausible expected result and interpretation: same shape as the KQL block above.

**[QUERY]** QRadar AQL — note this is AQL, not standard SQL — pulled as the investigative half of this pattern: every new unit-file write under the systemd path. Correlating it with the following `systemctl` invocation for the standing version needs a QRadar rule chaining two events within a time window (a Building Block, not a single AQL `SELECT`), the same multi-object shape noted for `QC-12-02`.

CONCEPTUAL SAMPLE — field/table names illustrative.

```sql
SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') AS "Time",
       username, filename, UTF8(payload) AS "Raw Event"
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) = 'Linux OS'
  AND filename ILIKE '/etc/systemd/system/%'
  AND (filename ILIKE '%.service' OR filename ILIKE '%.timer')
LAST 14 DAYS
```

Plausible expected result: every new unit-file write in the window, uncorrelated with the enable/start step. Interpretation: file-creation signal only, same caveat as the Sigma block.

**[QUERY]** Google SecOps YARA-L, a two-event rule matching a unit-file write against a subsequent `systemctl` process launch on the same host.

CONCEPTUAL SAMPLE — UDM field paths and event types illustrative.

```yaral
rule systemd_unit_install_and_enable {
  meta:
    description = "New systemd unit file write followed by a systemctl enable/start on the same asset"

  events:
    $file.metadata.event_type = "FILE_CREATION"
    $file.target.file.full_path = /\/etc\/systemd\/system\/.*\.(service|timer)$/ nocase
    $proc.metadata.event_type = "PROCESS_LAUNCH"
    $proc.target.process.file.full_path = /systemctl$/ nocase
    $proc.target.process.command_line = /enable|start|daemon-reload/ nocase
    $file.target.asset.hostname = $proc.target.asset.hostname
    $proc.metadata.event_timestamp.seconds > $file.metadata.event_timestamp.seconds

  match:
    $file.target.asset.hostname over 10m

  condition:
    $file and $proc
}
```

Plausible expected result and interpretation: same shape as the KQL/SPL joined versions.

**[QUERY]** Elastic EQL, an ordered sequence of a unit-file creation followed by a `systemctl` process launch on the same host — the sequence stage is why EQL, not Elastic KQL, is the right surface for this pattern per §4.2's decision rule.

CONCEPTUAL SAMPLE — field/index assumptions illustrative for an Elastic Defend/Auditbeat-shaped index.

```eql
sequence by host.name with maxspan=10m
  [file where event.action == "creation" and file.path : "/etc/systemd/system/*" and (file.extension == "service" or file.extension == "timer")]
  [process where process.name == "systemctl" and process.args : ("enable", "start", "daemon-reload")]
```

Plausible expected result and interpretation: identical shape to the KQL/SPL/YARA-L joined versions above.

**[FALSE POSITIVE]** Container runtimes and orchestration agents (kubelet, Docker Compose with restart policies) generate transient scope/slice units, and legitimate package upgrades write a new unit version on every release — DEH Part 11 §5.3's False Positive Trap box already names this driver for the broader systemd surface, and it applies identically here. Exclude systemd's own transient-unit naming convention (`run-*.scope`, `session-*.scope`) and known CI/CD deployment accounts rather than allowlisting individual unit names, which change too fast to maintain.

**[PIVOT]** Resolve the `ExecStart=` target inside the new unit file itself, not just the file-creation event — a path pointing to `/tmp`, a user home directory, or any location with no corresponding package-manager record is the strongest single follow-up signal, per DEH DET-11-03's own gating logic. Where `ExecStart` resolves to a shell or interpreter rather than a compiled binary, pull the full command-line arguments too, since DEH's own Blind Spot for this exact rule notes the payload can ride inside those arguments while the leading binary path looks unremarkable.

> **Hunter's Note**
> Don't stop at matching the unit file's path — actually read the unit file's `ExecStart=` line (or pull it from your EDR's file-content collection, if available) before deciding a hit is worth escalating. The file-creation event tells you *that* something changed; the `ExecStart` target is what tells you whether it's worth anyone's time.

## Cross-references

DEH Part 11 §5.2–§5.3 (Windows/Linux persistence telemetry, including the naive-rule teardown for systemd units and its DET-11-03 fix); DEH Part 28 §1.1 (YARA-L unconfirmed schema-field precedent); DEH Appendix A5 §4, §7.4, §8 (aggregation ceilings, investigative-search-before-standing-objects, and Elastic surface selection); DEH Parts 23–29 (query-language syntax and backend semantics, owned by DEH, not restated here); DEH Parts 41–43 (Detection Coverage, Quality, and Debt, applied to this book's own catalog in Part 28); this book's Part 11 (Account Creation & Privilege Escalation), Part 13 (Registry, Startup & Alternate Persistence), and Part 16 (Lateral Movement via Admin Tools & Remote Services).
